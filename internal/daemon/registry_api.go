package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/internal/sandbox"
)

// Installing modules from a hub's registry. Only sandboxed (WebAssembly)
// builds install from here: they run with no access to this computer and
// reach only the hosts their permissions name, which the person installing
// sees first. Every version is signed by its author; the author's key is
// pinned the first time a package is installed, so a hub can't later hand
// over a build signed by someone else.

var regNameRe = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{1,38})/([a-z0-9][a-z0-9-]{0,62})$`)

const (
	regInstalledSetting = "registry.installed"
	regURLSetting       = "registry.url"
	maxWasm             = 32 << 20
)

// InstalledModule is one module installed from a registry.
type InstalledModule struct {
	Name        string    `json:"name"` // handle/module
	Version     string    `json:"version"`
	AuthorKey   string    `json:"authorKey"`   // base64 ed25519, pinned
	Fingerprint string    `json:"fingerprint"` // short form to compare
	ModuleID    string    `json:"moduleId"`
	Network     []string  `json:"network"`
	InstalledAt time.Time `json:"installedAt"`
	Latest      string    `json:"latest,omitempty"`
}

type regVersionPayload struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Homepage    string          `json:"homepage,omitempty"`
	Manifest    json.RawMessage `json:"manifest"`
	Artifacts   []struct {
		Platform string `json:"platform"`
		URL      string `json:"url"`
		SHA256   string `json:"sha256"`
	} `json:"artifacts"`
}

type regPackage struct {
	Package struct {
		Name        string `json:"name"`
		Owner       string `json:"owner"`
		Description string `json:"description"`
		Latest      string `json:"latest"`
	} `json:"package"`
	AuthorKey string `json:"authorKey"`
	Versions  []struct {
		Version   string `json:"version"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
		Yanked    bool   `json:"yanked"`
	} `json:"versions"`
}

func (s *Server) registryRoutes() []route {
	return []route{
		{"GET /api/v1/registry", s.need("admin:*:*", s.registrySearch)},
		{"GET /api/v1/registry/package", s.need("admin:*:*", s.registryPackage)},
		{"GET /api/v1/registry/installed", s.need("admin:*:*", s.registryInstalled)},
		{"POST /api/v1/registry/install", s.need("admin:*:*", s.registryInstall)},
		{"DELETE /api/v1/registry/installed", s.need("admin:*:*", s.registryRemove)},
	}
}

// registryBase is the registry to use: an explicit setting, else the hub
// this daemon is linked to.
func (s *Server) registryBase(ctx context.Context) (string, error) {
	var u string
	_ = s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, regURLSetting).Scan(&u)
	if u == "" && s.Remote != nil {
		u, _ = s.Remote.HubCredentials()
	}
	if u == "" {
		return "", errors.New("link this daemon to a hub to browse its modules")
	}
	return strings.TrimRight(u, "/"), nil
}

// Downloads only follow redirects that stay on https, so a hub can't point
// the daemon at plain-http or internal addresses through a redirect.
var regHTTP = &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" {
		return errors.New("refusing a redirect away from https")
	}
	return nil
}}

// registryMu keeps installs, updates and removals one at a time.
var registryMu sync.Mutex

func regGet(ctx context.Context, rawURL string, max int64, out any) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := regHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("the download is too large")
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the registry answered %s", res.Status)
	}
	if out != nil {
		return b, json.Unmarshal(b, out)
	}
	return b, nil
}

func (s *Server) registrySearch(w http.ResponseWriter, r *http.Request) {
	base, err := s.registryBase(r.Context())
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	var out json.RawMessage
	if _, err := regGet(r.Context(), base+"/v1/registry/packages?q="+url.QueryEscape(r.URL.Query().Get("q")), 4<<20, &out); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// verifiedVersion fetches a package and returns the newest (or the asked
// for) unyanked version whose signature checks out against the author key,
// and that key. A pinned key, if any, must match.
func (s *Server) verifiedVersion(ctx context.Context, name, want string) (regVersionPayload, string, error) {
	var vp regVersionPayload
	if !regNameRe.MatchString(name) {
		return vp, "", errors.New("module names look like author/module")
	}
	base, err := s.registryBase(ctx)
	if err != nil {
		return vp, "", err
	}
	var pkg regPackage
	if _, err := regGet(ctx, base+"/v1/registry/packages/"+name, 4<<20, &pkg); err != nil {
		return vp, "", err
	}
	key, err := base64.StdEncoding.DecodeString(pkg.AuthorKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return vp, "", errors.New("the registry sent no valid author key")
	}
	for _, m := range s.installedModules(ctx) {
		if m.Name == name && m.AuthorKey != pkg.AuthorKey {
			return vp, "", errors.New("this package is now signed with a different author key than when you installed it; refusing (remove it first if the author really changed keys)")
		}
	}
	vs := pkg.Versions
	sort.SliceStable(vs, func(i, j int) bool { return semverLess(vs[j].Version, vs[i].Version) })
	for _, v := range vs {
		if v.Yanked || (want != "" && v.Version != want) {
			continue
		}
		if want == "" && strings.Contains(v.Version, "-") {
			continue // prereleases only when asked for
		}
		raw, err1 := base64.StdEncoding.DecodeString(v.Payload)
		sig, err2 := base64.StdEncoding.DecodeString(v.Signature)
		if err1 != nil || err2 != nil || !ed25519.Verify(key, raw, sig) {
			return vp, "", fmt.Errorf("version %s isn't signed by the package's author", v.Version)
		}
		if err := json.Unmarshal(raw, &vp); err != nil || vp.Name != name || vp.Version != v.Version {
			return vp, "", fmt.Errorf("version %s doesn't describe this package", v.Version)
		}
		return vp, pkg.AuthorKey, nil
	}
	return vp, "", errors.New("no installable version found")
}

func semverLess(a, b string) bool {
	pa := strings.SplitN(strings.TrimPrefix(a, "v"), "-", 2)
	pb := strings.SplitN(strings.TrimPrefix(b, "v"), "-", 2)
	na, nb := strings.Split(pa[0], "."), strings.Split(pb[0], ".")
	for i := 0; i < 3 && i < len(na) && i < len(nb); i++ {
		var x, y int
		fmt.Sscan(na[i], &x)
		fmt.Sscan(nb[i], &y)
		if x != y {
			return x < y
		}
	}
	return len(pa) > len(pb) // a prerelease sorts before its release
}

type regPermissions struct {
	Permissions sandbox.Permissions `json:"permissions"`
	ID          string              `json:"id"`
}

func (s *Server) registryPackage(w http.ResponseWriter, r *http.Request) {
	vp, key, err := s.verifiedVersion(r.Context(), r.URL.Query().Get("name"), r.URL.Query().Get("version"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var perm regPermissions
	_ = json.Unmarshal(vp.Manifest, &perm)
	hasWasm := false
	for _, a := range vp.Artifacts {
		hasWasm = hasWasm || a.Platform == "wasm"
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": vp.Name, "version": vp.Version, "description": vp.Description, "homepage": vp.Homepage,
		"authorKey": key, "fingerprint": keyFingerprint(key), "network": nonNilStrings(perm.Permissions.Network), "memoryMB": perm.Permissions.MemoryMB,
		"installable": hasWasm})
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func (s *Server) installedModules(ctx context.Context) []InstalledModule {
	out := []InstalledModule{}
	var raw string
	if s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, regInstalledSetting).Scan(&raw) == nil {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

func (s *Server) saveInstalled(ctx context.Context, list []InstalledModule) error {
	b, _ := json.Marshal(list)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, regInstalledSetting, string(b))
	return err
}

func (s *Server) registryInstalled(w http.ResponseWriter, r *http.Request) {
	list := s.installedModules(r.Context())
	if r.URL.Query().Get("check") == "1" {
		for i := range list {
			if vp, _, err := s.verifiedVersion(r.Context(), list[i].Name, ""); err == nil {
				list[i].Latest = vp.Version
			}
		}
	}
	writeJSON(w, http.StatusOK, list)
}

func wasmPath(dataDir, name string) string {
	return filepath.Join(dataDir, "modules", strings.ReplaceAll(name, "/", "__")+".wasm")
}

// registryInstall installs or updates a package. Only people can install:
// a module runs code, even if sandboxed.
func (s *Server) registryInstall(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	var req struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		// Fingerprint is the author key fingerprint the person saw and
		// accepted; the install is refused if it changed in between.
		Fingerprint string `json:"fingerprint"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	vp, key, err := s.verifiedVersion(ctx, req.Name, req.Version)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Fingerprint == "" || req.Fingerprint != keyFingerprint(key) {
		writeErr(w, http.StatusConflict, "the author key isn't the one you were shown; look at the package again")
		return
	}
	var art *struct {
		Platform string `json:"platform"`
		URL      string `json:"url"`
		SHA256   string `json:"sha256"`
	}
	for i := range vp.Artifacts {
		if vp.Artifacts[i].Platform == "wasm" {
			art = &vp.Artifacts[i]
		}
	}
	if art == nil {
		writeErr(w, http.StatusBadRequest, "this package has no sandboxed (WebAssembly) build; native modules are installed by hand")
		return
	}
	if !strings.HasPrefix(art.URL, "https://") {
		writeErr(w, http.StatusBadRequest, "the download isn't https")
		return
	}
	wasm, err := regGet(ctx, art.URL, maxWasm, nil)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "download: "+err.Error())
		return
	}
	sum := sha256.Sum256(wasm)
	if hex.EncodeToString(sum[:]) != strings.ToLower(art.SHA256) {
		writeErr(w, http.StatusBadGateway, "the download doesn't match the signed checksum")
		return
	}
	var perm regPermissions
	_ = json.Unmarshal(vp.Manifest, &perm)
	handle := strings.SplitN(vp.Name, "/", 2)[0]

	// Start it before keeping anything, and check it uses its own id space.
	m, err := sandbox.Start(context.WithoutCancel(ctx), wasm, perm.Permissions, s.Log, sandbox.Options{})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "the module didn't start: "+err.Error())
		return
	}
	id := m.Manifest().ID
	if strings.HasPrefix(id, "mcp-") {
		_ = m.Stop()
		writeErr(w, http.StatusBadRequest, "ids starting with mcp- belong to mounted MCP servers")
		return
	}
	if !strings.HasPrefix(id, handle+"-") {
		_ = m.Stop()
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("the module calls itself %q; modules from %s must use ids starting with %q", id, handle, handle+"-"))
		return
	}
	list := s.installedModules(ctx)
	for _, x := range list {
		if x.Name == vp.Name && semverLess(vp.Version, x.Version) {
			_ = m.Stop()
			writeErr(w, http.StatusConflict, fmt.Sprintf("%s %s is installed; remove it first to go back to %s", x.Name, x.Version, vp.Version))
			return
		}
	}
	for i, x := range list {
		if x.Name == vp.Name {
			// An update: stop the old one.
			if old, ok := s.Engine.Module(x.ModuleID); ok {
				s.Engine.Unregister(x.ModuleID)
				if st, ok := old.(interface{ Stop() error }); ok {
					_ = st.Stop()
				}
			}
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if err := s.Engine.Register(m); err != nil {
		_ = m.Stop()
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	dir := filepath.Join(s.dataDir(), "modules")
	_ = os.MkdirAll(dir, 0o700)
	p := wasmPath(s.dataDir(), vp.Name)
	spec, _ := json.Marshal(sandbox.Spec{Permissions: perm.Permissions})
	if err := os.WriteFile(p, wasm, 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = os.WriteFile(strings.TrimSuffix(p, ".wasm")+".json", spec, 0o600)
	im := InstalledModule{Name: vp.Name, Version: vp.Version, AuthorKey: key, Fingerprint: keyFingerprint(key), ModuleID: id,
		Network: nonNilStrings(perm.Permissions.Network), InstalledAt: time.Now().UTC()}
	list = append(list, im)
	_ = s.saveInstalled(ctx, list)
	s.auditConfig(r, "module_installed", "", map[string]any{"name": vp.Name, "version": vp.Version, "module": id, "network": im.Network, "fingerprint": im.Fingerprint})
	writeJSON(w, http.StatusOK, im)
}

func (s *Server) registryRemove(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	name := r.URL.Query().Get("name")
	list := s.installedModules(r.Context())
	for i, x := range list {
		if x.Name != name {
			continue
		}
		for _, in := range s.Engine.Instances(x.ModuleID) {
			_ = s.Engine.DeleteInstance(r.Context(), in.ID)
		}
		if old, ok := s.Engine.Module(x.ModuleID); ok {
			s.Engine.Unregister(x.ModuleID)
			if st, ok := old.(interface{ Stop() error }); ok {
				_ = st.Stop()
			}
		}
		p := wasmPath(s.dataDir(), name)
		_ = os.Remove(p)
		_ = os.Remove(strings.TrimSuffix(p, ".wasm") + ".json")
		_ = s.saveInstalled(r.Context(), append(list[:i], list[i+1:]...))
		s.auditConfig(r, "module_removed", "", map[string]string{"name": name})
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeErr(w, http.StatusNotFound, "not installed")
}

// keyFingerprint is a short, comparable form of an author key: the first 16
// bytes of its SHA-256, base64url.
func keyFingerprint(stdB64 string) string {
	b, err := base64.StdEncoding.DecodeString(stdB64)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(h[:16])
}
