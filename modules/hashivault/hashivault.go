// Package hashivault works with a HashiCorp Vault or OpenBao server through
// its HTTP API: health and seal status, mounts, KV version 2 secrets (key
// names and metadata, values only through the destructive reveal_secret for
// the keys it names, writing
// a secret and restoring an earlier version), the token's own lookup and
// lease counts. It never seals, unseals or changes policies.
package hashivault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Vault (or OpenBao) server or cluster.
type Config struct {
	Address            string `json:"address"`   // e.g. https://vault.example.com:8200
	Token              string `json:"token"`     // secret:// token
	Namespace          string `json:"namespace"` // Vault Enterprise / OpenBao namespace
	KVMount            string `json:"kvMount"`   // default KV v2 mount, "secret"
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api   *rest.Client
	mount string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Vault module.
func New() *Module { return &Module{} }

const (
	maxKeys       = 256
	maxValue      = 64 << 10
	maxLeaseCalls = 200
	maxLeases     = 10000
)

var (
	segRe  = regexp.MustCompile(`^[A-Za-z0-9_.@+=:,~ -]{1,256}$`)
	mntRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	nsRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}(/[A-Za-z0-9_.-]{1,128})*$`)
	system = map[string]bool{"sys": true, "auth": true, "identity": true, "cubbyhole": true}
)

// segments checks a slash-separated path and returns it with each segment
// escaped. Empty segments, "." and ".." are refused.
func segments(s string, re *regexp.Regexp, what string) (string, error) {
	if s == "" || len(s) > 1024 {
		return "", fmt.Errorf("the %s is like app/prod/db", what)
	}
	parts := strings.Split(s, "/")
	for i, p := range parts {
		if p == "." || p == ".." || !re.MatchString(p) || strings.TrimSpace(p) != p {
			return "", fmt.Errorf("%q isn't a valid %s (letters, digits and _ . @ + = : , ~ - between slashes)", s, what)
		}
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/"), nil
}

// mountPath checks a mount like "secret" or "team/kv".
func mountPath(s string) (string, error) {
	s = strings.Trim(strings.TrimSpace(s), "/")
	esc, err := segments(s, mntRe, "mount")
	if err != nil {
		return "", err
	}
	// Any segment, not just the first: with a namespace prefix (ns1/sys),
	// Vault routes the rest to that namespace's system backends.
	for _, seg := range strings.Split(s, "/") {
		if system[strings.ToLower(seg)] {
			return "", fmt.Errorf("%s isn't a KV mount", s)
		}
	}
	return esc, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	mount := `"mount":{"type":"string","description":"KV version 2 mount (the instance's default when empty)"}`
	path := `"path":{"type":"string","description":"Secret path in the mount, e.g. app/prod/db"}`
	return sdk.Manifest{
		ID: "hashivault", Name: "HashiCorp Vault", Version: "0.1.0", Category: "Security", Icon: "key",
		Description: "HashiCorp Vault or OpenBao: seal status, mounts, KV v2 key names and metadata, revealing named values (destructive), writing a secret and restoring a version, token lookup, lease counts.",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["address","token"],"properties":{
			"address":{"type":"string","description":"The Vault API, e.g. https://vault.example.com:8200"},
			"token":{"type":"string","x-secret":true,"description":"Vault token. Its policies decide what works; read on the KV paths for reading, create/update for writing"},
			"namespace":{"type":"string","description":"Namespace (Vault Enterprise, OpenBao); empty for the root"},
			"kvMount":{"type":"string","default":"secret","description":"Default KV version 2 mount"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Health and seal status", Description: "Initialized, sealed, standby, version, cluster and unseal progress. Never seals or unseals.", Risk: sdk.RiskRead},
			{Name: "mounts", Title: "Mounts", Description: "Secret engine mounts with type, KV version and description.", Risk: sdk.RiskRead},
			{Name: "list_keys", Title: "List secrets", Description: "Secret names and folders under a path of a KV v2 mount. Never values.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + mount + `,"path":{"type":"string","description":"Folder, empty for the top"}}}`)},
			{Name: "metadata", Title: "Secret metadata", Description: "A secret's current version, versions with created and deleted times, max versions and custom metadata. Never values.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["path"],"properties":{` + mount + `,` + path + `}}`)},
			{Name: "read_secret", Title: "Read a secret's keys", Description: "The key names of a secret (one version), with its version and created time. Never values: reveal_secret returns those.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["path"],"properties":{` + mount + `,` + path + `,"version":{"type":"integer","minimum":1,"description":"Version, the current one when empty"}}}`)},
			{Name: "reveal_secret", Title: "Reveal secret values", Description: "The values of the named keys of a secret (one version, up to 32 keys), and only those. Revealing a credential is destructive: it can't be taken back.", Risk: sdk.RiskDestructive, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["path","keys"],"properties":{` + mount + `,` + path + `,"version":{"type":"integer","minimum":1,"description":"Version, the current one when empty"},"keys":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":32,"description":"Keys whose values to return"}}}`)},
			{Name: "write_secret", Title: "Write a secret", Description: "Writes a new version of a secret, replacing the credentials it holds (or, with merge, only the keys given). The preview lists keys added, changed and removed, never values. Undo restores the previous version.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["path","data"],"properties":{` + mount + `,` + path + `,"data":{"type":"object","additionalProperties":{"type":"string"},"description":"Key to value"},"merge":{"type":"boolean","description":"Keep the keys not given"}}}`)},
			{Name: "restore_version", Title: "Restore a secret version", Description: "Writes an earlier version's data as the new current version (KV v2 keeps the history). The preview shows key names of both. Undo restores the version that was current.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["path","version"],"properties":{` + mount + `,` + path + `,"version":{"type":"integer","minimum":1},"expectCurrent":{"type":"integer","minimum":1,"description":"Refuse when the current version isn't this one"}}}`)},
			{Name: "token", Title: "This token", Description: "The configured token's name, policies, type, TTL and expiry. Never the token or its accessor.", Risk: sdk.RiskRead},
			{Name: "leases", Title: "Lease count", Description: "Number of leases: all of them (from telemetry), or under a prefix like database/creds/app.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"prefix":{"type":"string","description":"Lease prefix, e.g. database/creds/readonly"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.Address))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return errors.New("the address is like https://vault.example.com:8200")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the Vault token in the vault and enter its secret:// reference")
	}
	ns := strings.Trim(strings.TrimSpace(c.Namespace), "/")
	if ns != "" && !nsRe.MatchString(ns) {
		return errors.New("the namespace is like team-a or team-a/prod")
	}
	mount := strings.Trim(strings.TrimSpace(c.KVMount), "/")
	if mount == "" {
		mount = "secret"
	}
	if _, err := mountPath(mount); err != nil {
		return err
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	tok := c.Token
	api := rest.New(u.Scheme+"://"+u.Host, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("X-Vault-Token", strings.TrimSpace(t))
		if ns != "" {
			r.Header.Set("X-Vault-Namespace", ns)
		}
		return nil
	})
	// X-Vault-Token is a custom header, which Go forwards on redirects.
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, mount: mount})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// vaultMessage pulls Vault's {"errors":["..."]} out of an API error.
func vaultMessage(err error) string {
	var e *rest.Error
	if !errors.As(err, &e) {
		return ""
	}
	i := strings.Index(e.Message, "{")
	if i < 0 {
		return ""
	}
	var body struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal([]byte(e.Message[i:]), &body) != nil || len(body.Errors) == 0 {
		return ""
	}
	return strings.Join(body.Errors, "; ")
}

func friendly(err error, what string) error {
	if err == nil {
		return nil
	}
	msg := vaultMessage(err)
	switch {
	case strings.Contains(msg, "check-and-set"):
		return errors.New("the secret changed while this ran; look again and retry")
	case rest.IsStatus(err, http.StatusForbidden), rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Vault refused: permission denied (check the token and its policies)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusServiceUnavailable):
		return errors.New("Vault is sealed or unavailable")
	case msg != "":
		return fmt.Errorf("Vault: %s", msg)
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return err
}

type health struct {
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Standby     bool   `json:"standby"`
	PerfStandby bool   `json:"performance_standby"`
	Version     string `json:"version"`
	ClusterName string `json:"cluster_name"`
}

func healthQuery() url.Values {
	// Ask for 200 in every state, so the body always comes back.
	q := url.Values{}
	for _, k := range []string{"standbycode", "sealedcode", "uninitcode", "drsecondarycode", "performancestandbycode", "removedcode"} {
		q.Set(k, "200")
	}
	return q
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var hs health
	if err := c.do(ctx, http.MethodGet, "/v1/sys/health", healthQuery(), nil, &hs); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	switch {
	case !hs.Initialized:
		return sdk.Health{Status: "down", Message: "Vault isn't initialized"}
	case hs.Sealed:
		return sdk.Health{Status: "down", Message: "Vault is sealed"}
	}
	var self struct {
		Data struct {
			DisplayName string `json:"display_name"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/auth/token/lookup-self", nil, nil, &self); err != nil {
		if rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "Vault refused the token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "unsealed · " + hs.Version
	if hs.Standby {
		msg += " · standby"
	}
	return sdk.Health{Status: "ok", Message: msg + " · token " + self.Data.DisplayName}
}

type input struct {
	Mount         string            `json:"mount"`
	Path          string            `json:"path"`
	Version       int               `json:"version"`
	Reveal        []string          `json:"reveal"` // refused: read_secret returns names only
	Keys          []string          `json:"keys"`
	Data          map[string]string `json:"data"`
	Merge         bool              `json:"merge"`
	ExpectCurrent int               `json:"expectCurrent"`
	Prefix        string            `json:"prefix"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// secret is a validated KV v2 secret location.
type secret struct {
	mount, path      string // as given, for output
	emount           string // escaped, for URLs
	dataURL, metaURL string
	display          string
}

func (c *conn) locate(p input) (secret, error) {
	mount := strings.Trim(strings.TrimSpace(p.Mount), "/")
	if mount == "" {
		mount = c.mount
	}
	em, err := mountPath(mount)
	if err != nil {
		return secret{}, err
	}
	path := strings.Trim(strings.TrimSpace(p.Path), "/")
	ep, err := segments(path, segRe, "secret path")
	if err != nil {
		return secret{}, err
	}
	return secret{mount: mount, path: path, emount: em, dataURL: "/v1/" + em + "/data/" + ep, metaURL: "/v1/" + em + "/metadata/" + ep, display: mount + "/" + path}, nil
}

// checkKV2 makes sure a mount is a KV version 2 engine before writing to it.
func (c *conn) checkKV2(ctx context.Context, s secret) error {
	var mi struct {
		Data struct {
			Type    string            `json:"type"`
			Options map[string]string `json:"options"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/sys/internal/ui/mounts/"+s.emount, nil, nil, &mi); err != nil {
		return friendly(err, "mount "+s.mount)
	}
	if (mi.Data.Type != "kv" && mi.Data.Type != "generic") || mi.Data.Options["version"] != "2" {
		return fmt.Errorf("%s isn't a KV version 2 mount (it's %s)", s.mount, mi.Data.Type)
	}
	return nil
}

type versionInfo struct {
	Created   string `json:"created_time"`
	Deleted   string `json:"deletion_time"`
	Destroyed bool   `json:"destroyed"`
}

type metadata struct {
	Current     int                    `json:"current_version"`
	Oldest      int                    `json:"oldest_version"`
	MaxVersions int                    `json:"max_versions"`
	CASRequired bool                   `json:"cas_required"`
	Created     string                 `json:"created_time"`
	Updated     string                 `json:"updated_time"`
	DeleteAfter string                 `json:"delete_version_after"`
	Custom      map[string]string      `json:"custom_metadata"`
	Versions    map[string]versionInfo `json:"versions"`
}

// meta returns a secret's metadata; found is false when it doesn't exist.
func (c *conn) meta(ctx context.Context, s secret) (metadata, bool, error) {
	var out struct {
		Data metadata `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, s.metaURL, nil, nil, &out)
	if rest.IsStatus(err, http.StatusNotFound) {
		return metadata{}, false, nil
	}
	if err != nil {
		return metadata{}, false, friendly(err, "secret "+s.display)
	}
	return out.Data, true, nil
}

func (md metadata) live(v int) bool {
	vi, ok := md.Versions[strconv.Itoa(v)]
	return ok && vi.Deleted == "" && !vi.Destroyed
}

// read returns one version's data (0 for current).
func (c *conn) read(ctx context.Context, s secret, version int) (map[string]json.RawMessage, int, string, error) {
	q := url.Values{}
	if version > 0 {
		q.Set("version", strconv.Itoa(version))
	}
	var out struct {
		Data struct {
			Data     map[string]json.RawMessage `json:"data"`
			Metadata struct {
				Version int    `json:"version"`
				Created string `json:"created_time"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, s.dataURL, q, nil, &out); err != nil {
		what := "secret " + s.display
		if version > 0 {
			what = fmt.Sprintf("version %d of %s", version, s.display)
		}
		return nil, 0, "", friendly(err, what+" (or it was deleted)")
	}
	if out.Data.Data == nil {
		return nil, 0, "", fmt.Errorf("%s has no data at that version (deleted or destroyed)", s.display)
	}
	return out.Data.Data, out.Data.Metadata.Version, out.Data.Metadata.Created, nil
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "status":
		var hs health
		if err := c.do(ctx, http.MethodGet, "/v1/sys/health", healthQuery(), nil, &hs); err != nil {
			return sdk.Result{}, err
		}
		var seal struct {
			Type         string `json:"type"`
			T            int    `json:"t"`
			N            int    `json:"n"`
			Progress     int    `json:"progress"`
			Migration    bool   `json:"migration"`
			RecoverySeal bool   `json:"recovery_seal"`
			StorageType  string `json:"storage_type"`
		}
		out := map[string]any{"initialized": hs.Initialized, "sealed": hs.Sealed, "standby": hs.Standby, "performanceStandby": hs.PerfStandby, "version": hs.Version, "cluster": hs.ClusterName}
		if c.do(ctx, http.MethodGet, "/v1/sys/seal-status", nil, nil, &seal) == nil {
			out["seal"] = map[string]any{"type": seal.Type, "threshold": seal.T, "shares": seal.N, "progress": seal.Progress, "storage": seal.StorageType, "recoverySeal": seal.RecoverySeal}
		}
		return sdk.JSON(out)

	case "mounts":
		type mnt struct {
			Type        string            `json:"type"`
			Description string            `json:"description"`
			Local       bool              `json:"local"`
			SealWrap    bool              `json:"seal_wrap"`
			Options     map[string]string `json:"options"`
		}
		var all map[string]json.RawMessage
		err := c.do(ctx, http.MethodGet, "/v1/sys/mounts", nil, nil, &all)
		source := "sys/mounts"
		if rest.IsStatus(err, http.StatusForbidden) {
			// Without sudo-ish rights, the UI endpoint lists what the token can use.
			var ui struct {
				Data struct {
					Secret map[string]json.RawMessage `json:"secret"`
				} `json:"data"`
			}
			if err = c.do(ctx, http.MethodGet, "/v1/sys/internal/ui/mounts", nil, nil, &ui); err == nil {
				all, source = ui.Data.Secret, "the mounts this token can use"
			}
		}
		if err != nil {
			return sdk.Result{}, friendly(err, "mount")
		}
		if d, ok := all["data"]; ok && len(all) > 1 {
			// Newer servers repeat the mounts under "data".
			var inner map[string]json.RawMessage
			if json.Unmarshal(d, &inner) == nil {
				all = inner
			}
		}
		list := []map[string]any{}
		for _, path := range keys(all) {
			var mt mnt
			if !strings.HasSuffix(path, "/") || json.Unmarshal(all[path], &mt) != nil || mt.Type == "" {
				continue
			}
			e := map[string]any{"path": path, "type": mt.Type, "description": mt.Description}
			if mt.Type == "kv" || mt.Type == "generic" {
				v := mt.Options["version"]
				if v == "" {
					v = "1"
				}
				e["kvVersion"] = v
			}
			if mt.Local {
				e["local"] = true
			}
			list = append(list, e)
		}
		return sdk.JSON(map[string]any{"source": source, "mounts": list})

	case "list_keys":
		mount := strings.Trim(strings.TrimSpace(p.Mount), "/")
		if mount == "" {
			mount = c.mount
		}
		em, err := mountPath(mount)
		if err != nil {
			return sdk.Result{}, err
		}
		u := "/v1/" + em + "/metadata/"
		folder := strings.Trim(strings.TrimSpace(p.Path), "/")
		if folder != "" {
			ep, err := segments(folder, segRe, "folder")
			if err != nil {
				return sdk.Result{}, err
			}
			u += ep + "/"
		}
		var out struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		err = c.do(ctx, http.MethodGet, u, url.Values{"list": {"true"}}, nil, &out)
		if err != nil && !rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, friendly(err, "folder")
		}
		var secrets, folders []string
		for _, k := range out.Data.Keys {
			if strings.HasSuffix(k, "/") {
				folders = append(folders, k)
			} else {
				secrets = append(secrets, k)
			}
		}
		return sdk.JSON(map[string]any{"mount": mount, "path": folder, "secrets": nonNil(secrets), "folders": nonNil(folders)})

	case "metadata":
		s, err := c.locate(p)
		if err != nil {
			return sdk.Result{}, err
		}
		md, found, err := c.meta(ctx, s)
		if err != nil {
			return sdk.Result{}, err
		}
		if !found {
			return sdk.Result{}, fmt.Errorf("there's no secret %s", s.display)
		}
		versions := []map[string]any{}
		for _, k := range keys(md.Versions) {
			n, _ := strconv.Atoi(k)
			vi := md.Versions[k]
			e := map[string]any{"version": n, "created": vi.Created}
			if vi.Deleted != "" {
				e["deleted"] = vi.Deleted
			}
			if vi.Destroyed {
				e["destroyed"] = true
			}
			versions = append(versions, e)
		}
		sort.Slice(versions, func(i, j int) bool { return versions[i]["version"].(int) > versions[j]["version"].(int) })
		return sdk.JSON(map[string]any{"name": s.display, "currentVersion": md.Current, "oldestVersion": md.Oldest, "maxVersions": md.MaxVersions, "casRequired": md.CASRequired,
			"created": md.Created, "updated": md.Updated, "deleteVersionAfter": md.DeleteAfter, "customMetadata": md.Custom, "versions": versions})

	case "read_secret", "reveal_secret":
		if call.Action == "read_secret" && len(p.Reveal) > 0 {
			return sdk.Result{}, errors.New("read_secret returns key names only; reveal_secret (destructive) returns the values of named keys")
		}
		s, err := c.locate(p)
		if err != nil {
			return sdk.Result{}, err
		}
		if p.Version < 0 {
			return sdk.Result{}, errors.New("the version is 1 or more")
		}
		reveal := call.Action == "reveal_secret"
		if reveal {
			if len(p.Keys) == 0 {
				return sdk.Result{}, errors.New("name the keys whose values to reveal (read_secret lists them)")
			}
			if len(p.Keys) > 32 {
				return sdk.Result{}, errors.New("reveal up to 32 keys at a time")
			}
			for _, k := range p.Keys {
				if !validKey(k) {
					return sdk.Result{}, fmt.Errorf("%q isn't a key name", k)
				}
			}
		}
		data, v, created, err := c.read(ctx, s, p.Version)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"name": s.display, "version": v, "created": created, "names": keys(data)}
		if reveal {
			vals := map[string]json.RawMessage{}
			var missing []string
			for _, k := range p.Keys {
				if val, ok := data[k]; ok {
					vals[k] = val
				} else {
					missing = append(missing, k)
				}
			}
			out["values"] = vals
			if len(missing) > 0 {
				out["missing"] = missing
			}
		}
		return sdk.JSON(out)

	case "write_secret":
		return c.write(ctx, call, p)
	case "restore_version":
		return c.restore(ctx, call, p)

	case "token":
		var self struct {
			Data struct {
				DisplayName      string            `json:"display_name"`
				Policies         []string          `json:"policies"`
				IdentityPolicies []string          `json:"identity_policies"`
				Type             string            `json:"type"`
				TTL              int64             `json:"ttl"`
				CreationTTL      int64             `json:"creation_ttl"`
				ExplicitMaxTTL   int64             `json:"explicit_max_ttl"`
				ExpireTime       *string           `json:"expire_time"`
				IssueTime        string            `json:"issue_time"`
				Renewable        bool              `json:"renewable"`
				Orphan           bool              `json:"orphan"`
				NumUses          int               `json:"num_uses"`
				Path             string            `json:"path"`
				EntityID         string            `json:"entity_id"`
				Meta             map[string]string `json:"meta"`
				Namespace        string            `json:"namespace_path"`
			} `json:"data"`
		}
		if err := c.do(ctx, http.MethodGet, "/v1/auth/token/lookup-self", nil, nil, &self); err != nil {
			return sdk.Result{}, friendly(err, "token")
		}
		d := self.Data
		out := map[string]any{"displayName": d.DisplayName, "policies": d.Policies, "identityPolicies": d.IdentityPolicies, "type": d.Type, "ttlSeconds": d.TTL,
			"creationTtlSeconds": d.CreationTTL, "explicitMaxTtlSeconds": d.ExplicitMaxTTL, "issued": d.IssueTime, "renewable": d.Renewable, "orphan": d.Orphan,
			"numUses": d.NumUses, "authPath": d.Path, "entityId": d.EntityID, "meta": d.Meta, "namespace": d.Namespace}
		if d.ExpireTime != nil {
			out["expires"] = *d.ExpireTime
		}
		if d.TTL == 0 && d.ExpireTime == nil {
			out["note"] = "this token never expires"
		}
		return sdk.JSON(out)

	case "leases":
		return c.leases(ctx, p.Prefix)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func sameString(old json.RawMessage, v string) bool {
	var s string
	return json.Unmarshal(old, &s) == nil && s == v
}

func validKey(k string) bool {
	return k != "" && len(k) <= 256 && utf8.ValidString(k) && !strings.ContainsFunc(k, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func (c *conn) write(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	s, err := c.locate(p)
	if err != nil {
		return sdk.Result{}, err
	}
	if len(p.Data) == 0 {
		return sdk.Result{}, errors.New("give the secret's data as key to value")
	}
	if len(p.Data) > maxKeys {
		return sdk.Result{}, fmt.Errorf("up to %d keys", maxKeys)
	}
	for k, v := range p.Data {
		if !validKey(k) {
			return sdk.Result{}, fmt.Errorf("%q isn't a valid key name", k)
		}
		if len(v) > maxValue {
			return sdk.Result{}, fmt.Errorf("the value of %s is over %d KiB", k, maxValue>>10)
		}
	}
	if err := c.checkKV2(ctx, s); err != nil {
		return sdk.Result{}, err
	}
	md, found, err := c.meta(ctx, s)
	if err != nil {
		return sdk.Result{}, err
	}
	prev := 0
	if found && md.live(md.Current) {
		prev = md.Current
	}
	var cur map[string]json.RawMessage
	readable := true
	if prev > 0 {
		cur, _, _, err = c.read(ctx, s, prev)
		if err != nil {
			if p.Merge {
				return sdk.Result{}, fmt.Errorf("merging needs to read the current secret: %w", err)
			}
			readable = false
		}
	}
	next := map[string]any{}
	if p.Merge {
		for k, v := range cur {
			next[k] = v
		}
	}
	for k, v := range p.Data {
		next[k] = v
	}
	var added, changed, same, removed []string
	for _, k := range keys(next) {
		old, had := cur[k]
		nv, given := p.Data[k]
		switch {
		case !given:
			same = append(same, k)
		case !had:
			added = append(added, k)
		case sameString(old, nv):
			same = append(same, k)
		default:
			changed = append(changed, k)
		}
	}
	for _, k := range keys(cur) {
		if _, ok := next[k]; !ok {
			removed = append(removed, k)
		}
	}
	if call.DryRun {
		var sum string
		if prev == 0 {
			sum = fmt.Sprintf("Create %s with %d key(s)", s.display, len(next))
			if found {
				sum = fmt.Sprintf("Write %s (its current version %d is deleted) with %d key(s)", s.display, md.Current, len(next))
			}
		} else {
			sum = fmt.Sprintf("Write version %d of %s, replacing version %d", md.Current+1, s.display, prev)
			if !readable {
				sum += "; the token can't read the current values, so which keys change is unknown and every key not given is dropped"
				added = keys(p.Data)
			} else if len(removed) > 0 {
				sum += fmt.Sprintf("; %d key(s) are dropped", len(removed))
			}
			sum += fmt.Sprintf("; undo restores version %d", prev)
		}
		before := map[string]any{"version": md.Current, "keys": nonNil(keys(cur))}
		after := map[string]any{"version": md.Current + 1, "added": nonNil(added), "changed": nonNil(changed), "unchanged": nonNil(same), "removed": nonNil(removed)}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "secret " + s.display, Op: map[bool]string{true: "update", false: "create"}[prev > 0], Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	var out struct {
		Data struct {
			Version int `json:"version"`
		} `json:"data"`
	}
	// Check-and-set on the version just seen, so a write in between fails.
	body := map[string]any{"options": map[string]any{"cas": md.Current}, "data": next}
	if err := c.do(ctx, http.MethodPost, s.dataURL, nil, body, &out); err != nil {
		return sdk.Result{}, friendly(err, "secret "+s.display)
	}
	res, err := sdk.JSON(map[string]any{"name": s.display, "version": out.Data.Version, "previousVersion": prev, "names": keys(next)})
	if prev > 0 && out.Data.Version > 0 {
		res.Undo = sdk.UndoWith("restore_version", map[string]any{"mount": s.mount, "path": s.path, "version": prev, "expectCurrent": out.Data.Version}, fmt.Sprintf("Restore version %d of %s", prev, s.display))
	}
	return res, err
}

func (c *conn) restore(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	s, err := c.locate(p)
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Version < 1 || p.ExpectCurrent < 0 {
		return sdk.Result{}, errors.New("give the version to restore (see metadata)")
	}
	if err := c.checkKV2(ctx, s); err != nil {
		return sdk.Result{}, err
	}
	md, found, err := c.meta(ctx, s)
	if err != nil {
		return sdk.Result{}, err
	}
	if !found {
		return sdk.Result{}, fmt.Errorf("there's no secret %s", s.display)
	}
	if p.ExpectCurrent > 0 && md.Current != p.ExpectCurrent {
		return sdk.Result{}, fmt.Errorf("%s is at version %d now, not %d; it changed since, so this is refused", s.display, md.Current, p.ExpectCurrent)
	}
	if p.Version == md.Current {
		return sdk.Result{}, fmt.Errorf("version %d is already the current one", p.Version)
	}
	if !md.live(p.Version) {
		return sdk.Result{}, fmt.Errorf("version %d of %s is gone (deleted, destroyed or past max versions)", p.Version, s.display)
	}
	data, _, _, err := c.read(ctx, s, p.Version)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		var cur map[string]json.RawMessage
		before := map[string]any{"version": md.Current}
		if md.live(md.Current) {
			if cd, _, _, err := c.read(ctx, s, md.Current); err == nil {
				cur = cd
				before["keys"] = keys(cd)
			}
		}
		var changed []string
		for k, v := range data {
			if old, ok := cur[k]; ok && string(old) != string(v) {
				changed = append(changed, k)
			}
		}
		sort.Strings(changed)
		sum := fmt.Sprintf("Write version %d of %s as a copy of version %d, replacing version %d", md.Current+1, s.display, p.Version, md.Current)
		if md.live(md.Current) {
			sum += fmt.Sprintf("; undo restores version %d", md.Current)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "secret " + s.display, Op: "restore", Before: mustJSON(before),
			After: mustJSON(map[string]any{"version": md.Current + 1, "copyOf": p.Version, "keys": keys(data), "changed": nonNil(changed)})}}}}, nil
	}
	var out struct {
		Data struct {
			Version int `json:"version"`
		} `json:"data"`
	}
	body := map[string]any{"options": map[string]any{"cas": md.Current}, "data": data}
	if err := c.do(ctx, http.MethodPost, s.dataURL, nil, body, &out); err != nil {
		return sdk.Result{}, friendly(err, "secret "+s.display)
	}
	res, err := sdk.JSON(map[string]any{"name": s.display, "restored": p.Version, "version": out.Data.Version, "names": keys(data)})
	if md.live(md.Current) && out.Data.Version > 0 {
		res.Undo = sdk.UndoWith("restore_version", map[string]any{"mount": s.mount, "path": s.path, "version": md.Current, "expectCurrent": out.Data.Version}, fmt.Sprintf("Restore version %d of %s", md.Current, s.display))
	}
	return res, err
}

func (c *conn) leases(ctx context.Context, prefix string) (sdk.Result, error) {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix == "" {
		var mt struct {
			Gauges []struct {
				Name  string  `json:"Name"`
				Value float64 `json:"Value"`
			} `json:"Gauges"`
		}
		if err := c.do(ctx, http.MethodGet, "/v1/sys/metrics", nil, nil, &mt); err != nil {
			return sdk.Result{}, fmt.Errorf("counting all leases needs read on sys/metrics (or give a prefix): %w", friendly(err, "metrics endpoint"))
		}
		out := map[string]any{}
		for _, g := range mt.Gauges {
			switch {
			case strings.HasSuffix(g.Name, "expire.num_leases"):
				out["leases"] = int64(g.Value)
			case strings.HasSuffix(g.Name, "expire.num_irrevocable_leases"):
				out["irrevocable"] = int64(g.Value)
			}
		}
		if _, ok := out["leases"]; !ok {
			return sdk.Result{}, errors.New("Vault's telemetry has no lease count; give a prefix to count by listing")
		}
		out["source"] = "telemetry"
		return sdk.JSON(out)
	}
	if _, err := segments(prefix, segRe, "lease prefix"); err != nil {
		return sdk.Result{}, err
	}
	total, calls, truncated := 0, 0, false
	by := map[string]int{}
	queue := []string{prefix + "/"}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		if calls == maxLeaseCalls || total >= maxLeases {
			truncated = true
			break
		}
		calls++
		esc, _ := segments(strings.TrimSuffix(dir, "/"), segRe, "lease prefix")
		var out struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		err := c.do(ctx, http.MethodGet, "/v1/sys/leases/lookup/"+esc+"/", url.Values{"list": {"true"}}, nil, &out)
		if rest.IsStatus(err, http.StatusNotFound) {
			continue
		}
		if err != nil {
			return sdk.Result{}, friendly(err, "lease prefix "+prefix)
		}
		for _, k := range out.Data.Keys {
			if strings.HasSuffix(k, "/") {
				sub := strings.TrimSuffix(k, "/")
				if sub == "" || sub == "." || sub == ".." || !segRe.MatchString(sub) {
					continue
				}
				queue = append(queue, dir+k)
				continue
			}
			total++
			by[strings.TrimSuffix(dir, "/")]++
		}
	}
	out := map[string]any{"prefix": prefix, "leases": total, "byPrefix": by, "source": "listing"}
	if truncated {
		out["truncated"] = true
		out["note"] = fmt.Sprintf("stopped after %d listings or %d leases; the count is at least this", maxLeaseCalls, maxLeases)
	}
	return sdk.JSON(out)
}
