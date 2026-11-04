// Package seafile works with a Seafile server through its web API and an
// API token: libraries, folder listings, file details, and creating and
// revoking share links.
package seafile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Seafile account.
type Config struct {
	URL                string `json:"url"`   // e.g. https://seafile.example.com
	Token              string `json:"token"` // secret:// API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Seafile module.
func New() *Module { return &Module{} }

var (
	basePathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	repoRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	linkIDRe   = regexp.MustCompile(`^l[0-9a-f]{24}$`)
	tokenRe    = regexp.MustCompile(`^[A-Za-z0-9]{6,100}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	repo := `"repo":{"type":"string","description":"Library id (from libraries)"}`
	path := `"path":{"type":"string","description":"A path in the library, like /Documents/report.pdf"}`
	return sdk.Manifest{
		ID: "seafile", Name: "Seafile", Version: "0.1.0", Category: "Storage", Icon: "cloud",
		Description: "Seafile: libraries, folder listings, file details, and creating or revoking share links.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Your Seafile server, e.g. https://seafile.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API token (Settings, Web API Auth Token, or from /api2/auth-token/); it acts as its user"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "libraries", Title: "Libraries", Description: "Libraries you can reach: id, name, size, last change, whether it's yours, shared or a group's, encrypted, and your permission.", Risk: sdk.RiskRead},
			{Name: "list_dir", Title: "List a folder", Description: "Files and folders in a library folder: name, type, size, modified.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["repo"],"properties":{` + repo + `,"path":{"type":"string","default":"/","description":"Folder path (default: the top)"},"limit":{"type":"integer","default":500,"maximum":2000}}}`)},
			{Name: "file_info", Title: "File details", Description: "A file's name, size, modified time and id.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","path"],"properties":{` + repo + `,` + path + `}}`)},
			{Name: "share_links", Title: "Share links", Description: "Your share links, or those of one file or folder: link, path, views, expiry and the id revoke_share_link takes. Passwords are never returned.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + repo + `,` + path + `}}`)},
			{Name: "create_share_link", Title: "Create a share link", Description: "Makes a view-and-download link to a file or folder that anyone who has it can open, optionally with a password and an expiry. If the item already has a link and no password or expiry is asked, that one is returned. Undo revokes the new link.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["repo","path"],"properties":{` + repo + `,` + path + `,"password":{"type":"string","description":"Optional password (at least 8 characters on most servers); never shown again"},"expireDays":{"type":"integer","minimum":1,"maximum":3650}}}`)},
			{Name: "revoke_share_link", Title: "Revoke a share link", Description: "Deletes a share link by its id (from share_links); people with the link can't open it any more.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"The link's id from share_links or create_share_link"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !basePathRe.MatchString(u.Path) {
		return errors.New("the address is like https://seafile.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	ref := c.Token
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Token "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Seafile refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token's user isn't allowed to do this in Seafile")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("there's nothing at that path in Seafile")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

// checkPath validates a path inside a library: "/" or /a/b with no empty,
// . or .. parts and no control characters. Paths only go in query strings
// and JSON bodies.
func checkPath(s string, top bool) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "/" {
		if top {
			return "/", nil
		}
		return "", errors.New("give a path in the library, like /Documents/report.pdf")
	}
	if !strings.HasPrefix(s, "/") || len(s) > 1024 || strings.Contains(s, "//") || strings.ContainsAny(s, "\\") || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errors.New("a path starts with / and has no empty parts, backslashes or control characters, like /Documents/report.pdf")
	}
	for _, seg := range strings.Split(strings.TrimRight(s[1:], "/"), "/") {
		if seg == "." || seg == ".." {
			return "", errors.New("a path can't contain . or .. parts")
		}
	}
	if len(s) > 1 {
		s = strings.TrimRight(s, "/")
	}
	return s, nil
}

func checkRepo(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !repoRe.MatchString(s) {
		return "", errors.New("a library is its id from libraries")
	}
	return s, nil
}

// linkID names a share link without its token: the token is what opens the
// link, so it stays out of undo tokens and the audit log.
func linkID(token string) string {
	h := sha256.Sum256([]byte("seafile-share:" + token))
	return "l" + hex.EncodeToString(h[:12])
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var a struct {
		Usage int64 `json:"usage"`
		Total int64 `json:"total"`
	}
	if err := c.do(ctx, http.MethodGet, "/api2/account/info/", nil, nil, &a); err != nil {
		if strings.HasPrefix(err.Error(), "there's nothing") {
			return sdk.Health{Status: "down", Message: "no Seafile API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	gb := func(n int64) string { return fmt.Sprintf("%.1f GB", float64(n)/(1<<30)) }
	if a.Total > 0 {
		return sdk.Health{Status: "ok", Message: gb(a.Usage) + " of " + gb(a.Total) + " used"}
	}
	return sdk.Health{Status: "ok", Message: gb(a.Usage) + " used"}
}

type input struct {
	Repo       string `json:"repo"`
	Path       string `json:"path"`
	Limit      int    `json:"limit"`
	Password   string `json:"password"`
	ExpireDays int    `json:"expireDays"`
	ID         string `json:"id"`
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
	case "libraries":
		return c.libraries(ctx)
	case "list_dir":
		repo, err := checkRepo(p.Repo)
		if err != nil {
			return sdk.Result{}, err
		}
		path, err := checkPath(p.Path, true)
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.Limit
		if n <= 0 {
			n = 500
		}
		if n > 2000 {
			n = 2000
		}
		return c.listDir(ctx, repo, path, n)
	case "file_info":
		repo, err := checkRepo(p.Repo)
		if err != nil {
			return sdk.Result{}, err
		}
		path, err := checkPath(p.Path, false)
		if err != nil {
			return sdk.Result{}, err
		}
		var f struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Type  string `json:"type"`
			Size  int64  `json:"size"`
			MTime int64  `json:"mtime"`
		}
		if err := c.do(ctx, http.MethodGet, "/api2/repos/"+repo+"/file/detail/", url.Values{"p": {path}}, nil, &f); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"name": f.Name, "path": path, "size": f.Size, "modified": unix(f.MTime), "id": f.ID})
	case "share_links":
		q := url.Values{}
		if p.Repo != "" || p.Path != "" {
			repo, err := checkRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			q.Set("repo_id", repo)
			if p.Path != "" {
				path, err := checkPath(p.Path, true)
				if err != nil {
					return sdk.Result{}, err
				}
				q.Set("path", path)
			}
		}
		ls, err := c.links(ctx, q)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, l := range ls {
			out = append(out, l.row())
		}
		return sdk.JSON(out)
	case "create_share_link":
		repo, err := checkRepo(p.Repo)
		if err != nil {
			return sdk.Result{}, err
		}
		path, err := checkPath(p.Path, false)
		if err != nil {
			return sdk.Result{}, err
		}
		if p.Password != "" && (len(p.Password) > 256 || strings.ContainsFunc(p.Password, func(r rune) bool { return r < 0x20 })) {
			return sdk.Result{}, errors.New("the password is one line of at most 256 characters")
		}
		if p.ExpireDays < 0 || p.ExpireDays > 3650 {
			return sdk.Result{}, errors.New("expireDays is 1 to 3650")
		}
		return c.share(ctx, call, repo, path, p)
	case "revoke_share_link":
		id := strings.TrimSpace(p.ID)
		if !linkIDRe.MatchString(id) {
			return sdk.Result{}, errors.New("the id is a link's id from share_links, like l3f2a…")
		}
		return c.revoke(ctx, call, id)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func unix(t int64) string {
	if t <= 0 {
		return ""
	}
	return time.Unix(t, 0).UTC().Format(time.RFC3339)
}

func (c *conn) libraries(ctx context.Context) (sdk.Result, error) {
	// Owner names and emails aren't decoded: they'd end up in the audit log.
	var rs []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Type       string `json:"type"`
		Size       int64  `json:"size"`
		MTime      int64  `json:"mtime"`
		Encrypted  bool   `json:"encrypted"`
		Permission string `json:"permission"`
	}
	if err := c.do(ctx, http.MethodGet, "/api2/repos/", nil, nil, &rs); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, r := range rs {
		kind := r.Type
		switch r.Type {
		case "repo", "mine":
			kind = "mine"
		case "srepo":
			kind = "shared"
		case "grepo":
			kind = "group"
		}
		out = append(out, map[string]any{"id": r.ID, "name": r.Name, "kind": kind, "size": r.Size, "modified": unix(r.MTime), "encrypted": r.Encrypted, "permission": r.Permission})
	}
	return sdk.JSON(out)
}

func (c *conn) listDir(ctx context.Context, repo, path string, n int) (sdk.Result, error) {
	var es []struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Size  int64  `json:"size"`
		MTime int64  `json:"mtime"`
	}
	if err := c.do(ctx, http.MethodGet, "/api2/repos/"+repo+"/dir/", url.Values{"p": {path}}, nil, &es); err != nil {
		if rest.IsStatus(err, 440) || strings.Contains(err.Error(), "encrypted") {
			return sdk.Result{}, errors.New("the library is encrypted; unlock it in Seafile first")
		}
		return sdk.Result{}, err
	}
	list := []map[string]any{}
	for _, e := range es {
		if len(list) >= n {
			break
		}
		r := map[string]any{"type": e.Type, "name": e.Name, "modified": unix(e.MTime)}
		if e.Type == "file" {
			r["size"] = e.Size
		}
		list = append(list, r)
	}
	res := map[string]any{"path": path, "entries": list}
	if len(es) > n {
		res["more"] = true
	}
	return sdk.JSON(res)
}

type link struct {
	RepoID   string `json:"repo_id"`
	RepoName string `json:"repo_name"`
	Path     string `json:"path"`
	ObjName  string `json:"obj_name"`
	IsDir    bool   `json:"is_dir"`
	Token    string `json:"token"`
	Link     string `json:"link"`
	Views    int    `json:"view_cnt"`
	Created  string `json:"ctime"`
	Expires  string `json:"expire_date"`
	Expired  bool   `json:"is_expired"`
	// The password (some versions return it to the owner) isn't decoded.
}

func (l link) row() map[string]any {
	r := map[string]any{"id": linkID(l.Token), "url": l.Link, "library": l.RepoName, "repo": l.RepoID, "path": l.Path, "name": l.ObjName,
		"folder": l.IsDir, "views": l.Views, "created": l.Created}
	if l.Expires != "" {
		r["expires"] = l.Expires
		r["expired"] = l.Expired
	}
	return r
}

// links lists share links, every page of them.
func (c *conn) links(ctx context.Context, q url.Values) ([]link, error) {
	var all []link
	seen := map[string]bool{}
	const per = 200
	for page := 1; page <= 50; page++ {
		pq := url.Values{}
		for k, v := range q {
			pq[k] = v
		}
		pq.Set("page", strconv.Itoa(page))
		pq.Set("per_page", strconv.Itoa(per))
		var ls []link
		if err := c.do(ctx, http.MethodGet, "/api/v2.1/share-links/", pq, nil, &ls); err != nil {
			return nil, err
		}
		added := 0
		for _, l := range ls {
			if !tokenRe.MatchString(l.Token) || seen[l.Token] {
				continue
			}
			seen[l.Token] = true
			all = append(all, l)
			added++
		}
		// A server without paging returns everything on each page.
		if len(ls) < per || added == 0 {
			break
		}
	}
	return all, nil
}

func (c *conn) share(ctx context.Context, call sdk.Call, repo, path string, p input) (sdk.Result, error) {
	existing, err := c.links(ctx, url.Values{"repo_id": {repo}, "path": {path}})
	if err != nil {
		return sdk.Result{}, err
	}
	for _, l := range existing {
		if l.RepoID == repo && strings.TrimRight(l.Path, "/") == path && !l.Expired && p.Password == "" && p.ExpireDays == 0 {
			r := l.row()
			r["note"] = "nothing to change: the item already has a share link"
			return sdk.JSON(r)
		}
	}
	if call.DryRun {
		after := map[string]any{"library": repo, "path": path, "access": "view and download", "audience": "anyone with the link", "password": p.Password != ""}
		if p.ExpireDays > 0 {
			after["expiresInDays"] = p.ExpireDays
		}
		b, _ := json.Marshal(after)
		return sdk.Result{Plan: &sdk.Plan{Summary: "Create a share link to " + path + " that anyone who has it can open", Changes: []sdk.Change{{Target: path, Op: "share", After: b}}}}, nil
	}
	body := map[string]any{"repo_id": repo, "path": path, "permissions": map[string]bool{"can_edit": false, "can_download": true}}
	if p.Password != "" {
		body["password"] = p.Password
	}
	if p.ExpireDays > 0 {
		body["expire_days"] = p.ExpireDays
	}
	var l link
	if err := c.do(ctx, http.MethodPost, "/api/v2.1/share-links/", nil, body, &l); err != nil {
		if rest.IsStatus(err, http.StatusBadRequest) {
			return sdk.Result{}, errors.New("Seafile refused the link (the password may be too short, or the library is encrypted)")
		}
		return sdk.Result{}, err
	}
	if !tokenRe.MatchString(l.Token) {
		return sdk.Result{}, errors.New("unexpected answer from Seafile")
	}
	res, err := sdk.JSON(l.row())
	id := linkID(l.Token)
	// The undo names the link by its id, never by its token.
	res.Undo = sdk.UndoWith("revoke_share_link", map[string]string{"id": id}, "Revoke the link to "+path)
	return res, err
}

func (c *conn) revoke(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	ls, err := c.links(ctx, url.Values{})
	if err != nil {
		return sdk.Result{}, err
	}
	var found *link
	for i := range ls {
		if linkID(ls[i].Token) == id {
			found = &ls[i]
			break
		}
	}
	if found == nil {
		return sdk.JSON(map[string]any{"revoked": 0, "note": "nothing to change: there's no share link with that id"})
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]any{"library": found.RepoName, "path": found.Path, "views": found.Views})
		return sdk.Result{Plan: &sdk.Plan{Summary: "Revoke the share link to " + found.Path + "; people with it lose access",
			Changes: []sdk.Change{{Target: found.Path, Op: "revoke", Before: b}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, "/api/v2.1/share-links/"+url.PathEscape(found.Token)+"/", nil, nil, nil); err != nil {
		if strings.HasPrefix(err.Error(), "there's nothing") {
			return sdk.JSON(map[string]any{"revoked": 0, "note": "nothing to change: the link was already gone"})
		}
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"revoked": 1, "id": id, "path": found.Path})
}
