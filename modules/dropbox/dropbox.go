// Package dropbox works with a Dropbox account through its HTTP API with a
// refresh token and the app's key and secret: listing folders, searching,
// file details, and creating and revoking shared links.
package dropbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/oauth"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Dropbox account.
type Config struct {
	AppKey       string `json:"appKey"`
	AppSecret    string `json:"appSecret"`    // secret://
	RefreshToken string `json:"refreshToken"` // secret://
}

type conn struct {
	cfg      Config
	host     sdk.Host
	http     *http.Client
	base     string
	tokenURL string
	tok      oauth.Cache
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://api.dropboxapi.com, TokenURL the token endpoint
	// and HTTP the client (tests). They aren't settings, so an instance
	// can't send its credentials anywhere else.
	Base     string
	TokenURL string
	HTTP     *http.Client
}

// New returns the Dropbox module.
func New() *Module { return &Module{} }

var (
	appKeyRe  = regexp.MustCompile(`^[A-Za-z0-9]{8,32}$`)
	fileIDRe  = regexp.MustCompile(`^id:[A-Za-z0-9_-]{1,100}$`)
	summaryRe = regexp.MustCompile(`^[a-z_/.]{1,120}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	path := `"path":{"type":"string","description":"A path like /Documents/report.pdf, or a file id (id:…)"}`
	return sdk.Manifest{
		ID: "dropbox", Name: "Dropbox", Version: "0.1.0", Category: "Storage", Icon: "folder",
		Description: "Dropbox files: list folders, search, file details, and create or revoke shared links.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["appKey","appSecret","refreshToken"],"properties":{
			"appKey":{"type":"string","description":"Your Dropbox app's key (App Console, Settings)"},
			"appSecret":{"type":"string","x-secret":true,"description":"The app's secret"},
			"refreshToken":{"type":"string","x-secret":true,"description":"A refresh token from the offline-access sign-in the docs describe"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "list_folder", Title: "List a folder", Description: "Files and folders in a folder: name, path, size, modified.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"path":{"type":"string","description":"Folder path (empty: the top of your Dropbox)"},"recursive":{"type":"boolean"},"limit":{"type":"integer","default":200,"maximum":1000}}}`)},
			{Name: "search", Title: "Search", Description: "Files and folders whose name or content matches.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},"path":{"type":"string","description":"Only under this folder"},"limit":{"type":"integer","default":50,"maximum":100}}}`)},
			{Name: "metadata", Title: "File details", Description: "A file's or folder's name, path, id, size, modified time and content hash.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["path"],"properties":{` + path + `}}`)},
			{Name: "create_shared_link", Title: "Create a shared link", Description: "Makes a view-only link with the account's default audience: anyone who has it, unless a Dropbox team's policy limits links to members (the result names the audience). If the file already has one, that one is returned. Undo revokes every link to the file.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["path"],"properties":{` + path + `,"expires":{"type":"string","description":"RFC 3339 expiry (paid plans)"}}}`)},
			{Name: "revoke_shared_link", Title: "Revoke shared links", Description: "Revokes a shared link, or every link to a file (by its id). People with the link can't open it any more.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"url":{"type":"string","description":"The link to revoke"},"id":{"type":"string","description":"Or a file id (id:…): revoke all its links"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.AppKey = strings.TrimSpace(c.AppKey)
	if !appKeyRe.MatchString(c.AppKey) {
		return errors.New("add the app key from the Dropbox App Console")
	}
	if !strings.HasPrefix(c.AppSecret, "secret://") || !strings.HasPrefix(c.RefreshToken, "secret://") {
		return errors.New("store the app secret and the refresh token in the vault and enter their secret:// references")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	base, tokenURL := strings.TrimRight(m.Base, "/"), m.TokenURL
	if base == "" {
		base = "https://api.dropboxapi.com"
	}
	if tokenURL == "" {
		tokenURL = "https://api.dropboxapi.com/oauth2/token"
	}
	m.set.Put(id, &conn{cfg: c, host: h, http: rest.SameHostOnly(client), base: base, tokenURL: tokenURL})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) token(ctx context.Context) (string, error) {
	return c.tok.Get(ctx, func(ctx context.Context) (oauth.Grant, error) {
		secret, err := c.host.Secret(ctx, c.cfg.AppSecret)
		if err != nil {
			return oauth.Grant{}, err
		}
		refresh, err := c.host.Secret(ctx, c.cfg.RefreshToken)
		if err != nil {
			return oauth.Grant{}, err
		}
		g, err := oauth.Exchange(ctx, c.http, c.tokenURL, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {strings.TrimSpace(refresh)}},
			c.cfg.AppKey, strings.TrimSpace(secret))
		var e *oauth.Error
		if errors.As(err, &e) {
			switch e.Code {
			case "invalid_grant":
				return g, errors.New("Dropbox refused the refresh token (revoked, or issued to another app); sign in again for a new one")
			case "invalid_client", "unauthorized_client":
				return g, errors.New("Dropbox refused the app key or secret")
			}
			return g, fmt.Errorf("Dropbox didn't issue a token: %v", e)
		}
		return g, err
	})
}

// apiError is a Dropbox endpoint error (HTTP 409) with its tag path, like
// path/not_found.
type apiError struct{ Summary string }

func (e *apiError) Error() string {
	switch {
	case strings.HasPrefix(e.Summary, "path/not_found"), strings.HasPrefix(e.Summary, "path_lookup/not_found"):
		return "there's nothing at that path in Dropbox"
	case strings.Contains(e.Summary, "settings_error"):
		return "Dropbox refused the link settings (an expiry needs a paid plan)"
	case strings.Contains(e.Summary, "access_denied"), strings.Contains(e.Summary, "no_permission"):
		return "the app isn't allowed to do this (check its permissions in the App Console)"
	case e.Summary == "":
		return "Dropbox refused the request"
	}
	return "Dropbox: " + e.Summary
}

func (c *conn) rpc(ctx context.Context, endpoint string, args, out any) error {
	err := c.rpcOnce(ctx, endpoint, args, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.tok.Drop()
		err = c.rpcOnce(ctx, endpoint, args, out)
	}
	return err
}

func (c *conn) rpcOnce(ctx context.Context, endpoint string, args, out any) error {
	tok, err := c.token(ctx)
	if err != nil {
		return err
	}
	var body io.Reader
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/2/"+endpoint, body)
	if err != nil {
		return err
	}
	if args != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", "Conduit")
	res, err := c.http.Do(req)
	if err != nil {
		return rest.TransportError(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	switch {
	case res.StatusCode == http.StatusConflict:
		var e struct {
			Summary string `json:"error_summary"`
		}
		_ = json.Unmarshal(raw, &e)
		s := strings.TrimRight(strings.TrimSuffix(e.Summary, "..."), "/.")
		if !summaryRe.MatchString(s) {
			s = ""
		}
		return &apiError{Summary: s}
	case res.StatusCode == http.StatusUnauthorized:
		return &rest.Error{Status: res.StatusCode, Message: "Dropbox refused the access token"}
	case res.StatusCode == http.StatusForbidden:
		return &rest.Error{Status: res.StatusCode, Message: "the app isn't allowed to do this (check its permissions in the App Console)"}
	case res.StatusCode >= 300:
		return &rest.Error{Status: res.StatusCode, Message: "Dropbox answered " + res.Status}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return errors.New("unexpected answer from Dropbox")
		}
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u struct {
		Used       int64 `json:"used"`
		Allocation struct {
			Allocated int64 `json:"allocated"`
		} `json:"allocation"`
	}
	if err := c.rpc(ctx, "users/get_space_usage", nil, &u); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	gb := func(n int64) string { return fmt.Sprintf("%.1f GB", float64(n)/(1<<30)) }
	if u.Allocation.Allocated > 0 {
		return sdk.Health{Status: "ok", Message: gb(u.Used) + " of " + gb(u.Allocation.Allocated) + " used"}
	}
	return sdk.Health{Status: "ok", Message: gb(u.Used) + " used"}
}

// checkPath validates a Dropbox path ("" for the top when allowed) or a
// file id. Paths go in JSON bodies, never in URLs.
func checkPath(s string, top bool) (string, error) {
	s = strings.TrimSpace(s)
	if fileIDRe.MatchString(s) {
		return s, nil
	}
	if s == "" || s == "/" {
		if top {
			return "", nil
		}
		return "", errors.New("give a path like /Documents/report.pdf, or a file id")
	}
	if !strings.HasPrefix(s, "/") || len(s) > 1024 || strings.Contains(s, "//") || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", errors.New("a path starts with / and has no empty parts or control characters, like /Documents/report.pdf")
	}
	for _, seg := range strings.Split(s[1:], "/") {
		if seg == "." || seg == ".." {
			return "", errors.New("a path can't contain . or .. parts")
		}
	}
	return strings.TrimRight(s, "/"), nil
}

type entry struct {
	Tag      string `json:".tag"`
	Name     string `json:"name"`
	Path     string `json:"path_display"`
	ID       string `json:"id"`
	Size     int64  `json:"size"`
	Modified string `json:"server_modified"`
	Hash     string `json:"content_hash"`
}

func (e entry) row() map[string]any {
	r := map[string]any{"type": e.Tag, "name": e.Name, "path": e.Path, "id": e.ID}
	if e.Tag == "file" {
		r["size"] = e.Size
		r["modified"] = e.Modified
	}
	return r
}

type input struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
	Limit     int    `json:"limit"`
	Query     string `json:"query"`
	Expires   string `json:"expires"`
	URL       string `json:"url"`
	ID        string `json:"id"`
}

func limit(n, def, max int) int {
	if n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
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
	case "list_folder":
		path, err := checkPath(p.Path, true)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.listFolder(ctx, path, p.Recursive, limit(p.Limit, 200, 1000))
	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" || len(q) > 200 || strings.ContainsFunc(q, func(r rune) bool { return r < 0x20 }) {
			return sdk.Result{}, errors.New("the query is one line of 1 to 200 characters")
		}
		path, err := checkPath(p.Path, true)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.search(ctx, q, path, limit(p.Limit, 50, 100))
	case "metadata":
		path, err := checkPath(p.Path, false)
		if err != nil {
			return sdk.Result{}, err
		}
		var e entry
		if err := c.rpc(ctx, "files/get_metadata", map[string]any{"path": path}, &e); err != nil {
			return sdk.Result{}, err
		}
		r := e.row()
		if e.Hash != "" {
			r["contentHash"] = e.Hash
		}
		return sdk.JSON(r)
	case "create_shared_link":
		path, err := checkPath(p.Path, false)
		if err != nil {
			return sdk.Result{}, err
		}
		var exp string
		if s := strings.TrimSpace(p.Expires); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil || !t.After(time.Now()) {
				return sdk.Result{}, errors.New("expires is a future time in RFC 3339, like 2026-12-01T00:00:00Z")
			}
			exp = t.UTC().Format("2006-01-02T15:04:05Z")
		}
		return c.share(ctx, call, path, exp)
	case "revoke_shared_link":
		return c.revoke(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) listFolder(ctx context.Context, path string, recursive bool, n int) (sdk.Result, error) {
	var out struct {
		Entries []entry `json:"entries"`
		Cursor  string  `json:"cursor"`
		HasMore bool    `json:"has_more"`
	}
	if err := c.rpc(ctx, "files/list_folder", map[string]any{"path": path, "recursive": recursive, "limit": n}, &out); err != nil {
		return sdk.Result{}, err
	}
	list := []map[string]any{}
	for _, e := range out.Entries {
		if len(list) >= n {
			break
		}
		list = append(list, e.row())
	}
	res := map[string]any{"entries": list}
	if out.HasMore || len(out.Entries) > n {
		res["more"] = true
	}
	return sdk.JSON(res)
}

func (c *conn) search(ctx context.Context, q, path string, n int) (sdk.Result, error) {
	opts := map[string]any{"max_results": n, "file_status": "active"}
	if path != "" {
		opts["path"] = path
	}
	var out struct {
		Matches []struct {
			Metadata struct {
				Metadata entry `json:"metadata"`
			} `json:"metadata"`
		} `json:"matches"`
	}
	if err := c.rpc(ctx, "files/search_v2", map[string]any{"query": q, "options": opts}, &out); err != nil {
		return sdk.Result{}, err
	}
	list := []map[string]any{}
	for _, x := range out.Matches {
		list = append(list, x.Metadata.Metadata.row())
	}
	return sdk.JSON(list)
}

type link struct {
	URL         string `json:"url"`
	Name        string `json:"name"`
	Path        string `json:"path_lower"`
	ID          string `json:"id"`
	Expires     string `json:"expires"`
	Permissions struct {
		Audience struct {
			Tag string `json:".tag"`
		} `json:"effective_audience"`
		Visibility struct {
			Tag string `json:".tag"`
		} `json:"resolved_visibility"`
		Access struct {
			Tag string `json:".tag"`
		} `json:"link_access_level"`
	} `json:"link_permissions"`
}

var tagRe = regexp.MustCompile(`^[a-z_]{1,40}$`)

// row is what the module shows of a link: who can open it (public,
// team, password, no_one…) as Dropbox resolved it, since a team's policy
// can differ from what a personal account gets.
func (l link) row() map[string]any {
	r := map[string]any{"url": l.URL, "name": l.Name, "id": l.ID, "expires": l.Expires}
	aud := l.Permissions.Audience.Tag
	if aud == "" {
		aud = l.Permissions.Visibility.Tag
	}
	if tagRe.MatchString(aud) {
		r["audience"] = aud
	}
	if a := l.Permissions.Access.Tag; tagRe.MatchString(a) {
		r["access"] = a
	}
	return r
}

func (c *conn) links(ctx context.Context, path string) ([]link, error) {
	var out struct {
		Links []link `json:"links"`
	}
	if err := c.rpc(ctx, "sharing/list_shared_links", map[string]any{"path": path, "direct_only": true}, &out); err != nil {
		return nil, err
	}
	return out.Links, nil
}

func (c *conn) share(ctx context.Context, call sdk.Call, path, exp string) (sdk.Result, error) {
	var e entry
	if err := c.rpc(ctx, "files/get_metadata", map[string]any{"path": path}, &e); err != nil {
		return sdk.Result{}, err
	}
	existing, err := c.links(ctx, path)
	if err != nil {
		return sdk.Result{}, err
	}
	if len(existing) > 0 {
		r := existing[0].row()
		r["note"] = "nothing to change: the file already has a shared link"
		if exp != "" {
			r["note"] = "nothing to change: the file already has a shared link (its own expiry stays; the one asked for isn't applied)"
		}
		return sdk.JSON(r)
	}
	if call.DryRun {
		// Dropbox applies the account's default: anyone with the link on a
		// personal account; a team's sharing policy may make it team-only
		// (the result says which it got).
		after := map[string]any{"name": e.Name, "path": e.Path, "type": e.Tag, "access": "view only",
			"audience": "the account's default: anyone with the link (a Dropbox team's policy may limit it to members)"}
		if exp != "" {
			after["expires"] = exp
		}
		b, _ := json.Marshal(after)
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create a view-only shared link to %s (the account's default audience, usually anyone with the link)", e.Path), Changes: []sdk.Change{{Target: e.Path, Op: "share", After: b}}}}, nil
	}
	args := map[string]any{"path": path}
	if exp != "" {
		args["settings"] = map[string]any{"expires": exp}
	}
	var l link
	if err := c.rpc(ctx, "sharing/create_shared_link_with_settings", args, &l); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(l.row())
	id := l.ID
	if id == "" {
		id = e.ID
	}
	if fileIDRe.MatchString(id) {
		// The token is the file id alone, never the link itself.
		res.Undo = sdk.UndoWith("revoke_shared_link", map[string]string{"id": id}, "Revoke the file's shared links")
	}
	return res, err
}

func checkLink(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "https" || u.User != nil || len(s) > 600 ||
		!(strings.EqualFold(u.Hostname(), "dropbox.com") || strings.HasSuffix(strings.ToLower(u.Hostname()), ".dropbox.com")) {
		return "", errors.New("the link is a https://www.dropbox.com/… shared link")
	}
	return u.String(), nil
}

func (c *conn) revoke(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	var urls []string
	var target string
	switch {
	case p.URL != "" && p.ID != "":
		return sdk.Result{}, errors.New("give the link or the file id, not both")
	case p.URL != "":
		u, err := checkLink(p.URL)
		if err != nil {
			return sdk.Result{}, err
		}
		urls, target = []string{u}, "the shared link"
	case p.ID != "":
		id := strings.TrimSpace(p.ID)
		if !fileIDRe.MatchString(id) {
			return sdk.Result{}, errors.New("the id is a file id like id:a4ayc_80_OEAAAAAAAAAXw")
		}
		ls, err := c.links(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		for _, l := range ls {
			if u, err := checkLink(l.URL); err == nil {
				urls = append(urls, u)
				target = l.Name
			}
		}
		if len(urls) == 0 {
			return sdk.JSON(map[string]any{"revoked": 0, "note": "nothing to change: the file has no shared links"})
		}
	default:
		return sdk.Result{}, errors.New("give the link to revoke, or a file id")
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]any{"links": len(urls)})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Revoke %d shared link(s) to %s; people with them lose access", len(urls), target),
			Changes: []sdk.Change{{Target: target, Op: "revoke", Before: b}}}}, nil
	}
	n := 0
	for _, u := range urls {
		err := c.rpc(ctx, "sharing/revoke_shared_link", map[string]string{"url": u}, nil)
		var e *apiError
		if errors.As(err, &e) && strings.Contains(e.Summary, "shared_link_not_found") {
			continue
		}
		if err != nil {
			return sdk.Result{}, err
		}
		n++
	}
	if n == 0 {
		return sdk.JSON(map[string]any{"revoked": 0, "note": "nothing to change: the link was already gone"})
	}
	return sdk.JSON(map[string]any{"revoked": n})
}
