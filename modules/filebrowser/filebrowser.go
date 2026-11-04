// Package filebrowser works with a File Browser server through its web API,
// signing in with a user name and password for a session token: folder
// listings, search, disk usage, and creating and deleting share links.
package filebrowser

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one File Browser account.
type Config struct {
	URL                string `json:"url"`      // e.g. https://files.example.com
	User               string `json:"user"`     // user name
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	cfg      Config
	host     sdk.Host
	instance string
	base     string // scheme://host/path, no trailing slash
	api      *rest.Client

	mu  sync.Mutex
	jwt string
	at  time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the File Browser module.
func New() *Module { return &Module{} }

var (
	basePathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	userRe     = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,128}$`)
	jwtRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$`)
	hashRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{4,64}$`)
	linkIDRe   = regexp.MustCompile(`^l[0-9a-f]{24}$`)
)

// tokenAge is how long a session token is reused; File Browser's default
// lifetime is two hours.
const tokenAge = time.Hour

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	path := `"path":{"type":"string","description":"A path like /Documents/report.pdf"}`
	return sdk.Manifest{
		ID: "filebrowser", Name: "File Browser", Version: "0.1.0", Category: "Storage", Icon: "folder",
		Description: "File Browser: folder listings, search, disk usage, and creating or deleting share links.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","user","password"],"properties":{
			"url":{"type":"string","description":"Your File Browser, e.g. https://files.example.com"},
			"user":{"type":"string","description":"The user name to sign in with"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "list", Title: "List a folder", Description: "Files and folders in a folder: name, type, size, modified.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"path":{"type":"string","default":"/","description":"Folder path (default: the top)"},"limit":{"type":"integer","default":500,"maximum":2000}}}`)},
			{Name: "search", Title: "Search", Description: "Files and folders whose name matches, under a folder.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},"path":{"type":"string","default":"/","description":"Only under this folder"},"limit":{"type":"integer","default":100,"maximum":1000}}}`)},
			{Name: "usage", Title: "Disk usage", Description: "Used and total space of the disk behind a folder.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"path":{"type":"string","default":"/"}}}`)},
			{Name: "shares", Title: "Share links", Description: "Your share links (every user's for an admin): link, path, expiry, whether it has a password, and the id delete_share takes. Passwords are never returned.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "create_share", Title: "Create a share link", Description: "Makes a link to a file or folder that anyone who has it can open, optionally with a password and an expiry. If the item already has a link and no password or expiry is asked, that one is returned. Undo deletes the new link.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["path"],"properties":{` + path + `,"password":{"type":"string","description":"Optional password; never shown again"},"expireHours":{"type":"integer","minimum":1,"maximum":87600}}}`)},
			{Name: "delete_share", Title: "Delete a share link", Description: "Deletes a share link by its id (from shares); people with the link can't open it any more.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"The link's id from shares or create_share"}}}`)},
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
		return errors.New("the address is like https://files.example.com")
	}
	c.User = strings.TrimSpace(c.User)
	if !userRe.MatchString(c.User) {
		return errors.New("enter the File Browser user name")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
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
	cn := &conn{cfg: c, host: h, instance: id, base: u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")}
	cn.api = rest.New(cn.base, func(ctx context.Context, r *http.Request) error {
		t, err := cn.token(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("X-Auth", t)
		return nil
	})
	cn.api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errLogin = errors.New("File Browser refused the user name or password")

// token signs in when there's no recent session token.
func (c *conn) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jwt != "" && time.Since(c.at) < tokenAge {
		return c.jwt, nil
	}
	pw, err := c.host.Secret(ctx, c.cfg.Password)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]string{"username": c.cfg.User, "password": strings.TrimRight(pw, "\r\n"), "recaptcha": ""})
	login := &rest.Client{Base: c.base, HTTP: c.api.HTTP}
	res, err := login.Send(ctx, http.MethodPost, "/api/login", nil, bytes.NewReader(b), http.Header{"Content-Type": {"application/json"}})
	if err != nil {
		if rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusUnauthorized) {
			return "", errLogin
		}
		if rest.IsStatus(err, http.StatusNotFound) {
			return "", errors.New("no File Browser API at this address")
		}
		return "", err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 16<<10))
	t := strings.TrimSpace(string(raw))
	if res.StatusCode != http.StatusOK || !jwtRe.MatchString(t) {
		return "", errors.New("File Browser didn't answer the sign-in with a session token (is it set to password sign-in?)")
	}
	c.jwt, c.at = t, time.Now()
	return t, nil
}

func (c *conn) drop() {
	c.mu.Lock()
	c.jwt = ""
	c.mu.Unlock()
}

func friendly(err error) error {
	switch {
	case errors.Is(err, errLogin):
		return err
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("File Browser refused the session token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the user isn't allowed to do this in File Browser")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("there's nothing at that path in File Browser")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.drop()
		_, err = c.api.Do(ctx, method, path, q, body, out)
	}
	return friendly(err)
}

// checkPath validates a path like /a/b ("/" for the top when allowed) and
// returns it escaped segment by segment for a URL path, plus its clean form.
func checkPath(s string, top bool) (escaped, clean string, err error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "/" {
		if top {
			return "/", "/", nil
		}
		return "", "", errors.New("give a path like /Documents/report.pdf")
	}
	if !strings.HasPrefix(s, "/") || len(s) > 1024 || strings.Contains(s, "//") || strings.Contains(s, "\\") || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", "", errors.New("a path starts with / and has no empty parts, backslashes or control characters, like /Documents/report.pdf")
	}
	segs := strings.Split(strings.TrimRight(s[1:], "/"), "/")
	for i, seg := range segs {
		if seg == "." || seg == ".." {
			return "", "", errors.New("a path can't contain . or .. parts")
		}
		segs[i] = url.PathEscape(seg)
	}
	return "/" + strings.Join(segs, "/"), "/" + strings.TrimRight(s[1:], "/"), nil
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

// idKey is the key link ids are made with: derived from the instance and
// its password, so ids are stable across restarts but can't be worked back
// to a link's hash without the password. File Browser's hashes are only 6
// random bytes, few enough to try every one against a plain hash.
func (c *conn) idKey(ctx context.Context) ([]byte, error) {
	pw, err := c.host.Secret(ctx, c.cfg.Password)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte("conduit filebrowser link id\x00" + c.instance + "\x00" + strings.TrimRight(pw, "\r\n")))
	return sum[:], nil
}

// linkID names a share without its hash: the hash is what opens the link,
// so it stays out of undo tokens and the audit log.
func linkID(key []byte, hash string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(hash))
	return "l" + hex.EncodeToString(m.Sum(nil)[:12])
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u struct {
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/usage/", nil, nil, &u); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	gb := func(n int64) string { return fmt.Sprintf("%.1f GB", float64(n)/(1<<30)) }
	if u.Total > 0 {
		return sdk.Health{Status: "ok", Message: "signed in as " + c.cfg.User + "; " + gb(u.Used) + " of " + gb(u.Total) + " used"}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + c.cfg.User}
}

type input struct {
	Path        string `json:"path"`
	Query       string `json:"query"`
	Limit       int    `json:"limit"`
	Password    string `json:"password"`
	ExpireHours int    `json:"expireHours"`
	ID          string `json:"id"`
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
	case "list":
		esc, clean, err := checkPath(p.Path, true)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.list(ctx, esc, clean, limit(p.Limit, 500, 2000))
	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" || len(q) > 200 || strings.ContainsFunc(q, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return sdk.Result{}, errors.New("the query is one line of 1 to 200 characters")
		}
		esc, _, err := checkPath(p.Path, true)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.search(ctx, esc, q, limit(p.Limit, 100, 1000))
	case "usage":
		esc, clean, err := checkPath(p.Path, true)
		if err != nil {
			return sdk.Result{}, err
		}
		var u struct {
			Total int64 `json:"total"`
			Used  int64 `json:"used"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/usage"+esc, nil, nil, &u); err != nil {
			return sdk.Result{}, err
		}
		r := map[string]any{"path": clean, "usedBytes": u.Used, "totalBytes": u.Total}
		if u.Total > 0 {
			r["percent"] = float64(int(float64(u.Used)/float64(u.Total)*1000)) / 10
		}
		return sdk.JSON(r)
	case "shares":
		key, err := c.idKey(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		ls, err := c.allShares(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, l := range ls {
			out = append(out, c.row(key, l))
		}
		return sdk.JSON(out)
	case "create_share":
		esc, clean, err := checkPath(p.Path, false)
		if err != nil {
			return sdk.Result{}, err
		}
		if p.Password != "" && (len(p.Password) > 256 || strings.ContainsFunc(p.Password, func(r rune) bool { return r < 0x20 })) {
			return sdk.Result{}, errors.New("the password is one line of at most 256 characters")
		}
		if p.ExpireHours < 0 || p.ExpireHours > 87600 {
			return sdk.Result{}, errors.New("expireHours is 1 to 87600")
		}
		return c.share(ctx, call, esc, clean, p)
	case "delete_share":
		id := strings.TrimSpace(p.ID)
		if !linkIDRe.MatchString(id) {
			return sdk.Result{}, errors.New("the id is a link's id from shares, like l3f2a…")
		}
		return c.unshare(ctx, call, id)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type item struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
	IsDir    bool   `json:"isDir"`
	Symlink  bool   `json:"isSymlink"`
	Type     string `json:"type"`
	// A text file's content (File Browser includes it) isn't decoded.
}

func (i item) row() map[string]any {
	r := map[string]any{"name": i.Name, "path": i.Path, "modified": i.Modified}
	if i.IsDir {
		r["type"] = "folder"
	} else {
		r["type"] = "file"
		r["size"] = i.Size
		if i.Type != "" {
			r["kind"] = i.Type
		}
	}
	if i.Symlink {
		r["symlink"] = true
	}
	return r
}

func (c *conn) list(ctx context.Context, esc, clean string, n int) (sdk.Result, error) {
	var res struct {
		item
		Items    []item `json:"items"`
		NumDirs  int    `json:"numDirs"`
		NumFiles int    `json:"numFiles"`
	}
	if !strings.HasSuffix(esc, "/") {
		esc += "/"
	}
	if err := c.do(ctx, http.MethodGet, "/api/resources"+esc, nil, nil, &res); err != nil {
		return sdk.Result{}, err
	}
	if !res.IsDir {
		return sdk.Result{}, errors.New("that's a file, not a folder")
	}
	list := []map[string]any{}
	for _, i := range res.Items {
		if len(list) >= n {
			break
		}
		list = append(list, i.row())
	}
	out := map[string]any{"path": clean, "folders": res.NumDirs, "files": res.NumFiles, "entries": list}
	if len(res.Items) > n {
		out["more"] = true
	}
	return sdk.JSON(out)
}

func (c *conn) search(ctx context.Context, esc, q string, n int) (sdk.Result, error) {
	var hits []struct {
		Dir  bool   `json:"dir"`
		Path string `json:"path"`
	}
	if !strings.HasSuffix(esc, "/") {
		esc += "/"
	}
	if err := c.do(ctx, http.MethodGet, "/api/search"+esc, url.Values{"query": {q}}, nil, &hits); err != nil {
		return sdk.Result{}, err
	}
	list := []map[string]any{}
	for _, h := range hits {
		if len(list) >= n {
			break
		}
		t := "file"
		if h.Dir {
			t = "folder"
		}
		list = append(list, map[string]any{"type": t, "path": h.Path})
	}
	out := map[string]any{"matches": list}
	if len(hits) > n {
		out["more"] = true
	}
	return sdk.JSON(out)
}

type share struct {
	Hash         string `json:"hash"`
	Path         string `json:"path"`
	UserID       int    `json:"userID"`
	Username     string `json:"username"`
	Expire       int64  `json:"expire"`
	PasswordHash string `json:"password_hash"` // only whether it's set is shown
	// The download token File Browser returns for a password-protected link
	// isn't decoded.
}

func (c *conn) row(key []byte, l share) map[string]any {
	r := map[string]any{"id": linkID(key, l.Hash), "url": c.base + "/share/" + url.PathEscape(l.Hash), "path": l.Path, "password": l.PasswordHash != ""}
	if l.Expire > 0 {
		r["expires"] = time.Unix(l.Expire, 0).UTC().Format(time.RFC3339)
		r["expired"] = time.Unix(l.Expire, 0).Before(time.Now())
	}
	if l.Username != "" {
		r["user"] = l.Username
	}
	return r
}

func (c *conn) allShares(ctx context.Context) ([]share, error) {
	var ls []share
	if err := c.do(ctx, http.MethodGet, "/api/shares", nil, nil, &ls); err != nil {
		if strings.HasPrefix(err.Error(), "there's nothing") {
			return nil, nil
		}
		return nil, err
	}
	out := ls[:0]
	for _, l := range ls {
		if hashRe.MatchString(l.Hash) {
			out = append(out, l)
		}
	}
	return out, nil
}

func (c *conn) share(ctx context.Context, call sdk.Call, esc, clean string, p input) (sdk.Result, error) {
	key, err := c.idKey(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	// The item must exist (and this says whether it's a folder).
	var it item
	if err := c.do(ctx, http.MethodGet, "/api/resources"+esc, nil, nil, &it); err != nil {
		return sdk.Result{}, err
	}
	var existing []share
	if err := c.do(ctx, http.MethodGet, "/api/share"+esc, nil, nil, &existing); err != nil && !strings.HasPrefix(err.Error(), "there's nothing") {
		return sdk.Result{}, err
	}
	if p.Password == "" && p.ExpireHours == 0 {
		for _, l := range existing {
			if hashRe.MatchString(l.Hash) && l.PasswordHash == "" && (l.Expire == 0 || time.Unix(l.Expire, 0).After(time.Now())) {
				r := c.row(key, l)
				r["note"] = "nothing to change: the item already has a share link"
				return sdk.JSON(r)
			}
		}
	}
	if call.DryRun {
		after := map[string]any{"path": clean, "folder": it.IsDir, "audience": "anyone with the link", "password": p.Password != ""}
		if p.ExpireHours > 0 {
			after["expiresInHours"] = p.ExpireHours
		}
		b, _ := json.Marshal(after)
		return sdk.Result{Plan: &sdk.Plan{Summary: "Create a share link to " + clean + " that anyone who has it can open", Changes: []sdk.Change{{Target: clean, Op: "share", After: b}}}}, nil
	}
	body := map[string]string{"password": p.Password, "expires": "", "unit": "hours"}
	if p.ExpireHours > 0 {
		body["expires"] = strconv.Itoa(p.ExpireHours)
	}
	var l share
	if err := c.do(ctx, http.MethodPost, "/api/share"+esc, nil, body, &l); err != nil {
		return sdk.Result{}, err
	}
	if !hashRe.MatchString(l.Hash) {
		return sdk.Result{}, errors.New("unexpected answer from File Browser")
	}
	res, err := sdk.JSON(c.row(key, l))
	// The undo names the link by its id, never by its hash.
	res.Undo = sdk.UndoWith("delete_share", map[string]string{"id": linkID(key, l.Hash)}, "Delete the link to "+clean)
	return res, err
}

func (c *conn) unshare(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	key, err := c.idKey(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	ls, err := c.allShares(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	var found *share
	for i := range ls {
		if hmac.Equal([]byte(linkID(key, ls[i].Hash)), []byte(id)) {
			found = &ls[i]
			break
		}
	}
	if found == nil {
		return sdk.JSON(map[string]any{"deleted": 0, "note": "nothing to change: there's no share link with that id"})
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]any{"path": found.Path, "password": found.PasswordHash != ""})
		return sdk.Result{Plan: &sdk.Plan{Summary: "Delete the share link to " + found.Path + "; people with it lose access",
			Changes: []sdk.Change{{Target: found.Path, Op: "delete", Before: b}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, "/api/share/"+url.PathEscape(found.Hash), nil, nil, nil); err != nil {
		if strings.HasPrefix(err.Error(), "there's nothing") {
			return sdk.JSON(map[string]any{"deleted": 0, "note": "nothing to change: the link was already gone"})
		}
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"deleted": 1, "id": id, "path": found.Path})
}
