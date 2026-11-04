// Package wallabag works with a wallabag read-it-later server through its
// REST API, signing in with an API client and your user name and password
// (OAuth2 password grant): listing unread, starred and archived entries,
// saving a link, archiving and starring, and deleting.
package wallabag

import (
	"context"
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
	"github.com/elchi-dev/conduit/modules/internal/urlguard"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one wallabag account.
type Config struct {
	URL                string `json:"url"`          // e.g. https://wallabag.example.com
	ClientID           string `json:"clientId"`     // API client id, plain or secret://
	ClientSecret       string `json:"clientSecret"` // secret:// API client secret
	Username           string `json:"username"`
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client // {origin}/api, bearer token
	oauth  *rest.Client // {origin}/oauth/v2, no auth
	origin string
	cfg    Config
	host   sdk.Host
	now    func() time.Time

	mu      sync.Mutex
	token   string // kept in memory only
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the wallabag module.
func New() *Module { return &Module{} }

const (
	maxTags    = 20
	maxTagName = 100
	maxID      = 1 << 53
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	userRe = regexp.MustCompile(`^[^\s/\\]{1,180}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}`
	entry := `"entry":{"type":"integer","minimum":1,"description":"Entry id (see entries)"}`
	one := sdk.Schema(`{"type":"object","required":["entry"],"properties":{` + entry + `}}`)
	return sdk.Manifest{
		ID: "wallabag", Name: "wallabag", Version: "0.1.0", Category: "Productivity", Icon: "bookmark",
		Description: "Your wallabag reading list: unread, starred and archived articles, saving links, archiving and starring.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","clientId","clientSecret","username","password"],"properties":{
			"url":{"type":"string","description":"wallabag's address, e.g. https://wallabag.example.com"},
			"clientId":{"type":"string","description":"Client ID of an API client (wallabag: API clients management → Create a new client); a secret:// reference works too"},
			"clientSecret":{"type":"string","x-secret":true,"description":"That client's secret"},
			"username":{"type":"string","description":"Your wallabag user name"},
			"password":{"type":"string","x-secret":true,"description":"Your wallabag password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "entries", Title: "Entries", Description: "Saved articles, newest first: unread (the default), starred, archived or all, optionally with one tag. Titles, links, tags and reading time.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["unread","starred","archived","all"],"default":"unread"},"tag":{"type":"string"},` + limit + `}}`)},
			{Name: "save_url", Title: "Save a link", Description: "Saves a URL to read later; wallabag fetches the page. Links to local or private addresses (localhost, private and reserved IPs, single-label, .local and .internal names) are refused, since wallabag would fetch them from inside your network. Undo deletes it (not when the link was already saved).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["url"],"properties":{"url":{"type":"string","format":"uri"},"title":{"type":"string"},"tags":{"type":"array","maxItems":20,"items":{"type":"string"}}}}`)},
			{Name: "archive", Title: "Archive (mark read)", Description: "Moves an entry to the archive. Undo puts it back in unread.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: one},
			{Name: "unarchive", Title: "Mark unread", Description: "Moves an archived entry back to unread. Undo archives it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: one},
			{Name: "star", Title: "Star an entry", Description: "Stars an entry. Undo unstars it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: one},
			{Name: "unstar", Title: "Unstar an entry", Description: "Removes the star. Undo stars it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: one},
			{Name: "delete_entry", Title: "Delete an entry", Description: "Deletes an entry with its saved copy and annotations. wallabag can't bring it back.", Risk: sdk.RiskDestructive, DryRun: true, Input: one},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://wallabag.example.com")
	}
	c.ClientID, c.Username = strings.TrimSpace(c.ClientID), strings.TrimSpace(c.Username)
	if c.ClientID == "" || len(c.ClientID) > 200 {
		return errors.New("enter the API client's ID")
	}
	if !userRe.MatchString(c.Username) {
		return errors.New("enter your wallabag user name")
	}
	if !strings.HasPrefix(c.ClientSecret, "secret://") || !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the client secret and your password in the vault and enter their secret:// references")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	client = rest.SameHostOnly(client)
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	cn := &conn{origin: origin, cfg: c, host: h, now: time.Now}
	cn.oauth = rest.New(origin+"/oauth/v2", nil)
	cn.oauth.HTTP = client
	cn.api = rest.New(origin+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := cn.bearer(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errRefused = errors.New("wallabag refused the API client or the user name and password")

func (c *conn) secret(ctx context.Context, v string) (string, error) {
	if !strings.HasPrefix(v, "secret://") {
		return v, nil
	}
	s, err := c.host.Secret(ctx, v)
	return strings.TrimSpace(s), err
}

// bearer returns the access token, signing in again when it's missing or
// about to expire.
func (c *conn) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && c.now().Before(c.expires) {
		t := c.token
		c.mu.Unlock()
		return t, nil
	}
	c.mu.Unlock()
	form := url.Values{"grant_type": {"password"}, "username": {c.cfg.Username}}
	for k, v := range map[string]string{"client_id": c.cfg.ClientID, "client_secret": c.cfg.ClientSecret, "password": c.cfg.Password} {
		s, err := c.secret(ctx, v)
		if err != nil {
			return "", err
		}
		form.Set(k, s)
	}
	res, err := c.oauth.Send(ctx, http.MethodPost, "/token", nil, strings.NewReader(form.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}})
	if err != nil {
		if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return "", errRefused
		}
		if rest.IsStatus(err, http.StatusNotFound) {
			return "", errors.New("no wallabag API at this address")
		}
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return "", fmt.Errorf("wallabag answered %s", res.Status)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&tok); err != nil || tok.AccessToken == "" {
		return "", errors.New("unexpected answer from wallabag's sign-in")
	}
	life := time.Duration(tok.ExpiresIn) * time.Second
	if life <= 0 || life > 24*time.Hour {
		life = time.Hour
	}
	c.mu.Lock()
	c.token, c.expires = tok.AccessToken, c.now().Add(life-time.Minute)
	c.mu.Unlock()
	return tok.AccessToken, nil
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	for attempt := 0; ; attempt++ {
		_, err := c.api.Do(ctx, method, path, q, body, out)
		if rest.IsStatus(err, http.StatusUnauthorized) && attempt == 0 {
			c.mu.Lock()
			c.token = "" // revoked or expired early: sign in again once
			c.mu.Unlock()
			continue
		}
		switch {
		case rest.IsStatus(err, http.StatusUnauthorized):
			return errRefused
		case rest.IsStatus(err, http.StatusForbidden):
			return fmt.Errorf("wallabag refused the request: %v", err)
		}
		return err
	}
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		Username string `json:"username"`
	}
	if err := c.do(ctx, http.MethodGet, "/user.json", nil, nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no wallabag API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + me.Username}
}

// flag is wallabag's 0/1 (older servers) or true/false.
type flag bool

func (f *flag) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	*f = flag(s == "1" || s == "true")
	return nil
}

type entry struct {
	ID          int64  `json:"id"`
	Title       string `json:"title"`
	URL         string `json:"url"`
	Domain      string `json:"domain_name"`
	Archived    flag   `json:"is_archived"`
	Starred     flag   `json:"is_starred"`
	CreatedAt   string `json:"created_at"`
	ReadingTime int    `json:"reading_time"`
	Tags        []struct {
		Label string `json:"label"`
	} `json:"tags"`
}

func (c *conn) summary(e entry) map[string]any {
	tags := []string{}
	for _, t := range e.Tags {
		tags = append(tags, t.Label)
	}
	out := map[string]any{"id": e.ID, "title": e.Title, "url": e.URL, "tags": tags, "created": e.CreatedAt,
		"open": c.origin + "/view/" + strconv.FormatInt(e.ID, 10)}
	if e.Domain != "" {
		out["site"] = e.Domain
	}
	if e.ReadingTime > 0 {
		out["readingMinutes"] = e.ReadingTime
	}
	if e.Archived {
		out["archived"] = true
	}
	if e.Starred {
		out["starred"] = true
	}
	return out
}

type input struct {
	Status string   `json:"status"`
	Tag    string   `json:"tag"`
	Limit  int      `json:"limit"`
	Entry  int64    `json:"entry"`
	URL    string   `json:"url"`
	Title  string   `json:"title"`
	Tags   []string `json:"tags"`
}

func limitOf(n int) string {
	if n <= 0 || n > 100 {
		n = 20
	}
	return strconv.Itoa(n)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (c *conn) get(ctx context.Context, id int64) (entry, error) {
	if id <= 0 || id >= maxID {
		return entry{}, errors.New("the entry is an entry id (see entries)")
	}
	var e entry
	if err := c.do(ctx, http.MethodGet, "/entries/"+strconv.FormatInt(id, 10)+".json", nil, nil, &e); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return entry{}, fmt.Errorf("there's no entry %d", id)
		}
		return entry{}, err
	}
	return e, nil
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
	case "entries":
		q := url.Values{"sort": {"created"}, "order": {"desc"}, "perPage": {limitOf(p.Limit)}, "page": {"1"}, "detail": {"metadata"}}
		switch p.Status {
		case "", "unread":
			q.Set("archive", "0")
		case "archived":
			q.Set("archive", "1")
		case "starred":
			q.Set("starred", "1")
		case "all":
		default:
			return sdk.Result{}, errors.New("the status is unread, starred, archived or all")
		}
		if t := strings.TrimSpace(p.Tag); t != "" {
			if len([]rune(t)) > maxTagName || strings.Contains(t, ",") {
				return sdk.Result{}, fmt.Errorf("a tag is up to %d characters, without commas", maxTagName)
			}
			q.Set("tags", t)
		}
		var res struct {
			Total    int `json:"total"`
			Embedded struct {
				Items []entry `json:"items"`
			} `json:"_embedded"`
		}
		if err := c.do(ctx, http.MethodGet, "/entries.json", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range res.Embedded.Items {
			out = append(out, c.summary(e))
		}
		return sdk.JSON(map[string]any{"entries": out, "total": res.Total})

	case "save_url":
		return c.save(ctx, call, p)

	case "archive", "unarchive", "star", "unstar":
		return c.flag(ctx, call, p)

	case "delete_entry":
		e, err := c.get(ctx, p.Entry)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete %q", e.Title),
				Changes: []sdk.Change{{Target: fmt.Sprintf("entry %d", e.ID), Op: "delete", Before: mustJSON(c.summary(e))}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/entries/"+strconv.FormatInt(e.ID, 10)+".json", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": e.ID, "title": e.Title})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) save(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	// The server fetches what it saves: nothing on the local network
	// (urlguard; redirects and rebinding are the server's to refuse).
	u, err := urlguard.URL(ctx, p.URL)
	if err != nil {
		return sdk.Result{}, err
	}
	if len([]rune(p.Title)) > 1000 {
		return sdk.Result{}, errors.New("the title is too long")
	}
	if len(p.Tags) > maxTags {
		return sdk.Result{}, fmt.Errorf("give up to %d tags", maxTags)
	}
	tags := []string{}
	for _, t := range p.Tags {
		t = strings.TrimSpace(t)
		if t == "" || len([]rune(t)) > maxTagName || strings.Contains(t, ",") {
			return sdk.Result{}, fmt.Errorf("tags are 1 to %d characters, without commas", maxTagName)
		}
		tags = append(tags, t)
	}
	link := u.String()
	body := map[string]any{"url": link}
	if t := strings.TrimSpace(p.Title); t != "" {
		body["title"] = t
	}
	if len(tags) > 0 {
		body["tags"] = strings.Join(tags, ",")
	}
	// wallabag answers a link that's saved already with the existing
	// entry; asking first tells the two apart, so only a new one is undone.
	var ex struct {
		Exists json.RawMessage `json:"exists"`
	}
	if err := c.do(ctx, http.MethodGet, "/entries/exists.json", url.Values{"url": {link}, "return_id": {"1"}}, nil, &ex); err != nil {
		return sdk.Result{}, err
	}
	if s := strings.TrimSpace(string(ex.Exists)); s != "" && s != "null" && s != "false" && s != "0" {
		out := map[string]any{"url": link, "note": "this link was already saved"}
		if id, err := strconv.ParseInt(s, 10, 64); err == nil {
			out["id"] = id
		}
		return sdk.JSON(out)
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Save " + link, Changes: []sdk.Change{{Target: link, Op: "create", After: mustJSON(body)}}}}, nil
	}
	var e entry
	if err := c.do(ctx, http.MethodPost, "/entries.json", nil, body, &e); err != nil {
		return sdk.Result{}, err
	}
	r, err := sdk.JSON(c.summary(e))
	if e.ID > 0 && e.ID < maxID {
		r.Undo = sdk.UndoWith("delete_entry", map[string]any{"entry": e.ID}, "Delete the saved entry for "+u.Host)
	}
	return r, err
}

// flag archives, unarchives, stars or unstars one entry, leaving it alone
// when it's already as asked.
func (c *conn) flag(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	e, err := c.get(ctx, p.Entry)
	if err != nil {
		return sdk.Result{}, err
	}
	field, want, back, verb := "archive", true, "unarchive", "Archive"
	cur := bool(e.Archived)
	switch call.Action {
	case "unarchive":
		want, back, verb = false, "archive", "Move to unread"
	case "star":
		field, back, verb, cur = "starred", "unstar", "Star", bool(e.Starred)
	case "unstar":
		field, want, back, verb, cur = "starred", false, "star", "Unstar", bool(e.Starred)
	}
	if cur == want {
		return sdk.JSON(map[string]any{"entry": e.ID, "title": e.Title, "note": "nothing to change"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %q", verb, e.Title), Changes: []sdk.Change{{Target: fmt.Sprintf("entry %d %q", e.ID, e.Title), Op: call.Action,
			Before: mustJSON(map[string]bool{field: cur}), After: mustJSON(map[string]bool{field: want})}}}}, nil
	}
	v := 0
	if want {
		v = 1
	}
	var after entry
	if err := c.do(ctx, http.MethodPatch, "/entries/"+strconv.FormatInt(e.ID, 10)+".json", nil, map[string]any{field: v}, &after); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"entry": e.ID, "title": e.Title, field: want})
	undo := map[string]string{"archive": "Move %q back to unread", "unarchive": "Archive %q again", "star": "Unstar %q", "unstar": "Star %q again"}[call.Action]
	res.Undo = sdk.UndoWith(back, map[string]any{"entry": e.ID}, fmt.Sprintf(undo, e.Title))
	return res, err
}

// localHost refuses hosts the server would fetch from inside your network
// (see urlguard.Host), without resolving them.
func localHost(host string) error {
	_, err := urlguard.Host(host)
	return err
}
