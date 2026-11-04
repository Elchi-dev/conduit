// Package freshrss works with a FreshRSS feed reader through its Google
// Reader compatible API, signing in with the user name and the API password
// set in FreshRSS's profile: unread counts, unread items, subscriptions and
// marking items read or unread.
package freshrss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one FreshRSS user.
type Config struct {
	URL                string `json:"url"`      // e.g. https://rss.example.com
	User               string `json:"user"`     // FreshRSS user name
	Password           string `json:"password"` // secret:// API password
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client // {origin}/api/greader.php, no auth of its own
	origin string
	user   string
	pass   string // secret:// reference
	host   sdk.Host

	mu   sync.Mutex
	auth string // ClientLogin token, kept in memory only
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the FreshRSS module.
func New() *Module { return &Module{} }

const (
	maxItems  = 50
	readTag   = "user/-/state/com.google/read"
	readingSt = "user/-/state/com.google/reading-list"
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	userRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
	// Item ids come long (tag:google.com,2005:reader/item/<16 hex>) or
	// short (decimal, possibly negative as a signed 64-bit number).
	itemRe = regexp.MustCompile(`^(tag:google\.com,2005:reader/item/[0-9a-f]{16}|-?[0-9]{1,20})$`)
	feedRe = regexp.MustCompile(`^(feed/)?[0-9]{1,12}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}`
	items := `"items":{"type":"array","minItems":1,"maxItems":50,"items":{"type":"string"},"description":"Item ids (see unread)"}`
	return sdk.Manifest{
		ID: "freshrss", Name: "FreshRSS", Version: "0.1.0", Category: "Productivity", Icon: "rss",
		Description: "Unread counts and items in your FreshRSS reader, your subscriptions, and marking items read.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","user","password"],"properties":{
			"url":{"type":"string","description":"FreshRSS's address, e.g. https://rss.example.com (where /api/greader.php is)"},
			"user":{"type":"string","description":"Your FreshRSS user name"},
			"password":{"type":"string","x-secret":true,"description":"The API password from Settings → Profile → API management (not your login password)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "unread_count", Title: "Unread count", Description: "How many items are unread in all, and per feed.", Risk: sdk.RiskRead},
			{Name: "unread", Title: "Unread items", Description: "Unread items, newest first, everywhere or in one feed: titles, links, feed and date.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"feed":{"type":"string","description":"Feed id like feed/12 (see subscriptions)"},` + limit + `}}`)},
			{Name: "subscriptions", Title: "Subscriptions", Description: "The feeds you follow, with their categories and addresses.", Risk: sdk.RiskRead},
			{Name: "mark_read", Title: "Mark read", Description: "Marks items read. Undo marks the ones it changed unread again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["items"],"properties":{` + items + `}}`)},
			{Name: "mark_unread", Title: "Mark unread", Description: "Marks items unread. Undo marks the ones it changed read again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["items"],"properties":{` + items + `}}`)},
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
		return errors.New("the address is like https://rss.example.com")
	}
	user := strings.TrimSpace(c.User)
	if !userRe.MatchString(user) {
		return errors.New("enter your FreshRSS user name")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the API password in the vault and enter its secret:// reference")
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
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(p, "/greader.php")
	p = strings.TrimSuffix(p, "/api")
	origin := u.Scheme + "://" + u.Host + p
	api := rest.New(origin+"/api/greader.php", nil)
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, origin: origin, user: user, pass: c.Password, host: h})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errRefused = errors.New("FreshRSS refused the user name or API password")

// login signs in with ClientLogin and keeps the token.
func (c *conn) login(ctx context.Context) (string, error) {
	pw, err := c.host.Secret(ctx, c.pass)
	if err != nil {
		return "", err
	}
	form := url.Values{"Email": {c.user}, "Passwd": {strings.TrimSpace(pw)}}
	res, err := c.api.Send(ctx, http.MethodPost, "/accounts/ClientLogin", nil, strings.NewReader(form.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return "", errRefused
		}
		if rest.IsStatus(err, http.StatusNotFound) {
			return "", errors.New("no FreshRSS API at this address (is the API enabled?)")
		}
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return "", fmt.Errorf("FreshRSS answered %s", res.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Auth="); ok && v != "" {
			c.mu.Lock()
			c.auth = v
			c.mu.Unlock()
			return v, nil
		}
	}
	return "", errRefused
}

func (c *conn) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	t := c.auth
	c.mu.Unlock()
	if t != "" {
		return t, nil
	}
	return c.login(ctx)
}

// call makes an API request, with form as the body when set, and decodes
// the answer into out (JSON) or, when out is a *string, its text. A
// rejected session token is renewed once.
func (c *conn) call(ctx context.Context, method, path string, q url.Values, form url.Values, out any) error {
	for attempt := 0; ; attempt++ {
		tok, err := c.token(ctx)
		if err != nil {
			return err
		}
		var body io.Reader
		hdr := http.Header{"Authorization": {"GoogleLogin auth=" + tok}}
		if form != nil {
			body = strings.NewReader(form.Encode())
			hdr.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		res, err := c.api.Send(ctx, method, path, q, body, hdr)
		if rest.IsStatus(err, http.StatusUnauthorized) && attempt == 0 {
			c.mu.Lock()
			if c.auth == tok {
				c.auth = ""
			}
			c.mu.Unlock()
			continue
		}
		if err != nil {
			if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
				return errRefused
			}
			return err
		}
		defer res.Body.Close()
		if res.StatusCode >= 300 {
			return fmt.Errorf("FreshRSS answered %s", res.Status)
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
		if err != nil {
			return err
		}
		switch o := out.(type) {
		case nil:
			return nil
		case *string:
			*o = strings.TrimSpace(string(raw))
			return nil
		default:
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("unexpected answer from FreshRSS: %w", err)
			}
			return nil
		}
	}
}

func jsonQ(kv ...string) url.Values {
	q := url.Values{"output": {"json"}}
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	return q
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		UserName string `json:"userName"`
	}
	if err := c.call(ctx, http.MethodGet, "/reader/api/0/user-info", jsonQ(), nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + me.UserName}
}

type subscription struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	URL        string `json:"url"`
	HTMLURL    string `json:"htmlUrl"`
	Categories []struct {
		Label string `json:"label"`
	} `json:"categories"`
}

func (c *conn) subscriptions(ctx context.Context) ([]subscription, error) {
	var res struct {
		Subscriptions []subscription `json:"subscriptions"`
	}
	err := c.call(ctx, http.MethodGet, "/reader/api/0/subscription/list", jsonQ(), nil, &res)
	return res.Subscriptions, err
}

type item struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Published  int64    `json:"published"`
	Author     string   `json:"author"`
	Categories []string `json:"categories"`
	Canonical  []struct {
		Href string `json:"href"`
	} `json:"canonical"`
	Alternate []struct {
		Href string `json:"href"`
	} `json:"alternate"`
	Origin struct {
		StreamID string `json:"streamId"`
		Title    string `json:"title"`
	} `json:"origin"`
}

func (it item) read() bool {
	for _, c := range it.Categories {
		if c == readTag || strings.HasSuffix(c, "/state/com.google/read") {
			return true
		}
	}
	return false
}

func (it item) summary() map[string]any {
	link := ""
	if len(it.Canonical) > 0 {
		link = it.Canonical[0].Href
	} else if len(it.Alternate) > 0 {
		link = it.Alternate[0].Href
	}
	out := map[string]any{"id": it.ID, "title": it.Title, "url": link, "feed": it.Origin.Title, "feedId": it.Origin.StreamID}
	if it.Published > 0 {
		out["published"] = time.Unix(it.Published, 0).UTC().Format(time.RFC3339)
	}
	if it.Author != "" {
		out["author"] = it.Author
	}
	return out
}

type input struct {
	Feed  string   `json:"feed"`
	Limit int      `json:"limit"`
	Items []string `json:"items"`
}

func limitOf(n int) string {
	if n <= 0 || n > 100 {
		n = 20
	}
	return strconv.Itoa(n)
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
	case "unread_count":
		var res struct {
			Counts []struct {
				ID    string `json:"id"`
				Count int    `json:"count"`
			} `json:"unreadcounts"`
		}
		if err := c.call(ctx, http.MethodGet, "/reader/api/0/unread-count", jsonQ(), nil, &res); err != nil {
			return sdk.Result{}, err
		}
		titles := map[string]string{}
		if subs, err := c.subscriptions(ctx); err == nil {
			for _, s := range subs {
				titles[s.ID] = s.Title
			}
		}
		total, feeds := 0, []map[string]any{}
		for _, x := range res.Counts {
			switch {
			case x.ID == readingSt || strings.HasSuffix(x.ID, "/state/com.google/reading-list"):
				total = x.Count
			case strings.HasPrefix(x.ID, "feed/") && x.Count > 0:
				feeds = append(feeds, map[string]any{"feedId": x.ID, "title": titles[x.ID], "unread": x.Count})
			}
		}
		sort.SliceStable(feeds, func(i, j int) bool { return feeds[i]["unread"].(int) > feeds[j]["unread"].(int) })
		return sdk.JSON(map[string]any{"unread": total, "feeds": feeds})

	case "unread":
		stream := readingSt
		if f := strings.TrimSpace(p.Feed); f != "" {
			if !feedRe.MatchString(f) {
				return sdk.Result{}, errors.New("the feed is a feed id like feed/12 (see subscriptions)")
			}
			stream = "feed/" + strings.TrimPrefix(f, "feed/")
		}
		var res struct {
			Items []item `json:"items"`
		}
		if err := c.call(ctx, http.MethodGet, "/reader/api/0/stream/contents/"+stream, jsonQ("n", limitOf(p.Limit), "xt", readTag), nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, it := range res.Items {
			out = append(out, it.summary())
		}
		return sdk.JSON(map[string]any{"items": out})

	case "subscriptions":
		subs, err := c.subscriptions(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range subs {
			cats := []string{}
			for _, x := range s.Categories {
				cats = append(cats, x.Label)
			}
			out = append(out, map[string]any{"feedId": s.ID, "title": s.Title, "feedUrl": s.URL, "site": s.HTMLURL, "categories": cats})
		}
		return sdk.JSON(out)

	case "mark_read", "mark_unread":
		return c.mark(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// mark sets items read or unread. It reads the items first so the preview
// names them and the undo reverses only the ones it changed.
func (c *conn) mark(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	toRead := call.Action == "mark_read"
	status, back := "read", "mark_unread"
	if !toRead {
		status, back = "unread", "mark_read"
	}
	if len(p.Items) == 0 || len(p.Items) > maxItems {
		return sdk.Result{}, fmt.Errorf("give 1 to %d item ids", maxItems)
	}
	seen := map[string]bool{}
	form := url.Values{}
	for _, id := range p.Items {
		id = strings.TrimSpace(id)
		if !itemRe.MatchString(id) {
			return sdk.Result{}, errors.New("items are item ids (see unread)")
		}
		if !seen[id] {
			seen[id] = true
			form.Add("i", id)
		}
	}
	var res struct {
		Items []item `json:"items"`
	}
	if err := c.call(ctx, http.MethodPost, "/reader/api/0/stream/items/contents", jsonQ(), form, &res); err != nil {
		return sdk.Result{}, err
	}
	var change []item
	for _, it := range res.Items {
		if it.read() != toRead && itemRe.MatchString(it.ID) {
			change = append(change, it)
		}
	}
	if len(res.Items) == 0 {
		return sdk.Result{}, errors.New("FreshRSS has none of these items")
	}
	if len(change) == 0 {
		return sdk.JSON(map[string]any{"changed": []string{}, "note": "already " + status})
	}
	if call.DryRun {
		changes := []sdk.Change{}
		for _, it := range change {
			changes = append(changes, sdk.Change{Target: fmt.Sprintf("%q (%s)", it.Title, it.Origin.Title), Op: "mark " + status})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Mark %d items %s", len(change), status), Changes: changes}}, nil
	}
	var wt string
	if err := c.call(ctx, http.MethodGet, "/reader/api/0/token", nil, nil, &wt); err != nil {
		return sdk.Result{}, err
	}
	edit := url.Values{"T": {wt}}
	if toRead {
		edit.Set("a", readTag)
	} else {
		edit.Set("r", readTag)
	}
	changed, titles := []string{}, []string{}
	for _, it := range change {
		edit.Add("i", it.ID)
		changed = append(changed, it.ID)
		titles = append(titles, it.Title)
	}
	var ok string
	if err := c.call(ctx, http.MethodPost, "/reader/api/0/edit-tag", nil, edit, &ok); err != nil {
		return sdk.Result{}, err
	}
	if ok != "OK" {
		return sdk.Result{}, errors.New("FreshRSS didn't confirm the change")
	}
	out, err := sdk.JSON(map[string]any{"changed": changed, "titles": titles, "status": status})
	other := "unread"
	if !toRead {
		other = "read"
	}
	out.Undo = sdk.UndoWith(back, map[string]any{"items": changed}, fmt.Sprintf("Mark %d items %s again", len(changed), other))
	return out, err
}
