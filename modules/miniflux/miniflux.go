// Package miniflux works with a Miniflux feed reader through its REST API and
// an API key: feeds and the ones failing to update, unread and starred
// entries, marking entries read or unread, starring them, and refreshing
// feeds.
package miniflux

import (
	"context"
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

// Config is one Miniflux server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://reader.example.com
	Token              string `json:"token"` // secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Miniflux module.
func New() *Module { return &Module{} }

const (
	maxEntries = 50 // per mark_read / mark_unread call
	maxID      = 1 << 53
)

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}`
	feed := `"feed":{"type":"integer","minimum":1,"description":"Feed id (see feeds)"}`
	entries := `"entries":{"type":"array","minItems":1,"maxItems":50,"items":{"type":"integer","minimum":1},"description":"Entry ids (see unread)"}`
	entry := `"entry":{"type":"integer","minimum":1,"description":"Entry id (see unread)"}`
	return sdk.Manifest{
		ID: "miniflux", Name: "Miniflux", Version: "0.1.0", Category: "Productivity", Icon: "rss",
		Description: "Unread and starred entries in your Miniflux reader, feeds that fail to update, marking read and starring.",
		Presets:     []string{"homelab", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Miniflux's address, e.g. https://reader.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API key from Settings → API Keys. It acts as you"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "feeds", Title: "Feeds", Description: "Your feeds with their category, unread count and last check; with errorsOnly, just the ones failing to update and why.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"errorsOnly":{"type":"boolean","default":false}}}`)},
			{Name: "unread", Title: "Unread entries", Description: "Unread entries, newest first, everywhere or in one feed: titles, links, feed and date.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + feed + `,` + limit + `}}`)},
			{Name: "starred", Title: "Starred entries", Description: "Starred entries, newest first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit + `}}`)},
			{Name: "mark_read", Title: "Mark read", Description: "Marks entries read. Undo marks the ones it changed unread again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["entries"],"properties":{` + entries + `}}`)},
			{Name: "mark_unread", Title: "Mark unread", Description: "Marks entries unread. Undo marks the ones it changed read again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["entries"],"properties":{` + entries + `}}`)},
			{Name: "star", Title: "Star an entry", Description: "Stars an entry. Undo unstars it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["entry"],"properties":{` + entry + `}}`)},
			{Name: "unstar", Title: "Unstar an entry", Description: "Removes the star from an entry. Undo stars it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["entry"],"properties":{` + entry + `}}`)},
			{Name: "refresh_feeds", Title: "Refresh feeds", Description: "Asks Miniflux to fetch every feed now, or one feed. It runs in the background.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","properties":{` + feed + `}}`)},
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
		return errors.New("the address is like https://reader.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
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
	ref := c.Token
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/v1")
	api := rest.New(origin+"/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-Auth-Token", strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, origin: origin})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func explain(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Miniflux refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Miniflux refused the request: %v", err)
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return explain(err)
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
	if err := c.do(ctx, http.MethodGet, "/me", nil, nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Miniflux API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + me.Username}
}

type feed struct {
	ID           int64  `json:"id"`
	Title        string `json:"title"`
	SiteURL      string `json:"site_url"`
	FeedURL      string `json:"feed_url"`
	CheckedAt    string `json:"checked_at"`
	ErrorCount   int    `json:"parsing_error_count"`
	ErrorMessage string `json:"parsing_error_message"`
	Disabled     bool   `json:"disabled"`
	Category     *struct {
		Title string `json:"title"`
	} `json:"category"`
}

type entry struct {
	ID          int64  `json:"id"`
	FeedID      int64  `json:"feed_id"`
	Status      string `json:"status"`
	Title       string `json:"title"`
	URL         string `json:"url"`
	PublishedAt string `json:"published_at"`
	Author      string `json:"author"`
	Starred     bool   `json:"starred"`
	ReadingTime int    `json:"reading_time"`
	Feed        *struct {
		Title string `json:"title"`
	} `json:"feed"`
}

func (e entry) summary() map[string]any {
	out := map[string]any{"id": e.ID, "title": e.Title, "url": e.URL, "published": e.PublishedAt, "status": e.Status}
	if e.Feed != nil {
		out["feed"] = e.Feed.Title
	}
	out["feedId"] = e.FeedID
	if e.Starred {
		out["starred"] = true
	}
	if e.ReadingTime > 0 {
		out["readingMinutes"] = e.ReadingTime
	}
	return out
}

type input struct {
	ErrorsOnly bool    `json:"errorsOnly"`
	Feed       int64   `json:"feed"`
	Limit      int     `json:"limit"`
	Entries    []int64 `json:"entries"`
	Entry      int64   `json:"entry"`
}

func limitOf(n int) string {
	if n <= 0 || n > 100 {
		n = 20
	}
	return strconv.Itoa(n)
}

func validID(id int64) bool { return id > 0 && id < maxID }

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
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
	if p.Feed != 0 && !validID(p.Feed) {
		return sdk.Result{}, errors.New("the feed is a feed id (see feeds)")
	}
	switch call.Action {
	case "feeds":
		var feeds []feed
		if err := c.do(ctx, http.MethodGet, "/feeds", nil, nil, &feeds); err != nil {
			return sdk.Result{}, err
		}
		var counters struct {
			Unreads map[string]int `json:"unreads"`
		}
		_ = c.do(ctx, http.MethodGet, "/feeds/counters", nil, nil, &counters) // older servers lack it
		out := []map[string]any{}
		failing := 0
		for _, f := range feeds {
			if f.ErrorCount > 0 {
				failing++
			} else if p.ErrorsOnly {
				continue
			}
			r := map[string]any{"id": f.ID, "title": f.Title, "site": f.SiteURL, "feedUrl": rest.ShortURL(f.FeedURL), "checked": f.CheckedAt,
				"unread": counters.Unreads[strconv.FormatInt(f.ID, 10)]}
			if f.Category != nil {
				r["category"] = f.Category.Title
			}
			if f.ErrorCount > 0 {
				r["errors"], r["error"] = f.ErrorCount, rest.Redact(f.ErrorMessage)
			}
			if f.Disabled {
				r["disabled"] = true
			}
			out = append(out, r)
		}
		return sdk.JSON(map[string]any{"feeds": out, "total": len(feeds), "failing": failing})

	case "unread", "starred":
		q := url.Values{"order": {"published_at"}, "direction": {"desc"}, "limit": {limitOf(p.Limit)}}
		path := "/entries"
		if call.Action == "unread" {
			q.Set("status", "unread")
			if p.Feed != 0 {
				path = "/feeds/" + strconv.FormatInt(p.Feed, 10) + "/entries"
			}
		} else {
			q.Set("starred", "true")
		}
		var res struct {
			Total   int     `json:"total"`
			Entries []entry `json:"entries"`
		}
		if err := c.do(ctx, http.MethodGet, path, q, nil, &res); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) && p.Feed != 0 {
				return sdk.Result{}, fmt.Errorf("there's no feed %d", p.Feed)
			}
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range res.Entries {
			out = append(out, e.summary())
		}
		return sdk.JSON(map[string]any{"entries": out, "total": res.Total})

	case "mark_read", "mark_unread":
		return c.mark(ctx, call, p)
	case "star", "unstar":
		return c.star(ctx, call, p)

	case "refresh_feeds":
		path, what := "/feeds/refresh", "every feed"
		if p.Feed != 0 {
			var f feed
			if err := c.do(ctx, http.MethodGet, "/feeds/"+strconv.FormatInt(p.Feed, 10), nil, nil, &f); err != nil {
				if rest.IsStatus(err, http.StatusNotFound) {
					return sdk.Result{}, fmt.Errorf("there's no feed %d", p.Feed)
				}
				return sdk.Result{}, err
			}
			path, what = "/feeds/"+strconv.FormatInt(f.ID, 10)+"/refresh", fmt.Sprintf("feed %q", f.Title)
		}
		if err := c.do(ctx, http.MethodPut, path, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"refreshing": what})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) get(ctx context.Context, id int64) (entry, error) {
	if !validID(id) {
		return entry{}, errors.New("the entry is an entry id (see unread)")
	}
	var e entry
	if err := c.do(ctx, http.MethodGet, "/entries/"+strconv.FormatInt(id, 10), nil, nil, &e); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return entry{}, fmt.Errorf("there's no entry %d", id)
		}
		return entry{}, err
	}
	return e, nil
}

// mark sets entries read or unread. It reads each entry first so the
// preview names them and the undo reverses only the ones it changed.
func (c *conn) mark(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	status, back := "read", "mark_unread"
	if call.Action == "mark_unread" {
		status, back = "unread", "mark_read"
	}
	if len(p.Entries) == 0 || len(p.Entries) > maxEntries {
		return sdk.Result{}, fmt.Errorf("give 1 to %d entry ids", maxEntries)
	}
	seen := map[int64]bool{}
	ids := []int64{}
	for _, id := range p.Entries {
		if !validID(id) {
			return sdk.Result{}, errors.New("entries are entry ids (see unread)")
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	var change []entry
	for _, id := range ids {
		e, err := c.get(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		if e.Status != status && e.Status != "removed" {
			change = append(change, e)
		}
	}
	if len(change) == 0 {
		return sdk.JSON(map[string]any{"changed": []int64{}, "note": "already " + status})
	}
	changed := []int64{}
	titles := []string{}
	for _, e := range change {
		changed = append(changed, e.ID)
		titles = append(titles, e.Title)
	}
	if call.DryRun {
		changes := []sdk.Change{}
		for _, e := range change {
			changes = append(changes, sdk.Change{Target: fmt.Sprintf("entry %d %q", e.ID, e.Title), Op: "mark " + status,
				Before: mustJSON(map[string]string{"status": e.Status}), After: mustJSON(map[string]string{"status": status})})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Mark %d entries %s", len(change), status), Changes: changes}}, nil
	}
	if err := c.do(ctx, http.MethodPut, "/entries", nil, map[string]any{"entry_ids": changed, "status": status}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"changed": changed, "titles": titles, "status": status})
	other := "unread"
	if status == "unread" {
		other = "read"
	}
	res.Undo = sdk.UndoWith(back, map[string]any{"entries": changed}, fmt.Sprintf("Mark %d entries %s again", len(changed), other))
	return res, err
}

// star stars or unstars one entry. Miniflux only offers a toggle, so the
// entry is read first and left alone when it's already as asked.
func (c *conn) star(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	want := call.Action == "star"
	e, err := c.get(ctx, p.Entry)
	if err != nil {
		return sdk.Result{}, err
	}
	verb, back := "Star", "unstar"
	if !want {
		verb, back = "Unstar", "star"
	}
	if e.Starred == want {
		return sdk.JSON(map[string]any{"entry": e.ID, "title": e.Title, "starred": want, "note": "nothing to change"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %q", verb, e.Title), Changes: []sdk.Change{{Target: fmt.Sprintf("entry %d %q", e.ID, e.Title), Op: strings.ToLower(verb),
			Before: mustJSON(map[string]bool{"starred": e.Starred}), After: mustJSON(map[string]bool{"starred": want})}}}}, nil
	}
	if err := c.do(ctx, http.MethodPut, "/entries/"+strconv.FormatInt(e.ID, 10)+"/bookmark", nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"entry": e.ID, "title": e.Title, "starred": want})
	desc := fmt.Sprintf("Unstar %q", e.Title)
	if !want {
		desc = fmt.Sprintf("Star %q again", e.Title)
	}
	res.Undo = sdk.UndoWith(back, map[string]any{"entry": e.ID}, desc)
	return res, err
}
