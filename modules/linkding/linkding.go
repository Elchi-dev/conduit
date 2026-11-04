// Package linkding works with a linkding bookmark server through its REST
// API and an API token: searching bookmarks, the newest ones, tags, saving a
// link, archiving and deleting.
package linkding

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/modules/internal/urlguard"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one linkding server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://links.example.com
	Token              string `json:"token"` // secret:// REST API token
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

// New returns the linkding module.
func New() *Module { return &Module{} }

const (
	maxTags     = 20
	maxTagName  = 64
	maxTitle    = 512
	maxDescr    = 2000
	maxQuery    = 1000
	maxListings = 100
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// linkding tags are single words: no spaces.
	tagRe = regexp.MustCompile(`^[^\s,]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}`
	bm := `"bookmark":{"type":"integer","minimum":1,"description":"Bookmark id (see search or recent)"}`
	return sdk.Manifest{
		ID: "linkding", Name: "linkding", Version: "0.1.0", Category: "Productivity", Icon: "bookmark",
		Description: "Search and browse your linkding bookmarks and tags, save links, archive and delete them.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"linkding's address, e.g. https://links.example.com"},
			"token":{"type":"string","x-secret":true,"description":"The REST API token from Settings → Integrations. It acts as you"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "search", Title: "Search bookmarks", Description: "Bookmarks matching words or linkding's search syntax (#tag, !untagged, !unread), newest first; archived ones only when asked.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},"archived":{"type":"boolean","default":false},` + limit + `}}`)},
			{Name: "recent", Title: "Recent bookmarks", Description: "The newest bookmarks, or the newest archived ones.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"archived":{"type":"boolean","default":false},` + limit + `}}`)},
			{Name: "tags", Title: "Tags", Description: "Your tags, by name.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":1000,"default":200}}}`)},
			{Name: "add_bookmark", Title: "Save a link", Description: "Bookmarks a URL with an optional title, description and tags; linkding fetches the page's title and icon. Links to local or private addresses are refused, since linkding would fetch them from inside your network. A link that's saved already is left as it is. The bookmark isn't shared. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["url"],"properties":{"url":{"type":"string","format":"uri"},"title":{"type":"string","maxLength":512},"description":{"type":"string","maxLength":2000},"tags":{"type":"array","maxItems":20,"items":{"type":"string"}},"unread":{"type":"boolean","default":false}}}`)},
			{Name: "archive_bookmark", Title: "Archive a bookmark", Description: "Moves a bookmark to the archive. Undo unarchives it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["bookmark"],"properties":{` + bm + `}}`)},
			{Name: "unarchive_bookmark", Title: "Unarchive a bookmark", Description: "Brings a bookmark back from the archive. Undo archives it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["bookmark"],"properties":{` + bm + `}}`)},
			{Name: "delete_bookmark", Title: "Delete a bookmark", Description: "Deletes a bookmark with its notes and snapshots. linkding can't bring it back.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["bookmark"],"properties":{` + bm + `}}`)},
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
		return errors.New("the address is like https://links.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(origin+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Token "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, origin: origin})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("linkding refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("linkding refused the request: %v", err)
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var res struct {
		Count int `json:"count"`
	}
	if err := c.do(ctx, http.MethodGet, "/bookmarks/", url.Values{"limit": {"1"}}, nil, &res); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no linkding API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d bookmarks", res.Count)}
}

type bookmark struct {
	ID           int      `json:"id"`
	URL          string   `json:"url"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Notes        string   `json:"notes"`
	WebsiteTitle string   `json:"website_title"`
	IsArchived   bool     `json:"is_archived"`
	Unread       bool     `json:"unread"`
	Shared       bool     `json:"shared"`
	TagNames     []string `json:"tag_names"`
	DateAdded    string   `json:"date_added"`
}

func (b bookmark) title() string {
	for _, t := range []string{b.Title, b.WebsiteTitle} {
		if strings.TrimSpace(t) != "" {
			return t
		}
	}
	return bareURL(b.URL)
}

// bareURL is a link without its user part, query and fragment ("?…" says
// one was there): outputs and previews end up in the audit log, events and
// webhooks, and a query or fragment often holds a token, a session or
// something personal (a reset link, a search).
func bareURL(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return rest.ShortURL(s)
	}
	out := u.Scheme + "://" + u.Host + u.EscapedPath()
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") {
		out += "?…"
	}
	return out
}

// summary is what listings and previews show: no notes (they're private),
// and links without their query and fragment.
func (c *conn) summary(b bookmark) map[string]any {
	tags := b.TagNames
	if tags == nil {
		tags = []string{}
	}
	link := bareURL(b.URL)
	out := map[string]any{"id": b.ID, "title": b.title(), "url": link, "tags": tags, "added": b.DateAdded,
		"open": c.origin + "/bookmarks?q=" + url.QueryEscape(strings.TrimSuffix(link, "?…"))}
	if b.IsArchived {
		out["archived"] = true
	}
	if b.Unread {
		out["unread"] = true
	}
	if b.Shared {
		out["shared"] = true
	}
	return out
}

func limitOf(n, def, max int) string {
	if n <= 0 || n > max {
		n = def
	}
	return strconv.Itoa(n)
}

func (c *conn) listing(ctx context.Context, archived bool, q url.Values) (sdk.Result, error) {
	path := "/bookmarks/"
	if archived {
		path = "/bookmarks/archived/"
	}
	var res struct {
		Count   int        `json:"count"`
		Next    *string    `json:"next"`
		Results []bookmark `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, path, q, nil, &res); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, b := range res.Results {
		out = append(out, c.summary(b))
	}
	return sdk.JSON(map[string]any{"bookmarks": out, "total": res.Count, "more": res.Next != nil && *res.Next != ""})
}

func (c *conn) get(ctx context.Context, id int) (bookmark, error) {
	if id <= 0 {
		return bookmark{}, errors.New("the bookmark is a bookmark id (see search or recent)")
	}
	var b bookmark
	if err := c.do(ctx, http.MethodGet, "/bookmarks/"+strconv.Itoa(id)+"/", nil, nil, &b); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return bookmark{}, fmt.Errorf("there's no bookmark %d", id)
		}
		return bookmark{}, err
	}
	return b, nil
}

type input struct {
	Query       string   `json:"query"`
	Limit       int      `json:"limit"`
	Archived    bool     `json:"archived"`
	Bookmark    int      `json:"bookmark"`
	URL         string   `json:"url"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Unread      bool     `json:"unread"`
}

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
	switch call.Action {
	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" {
			return sdk.Result{}, errors.New("enter what to search for")
		}
		if len(q) > maxQuery {
			return sdk.Result{}, errors.New("the query is too long")
		}
		return c.listing(ctx, p.Archived, url.Values{"q": {q}, "limit": {limitOf(p.Limit, 20, maxListings)}})

	case "recent":
		return c.listing(ctx, p.Archived, url.Values{"limit": {limitOf(p.Limit, 20, maxListings)}})

	case "tags":
		var res struct {
			Count   int `json:"count"`
			Results []struct {
				Name string `json:"name"`
			} `json:"results"`
		}
		if err := c.do(ctx, http.MethodGet, "/tags/", url.Values{"limit": {limitOf(p.Limit, 200, 1000)}}, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		names := []string{}
		for _, t := range res.Results {
			names = append(names, t.Name)
		}
		sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
		return sdk.JSON(map[string]any{"tags": names, "total": res.Count})

	case "add_bookmark":
		return c.add(ctx, call, p)

	case "archive_bookmark", "unarchive_bookmark":
		archive := call.Action == "archive_bookmark"
		b, err := c.get(ctx, p.Bookmark)
		if err != nil {
			return sdk.Result{}, err
		}
		if b.IsArchived == archive {
			state := "isn't archived"
			if archive {
				state = "is archived already"
			}
			return sdk.JSON(map[string]any{"bookmark": b.ID, "title": b.title(), "note": "nothing to change: it " + state})
		}
		verb, back, sub := "Archive", "unarchive_bookmark", "archive"
		if !archive {
			verb, back, sub = "Unarchive", "archive_bookmark", "unarchive"
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s bookmark %q", verb, b.title()),
				Changes: []sdk.Change{{Target: "bookmark " + strconv.Itoa(b.ID), Op: sub, Before: mustJSON(map[string]bool{"archived": b.IsArchived}), After: mustJSON(map[string]bool{"archived": archive})}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/bookmarks/"+strconv.Itoa(b.ID)+"/"+sub+"/", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"bookmark": b.ID, "title": b.title(), "archived": archive})
		undo := "Unarchive "
		if !archive {
			undo = "Archive "
		}
		res.Undo = sdk.UndoWith(back, map[string]any{"bookmark": b.ID}, undo+strconv.Quote(b.title()))
		return res, err

	case "delete_bookmark":
		b, err := c.get(ctx, p.Bookmark)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete bookmark %q", b.title()),
				Changes: []sdk.Change{{Target: "bookmark " + strconv.Itoa(b.ID), Op: "delete", Before: mustJSON(c.summary(b))}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/bookmarks/"+strconv.Itoa(b.ID)+"/", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": b.ID, "title": b.title()})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func cleanTags(in []string) ([]string, error) {
	if len(in) > maxTags {
		return nil, fmt.Errorf("give at most %d tags", maxTags)
	}
	out := []string{}
	seen := map[string]bool{}
	for _, t := range in {
		t = strings.TrimPrefix(strings.TrimSpace(t), "#")
		if !tagRe.MatchString(t) || len([]rune(t)) > maxTagName {
			return nil, fmt.Errorf("tags are single words of 1 to %d characters, with no spaces or commas", maxTagName)
		}
		if k := strings.ToLower(t); !seen[k] {
			seen[k] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func (c *conn) add(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	// linkding fetches what it saves (title, icon, snapshots): nothing on
	// the local network (urlguard; redirects and rebinding are the
	// server's to refuse).
	u, err := urlguard.URL(ctx, p.URL)
	if err != nil {
		return sdk.Result{}, err
	}
	if len([]rune(p.Title)) > maxTitle || len([]rune(p.Description)) > maxDescr {
		return sdk.Result{}, errors.New("the title or description is too long")
	}
	tags, err := cleanTags(p.Tags)
	if err != nil {
		return sdk.Result{}, err
	}
	// linkding's create updates a bookmark that has the URL already, so
	// check first and leave an existing one alone.
	var check struct {
		Bookmark *bookmark `json:"bookmark"`
	}
	if err := c.do(ctx, http.MethodGet, "/bookmarks/check/", url.Values{"url": {u.String()}}, nil, &check); err != nil {
		return sdk.Result{}, err
	}
	if check.Bookmark != nil && check.Bookmark.ID > 0 {
		out := c.summary(*check.Bookmark)
		out["note"] = "this link was already saved; nothing was changed"
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Nothing to do: " + rest.ShortURL(u.String()) + " is saved already", Changes: []sdk.Change{}}}, nil
		}
		return sdk.JSON(out)
	}
	body := map[string]any{"url": u.String(), "tag_names": tags, "unread": p.Unread, "shared": false, "is_archived": false}
	if t := strings.TrimSpace(p.Title); t != "" {
		body["title"] = t
	}
	if d := strings.TrimSpace(p.Description); d != "" {
		body["description"] = d
	}
	if call.DryRun {
		// The preview shows the link without its query and fragment.
		link := bareURL(u.String())
		shown := map[string]any{}
		for k, v := range body {
			shown[k] = v
		}
		shown["url"] = link
		return sdk.Result{Plan: &sdk.Plan{Summary: "Save " + link, Changes: []sdk.Change{{Target: link, Op: "create", After: mustJSON(shown)}}}}, nil
	}
	var b bookmark
	if err := c.do(ctx, http.MethodPost, "/bookmarks/", nil, body, &b); err != nil {
		return sdk.Result{}, err
	}
	r, err := sdk.JSON(c.summary(b))
	if b.ID > 0 {
		r.Undo = sdk.UndoWith("delete_bookmark", map[string]any{"bookmark": b.ID}, "Delete the bookmark for "+u.Host)
	}
	return r, err
}
