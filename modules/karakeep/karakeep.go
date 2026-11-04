// Package karakeep works with a Karakeep (formerly Hoarder) bookmark server
// through its REST API and an API key: searching bookmarks, the newest ones,
// lists, adding a link, deleting a bookmark, and tagging.
package karakeep

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
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Karakeep server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://bookmarks.example.com
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

// New returns the Karakeep module.
func New() *Module { return &Module{} }

const (
	maxTags    = 20
	maxTagName = 100
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}`
	bm := `"bookmark":{"type":"string","description":"Bookmark id (see search or recent)"}`
	tags := `"tags":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"string"},"description":"Tag names"}`
	return sdk.Manifest{
		ID: "karakeep", Name: "Karakeep", Version: "0.1.0", Category: "Productivity", Icon: "bookmark",
		Description: "Search and browse your Karakeep (Hoarder) bookmarks and lists, save links and tag them.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Karakeep's address, e.g. https://bookmarks.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API key from User Settings → API Keys. It acts as you"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "search", Title: "Search bookmarks", Description: "Bookmarks matching words or Karakeep qualifiers (#tag, list:name, is:fav, after:2026-01-01), most relevant first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},` + limit + `}}`)},
			{Name: "recent", Title: "Recent bookmarks", Description: "The newest bookmarks, everywhere or in one list; archived ones only when asked.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"list":{"type":"string","description":"List id (see lists)"},"favourited":{"type":"boolean"},"archived":{"type":"boolean","default":false},` + limit + `}}`)},
			{Name: "lists", Title: "Lists", Description: "Your bookmark lists, nested ones with their parent.", Risk: sdk.RiskRead},
			{Name: "bookmark", Title: "Bookmark details", Description: "One bookmark: link, title, description, tags, your note and Karakeep's summary.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["bookmark"],"properties":{` + bm + `}}`)},
			{Name: "add_bookmark", Title: "Save a link", Description: "Bookmarks a URL; Karakeep fetches the page and tags it in the background. Undo deletes it (not when the link was already saved).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["url"],"properties":{"url":{"type":"string","format":"uri"},"title":{"type":"string"},"note":{"type":"string"}}}`)},
			{Name: "tag", Title: "Tag a bookmark", Description: "Attaches tags (made if new). Undo removes the ones it added.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["bookmark","tags"],"properties":{` + bm + `,` + tags + `}}`)},
			{Name: "untag", Title: "Untag a bookmark", Description: "Detaches tags from a bookmark (the tags stay). Undo attaches them again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["bookmark","tags"],"properties":{` + bm + `,` + tags + `}}`)},
			{Name: "delete_bookmark", Title: "Delete a bookmark", Description: "Deletes a bookmark with its archived copy, note and highlights. Karakeep can't bring it back.", Risk: sdk.RiskDestructive, DryRun: true,
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
		return errors.New("the address is like https://bookmarks.example.com")
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
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1"), "/api")
	api := rest.New(origin+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
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
		return errors.New("Karakeep refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Karakeep refused the request: %v", err)
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
		Name string `json:"name"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/me", nil, nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Karakeep API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + me.Name}
}

type tagRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type bookmark struct {
	ID         string   `json:"id"`
	CreatedAt  string   `json:"createdAt"`
	Title      *string  `json:"title"`
	Archived   bool     `json:"archived"`
	Favourited bool     `json:"favourited"`
	Note       *string  `json:"note"`
	Summary    *string  `json:"summary"`
	Tags       []tagRef `json:"tags"`
	Content    struct {
		Type        string  `json:"type"`
		URL         string  `json:"url"`
		Title       *string `json:"title"`
		Description *string `json:"description"`
		Text        *string `json:"text"`
		FileName    *string `json:"fileName"`
	} `json:"content"`
	AlreadyExists bool `json:"alreadyExists"`
}

func ptr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (b bookmark) title() string {
	for _, t := range []string{ptr(b.Title), ptr(b.Content.Title), ptr(b.Content.FileName)} {
		if strings.TrimSpace(t) != "" {
			return t
		}
	}
	if t := ptr(b.Content.Text); t != "" {
		r := []rune(t)
		if len(r) > 80 {
			return string(r[:80]) + "…"
		}
		return t
	}
	return b.Content.URL
}

func (b bookmark) tagNames() []string {
	out := []string{}
	for _, t := range b.Tags {
		out = append(out, t.Name)
	}
	return out
}

func (c *conn) summary(b bookmark) map[string]any {
	out := map[string]any{"id": b.ID, "title": b.title(), "type": b.Content.Type, "tags": b.tagNames(), "created": b.CreatedAt,
		"open": c.origin + "/dashboard/preview/" + url.PathEscape(b.ID)}
	if b.Content.URL != "" {
		out["url"] = b.Content.URL
	}
	if b.Archived {
		out["archived"] = true
	}
	if b.Favourited {
		out["favourite"] = true
	}
	return out
}

func limitOf(n int) string {
	if n <= 0 || n > 100 {
		n = 20
	}
	return strconv.Itoa(n)
}

func (c *conn) listing(ctx context.Context, path string, q url.Values) (sdk.Result, error) {
	q.Set("includeContent", "false")
	var res struct {
		Bookmarks  []bookmark `json:"bookmarks"`
		NextCursor *string    `json:"nextCursor"`
	}
	if err := c.do(ctx, http.MethodGet, path, q, nil, &res); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, b := range res.Bookmarks {
		out = append(out, c.summary(b))
	}
	return sdk.JSON(map[string]any{"bookmarks": out, "more": res.NextCursor != nil && *res.NextCursor != ""})
}

func (c *conn) get(ctx context.Context, id string) (bookmark, error) {
	if !idRe.MatchString(id) {
		return bookmark{}, errors.New("the bookmark is a bookmark id (see search or recent)")
	}
	var b bookmark
	if err := c.do(ctx, http.MethodGet, "/bookmarks/"+id, url.Values{"includeContent": {"false"}}, nil, &b); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return bookmark{}, fmt.Errorf("there's no bookmark %s", id)
		}
		return bookmark{}, err
	}
	return b, nil
}

type input struct {
	Query      string   `json:"query"`
	Limit      int      `json:"limit"`
	List       string   `json:"list"`
	Favourited *bool    `json:"favourited"`
	Archived   bool     `json:"archived"`
	Bookmark   string   `json:"bookmark"`
	URL        string   `json:"url"`
	Title      string   `json:"title"`
	Note       string   `json:"note"`
	Tags       []string `json:"tags"`
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
		if len(q) > 1000 {
			return sdk.Result{}, errors.New("the query is too long")
		}
		return c.listing(ctx, "/bookmarks/search", url.Values{"q": {q}, "limit": {limitOf(p.Limit)}, "sortOrder": {"relevance"}})

	case "recent":
		q := url.Values{"limit": {limitOf(p.Limit)}, "sortOrder": {"desc"}, "archived": {strconv.FormatBool(p.Archived)}}
		if p.Favourited != nil {
			q.Set("favourited", strconv.FormatBool(*p.Favourited))
		}
		path := "/bookmarks"
		if p.List != "" {
			if !idRe.MatchString(p.List) {
				return sdk.Result{}, errors.New("the list is a list id (see lists)")
			}
			path = "/lists/" + p.List + "/bookmarks"
		}
		return c.listing(ctx, path, q)

	case "lists":
		var res struct {
			Lists []struct {
				ID       string  `json:"id"`
				Name     string  `json:"name"`
				Icon     string  `json:"icon"`
				ParentID *string `json:"parentId"`
				Type     string  `json:"type"`
				Query    *string `json:"query"`
			} `json:"lists"`
		}
		if err := c.do(ctx, http.MethodGet, "/lists", nil, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, l := range res.Lists {
			r := map[string]any{"id": l.ID, "name": l.Name, "icon": l.Icon}
			if parent := ptr(l.ParentID); parent != "" {
				r["parentId"] = parent
			}
			if l.Type == "smart" {
				r["smart"], r["query"] = true, ptr(l.Query)
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "bookmark":
		b, err := c.get(ctx, p.Bookmark)
		if err != nil {
			return sdk.Result{}, err
		}
		out := c.summary(b)
		if d := ptr(b.Content.Description); d != "" {
			out["description"] = d
		}
		if n := ptr(b.Note); n != "" {
			out["note"] = n
		}
		if s := ptr(b.Summary); s != "" {
			out["summary"] = s
		}
		return sdk.JSON(out)

	case "add_bookmark":
		return c.add(ctx, call, p)
	case "tag", "untag":
		return c.tag(ctx, call, p)

	case "delete_bookmark":
		b, err := c.get(ctx, p.Bookmark)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete bookmark %q", b.title()),
				Changes: []sdk.Change{{Target: "bookmark " + b.ID, Op: "delete", Before: mustJSON(c.summary(b))}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/bookmarks/"+b.ID, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": b.ID, "title": b.title()})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) add(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	raw := strings.TrimSpace(p.URL)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(raw) > 4096 {
		return sdk.Result{}, errors.New("the link is an http(s) address")
	}
	if u.User != nil {
		return sdk.Result{}, errors.New("the link has a user name or password in it; leave those out")
	}
	if len([]rune(p.Title)) > 1000 || len([]rune(p.Note)) > 10000 {
		return sdk.Result{}, errors.New("the title or note is too long")
	}
	body := map[string]any{"type": "link", "url": u.String()}
	if t := strings.TrimSpace(p.Title); t != "" {
		body["title"] = t
	}
	if n := strings.TrimSpace(p.Note); n != "" {
		body["note"] = n
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Save " + u.String(), Changes: []sdk.Change{{Target: u.String(), Op: "create", After: mustJSON(body)}}}}, nil
	}
	b, _ := json.Marshal(body)
	res, err := c.api.Send(ctx, http.MethodPost, "/bookmarks", nil, strings.NewReader(string(b)), http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json"}})
	if err != nil {
		return sdk.Result{}, explain(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return sdk.Result{}, err
	}
	if res.StatusCode >= 300 {
		return sdk.Result{}, fmt.Errorf("Karakeep answered %s", res.Status)
	}
	var bm bookmark
	if err := json.Unmarshal(data, &bm); err != nil {
		return sdk.Result{}, fmt.Errorf("unexpected answer from Karakeep: %w", err)
	}
	// Karakeep answers 200 with alreadyExists for a link that's saved
	// already, and 201 for a new one; only a new one is undone.
	existed := bm.AlreadyExists || res.StatusCode == http.StatusOK
	out := c.summary(bm)
	if existed {
		out["note"] = "this link was already saved"
	}
	r, err := sdk.JSON(out)
	if !existed && idRe.MatchString(bm.ID) {
		r.Undo = sdk.UndoWith("delete_bookmark", map[string]any{"bookmark": bm.ID}, "Delete the bookmark for "+u.Host)
	}
	return r, err
}

func (c *conn) tag(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	adding := call.Action == "tag"
	if !idRe.MatchString(p.Bookmark) {
		return sdk.Result{}, errors.New("the bookmark is a bookmark id (see search or recent)")
	}
	if len(p.Tags) == 0 || len(p.Tags) > maxTags {
		return sdk.Result{}, fmt.Errorf("give 1 to %d tags", maxTags)
	}
	want := []string{}
	seen := map[string]bool{}
	for _, t := range p.Tags {
		t = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(t), "#"))
		if t == "" || len([]rune(t)) > maxTagName {
			return sdk.Result{}, fmt.Errorf("tag names are 1 to %d characters", maxTagName)
		}
		if k := strings.ToLower(t); !seen[k] {
			seen[k] = true
			want = append(want, t)
		}
	}
	b, err := c.get(ctx, p.Bookmark)
	if err != nil {
		return sdk.Result{}, err
	}
	has := map[string]string{}
	for _, t := range b.Tags {
		has[strings.ToLower(t.Name)] = t.Name
	}
	var change []string
	for _, t := range want {
		name, ok := has[strings.ToLower(t)]
		switch {
		case adding && !ok:
			change = append(change, t)
		case !adding && ok:
			change = append(change, name)
		}
	}
	sort.Strings(change)
	if len(change) == 0 {
		return sdk.JSON(map[string]any{"bookmark": b.ID, "tags": b.tagNames(), "note": "nothing to change"})
	}
	verb, back, undo := "Tag", "untag", fmt.Sprintf("Remove %s from %q", strings.Join(change, ", "), b.title())
	if !adding {
		verb, back, undo = "Untag", "tag", fmt.Sprintf("Tag %q with %s again", b.title(), strings.Join(change, ", "))
	}
	if call.DryRun {
		changes := []sdk.Change{}
		for _, t := range change {
			op := "add tag " + t
			if !adding {
				op = "remove tag " + t
			}
			changes = append(changes, sdk.Change{Target: fmt.Sprintf("bookmark %q", b.title()), Op: op})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s %q: %s", verb, b.title(), strings.Join(change, ", ")), Changes: changes}}, nil
	}
	refs := []map[string]string{}
	for _, t := range change {
		refs = append(refs, map[string]string{"tagName": t})
	}
	method := http.MethodPost
	if !adding {
		method = http.MethodDelete
	}
	if err := c.do(ctx, method, "/bookmarks/"+b.ID+"/tags", nil, map[string]any{"tags": refs}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"bookmark": b.ID, "title": b.title(), "changed": change})
	res.Undo = sdk.UndoWith(back, map[string]any{"bookmark": b.ID, "tags": change}, undo)
	return res, err
}
