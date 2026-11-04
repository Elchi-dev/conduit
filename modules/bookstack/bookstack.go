// Package bookstack works with a BookStack wiki through its REST API and an
// API token: browsing shelves, books and chapters, searching, reading a page
// as Markdown, and creating, updating and deleting pages.
package bookstack

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
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one BookStack instance.
type Config struct {
	URL                string `json:"url"`   // e.g. https://wiki.example.com
	Token              string `json:"token"` // secret:// holding "<token id>:<token secret>"
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the BookStack module.
func New() *Module { return &Module{} }

const (
	maxName    = 255
	maxContent = 2 << 20 // 2 MiB of Markdown or HTML
	maxTags    = 50
)

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":50}`
	id := `"id":{"type":"integer","minimum":1}`
	tags := `"tags":{"type":"array","maxItems":50,"items":{"type":"object","required":["name"],"properties":{"name":{"type":"string"},"value":{"type":"string"}}}}`
	content := `"markdown":{"type":"string","description":"The page content as Markdown"},"html":{"type":"string","description":"The page content as HTML, instead of markdown"}`
	return sdk.Manifest{
		ID: "bookstack", Name: "BookStack", Version: "0.1.0", Category: "Productivity", Icon: "book",
		Description: "Browse and search a BookStack wiki, read pages as Markdown, and create, edit and delete pages.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"BookStack's address, e.g. https://wiki.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API token from your profile → API Tokens, stored as <token id>:<token secret>. It acts with that user's permissions"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "shelves", Title: "Shelves", Description: "Every shelf, by name.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit + `}}`)},
			{Name: "books", Title: "Books", Description: "Every book, or the books on one shelf.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"shelf":{"type":"integer","minimum":1,"description":"Shelf id (see shelves)"},` + limit + `}}`)},
			{Name: "book", Title: "Book contents", Description: "A book's chapters and pages, in order.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
			{Name: "chapter", Title: "Chapter contents", Description: "A chapter's pages, in order.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
			{Name: "search", Title: "Search", Description: "Shelves, books, chapters and pages matching words or BookStack search syntax ([tag=value], {type:page}). Names and links, no page text.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},` + limit + `}}`)},
			{Name: "read_page", Title: "Read a page", Description: "A page as Markdown, with its book, chapter, tags and revision count. Page content is private, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `,"maxChars":{"type":"integer","minimum":1,"maximum":200000,"default":50000}}}`)},
			{Name: "create_page", Title: "Create a page", Description: "A new page in a book or chapter. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["name"],"properties":{"book":{"type":"integer","minimum":1,"description":"Book id"},"chapter":{"type":"integer","minimum":1,"description":"Chapter id, instead of book"},"name":{"type":"string"},` + content + `,` + tags + `}}`)},
			{Name: "update_page", Title: "Edit a page", Description: "Changes a page's name, content or tags (only the fields given). A change of name or tags alone can be undone (the old ones are put back); a content change can't be undone here, because the old content would have to go in the log: BookStack keeps it in the page's revisions.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `,"name":{"type":"string"},` + content + `,` + tags + `}}`)},
			{Name: "delete_page", Title: "Delete a page", Description: "Deletes a page. BookStack moves it to the recycle bin, where an admin can restore it.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
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
		return errors.New("the address is like https://wiki.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token (<token id>:<token secret>) in the vault and enter its secret:// reference")
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
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(base+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if i := strings.IndexByte(t, ':'); i <= 0 || i == len(t)-1 || strings.ContainsAny(t, " \r\n") {
			return errors.New("the BookStack token must be stored as <token id>:<token secret>")
		}
		r.Header.Set("Authorization", "Token "+t)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return explain(err)
}

func explain(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("BookStack refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("BookStack refused the request: %v (the token's user needs the \"Access system API\" permission and access to this item)", err)
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var books struct {
		Total int `json:"total"`
	}
	if err := c.do(ctx, http.MethodGet, "/books", url.Values{"count": {"1"}}, nil, &books); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no BookStack API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%d books", books.Total)
	var sys struct {
		Version string `json:"version"`
	}
	if c.do(ctx, http.MethodGet, "/system", nil, nil, &sys) == nil && sys.Version != "" {
		msg += " · BookStack " + sys.Version
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type tag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type item struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Type      string `json:"type"`
	URL       string `json:"url"`
	BookID    int    `json:"book_id"`
	ChapterID int    `json:"chapter_id"`
	UpdatedAt string `json:"updated_at"`
	Draft     bool   `json:"draft"`
	Pages     []item `json:"pages"`
	Books     []item `json:"books"`
	Contents  []item `json:"contents"`
	Tags      []tag  `json:"tags"`
	Desc      string `json:"description"`
}

type page struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	BookID        int    `json:"book_id"`
	ChapterID     int    `json:"chapter_id"`
	BookSlug      string `json:"book_slug"`
	HTML          string `json:"html"`
	RawHTML       string `json:"raw_html"`
	Markdown      string `json:"markdown"`
	Editor        string `json:"editor"`
	RevisionCount int    `json:"revision_count"`
	UpdatedAt     string `json:"updated_at"`
	Draft         bool   `json:"draft"`
	Tags          []tag  `json:"tags"`
}

func nonNilTags(t []tag) []tag {
	if t == nil {
		return []tag{}
	}
	return t
}

func brief(it item) map[string]any {
	out := map[string]any{"id": it.ID, "name": it.Name}
	if it.Type != "" {
		out["type"] = it.Type
	}
	if it.URL != "" {
		out["url"] = it.URL
	}
	if it.UpdatedAt != "" {
		out["updated"] = it.UpdatedAt
	}
	if it.Draft {
		out["draft"] = true
	}
	return out
}

func limitOf(n int) int {
	if n <= 0 || n > 100 {
		return 50
	}
	return n
}

func (c *conn) list(ctx context.Context, path string, limit int) (sdk.Result, error) {
	var res struct {
		Data  []item `json:"data"`
		Total int    `json:"total"`
	}
	q := url.Values{"count": {strconv.Itoa(limitOf(limit))}, "sort": {"+name"}}
	if err := c.do(ctx, http.MethodGet, path, q, nil, &res); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, it := range res.Data {
		r := brief(it)
		if d := strings.TrimSpace(it.Desc); d != "" {
			r["description"] = clip(d, 300)
		}
		out = append(out, r)
	}
	return sdk.JSON(map[string]any{"total": res.Total, "items": out})
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func (c *conn) getPage(ctx context.Context, id int) (page, error) {
	if id <= 0 {
		return page{}, errors.New("enter the page id")
	}
	var p page
	if err := c.do(ctx, http.MethodGet, "/pages/"+strconv.Itoa(id), nil, nil, &p); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return page{}, fmt.Errorf("there's no page %d (or the token can't see it)", id)
		}
		return page{}, err
	}
	return p, nil
}

type input struct {
	ID       int     `json:"id"`
	Shelf    int     `json:"shelf"`
	Book     int     `json:"book"`
	Chapter  int     `json:"chapter"`
	Query    string  `json:"query"`
	Limit    int     `json:"limit"`
	MaxChars int     `json:"maxChars"`
	Name     *string `json:"name"`
	Markdown *string `json:"markdown"`
	HTML     *string `json:"html"`
	Tags     *[]tag  `json:"tags"`
}

// body checks the page fields given and returns them as BookStack wants them.
func (p input) body() (map[string]any, error) {
	b := map[string]any{}
	if p.Name != nil {
		n := strings.TrimSpace(*p.Name)
		if n == "" || len([]rune(n)) > maxName {
			return nil, fmt.Errorf("the page name is 1 to %d characters", maxName)
		}
		b["name"] = n
	}
	if p.Markdown != nil && p.HTML != nil {
		return nil, errors.New("give the content as markdown or as html, not both")
	}
	if p.Markdown != nil {
		if len(*p.Markdown) > maxContent {
			return nil, errors.New("the content is too long (2 MiB at most)")
		}
		b["markdown"] = *p.Markdown
	}
	if p.HTML != nil {
		if len(*p.HTML) > maxContent {
			return nil, errors.New("the content is too long (2 MiB at most)")
		}
		b["html"] = *p.HTML
	}
	if p.Tags != nil {
		if len(*p.Tags) > maxTags {
			return nil, fmt.Errorf("at most %d tags", maxTags)
		}
		ts := []tag{}
		for _, t := range *p.Tags {
			t.Name, t.Value = strings.TrimSpace(t.Name), strings.TrimSpace(t.Value)
			if t.Name == "" || len([]rune(t.Name)) > maxName || len([]rune(t.Value)) > maxName {
				return nil, fmt.Errorf("each tag has a name, and names and values are at most %d characters", maxName)
			}
			ts = append(ts, t)
		}
		b["tags"] = ts
	}
	return b, nil
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
	case "shelves":
		return c.list(ctx, "/shelves", p.Limit)

	case "books":
		if p.Shelf < 0 {
			return sdk.Result{}, errors.New("the shelf is a shelf id (see shelves)")
		}
		if p.Shelf == 0 {
			return c.list(ctx, "/books", p.Limit)
		}
		var s item
		if err := c.do(ctx, http.MethodGet, "/shelves/"+strconv.Itoa(p.Shelf), nil, nil, &s); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no shelf %d", p.Shelf)
			}
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, b := range s.Books {
			out = append(out, brief(b))
		}
		return sdk.JSON(map[string]any{"shelf": s.Name, "total": len(out), "items": out})

	case "book", "chapter":
		if p.ID <= 0 {
			return sdk.Result{}, fmt.Errorf("enter the %s id", call.Action)
		}
		var it item
		if err := c.do(ctx, http.MethodGet, "/"+call.Action+"s/"+strconv.Itoa(p.ID), nil, nil, &it); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no %s %d", call.Action, p.ID)
			}
			return sdk.Result{}, err
		}
		out := map[string]any{"id": it.ID, "name": it.Name, "description": clip(strings.TrimSpace(it.Desc), 1000), "tags": nonNilTags(it.Tags)}
		if call.Action == "chapter" {
			out["book"] = it.BookID
			pages := []map[string]any{}
			for _, pg := range it.Pages {
				pages = append(pages, brief(pg))
			}
			out["pages"] = pages
			return sdk.JSON(out)
		}
		contents := []map[string]any{}
		for _, x := range it.Contents {
			r := brief(x)
			if x.Type == "chapter" {
				pages := []map[string]any{}
				for _, pg := range x.Pages {
					pages = append(pages, brief(pg))
				}
				r["pages"] = pages
			}
			contents = append(contents, r)
		}
		out["contents"] = contents
		return sdk.JSON(out)

	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" {
			return sdk.Result{}, errors.New("enter what to search for")
		}
		if len(q) > 1000 {
			return sdk.Result{}, errors.New("the query is too long")
		}
		var res struct {
			Data []struct {
				item
				Book    *item `json:"book"`
				Chapter *item `json:"chapter"`
			} `json:"data"`
			Total int `json:"total"`
		}
		if err := c.do(ctx, http.MethodGet, "/search", url.Values{"query": {q}, "count": {strconv.Itoa(limitOf(p.Limit))}}, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, r := range res.Data {
			x := brief(r.item)
			if r.Book != nil {
				x["book"] = r.Book.Name
			}
			if r.Chapter != nil {
				x["chapter"] = r.Chapter.Name
			}
			if len(r.Tags) > 0 {
				x["tags"] = r.Tags
			}
			out = append(out, x)
		}
		return sdk.JSON(map[string]any{"total": res.Total, "results": out})

	case "read_page":
		pg, err := c.getPage(ctx, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		res, err := c.api.Send(ctx, http.MethodGet, "/pages/"+strconv.Itoa(pg.ID)+"/export/markdown", nil, nil, nil)
		if err != nil {
			return sdk.Result{}, explain(err)
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.MaxChars
		if n <= 0 || n > 200000 {
			n = 50000
		}
		text, cut := []rune(string(raw)), false
		if len(text) > n {
			text, cut = text[:n], true
		}
		return sdk.JSON(map[string]any{"id": pg.ID, "name": pg.Name, "book": pg.BookID, "chapter": pg.ChapterID, "tags": nonNilTags(pg.Tags),
			"revisions": pg.RevisionCount, "updated": pg.UpdatedAt, "chars": len([]rune(string(raw))), "truncated": cut, "markdown": string(text)})

	case "create_page":
		return c.create(ctx, call, p)
	case "update_page":
		return c.update(ctx, call, p)

	case "delete_page":
		pg, err := c.getPage(ctx, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		target := fmt.Sprintf("page %d %q", pg.ID, pg.Name)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete page %q (to the recycle bin)", pg.Name),
				Changes: []sdk.Change{{Target: target, Op: "delete", Before: mustJSON(map[string]any{"name": pg.Name, "book": pg.BookID, "chapter": pg.ChapterID, "revisions": pg.RevisionCount})}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/pages/"+strconv.Itoa(pg.ID), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": pg.ID, "name": pg.Name, "note": "moved to the recycle bin"})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Name == nil {
		return sdk.Result{}, errors.New("the page needs a name")
	}
	if (p.Book > 0) == (p.Chapter > 0) || p.Book < 0 || p.Chapter < 0 {
		return sdk.Result{}, errors.New("give the book or the chapter (an id) to put the page in")
	}
	b, err := p.body()
	if err != nil {
		return sdk.Result{}, err
	}
	if b["markdown"] == nil && b["html"] == nil {
		b["markdown"] = ""
	}
	kind, id := "book", p.Book
	if p.Chapter > 0 {
		kind, id = "chapter", p.Chapter
	}
	var parent item
	if err := c.do(ctx, http.MethodGet, "/"+kind+"s/"+strconv.Itoa(id), nil, nil, &parent); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no %s %d", kind, id)
		}
		return sdk.Result{}, err
	}
	b[kind+"_id"] = id
	where := fmt.Sprintf("%s %q", kind, parent.Name)
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create page %q in %s", b["name"], where),
			Changes: []sdk.Change{{Target: "page in " + where, Op: "create", After: mustJSON(b)}}}}, nil
	}
	var pg page
	if err := c.do(ctx, http.MethodPost, "/pages", nil, b, &pg); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"id": pg.ID, "name": pg.Name, "book": pg.BookID, "chapter": pg.ChapterID})
	if pg.ID > 0 {
		res.Undo = sdk.UndoWith("delete_page", map[string]any{"id": pg.ID}, fmt.Sprintf("Delete page %q", pg.Name))
	}
	return res, err
}

func (c *conn) update(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	b, err := p.body()
	if err != nil {
		return sdk.Result{}, err
	}
	if p.ID <= 0 {
		return sdk.Result{}, errors.New("enter the page id")
	}
	if len(b) == 0 {
		return sdk.Result{}, errors.New("say what to change: name, markdown, html or tags")
	}
	pg, err := c.getPage(ctx, p.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	before, back := map[string]any{}, map[string]any{"id": pg.ID}
	if _, ok := b["name"]; ok {
		before["name"], back["name"] = pg.Name, pg.Name
	}
	_, md := b["markdown"]
	_, ht := b["html"]
	content := md || ht
	if content {
		// Only its size: page content is private (read_page is
		// sensitive), and undo tokens are kept in the audit log, so a
		// content change has no undo; BookStack's revisions keep the old one.
		if pg.Markdown != "" || pg.Editor == "markdown" {
			before["chars"] = len([]rune(pg.Markdown))
		} else {
			old := pg.RawHTML
			if old == "" {
				old = pg.HTML
			}
			before["chars"] = len([]rune(old))
		}
	}
	if _, ok := b["tags"]; ok {
		before["tags"], back["tags"] = nonNilTags(pg.Tags), nonNilTags(pg.Tags)
	}
	if call.DryRun {
		after := map[string]any{}
		for k, v := range b {
			if s, ok := v.(string); ok && (k == "markdown" || k == "html") {
				after["chars"] = len([]rune(s))
				continue
			}
			after[k] = v
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Edit page %q", pg.Name),
			Changes: []sdk.Change{{Target: fmt.Sprintf("page %d %q", pg.ID, pg.Name), Op: "update", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	var after page
	if err := c.do(ctx, http.MethodPut, "/pages/"+strconv.Itoa(pg.ID), nil, b, &after); err != nil {
		return sdk.Result{}, err
	}
	if after.ID == 0 {
		after = pg
	}
	out := map[string]any{"id": after.ID, "name": after.Name, "revisions": after.RevisionCount, "updated": after.UpdatedAt}
	if content {
		out["note"] = "the previous content is in the page's revisions in BookStack (no undo here)"
	}
	res, err := sdk.JSON(out)
	if !content {
		res.Undo = sdk.UndoWith("update_page", back, fmt.Sprintf("Restore page %q as it was", pg.Name))
	}
	return res, err
}
