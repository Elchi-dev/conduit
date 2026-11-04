// Package paperless works with a Paperless-ngx document archive through an
// API token: search and browse documents, read their metadata and text, list
// tags, correspondents and document types, and add or remove tags.
package paperless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Paperless-ngx server.
type Config struct {
	URL   string `json:"url"`   // e.g. https://paperless.example.com
	Token string `json:"token"` // secret:// API token
}

type conn struct {
	api    *rest.Client
	origin string // for links to documents
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Paperless-ngx module.
func New() *Module { return &Module{} }

const maxBulk = 100

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","default":25,"maximum":100}`
	tagEdit := `{"type":"object","required":["documents","tag"],"properties":{"documents":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"integer","minimum":1},"description":"Document ids"},"tag":{"type":"integer","minimum":1,"description":"Tag id (see tags)"}}}`
	return sdk.Manifest{
		ID: "paperless", Name: "Paperless-ngx", Version: "0.1.0", Category: "Productivity", Icon: "document",
		Description: "Search your Paperless-ngx archive, read documents' details and text, and tag documents.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://paperless.example.com"},
			"token":{"type":"string","x-secret":true,"description":"API token (your profile, API Auth Token). It acts with that user's permissions"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "search", Title: "Search documents", Description: "Full-text search; the most relevant documents first (metadata only, no text).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string","description":"Words, or Paperless query syntax like tag:bills created:[2025 to 2026]"},` + limit + `}}`)},
			{Name: "recent", Title: "Recent documents", Description: "The newest documents added.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit + `}}`)},
			{Name: "document", Title: "Document details", Description: "A document's metadata: title, correspondent, type, tags, dates, file name, size, page count.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1}}}`)},
			{Name: "document_content", Title: "Document text", Description: "The text Paperless extracted from a document (OCR). Can hold personal data, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1},"maxChars":{"type":"integer","default":20000,"maximum":200000}}}`)},
			{Name: "tags", Title: "Tags", Description: "Tags with how many documents carry each.", Risk: sdk.RiskRead},
			{Name: "correspondents", Title: "Correspondents", Risk: sdk.RiskRead},
			{Name: "document_types", Title: "Document types", Risk: sdk.RiskRead},
			{Name: "add_tag", Title: "Tag documents", Description: "Adds a tag to documents. Undo removes it from the ones that didn't have it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(tagEdit)},
			{Name: "remove_tag", Title: "Untag documents", Description: "Removes a tag from documents. Undo adds it back to the ones that had it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(tagEdit)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is like https://paperless.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	tok := c.Token
	root := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(root+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Token "+strings.TrimSpace(t))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second) // through the instance's network, if any
	}
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api, origin: root})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	hdr, err := c.api.Do(ctx, http.MethodGet, "/ui_settings/", nil, nil, &s)
	if err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "Paperless refused the token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + s.User.Username
	if v := hdr.Get("X-Version"); v != "" {
		msg += " · Paperless-ngx " + v
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type document struct {
	ID               int               `json:"id"`
	Title            string            `json:"title"`
	Correspondent    *int              `json:"correspondent"`
	DocumentType     *int              `json:"document_type"`
	Tags             []int             `json:"tags"`
	Created          string            `json:"created"`
	Added            string            `json:"added"`
	ASN              *int              `json:"archive_serial_number"`
	OriginalFileName string            `json:"original_file_name"`
	PageCount        *int              `json:"page_count"`
	Notes            []json.RawMessage `json:"notes"`
	SearchHit        *struct {
		Score float64 `json:"score"`
	} `json:"__search_hit__"`
}

type page[T any] struct {
	Count   int     `json:"count"`
	Next    *string `json:"next"`
	Results []T     `json:"results"`
}

type named struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	DocumentCount int    `json:"document_count"`
}

// names reads every tag, correspondent or document type (up to 1000).
func (c *conn) names(ctx context.Context, kind string) ([]named, error) {
	var all []named
	for pg := 1; pg <= 10; pg++ {
		var p page[named]
		q := url.Values{"page_size": {"100"}, "page": {strconv.Itoa(pg)}, "ordering": {"name"}}
		if _, err := c.api.Do(ctx, http.MethodGet, "/"+kind+"/", q, nil, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Results...)
		if p.Next == nil || len(p.Results) == 0 {
			break
		}
	}
	return all, nil
}

type lookups struct{ tags, correspondents, types map[int]string }

func (c *conn) lookups(ctx context.Context) (lookups, error) {
	var l lookups
	for kind, dst := range map[string]*map[int]string{"tags": &l.tags, "correspondents": &l.correspondents, "document_types": &l.types} {
		list, err := c.names(ctx, kind)
		if err != nil {
			return l, err
		}
		*dst = map[int]string{}
		for _, n := range list {
			(*dst)[n.ID] = n.Name
		}
	}
	return l, nil
}

func (c *conn) summary(d document, l lookups) map[string]any {
	tags := []string{}
	for _, t := range d.Tags {
		if n, ok := l.tags[t]; ok {
			tags = append(tags, n)
		} else {
			tags = append(tags, "#"+strconv.Itoa(t))
		}
	}
	out := map[string]any{"id": d.ID, "title": d.Title, "tags": tags, "created": d.Created, "added": d.Added,
		"url": fmt.Sprintf("%s/documents/%d/details", c.origin, d.ID)}
	if d.Correspondent != nil {
		out["correspondent"] = l.correspondents[*d.Correspondent]
	}
	if d.DocumentType != nil {
		out["type"] = l.types[*d.DocumentType]
	}
	if d.ASN != nil {
		out["asn"] = *d.ASN
	}
	if d.SearchHit != nil {
		out["score"] = d.SearchHit.Score
	}
	return out
}

func (c *conn) list(ctx context.Context, q url.Values) (sdk.Result, error) {
	q.Set("truncate_content", "true")
	var p page[document]
	if _, err := c.api.Do(ctx, http.MethodGet, "/documents/", q, nil, &p); err != nil {
		return sdk.Result{}, err
	}
	l, err := c.lookups(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	docs := []map[string]any{}
	for _, d := range p.Results {
		docs = append(docs, c.summary(d, l))
	}
	return sdk.JSON(map[string]any{"total": p.Count, "documents": docs})
}

func limitOf(n int) string {
	if n <= 0 || n > 100 {
		n = 25
	}
	return strconv.Itoa(n)
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Query     string `json:"query"`
		Limit     int    `json:"limit"`
		ID        int    `json:"id"`
		MaxChars  int    `json:"maxChars"`
		Documents []int  `json:"documents"`
		Tag       int    `json:"tag"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" {
			return sdk.Result{}, errors.New("enter what to search for")
		}
		return c.list(ctx, url.Values{"query": {q}, "page_size": {limitOf(p.Limit)}})

	case "recent":
		return c.list(ctx, url.Values{"ordering": {"-added"}, "page_size": {limitOf(p.Limit)}})

	case "document", "document_content":
		if p.ID <= 0 {
			return sdk.Result{}, errors.New("enter the document id")
		}
		path := "/documents/" + strconv.Itoa(p.ID) + "/"
		if call.Action == "document_content" {
			var d struct {
				Title   string `json:"title"`
				Content string `json:"content"`
			}
			if _, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, &d); err != nil {
				return sdk.Result{}, err
			}
			n := p.MaxChars
			if n <= 0 || n > 200000 {
				n = 20000
			}
			text, cut := []rune(d.Content), false
			if len(text) > n {
				text, cut = text[:n], true
			}
			return sdk.JSON(map[string]any{"id": p.ID, "title": d.Title, "chars": len([]rune(d.Content)), "truncated": cut, "content": string(text)})
		}
		var d document
		if _, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, &d); err != nil {
			return sdk.Result{}, err
		}
		l, err := c.lookups(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := c.summary(d, l)
		out["file"] = d.OriginalFileName
		out["notes"] = len(d.Notes)
		if d.PageCount != nil {
			out["pages"] = *d.PageCount
		}
		var md struct {
			MimeType   string `json:"original_mime_type"`
			Size       int64  `json:"original_size"`
			HasArchive bool   `json:"has_archive_version"`
			Lang       string `json:"lang"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, path+"metadata/", nil, nil, &md); err == nil {
			out["mimeType"], out["sizeKB"], out["archived"] = md.MimeType, md.Size/1024, md.HasArchive
			if md.Lang != "" {
				out["language"] = md.Lang
			}
		}
		return sdk.JSON(out)

	case "tags", "correspondents", "document_types":
		list, err := c.names(ctx, call.Action)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, n := range list {
			out = append(out, map[string]any{"id": n.ID, "name": n.Name, "documents": n.DocumentCount})
		}
		return sdk.JSON(out)

	case "add_tag", "remove_tag":
		return c.editTag(ctx, call, p.Documents, p.Tag)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) editTag(ctx context.Context, call sdk.Call, ids []int, tag int) (sdk.Result, error) {
	adding := call.Action == "add_tag"
	if tag <= 0 {
		return sdk.Result{}, errors.New("enter the tag id")
	}
	if len(ids) == 0 || len(ids) > maxBulk {
		return sdk.Result{}, fmt.Errorf("pick 1 to %d documents", maxBulk)
	}
	seen := map[int]bool{}
	strs := []string{}
	for _, id := range ids {
		if id <= 0 {
			return sdk.Result{}, errors.New("document ids are positive")
		}
		if !seen[id] {
			seen[id] = true
			strs = append(strs, strconv.Itoa(id))
		}
	}
	var t named
	if _, err := c.api.Do(ctx, http.MethodGet, "/tags/"+strconv.Itoa(tag)+"/", nil, nil, &t); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no tag %d", tag)
		}
		return sdk.Result{}, err
	}
	var pg page[document]
	q := url.Values{"id__in": {strings.Join(strs, ",")}, "page_size": {strconv.Itoa(maxBulk)}, "truncate_content": {"true"}}
	if _, err := c.api.Do(ctx, http.MethodGet, "/documents/", q, nil, &pg); err != nil {
		return sdk.Result{}, err
	}
	found := map[int]document{}
	for _, d := range pg.Results {
		found[d.ID] = d
	}
	var change []int
	var changes []sdk.Change
	for id := range seen {
		d, ok := found[id]
		if !ok {
			return sdk.Result{}, fmt.Errorf("there's no document %d (or the token can't see it)", id)
		}
		has := false
		for _, x := range d.Tags {
			has = has || x == tag
		}
		if has == adding {
			continue
		}
		change = append(change, id)
		op := "add tag " + t.Name
		if !adding {
			op = "remove tag " + t.Name
		}
		changes = append(changes, sdk.Change{Target: fmt.Sprintf("document %d %q", id, d.Title), Op: op})
	}
	sort.Ints(change)
	sort.Slice(changes, func(i, j int) bool { return changes[i].Target < changes[j].Target })
	summary := fmt.Sprintf("Add tag %s to %d documents", t.Name, len(change))
	back, undo := "remove_tag", fmt.Sprintf("Remove tag %s from %d documents", t.Name, len(change))
	if !adding {
		summary = fmt.Sprintf("Remove tag %s from %d documents", t.Name, len(change))
		back, undo = "add_tag", fmt.Sprintf("Add tag %s back to %d documents", t.Name, len(change))
	}
	if len(change) == 0 {
		return sdk.JSON(map[string]any{"changed": []int{}, "tag": t.Name, "note": "nothing to change"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: changes}}, nil
	}
	body := map[string]any{"documents": change, "method": call.Action, "parameters": map[string]any{"tag": tag}}
	if _, err := c.api.Do(ctx, http.MethodPost, "/documents/bulk_edit/", nil, body, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"changed": change, "tag": t.Name})
	res.Undo = sdk.UndoWith(back, map[string]any{"documents": change, "tag": tag}, undo)
	return res, err
}
