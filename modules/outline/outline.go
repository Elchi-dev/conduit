// Package outline works with an Outline knowledge base (getoutline.com or
// self-hosted) through its RPC-style API and an API key: collections,
// search, reading a document as Markdown, and creating, editing, archiving,
// restoring and deleting documents.
package outline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Cloud is Outline's hosted service, used when no address is set.
const Cloud = "https://app.getoutline.com"

// Config is one Outline workspace.
type Config struct {
	URL                string `json:"url"`   // empty for app.getoutline.com
	Token              string `json:"token"` // secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
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

// New returns the Outline module.
func New() *Module { return &Module{} }

const (
	maxTitle = 255
	maxText  = 2 << 20
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// A document is named by its UUID, its 10-character urlId, or the slug
	// in its address (title-words-urlId).
	docRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,255}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}`
	doc := `"id":{"type":"string","description":"Document id, urlId or the last part of its address"}`
	collection := `"collection":{"type":"string","description":"Collection id (see collections)"}`
	return sdk.Manifest{
		ID: "outline", Name: "Outline", Version: "0.1.0", Category: "Productivity", Icon: "document",
		Description: "Search an Outline wiki, read documents as Markdown, and create, edit, archive and delete them.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"url":{"type":"string","description":"Your Outline's address, e.g. https://wiki.example.com. Leave empty for app.getoutline.com"},
			"token":{"type":"string","x-secret":true,"description":"An API key from Settings → API & Apps. It acts with your permissions; give it only the scopes you need"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-hosted server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "collections", Title: "Collections", Description: "The collections you can see.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit + `}}`)},
			{Name: "search", Title: "Search documents", Description: "Documents matching words, most relevant first: titles, collections and links, no document text.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"},` + collection + `,"statusFilter":{"type":"string","enum":["published","draft","archived"]},` + limit + `}}`)},
			{Name: "recent", Title: "Recently updated", Description: "Documents updated most recently, in a collection or everywhere.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + collection + `,` + limit + `}}`)},
			{Name: "read_document", Title: "Read a document", Description: "A document's title and Markdown text, with its collection and dates. Document text is private, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + doc + `,"maxChars":{"type":"integer","minimum":1,"maximum":200000,"default":50000}}}`)},
			{Name: "create_document", Title: "Create a document", Description: "A new published document in a collection, optionally under a parent document. Undo deletes it (to the trash).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["collection","title"],"properties":{` + collection + `,"parent":{"type":"string","description":"Parent document id, to nest it"},"title":{"type":"string"},"text":{"type":"string","description":"Markdown"}}}`)},
			{Name: "update_document", Title: "Edit a document", Description: "Changes a document's title and/or replaces its text. Undo restores the revision that was current (by its id, so no text goes in the log), when Outline has saved one; a title-only change is undone by putting the old title back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + doc + `,"title":{"type":"string"},"text":{"type":"string","description":"Markdown, replacing the whole text"}}}`)},
			{Name: "archive_document", Title: "Archive a document", Description: "Moves a document (and its children) to the archive, out of the sidebar and search. Undo restores it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + doc + `}}`)},
			{Name: "restore_document", Title: "Restore a document", Description: "Brings an archived or trashed document back, into the collection it was in. A collection is accepted only when that one no longer exists (restoring anywhere else is restore_document_to). Undo archives or trashes it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + doc + `,` + collection + `}}`)},
			{Name: "restore_document_to", Title: "Restore a document into another collection", Description: "Brings an archived or trashed document back into a different collection, which changes who can see it. The preview names both collections. Undo moves it back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id","collection"],"properties":{` + doc + `,` + collection + `}}`)},
			{Name: "move_document", Title: "Move a document to another collection", Description: "Moves a document (and its children) to the top of another collection, which changes who can see it. The preview names both collections. Undo moves it back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id","collection"],"properties":{` + doc + `,` + collection + `}}`)},
			{Name: "restore_revision", Title: "Restore a revision", Description: "Puts a document back as it was in one of its revisions (title and text). Used by update_document's undo. Undo restores the revision that was current, when Outline has saved one.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id","revision"],"properties":{` + doc + `,"revision":{"type":"string","description":"Revision id"}}}`)},
			{Name: "delete_document", Title: "Delete a document", Description: "Moves a document and its children to the trash; Outline empties it after 30 days. Undo restores it while it's there.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + doc + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	addr := strings.TrimSpace(c.URL)
	if addr == "" {
		addr = Cloud
	}
	u, err := url.Parse(addr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://wiki.example.com (or empty for app.getoutline.com)")
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
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(origin+"/api", func(ctx context.Context, r *http.Request) error {
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

// call posts to one API method; every Outline method is a POST with a JSON
// body, answering {"data": ...}.
func (c *conn) call(ctx context.Context, method string, body map[string]any, out any) error {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	_, err := c.api.Do(ctx, http.MethodPost, "/"+method, nil, body, &env)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Outline refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Outline refused the request: %v (the key's scopes or your role don't allow it)", err)
	case err != nil:
		return err
	}
	if out != nil && len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return fmt.Errorf("unexpected answer from Outline: %w", err)
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
	var info struct {
		User struct {
			Name string `json:"name"`
		} `json:"user"`
		Team struct {
			Name string `json:"name"`
		} `json:"team"`
	}
	if err := c.call(ctx, "auth.info", map[string]any{}, &info); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Outline API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + info.User.Name
	if info.Team.Name != "" {
		msg += " · " + info.Team.Name
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type document struct {
	ID               string  `json:"id"`
	URLID            string  `json:"urlId"`
	Title            string  `json:"title"`
	Text             string  `json:"text"`
	URL              string  `json:"url"`
	CollectionID     string  `json:"collectionId"`
	ParentDocumentID *string `json:"parentDocumentId"`
	UpdatedAt        string  `json:"updatedAt"`
	PublishedAt      *string `json:"publishedAt"`
	ArchivedAt       *string `json:"archivedAt"`
	DeletedAt        *string `json:"deletedAt"`
	UpdatedBy        *struct {
		Name string `json:"name"`
	} `json:"updatedBy"`
}

func (c *conn) link(path string) string {
	if path == "" || strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return c.origin + path
}

func (c *conn) summary(d document, collections map[string]string) map[string]any {
	out := map[string]any{"id": d.ID, "title": d.Title, "url": c.link(d.URL), "updated": d.UpdatedAt, "collectionId": d.CollectionID}
	if n, ok := collections[d.CollectionID]; ok {
		out["collection"] = n
	}
	if d.ParentDocumentID != nil && *d.ParentDocumentID != "" {
		out["parentId"] = *d.ParentDocumentID
	}
	if d.UpdatedBy != nil && d.UpdatedBy.Name != "" {
		out["updatedBy"] = d.UpdatedBy.Name
	}
	switch {
	case d.DeletedAt != nil && *d.DeletedAt != "":
		out["state"] = "trashed"
	case d.ArchivedAt != nil && *d.ArchivedAt != "":
		out["state"] = "archived"
	case d.PublishedAt == nil || *d.PublishedAt == "":
		out["state"] = "draft"
	}
	return out
}

type collection struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Permission  string `json:"permission"`
}

func (c *conn) collections(ctx context.Context, limit int) ([]collection, error) {
	var all []collection
	for offset := 0; offset < limit; offset += 100 {
		n := min(100, limit-offset)
		var page []collection
		if err := c.call(ctx, "collections.list", map[string]any{"limit": n, "offset": offset}, &page); err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < n {
			break
		}
	}
	return all, nil
}

func (c *conn) names(ctx context.Context) map[string]string {
	out := map[string]string{}
	list, err := c.collections(ctx, 500)
	if err != nil {
		return out
	}
	for _, x := range list {
		out[x.ID] = x.Name
	}
	return out
}

func docID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "/doc/"); i >= 0 && (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")) {
		s = strings.TrimRight(s[i+5:], "/")
	}
	if uuidRe.MatchString(s) {
		return s, nil
	}
	if !docRe.MatchString(s) {
		return "", errors.New("the document is its id, urlId or address (see search)")
	}
	// A slug ends in the 10-character urlId: runbook-for-backups-AbCdE12345.
	if i := strings.LastIndexByte(s, '-'); i >= 0 && len(s)-i-1 == 10 {
		return s[i+1:], nil
	}
	return s, nil
}

func collectionID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !uuidRe.MatchString(s) {
		return "", errors.New("the collection is a collection id (see collections)")
	}
	return s, nil
}

func (c *conn) get(ctx context.Context, raw string) (document, error) {
	id, err := docID(raw)
	if err != nil {
		return document{}, err
	}
	var d document
	if err := c.call(ctx, "documents.info", map[string]any{"id": id}, &d); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return document{}, fmt.Errorf("there's no document %s (or the key can't see it)", id)
		}
		return document{}, err
	}
	return d, nil
}

func limitOf(n int) int {
	if n <= 0 || n > 100 {
		return 25
	}
	return n
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

type input struct {
	ID           string  `json:"id"`
	Query        string  `json:"query"`
	Collection   string  `json:"collection"`
	Parent       string  `json:"parent"`
	StatusFilter string  `json:"statusFilter"`
	Limit        int     `json:"limit"`
	MaxChars     int     `json:"maxChars"`
	Title        *string `json:"title"`
	Text         *string `json:"text"`
	Revision     string  `json:"revision"`
}

func (p input) fields() (map[string]any, error) {
	b := map[string]any{}
	if p.Title != nil {
		t := strings.TrimSpace(*p.Title)
		if t == "" || len([]rune(t)) > maxTitle {
			return nil, fmt.Errorf("the title is 1 to %d characters", maxTitle)
		}
		b["title"] = t
	}
	if p.Text != nil {
		if len(*p.Text) > maxText {
			return nil, errors.New("the text is too long (2 MiB at most)")
		}
		b["text"] = *p.Text
	}
	return b, nil
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
	case "collections":
		list, err := c.collections(ctx, limitOf(p.Limit))
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range list {
			r := map[string]any{"id": x.ID, "name": x.Name, "url": c.link(x.URL)}
			if d := strings.TrimSpace(x.Description); d != "" {
				r["description"] = d
			}
			if x.Permission != "" {
				r["permission"] = x.Permission
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "search", "recent":
		body := map[string]any{"limit": limitOf(p.Limit)}
		method := "documents.list"
		if call.Action == "search" {
			q := strings.TrimSpace(p.Query)
			if q == "" {
				return sdk.Result{}, errors.New("enter what to search for")
			}
			if len(q) > 1000 {
				return sdk.Result{}, errors.New("the query is too long")
			}
			body["query"], method = q, "documents.search"
			switch p.StatusFilter {
			case "":
			case "published", "draft", "archived":
				body["statusFilter"] = []string{p.StatusFilter}
			default:
				return sdk.Result{}, errors.New("statusFilter is published, draft or archived")
			}
		} else {
			body["sort"], body["direction"] = "updatedAt", "DESC"
		}
		if p.Collection != "" {
			id, err := collectionID(p.Collection)
			if err != nil {
				return sdk.Result{}, err
			}
			body["collectionId"] = id
		}
		var docs []document
		if method == "documents.search" {
			var hits []struct {
				Ranking  float64  `json:"ranking"`
				Document document `json:"document"`
			}
			if err := c.call(ctx, method, body, &hits); err != nil {
				return sdk.Result{}, err
			}
			names := c.names(ctx)
			out := []map[string]any{}
			for _, h := range hits {
				r := c.summary(h.Document, names)
				r["ranking"] = h.Ranking
				out = append(out, r)
			}
			return sdk.JSON(out)
		}
		if err := c.call(ctx, method, body, &docs); err != nil {
			return sdk.Result{}, err
		}
		names := c.names(ctx)
		out := []map[string]any{}
		for _, d := range docs {
			out = append(out, c.summary(d, names))
		}
		return sdk.JSON(out)

	case "read_document":
		d, err := c.get(ctx, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.MaxChars
		if n <= 0 || n > 200000 {
			n = 50000
		}
		text, cut := []rune(d.Text), false
		if len(text) > n {
			text, cut = text[:n], true
		}
		out := c.summary(d, c.names(ctx))
		out["chars"], out["truncated"], out["text"] = len([]rune(d.Text)), cut, string(text)
		return sdk.JSON(out)

	case "create_document":
		return c.create(ctx, call, p)
	case "update_document":
		return c.update(ctx, call, p)
	case "archive_document", "delete_document", "restore_document", "restore_document_to":
		return c.move(ctx, call, p)
	case "move_document":
		return c.moveTo(ctx, call, p)
	case "restore_revision":
		return c.restoreRevision(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.Title == nil {
		return sdk.Result{}, errors.New("the document needs a title")
	}
	b, err := p.fields()
	if err != nil {
		return sdk.Result{}, err
	}
	col, err := collectionID(p.Collection)
	if err != nil {
		return sdk.Result{}, err
	}
	var parent document
	if p.Parent != "" {
		if _, err := docID(p.Parent); err != nil {
			return sdk.Result{}, errors.New("the parent is a document id (see search)")
		}
	}
	if b["text"] == nil {
		b["text"] = ""
	}
	var cinfo collection
	if err := c.call(ctx, "collections.info", map[string]any{"id": col}, &cinfo); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no collection %s", col)
		}
		return sdk.Result{}, err
	}
	where := fmt.Sprintf("collection %q", cinfo.Name)
	if p.Parent != "" {
		if parent, err = c.get(ctx, p.Parent); err != nil {
			return sdk.Result{}, err
		}
		if parent.CollectionID != col {
			return sdk.Result{}, errors.New("the parent document is in another collection")
		}
		b["parentDocumentId"] = parent.ID
		where = fmt.Sprintf("%q in collection %q", parent.Title, cinfo.Name)
	}
	b["collectionId"], b["publish"] = col, true
	if call.DryRun {
		after := map[string]any{"title": b["title"], "chars": len([]rune(b["text"].(string)))}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create document %q under %s", b["title"], where),
			Changes: []sdk.Change{{Target: "document under " + where, Op: "create", After: mustJSON(after)}}}}, nil
	}
	var d document
	if err := c.call(ctx, "documents.create", b, &d); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(c.summary(d, map[string]string{col: cinfo.Name}))
	if d.ID != "" {
		res.Undo = sdk.UndoWith("delete_document", map[string]any{"id": d.ID}, fmt.Sprintf("Delete document %q", d.Title))
	}
	return res, err
}

func (c *conn) update(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	b, err := p.fields()
	if err != nil {
		return sdk.Result{}, err
	}
	if _, err := docID(p.ID); err != nil {
		return sdk.Result{}, err
	}
	if len(b) == 0 {
		return sdk.Result{}, errors.New("say what to change: title or text")
	}
	d, err := c.get(ctx, p.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	before, after := map[string]any{}, map[string]any{}
	if t, ok := b["title"]; ok {
		before["title"], after["title"] = d.Title, t
	}
	_, textChanged := b["text"]
	if textChanged {
		before["chars"], after["chars"] = len([]rune(d.Text)), len([]rune(b["text"].(string)))
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Edit document %q", d.Title),
			Changes: []sdk.Change{{Target: fmt.Sprintf("document %q", d.Title), Op: "update", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	// The undo never carries the old text (document text is private, and
	// the audit log keeps undo tokens): it names the revision that holds it.
	var undo *sdk.Undo
	if textChanged {
		undo = c.revisionUndo(ctx, d)
	} else {
		undo = sdk.UndoWith("update_document", map[string]any{"id": d.ID, "title": d.Title}, fmt.Sprintf("Rename the document back to %q", d.Title))
	}
	b["id"] = d.ID
	var nd document
	if err := c.call(ctx, "documents.update", b, &nd); err != nil {
		return sdk.Result{}, err
	}
	if nd.ID == "" {
		nd = d
	}
	out := c.summary(nd, nil)
	if undo == nil {
		out["note"] = "Outline hasn't saved a revision of the previous text yet, so there's no undo; its document history may still have it"
	}
	res, err := sdk.JSON(out)
	res.Undo = undo
	return res, err
}

type revision struct {
	ID         string `json:"id"`
	DocumentID string `json:"documentId"`
	Title      string `json:"title"`
	CreatedAt  string `json:"createdAt"`
}

// revisionUndo returns an undo that restores d's latest revision, when that
// revision holds d as it is now (it was saved no earlier than d's last
// update); nil otherwise.
func (c *conn) revisionUndo(ctx context.Context, d document) *sdk.Undo {
	var list []revision
	if err := c.call(ctx, "revisions.list", map[string]any{"documentId": d.ID, "limit": 1, "sort": "createdAt", "direction": "DESC"}, &list); err != nil || len(list) == 0 {
		return nil
	}
	r := list[0]
	created, err1 := time.Parse(time.RFC3339Nano, r.CreatedAt)
	updated, err2 := time.Parse(time.RFC3339Nano, d.UpdatedAt)
	if !uuidRe.MatchString(r.ID) || (r.DocumentID != "" && r.DocumentID != d.ID) || err1 != nil || err2 != nil || created.Before(updated) {
		return nil
	}
	return sdk.UndoWith("restore_revision", map[string]any{"id": d.ID, "revision": r.ID}, fmt.Sprintf("Restore document %q as it was", d.Title))
}

// restoreRevision puts a document back as it was in one of its revisions.
func (c *conn) restoreRevision(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if !uuidRe.MatchString(strings.TrimSpace(p.Revision)) {
		return sdk.Result{}, errors.New("the revision is a revision id")
	}
	d, err := c.get(ctx, p.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	var r revision
	if err := c.call(ctx, "revisions.info", map[string]any{"id": strings.TrimSpace(p.Revision)}, &r); err != nil {
		return sdk.Result{}, err
	}
	if r.DocumentID != d.ID {
		return sdk.Result{}, errors.New("that revision belongs to another document")
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Restore document %q to its revision of %s", d.Title, r.CreatedAt),
			Changes: []sdk.Change{{Target: fmt.Sprintf("document %q", d.Title), Op: "update", Before: mustJSON(map[string]any{"title": d.Title, "chars": len([]rune(d.Text))}), After: mustJSON(map[string]any{"title": r.Title, "revision": r.ID})}}}}, nil
	}
	undo := c.revisionUndo(ctx, d)
	if err := c.call(ctx, "documents.restore", map[string]any{"id": d.ID, "revisionId": r.ID}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"id": d.ID, "title": r.Title, "restored": r.ID})
	res.Undo = undo
	return res, err
}

// collectionName names a collection; gone says it doesn't exist (any more).
func (c *conn) collectionName(ctx context.Context, id string) (name string, gone bool, err error) {
	var ci collection
	if err := c.call(ctx, "collections.info", map[string]any{"id": id}, &ci); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return "", true, nil
		}
		return "", false, err
	}
	return ci.Name, false, nil
}

// moveTo moves a document to the top of another collection.
func (c *conn) moveTo(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	col, err := collectionID(p.Collection)
	if err != nil {
		return sdk.Result{}, err
	}
	d, err := c.get(ctx, p.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	if d.CollectionID == col && (d.ParentDocumentID == nil || *d.ParentDocumentID == "") {
		return sdk.JSON(map[string]any{"id": d.ID, "title": d.Title, "note": "the document is already at the top of that collection"})
	}
	to, gone, err := c.collectionName(ctx, col)
	if err != nil {
		return sdk.Result{}, err
	}
	if gone {
		return sdk.Result{}, fmt.Errorf("there's no collection %s", col)
	}
	from := "a deleted collection"
	if d.CollectionID != "" {
		if n, gone, err := c.collectionName(ctx, d.CollectionID); err != nil {
			return sdk.Result{}, err
		} else if !gone {
			from = fmt.Sprintf("collection %q", n)
		}
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Move %q and its child documents from %s to collection %q (people with access to that collection will see it)", d.Title, from, to),
			Changes: []sdk.Change{{Target: fmt.Sprintf("document %q", d.Title), Op: "move", Before: mustJSON(map[string]any{"collection": from, "collectionId": d.CollectionID}), After: mustJSON(map[string]any{"collection": to, "collectionId": col})}}}}, nil
	}
	if err := c.call(ctx, "documents.move", map[string]any{"id": d.ID, "collectionId": col}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"id": d.ID, "title": d.Title, "collectionId": col, "collection": to})
	if uuidRe.MatchString(d.CollectionID) && d.CollectionID != col {
		res.Undo = sdk.UndoWith("move_document", map[string]any{"id": d.ID, "collection": d.CollectionID}, fmt.Sprintf("Move %q back to %s", d.Title, from))
	}
	return res, err
}

// move archives, trashes or restores a document.
func (c *conn) move(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	col := ""
	restore := call.Action == "restore_document" || call.Action == "restore_document_to"
	if (p.Collection != "" && restore) || call.Action == "restore_document_to" {
		var err error
		if col, err = collectionID(p.Collection); err != nil {
			return sdk.Result{}, err
		}
	}
	d, err := c.get(ctx, p.ID)
	if err != nil {
		return sdk.Result{}, err
	}
	// Restoring into another collection changes who can see the document:
	// restore_document allows it only when its own collection is gone (then
	// Outline needs one); anything else is restore_document_to, which is
	// destructive. Both previews name the destination.
	dest, from := "", ""
	if col != "" && col == d.CollectionID {
		if call.Action == "restore_document_to" {
			return sdk.Result{}, errors.New("that's the collection the document is in; use restore_document")
		}
		col = ""
	}
	if col != "" {
		gone := true
		if uuidRe.MatchString(d.CollectionID) {
			var n string
			if n, gone, err = c.collectionName(ctx, d.CollectionID); err != nil {
				return sdk.Result{}, err
			}
			from = fmt.Sprintf("collection %q", n)
		}
		if gone {
			from = "a deleted collection"
		} else if call.Action == "restore_document" {
			return sdk.Result{}, fmt.Errorf("the document's %s still exists: restore it without a collection, or into another one with restore_document_to (destructive: it changes who can see it)", from)
		}
		n, missing, err := c.collectionName(ctx, col)
		if err != nil {
			return sdk.Result{}, err
		}
		if missing {
			return sdk.Result{}, fmt.Errorf("there's no collection %s", col)
		}
		dest = fmt.Sprintf("collection %q", n)
	} else if call.Action == "restore_document_to" {
		return sdk.Result{}, errors.New("restore_document_to needs a collection")
	}
	archived := d.ArchivedAt != nil && *d.ArchivedAt != ""
	trashed := d.DeletedAt != nil && *d.DeletedAt != ""
	target := fmt.Sprintf("document %q", d.Title)
	body := map[string]any{"id": d.ID}
	var method, op, summary, back, undo string
	switch call.Action {
	case "archive_document":
		if archived {
			return sdk.JSON(map[string]any{"id": d.ID, "title": d.Title, "note": "the document is already archived"})
		}
		method, op, summary = "documents.archive", "archive", fmt.Sprintf("Archive %q and its child documents", d.Title)
		back, undo = "restore_document", fmt.Sprintf("Restore %q from the archive", d.Title)
	case "delete_document":
		if trashed {
			return sdk.JSON(map[string]any{"id": d.ID, "title": d.Title, "note": "the document is already in the trash"})
		}
		method, op, summary = "documents.delete", "delete", fmt.Sprintf("Move %q and its child documents to the trash", d.Title)
		back, undo = "restore_document", fmt.Sprintf("Restore %q from the trash", d.Title)
	default:
		if !archived && !trashed {
			return sdk.JSON(map[string]any{"id": d.ID, "title": d.Title, "note": "the document isn't archived or in the trash"})
		}
		method, op = "documents.restore", "restore"
		summary = fmt.Sprintf("Restore %q", d.Title)
		back, undo = "archive_document", fmt.Sprintf("Archive %q again", d.Title)
		if trashed {
			back, undo = "delete_document", fmt.Sprintf("Move %q to the trash again", d.Title)
		}
		if col != "" {
			body["collectionId"] = col
			summary = fmt.Sprintf("Restore %q into %s (it was in %s)", d.Title, dest, from)
			if call.Action == "restore_document_to" {
				summary += "; people with access to that collection will see it"
				back, undo = "move_document", fmt.Sprintf("Move %q back to %s", d.Title, from)
			}
		}
	}
	if call.DryRun {
		ch := sdk.Change{Target: target, Op: op}
		if col != "" {
			ch.Before = mustJSON(map[string]any{"collection": from, "collectionId": d.CollectionID})
			ch.After = mustJSON(map[string]any{"collection": dest, "collectionId": col})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{ch}}}, nil
	}
	if err := c.call(ctx, method, body, nil); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"id": d.ID, "title": d.Title, "done": op}
	if col != "" {
		out["collectionId"] = col
	}
	res, err := sdk.JSON(out)
	switch {
	case back != "move_document":
		res.Undo = sdk.UndoWith(back, map[string]any{"id": d.ID}, undo)
	case uuidRe.MatchString(d.CollectionID):
		res.Undo = sdk.UndoWith(back, map[string]any{"id": d.ID, "collection": d.CollectionID}, undo)
	}
	return res, err
}
