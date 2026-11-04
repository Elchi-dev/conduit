package outline

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	colID = "11111111-2222-3333-4444-555555555555"
	colB  = "22222222-2222-3333-4444-555555555555"
	colX  = "99999999-2222-3333-4444-555555555555" // deleted
	docA  = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	rev0  = "00000000-0000-0000-0000-0000000000a0"
)

type fakeOutline struct {
	mu   sync.Mutex
	seen []string
	docs map[string]map[string]any
	revs []map[string]any // newest last
	n    int
	nrev int
}

// revise records a revision of d, as Outline does after an edit.
func (f *fakeOutline) revise(d map[string]any) {
	f.nrev++
	at := "2026-11-0" + string(rune('1'+f.nrev)) + "T10:00:00Z"
	d["updatedAt"] = at
	f.revs = append(f.revs, map[string]any{"id": "00000000-0000-0000-0000-0000000000b" + string(rune('0'+f.nrev)), "documentId": d["id"], "title": d["title"], "text": d["text"], "createdAt": at})
}

func (f *fakeOutline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer ol_key" {
		w.WriteHeader(401)
		io.WriteString(w, `{"ok":false,"error":"authentication_required","status":401,"message":"Authentication required"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	var b map[string]any
	json.Unmarshal(body, &b)
	reply := func(v any) { json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": v}) }
	doc := func() map[string]any {
		id, _ := b["id"].(string)
		for _, d := range f.docs {
			if d["id"] == id || d["urlId"] == id {
				return d
			}
		}
		w.WriteHeader(404)
		io.WriteString(w, `{"ok":false,"error":"not_found","status":404,"message":"Resource not found"}`)
		return nil
	}
	switch strings.TrimPrefix(r.URL.Path, "/api/") {
	case "auth.info":
		reply(map[string]any{"user": map[string]any{"name": "Elchi", "email": "e@example.com"}, "team": map[string]any{"name": "Acme"}})
	case "collections.list":
		reply([]any{map[string]any{"id": colID, "name": "Engineering", "url": "/collection/eng-x1", "permission": "read_write"}})
	case "collections.info":
		name := map[any]string{colID: "Engineering", colB: "Finance"}[b["id"]]
		if name == "" {
			w.WriteHeader(404)
			io.WriteString(w, `{"ok":false,"message":"Resource not found"}`)
			return
		}
		reply(map[string]any{"id": b["id"], "name": name})
	case "revisions.list":
		if b["documentId"] != docA || b["direction"] != "DESC" {
			w.WriteHeader(400)
			return
		}
		out := []any{}
		for i := len(f.revs) - 1; i >= 0; i-- {
			out = append(out, f.revs[i])
		}
		reply(out)
	case "revisions.info":
		for _, r := range f.revs {
			if r["id"] == b["id"] {
				reply(r)
				return
			}
		}
		w.WriteHeader(404)
	case "documents.move":
		if d := doc(); d != nil {
			d["collectionId"] = b["collectionId"]
			reply([]any{d})
		}
	case "documents.search":
		reply([]any{map[string]any{"ranking": 0.9, "context": "private snippet", "document": f.docs[docA]}})
	case "documents.list":
		if b["sort"] != "updatedAt" {
			w.WriteHeader(400)
			return
		}
		reply([]any{f.docs[docA]})
	case "documents.info":
		if d := doc(); d != nil {
			reply(d)
		}
	case "documents.create":
		f.n++
		id := strings.Repeat("f", 8) + "-0000-0000-0000-00000000000" + string(rune('0'+f.n))
		d := map[string]any{"id": id, "urlId": "new" + string(rune('0'+f.n)), "title": b["title"], "text": b["text"], "collectionId": b["collectionId"], "parentDocumentId": b["parentDocumentId"], "url": "/doc/new", "publishedAt": "2026-11-04"}
		f.docs[id] = d
		reply(d)
	case "documents.update":
		if d := doc(); d != nil {
			for _, k := range []string{"title", "text"} {
				if v, ok := b[k]; ok {
					d[k] = v
				}
			}
			f.revise(d)
			reply(d)
		}
	case "documents.archive":
		if d := doc(); d != nil {
			d["archivedAt"] = "2026-11-04"
			reply(d)
		}
	case "documents.delete":
		if d := doc(); d != nil {
			d["deletedAt"] = "2026-11-04"
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "success": true})
		}
	case "documents.restore":
		if d := doc(); d != nil {
			if rid, ok := b["revisionId"]; ok {
				for _, r := range f.revs {
					if r["id"] == rid {
						d["title"], d["text"] = r["title"], r["text"]
					}
				}
				f.revise(d)
			} else {
				d["archivedAt"], d["deletedAt"] = nil, nil
				if c, ok := b["collectionId"]; ok {
					d["collectionId"] = c
				}
			}
			reply(d)
		}
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"ok":false,"message":"Not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeOutline) {
	f := &fakeOutline{docs: map[string]map[string]any{docA: {"id": docA, "urlId": "AbCdE12345", "title": "Runbook", "text": "secret steps", "collectionId": colID, "url": "/doc/runbook-AbCdE12345", "publishedAt": "2026-01-01", "updatedAt": "2026-11-01T10:00:00Z", "updatedBy": map[string]any{"name": "Elchi"}}},
		revs: []map[string]any{{"id": rev0, "documentId": docA, "title": "Runbook", "text": "secret steps", "createdAt": "2026-11-01T10:00:00Z"}}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://o": "ol_key", "secret://bad": "nope"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestOutline(t *testing.T) {
	m, f := setup(t, "secret://o")
	if h := m.Health(context.Background(), "o"); h.Status != "ok" || h.Message != "signed in as Elchi · Acme" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"collections", `{}`, `"name":"Engineering"`},
		{"search", `{"query":"runbook"}`, `"collection":"Engineering"`},
		{"recent", `{"collection":"` + colID + `"}`, `"title":"Runbook"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "secret") || strings.Contains(string(r.Output), "private") {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	r, err := invoke(m, "read_document", `{"id":"https://wiki.example.com/doc/runbook-AbCdE12345"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"text":"secret steps"`) || !strings.Contains(string(r.Output), `"url":"http://127.0.0.1`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "read_document") != a.Sensitive {
			t.Fatalf("%s sensitive=%v", a.Name, a.Sensitive)
		}
	}

	// Create, undo deletes it.
	r, err = invoke(m, "create_document", `{"collection":"`+colID+`","parent":"`+docA+`","title":"Child","text":"hi"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Create document "Child" under "Runbook" in collection "Engineering"` || len(f.docs) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_document", `{"collection":"`+colID+`","parent":"`+docA+`","title":"Child","text":"hi"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_document" || len(f.docs) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], `"publish":true`) || !strings.Contains(f.seen[len(f.seen)-1], `"parentDocumentId":"`+docA) {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || r.Undo == nil || r.Undo.Action != "restore_document" {
		t.Fatalf("%+v %v", r, err)
	}

	// Update: the undo restores the revision that held the old text, by
	// id, so the (private) text never goes in the audit log.
	r, err = invoke(m, "update_document", `{"id":"`+docA+`","title":"Runbook 2","text":"new"}`, false)
	if err != nil || r.Undo == nil || f.docs[docA]["text"] != "new" || r.Undo.Action != "restore_revision" || string(r.Undo.Input) != `{"id":"`+docA+`","revision":"`+rev0+`"}` {
		t.Fatalf("%+v %v", r, err)
	}
	p, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || strings.Contains(string(mustJSON(p.Plan)), "secret steps") {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.docs[docA]["title"] != "Runbook" || f.docs[docA]["text"] != "secret steps" {
		t.Fatal(err, f.docs[docA])
	}
	// Undoing the undo restores the revision saved by the edit.
	if r.Undo == nil || r.Undo.Action != "restore_revision" || strings.Contains(string(r.Undo.Input), rev0) {
		t.Fatalf("%+v", r.Undo)
	}
	// A title-only change is undone by the old title alone.
	r, err = invoke(m, "update_document", `{"id":"`+docA+`","title":"Renamed"}`, false)
	if err != nil || r.Undo == nil || string(r.Undo.Input) != `{"id":"`+docA+`","title":"Runbook"}` {
		t.Fatalf("%+v %v", r.Undo, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.docs[docA]["title"] != "Runbook" {
		t.Fatal(err, f.docs[docA])
	}
	// No revision holds the current text (edited since): no undo, and
	// never one carrying the text.
	f.docs[docA]["updatedAt"] = "2026-12-01T10:00:00Z"
	r, err = invoke(m, "update_document", `{"id":"`+docA+`","text":"newer"}`, false)
	if err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "no undo") {
		t.Fatalf("%+v %v", r, err)
	}
	f.docs[docA]["text"] = "secret steps"

	// Archive, undo restores; restoring again is a no-op.
	r, err = invoke(m, "archive_document", `{"id":"`+docA+`"}`, true)
	if err != nil || r.Plan == nil || f.docs[docA]["archivedAt"] != nil {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "archive_document", `{"id":"`+docA+`"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "restore_document" || f.docs[docA]["archivedAt"] == nil {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || r.Undo == nil || r.Undo.Action != "archive_document" || f.docs[docA]["archivedAt"] != nil {
		t.Fatalf("%+v %v", r, err)
	}
	n := len(f.seen)
	if r, err := invoke(m, "restore_document", `{"id":"`+docA+`"}`, false); err != nil || r.Undo != nil || strings.Contains(strings.Join(f.seen[n:], "\n"), "documents.restore") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
}

func TestOutlineValidation(t *testing.T) {
	m, f := setup(t, "secret://o")
	long := strings.Repeat("x", 256)
	for _, c := range []struct{ action, in string }{
		{"read_document", `{"id":""}`},
		{"read_document", `{"id":"../../users.list"}`},
		{"read_document", `{"id":"a b"}`},
		{"search", `{"query":" "}`},
		{"search", `{"query":"x","statusFilter":"all"}`},
		{"recent", `{"collection":"eng"}`},
		{"create_document", `{"title":"x"}`},
		{"create_document", `{"collection":"` + colID + `"}`},
		{"create_document", `{"collection":"` + colID + `","title":"  "}`},
		{"create_document", `{"collection":"` + colID + `","title":"` + long + `"}`},
		{"create_document", `{"collection":"` + colID + `","title":"x","parent":"../x"}`},
		{"update_document", `{"id":"` + docA + `"}`},
		{"update_document", `{"id":"/x","title":"y"}`},
		{"restore_document", `{"id":"` + docA + `","collection":"nope"}`},
		{"delete_document", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Token: "ol_plain"}, {URL: "wiki.example.com", Token: "secret://o"}, {URL: "https://wiki.example.com?x=1", Token: "secret://o"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	// No address means the cloud service.
	cloud := New()
	if err := cloud.Configure(context.Background(), fakehost.New(nil), "c", json.RawMessage(`{"token":"secret://o"}`)); err != nil {
		t.Fatal(err)
	}
	if c, _ := cloud.set.Get("c"); c.api.Base != Cloud+"/api" {
		t.Fatal(c.api.Base)
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "o"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestOutlineRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://o"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://o": "ol_key"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "o"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// Restoring into another collection changes who can see a document: at
// write it's allowed only when the document's own collection is gone;
// otherwise it's restore_document_to (destructive), whose preview names
// both collections and whose undo moves it back.
func TestOutlineRestoreIntoAnotherCollection(t *testing.T) {
	m, f := setup(t, "secret://o")
	for _, a := range m.Manifest().Actions {
		if (a.Name == "restore_document_to" || a.Name == "move_document") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
	f.docs[docA]["archivedAt"] = "2026-11-02"
	in := `{"id":"` + docA + `","collection":"` + colB + `"}`
	n := len(f.seen)
	if _, err := invoke(m, "restore_document", in, false); err == nil || !strings.Contains(err.Error(), "restore_document_to") {
		t.Fatalf("restored into another collection at write: %v", err)
	}
	if strings.Contains(strings.Join(f.seen[n:], "\n"), "documents.restore") || f.docs[docA]["collectionId"] != colID {
		t.Fatal("restored anyway", f.seen[n:])
	}
	// Naming its own collection is a plain restore.
	if r, err := invoke(m, "restore_document", `{"id":"`+docA+`","collection":"`+colID+`"}`, true); err != nil || r.Plan.Summary != `Restore "Runbook"` {
		t.Fatalf("%+v %v", r.Plan, err)
	}

	p, err := invoke(m, "restore_document_to", in, true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, `into collection "Finance" (it was in collection "Engineering")`) || !strings.Contains(string(p.Plan.Changes[0].After), colB) {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err := invoke(m, "restore_document_to", in, false)
	if err != nil || f.docs[docA]["collectionId"] != colB || f.docs[docA]["archivedAt"] != nil || r.Undo == nil || r.Undo.Action != "move_document" || string(r.Undo.Input) != `{"collection":"`+colID+`","id":"`+docA+`"}` {
		t.Fatalf("%+v %v %v", r.Undo, err, f.docs[docA])
	}
	p, err = invoke(m, "move_document", string(r.Undo.Input), true)
	if err != nil || !strings.Contains(p.Plan.Summary, `from collection "Finance" to collection "Engineering"`) {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if r, err = invoke(m, "move_document", string(r.Undo.Input), false); err != nil || f.docs[docA]["collectionId"] != colID || r.Undo == nil {
		t.Fatal(err, f.docs[docA])
	}

	// Its collection was deleted: restore_document takes a collection, and
	// the preview names it.
	f.docs[docA]["collectionId"], f.docs[docA]["deletedAt"] = colX, "2026-11-03"
	p, err = invoke(m, "restore_document", in, true)
	if err != nil || !strings.Contains(p.Plan.Summary, `into collection "Finance" (it was in a deleted collection)`) {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if r, err = invoke(m, "restore_document", in, false); err != nil || f.docs[docA]["collectionId"] != colB || r.Undo == nil || r.Undo.Action != "delete_document" {
		t.Fatalf("%+v %v", r.Undo, err)
	}
	if _, err := invoke(m, "restore_document_to", `{"id":"`+docA+`"}`, false); err == nil {
		t.Fatal("restore_document_to without a collection")
	}
}
