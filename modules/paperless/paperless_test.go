package paperless

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakePaperless struct {
	mu   sync.Mutex
	seen []string
	tags map[int][]int // document -> tags
}

func (f *fakePaperless) doc(id int) string {
	tags, _ := json.Marshal(f.tags[id])
	return fmt.Sprintf(`{"id":%d,"title":"Invoice %d","correspondent":5,"document_type":9,"tags":%s,"created":"2026-10-01","added":"2026-10-02T09:00:00Z","original_file_name":"inv%d.pdf","page_count":2,"notes":[],"content":"IBAN DE00 1234 secret text"}`, id, id, tags, id)
}

func (f *fakePaperless) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Token ptok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":"Invalid token."}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	w.Header().Set("X-Version", "2.13.5")
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /api/ui_settings/":
		io.WriteString(w, `{"user":{"id":1,"username":"elchi"},"settings":{}}`)
	case "GET /api/tags/":
		io.WriteString(w, `{"count":2,"next":null,"results":[{"id":1,"name":"bills","document_count":3},{"id":2,"name":"tax","document_count":1}]}`)
	case "GET /api/correspondents/":
		io.WriteString(w, `{"count":1,"next":null,"results":[{"id":5,"name":"Power Co","document_count":3}]}`)
	case "GET /api/document_types/":
		io.WriteString(w, `{"count":1,"next":null,"results":[{"id":9,"name":"Invoice","document_count":3}]}`)
	case "GET /api/tags/2/":
		io.WriteString(w, `{"id":2,"name":"tax"}`)
	case "GET /api/documents/":
		var docs []string
		switch {
		case q.Get("query") == "power" && q.Get("truncate_content") == "true":
			docs = []string{strings.Replace(f.doc(10), `"notes"`, `"__search_hit__":{"score":3.5},"notes"`, 1)}
		case q.Get("ordering") == "-added":
			docs = []string{f.doc(11), f.doc(10)}
		case q.Get("id__in") != "":
			for _, s := range strings.Split(q.Get("id__in"), ",") {
				var id int
				fmt.Sscan(s, &id)
				if _, ok := f.tags[id]; ok {
					docs = append(docs, f.doc(id))
				}
			}
		default:
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `{"count":%d,"next":null,"results":[%s]}`, len(docs), strings.Join(docs, ","))
	case "GET /api/documents/10/":
		io.WriteString(w, f.doc(10))
	case "GET /api/documents/10/metadata/":
		io.WriteString(w, `{"original_mime_type":"application/pdf","original_size":204800,"has_archive_version":true,"lang":"de"}`)
	case "POST /api/documents/bulk_edit/":
		var b struct {
			Documents  []int
			Method     string
			Parameters struct{ Tag int }
		}
		json.Unmarshal(body, &b)
		for _, d := range b.Documents {
			if b.Method == "add_tag" {
				f.tags[d] = append(f.tags[d], b.Parameters.Tag)
			} else {
				var keep []int
				for _, t := range f.tags[d] {
					if t != b.Parameters.Tag {
						keep = append(keep, t)
					}
				}
				f.tags[d] = keep
			}
		}
		io.WriteString(w, `{"result":"OK"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not found."}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakePaperless) {
	f := &fakePaperless{tags: map[int][]int{10: {1}, 11: {1, 2}}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://p": "ptok", "secret://bad": "x"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestPaperless(t *testing.T) {
	m, f := setup(t, "secret://p")
	if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "signed in as elchi · Paperless-ngx 2.13.5" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"search", `{"query":"power"}`, `"score":3.5`},
		{"recent", `{}`, `"title":"Invoice 11"`},
		{"document", `{"id":10}`, `"mimeType":"application/pdf"`},
		{"tags", `{}`, `"documents":3`},
		{"correspondents", `{}`, `"Power Co"`},
		{"document_types", `{}`, `"Invoice"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "IBAN") {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	r, _ := invoke(m, "document", `{"id":10}`, false)
	if !strings.Contains(string(r.Output), `"correspondent":"Power Co"`) || !strings.Contains(string(r.Output), `"tags":["bills"]`) || !strings.Contains(string(r.Output), "/documents/10/details") {
		t.Fatal(string(r.Output))
	}
	if r, err := invoke(m, "document_content", `{"id":10,"maxChars":4}`, false); err != nil || !strings.Contains(string(r.Output), `"content":"IBAN"`) || !strings.Contains(string(r.Output), `"truncated":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if !m.Manifest().Actions[3].Sensitive || m.Manifest().Actions[3].Name != "document_content" {
		t.Fatal("document_content must be sensitive")
	}

	// 11 already has tag 2, so only 10 changes, and undo only touches 10.
	r, err := invoke(m, "add_tag", `{"documents":[10,11,10],"tag":2}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Add tag tax to 1 documents" || len(r.Plan.Changes) != 1 || len(f.tags[10]) != 1 {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_tag", `{"documents":[10,11],"tag":2}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "remove_tag" || string(r.Undo.Input) != `{"documents":[10],"tag":2}` {
		t.Fatalf("%+v %v", r, err)
	}
	if fmt.Sprint(f.tags[10]) != "[1 2]" {
		t.Fatal(f.tags)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || fmt.Sprint(f.tags[10]) != "[1]" || fmt.Sprint(f.tags[11]) != "[1 2]" || r.Undo.Action != "add_tag" {
		t.Fatalf("%+v %v %v", r, err, f.tags)
	}
	n := len(f.seen)
	if r, err := invoke(m, "remove_tag", `{"documents":[10],"tag":2}`, false); err != nil || r.Undo != nil || strings.Contains(strings.Join(f.seen[n:], "\n"), "bulk_edit") {
		t.Fatalf("no-op: %+v %v", r, err)
	}
	if _, err := invoke(m, "add_tag", `{"documents":[99],"tag":2}`, false); err == nil || !strings.Contains(err.Error(), "no document 99") {
		t.Fatal(err)
	}
}

func TestPaperlessValidation(t *testing.T) {
	m, f := setup(t, "secret://p")
	many, _ := json.Marshal(map[string]any{"documents": make([]int, 101), "tag": 1})
	for _, c := range []struct{ action, in string }{
		{"document", `{"id":0}`},
		{"document", `{"id":"1/../../users"}`},
		{"document_content", `{}`},
		{"search", `{"query":"  "}`},
		{"add_tag", `{"documents":[1],"tag":0}`},
		{"add_tag", `{"documents":[],"tag":1}`},
		{"add_tag", `{"documents":[-1],"tag":1}`},
		{"remove_tag", string(many)},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://paperless", Token: "plain"}, {URL: "paperless.local", Token: "secret://p"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestPaperlessRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://p"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://p": "ptok"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
