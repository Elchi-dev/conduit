package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/modules/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// fakeCF keeps DNS records in memory.
type fakeCF struct {
	mu      sync.Mutex
	records map[string]Record
	next    int
	purged  bool
}

func (f *fakeCF) reply(w http.ResponseWriter, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, `{"success":true,"errors":[],"result":%s}`, b)
}

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer cf" {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}`)
		return
	}
	path := r.URL.Path
	switch {
	case path == "/user/tokens/verify":
		f.reply(w, map[string]string{"status": "active"})
	case path == "/zones" && r.URL.Query().Get("name") == "example.com":
		f.reply(w, []Zone{{ID: "z1", Name: "example.com"}})
	case path == "/zones":
		f.reply(w, []Zone{})
	case path == "/zones/z1/dns_records" && r.Method == "GET":
		out := []Record{}
		for _, rec := range f.records {
			if (r.URL.Query().Get("type") == "" || rec.Type == r.URL.Query().Get("type")) && (r.URL.Query().Get("name") == "" || rec.Name == r.URL.Query().Get("name")) {
				out = append(out, rec)
			}
		}
		f.reply(w, out)
	case path == "/zones/z1/dns_records" && r.Method == "POST":
		var rec Record
		json.NewDecoder(r.Body).Decode(&rec)
		f.next++
		rec.ID = fmt.Sprintf("r%d", f.next)
		f.records[rec.ID] = rec
		f.reply(w, rec)
	case strings.HasPrefix(path, "/zones/z1/dns_records/"):
		id := strings.TrimPrefix(path, "/zones/z1/dns_records/")
		if r.Method == "DELETE" {
			delete(f.records, id)
			f.reply(w, map[string]string{"id": id})
			return
		}
		var rec Record
		json.NewDecoder(r.Body).Decode(&rec)
		rec.ID = id
		f.records[id] = rec
		f.reply(w, rec)
	case path == "/zones/z1/purge_cache":
		f.purged = true
		f.reply(w, map[string]string{"id": "z1"})
	default:
		w.WriteHeader(404)
		fmt.Fprint(w, `{"success":false,"errors":[{"message":"not found"}]}`)
	}
}

func run(t *testing.T, m *Module, action string, in any, dry bool) sdk.Result {
	t.Helper()
	b, _ := json.Marshal(in)
	r, err := m.Invoke(context.Background(), sdk.Call{Instance: "cf", Action: action, Input: b, DryRun: dry})
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return r
}

func undo(t *testing.T, m *Module, r sdk.Result) sdk.Result {
	t.Helper()
	if r.Undo == nil {
		t.Fatal("expected an undo")
	}
	out, err := m.Invoke(context.Background(), sdk.Call{Instance: "cf", Action: r.Undo.Action, Input: r.Undo.Input})
	if err != nil {
		t.Fatalf("undo %s: %v", r.Undo.Action, err)
	}
	return out
}

func TestRecordLifecycle(t *testing.T) {
	f := &fakeCF{records: map[string]Record{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m := New()
	cfg, _ := json.Marshal(Config{Token: "secret://cf", API: srv.URL})
	m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cf": "cf"}), "cf", cfg)
	if h := m.Health(context.Background(), "cf"); h.Status != "ok" {
		t.Fatalf("health %+v", h)
	}

	set := map[string]any{"zone": "example.com", "type": "A", "name": "www", "content": "1.2.3.4"}
	plan := run(t, m, "set_record", set, true)
	if plan.Plan.Changes[0].Op != "create" || len(f.records) != 0 {
		t.Fatalf("dry run %+v", plan.Plan)
	}
	created := run(t, m, "set_record", set, false)
	if len(f.records) != 1 {
		t.Fatal("record not created")
	}
	set["content"] = "5.6.7.8"
	plan = run(t, m, "set_record", set, true)
	if plan.Plan.Changes[0].Op != "update" || !strings.Contains(string(plan.Plan.Changes[0].Before), "1.2.3.4") {
		t.Fatalf("update plan %+v", plan.Plan)
	}
	changed := run(t, m, "set_record", set, false)
	undo(t, m, changed)
	for _, r := range f.records {
		if r.Content != "1.2.3.4" || r.Name != "www.example.com" {
			t.Fatalf("undo of a change must restore the old value: %+v", r)
		}
	}
	deleted := run(t, m, "delete_record", map[string]any{"zone": "example.com", "type": "A", "name": "www.example.com"}, false)
	if len(f.records) != 0 {
		t.Fatal("not deleted")
	}
	undo(t, m, deleted)
	if len(f.records) != 1 {
		t.Fatal("undo of a delete must recreate the record")
	}
	undo(t, m, created) // removes it again
	if len(f.records) != 0 {
		t.Fatal("undo of a create must delete")
	}
	run(t, m, "purge_cache", map[string]any{"zone": "example.com"}, false)
	if !f.purged {
		t.Fatal("not purged")
	}
	if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "cf", Action: "records", Input: json.RawMessage(`{"zone":"other.com"}`)}); err == nil {
		t.Fatal("unknown zone must fail")
	}
}

func TestFQDN(t *testing.T) {
	for in, want := range map[string]string{"@": "example.com", "www": "www.example.com", "www.example.com.": "www.example.com", "a.b": "a.b.example.com"} {
		if got := fqdn(in, "example.com"); got != want {
			t.Errorf("fqdn(%q) = %q", in, got)
		}
	}
}
