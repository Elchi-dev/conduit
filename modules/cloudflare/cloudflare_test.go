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

	"github.com/elchi-dev/conduit/internal/fakehost"
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
		if r.Method == "GET" {
			rec, ok := f.records[id]
			if !ok {
				w.WriteHeader(404)
				fmt.Fprint(w, `{"success":false,"errors":[{"message":"not found"}]}`)
				return
			}
			f.reply(w, rec)
			return
		}
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

// Names that carry control over the domain (mail policy, ownership proofs,
// client auto-configuration) can't be set or restored at write.
func TestControlRecordsNeedSetRecordAny(t *testing.T) {
	f := &fakeCF{records: map[string]Record{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m := New()
	cfg, _ := json.Marshal(Config{Token: "secret://cf", API: srv.URL})
	m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cf": "cf"}), "cf", cfg)
	for _, n := range []string{"_dmarc", "_mta-sts", "_smtp._tls", "_atproto", "_github-challenge-x", "_acme-challenge.www", "sel._domainkey", "mta-sts", "autodiscover", "autoconfig.example.com", "wpad.office"} {
		in, _ := json.Marshal(map[string]any{"zone": "example.com", "type": "TXT", "name": n, "content": "x"})
		if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "cf", Action: "set_record", Input: in}); err == nil || !strings.Contains(err.Error(), "set_record_any") {
			t.Fatalf("set_record %s: %v", n, err)
		}
		rec, _ := json.Marshal(map[string]any{"zone": "example.com", "record": map[string]any{"type": "TXT", "name": n + ".example.com", "content": "x"}})
		if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "cf", Action: "restore_record", Input: rec}); err == nil {
			t.Fatalf("restore_record %s went through", n)
		}
	}
	if len(f.records) != 0 {
		t.Fatalf("created %v", f.records)
	}
	set := map[string]any{"zone": "example.com", "type": "TXT", "name": "_dmarc", "content": "v=DMARC1; p=reject"}
	if p := run(t, m, "set_record_any", set, true); !strings.Contains(p.Plan.Summary, "It controls:") {
		t.Fatalf("plan %+v", p.Plan)
	}
	run(t, m, "set_record_any", set, false)
	set["content"] = "v=DMARC1; p=none"
	changed := run(t, m, "set_record_any", set, false)
	if changed.Undo == nil || changed.Undo.Action != "restore_record_any" {
		t.Fatalf("undo %+v", changed.Undo)
	}
	undo(t, m, changed)
	for _, a := range m.Manifest().Actions {
		if strings.HasSuffix(a.Name, "_any") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

// restore_record's replace only puts a record back over itself: it can't
// rename or retype another record (that deletes it), least of all a control
// record, which would get around restore_record_any.
func TestRestoreRecordReplacesOnlyItself(t *testing.T) {
	f := &fakeCF{records: map[string]Record{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m := New()
	cfg, _ := json.Marshal(Config{Token: "secret://cf", API: srv.URL})
	m.Configure(context.Background(), fakehost.New(map[string]string{"secret://cf": "cf"}), "cf", cfg)
	run(t, m, "set_record_any", map[string]any{"zone": "example.com", "type": "TXT", "name": "_dmarc", "content": "v=DMARC1; p=reject"}, false)
	run(t, m, "set_record", map[string]any{"zone": "example.com", "type": "A", "name": "www", "content": "1.2.3.4"}, false)
	ids := map[string]string{}
	for id, r := range f.records {
		ids[r.Name] = id
	}
	for _, c := range []struct{ replace, typ, name string }{
		{ids["_dmarc.example.com"], "TXT", "x.example.com"}, // a control record renamed away
		{ids["_dmarc.example.com"], "A", "www.example.com"}, // retyped and renamed
		{ids["www.example.com"], "A", "api.example.com"},    // another host renamed
		{ids["www.example.com"], "TXT", "www.example.com"},  // retyped
	} {
		in, _ := json.Marshal(map[string]any{"zone": "example.com", "replace": c.replace, "record": map[string]any{"type": c.typ, "name": c.name, "content": "6.6.6.6"}})
		if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "cf", Action: "restore_record", Input: in}); err == nil || !strings.Contains(err.Error(), "over itself") {
			t.Fatalf("restore_record over %s as %s %s: %v", c.replace, c.typ, c.name, err)
		}
	}
	if f.records[ids["_dmarc.example.com"]].Content != "v=DMARC1; p=reject" || f.records[ids["www.example.com"]].Content != "1.2.3.4" {
		t.Fatalf("records changed: %v", f.records)
	}
	// The real undo (same type and name) still works.
	changed := run(t, m, "set_record", map[string]any{"zone": "example.com", "type": "A", "name": "www", "content": "5.6.7.8"}, false)
	undo(t, m, changed)
	if f.records[ids["www.example.com"]].Content != "1.2.3.4" {
		t.Fatalf("undo didn't restore: %v", f.records)
	}
}
