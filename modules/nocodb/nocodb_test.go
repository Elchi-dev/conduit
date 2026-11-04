package nocodb

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
	"github.com/elchi-dev/conduit/modules/internal/records"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeNoco struct {
	mu    sync.Mutex
	seen  []string
	where string
	sort  string
	recs  map[string]map[string]any
	next  int
	last  string
}

func (f *fakeNoco) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if r.Header.Get("xc-token") != "nc-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"msg":"Authentication required - Invalid token"}`)
		return
	}
	enc := json.NewEncoder(w)
	id := strings.TrimPrefix(r.URL.Path, "/api/v2/tables/mtasks/records/")
	switch {
	case r.URL.Path == "/api/v2/meta/bases/":
		io.WriteString(w, `{"list":[{"id":"pbase1","title":"Ops"}],"pageInfo":{}}`)
	case r.URL.Path == "/api/v2/meta/bases/pbase1/tables":
		io.WriteString(w, `{"list":[{"id":"mtasks","title":"Tasks","type":"table"},{"id":"mlink","title":"_nc_m2m","mm":true}]}`)
	case r.URL.Path == "/api/v2/meta/tables/mtasks":
		io.WriteString(w, `{"id":"mtasks","title":"Tasks","columns":[
			{"title":"Id","uidt":"ID","pk":true,"ai":true},{"title":"Title","uidt":"SingleLineText","rqd":true},{"title":"Due date","uidt":"Date"},
			{"title":"Owner","uidt":"User"},{"title":"CreatedBy","uidt":"CreatedBy","system":true},{"title":"Total","uidt":"Formula"},
			{"title":"Lead","uidt":"Lookup"}]}`)
	case r.URL.Path == "/api/v2/meta/tables/mother": // answers with another table
		io.WriteString(w, `{"id":"mtasks","title":"Tasks","columns":[]}`)
	case r.Method == "GET" && r.URL.Path == "/api/v2/tables/mtasks/records":
		f.where, f.sort = r.URL.Query().Get("where"), r.URL.Query().Get("sort")
		rows := []any{}
		for _, x := range f.recs {
			rows = append(rows, x)
		}
		enc.Encode(map[string]any{"list": rows, "pageInfo": map[string]any{"totalRows": len(rows), "isLastPage": true}})
	case r.Method == "GET" && f.recs[id] != nil:
		enc.Encode(f.recs[id])
	case r.Method == "POST" && r.URL.Path == "/api/v2/tables/mtasks/records":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.next++
		b["Id"] = float64(f.next)
		f.recs[fmt.Sprint(f.next)] = b
		enc.Encode(map[string]any{"Id": f.next})
	case r.Method == "PATCH" && r.URL.Path == "/api/v2/tables/mtasks/records":
		f.last = string(body)
		var b []map[string]any
		json.Unmarshal(body, &b)
		k := fmt.Sprint(b[0]["Id"])
		for kk, v := range b[0] {
			f.recs[k][kk] = v
		}
		io.WriteString(w, `[{"Id":`+k+`}]`)
	case r.Method == "DELETE" && r.URL.Path == "/api/v2/tables/mtasks/records":
		f.last = string(body)
		var b []map[string]any
		json.Unmarshal(body, &b)
		delete(f.recs, fmt.Sprint(b[0]["Id"]))
		io.WriteString(w, string(body))
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"msg":"Not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeNoco) {
	f := &fakeNoco{next: 1, recs: map[string]map[string]any{"1": {"Id": 1.0, "Title": "Backup", "Due date": "2026-11-05",
		"Owner": []any{map[string]any{"id": "us1", "email": "LEAKME@example.com", "display_name": "Ana"}}, "CreatedBy": map[string]any{"id": "us2", "email": "LEAKME@example.com"},
		"Lead": []any{[]any{map[string]any{"id": "us3", "email": "LEAKME@example.com", "display_name": "Bo"}}}}}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nc": "nc-good", "secret://bad": "nc-bad"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func noLeak(t *testing.T, r sdk.Result, err error) string {
	t.Helper()
	s := string(r.Output)
	if r.Plan != nil {
		b, _ := json.Marshal(r.Plan)
		s += string(b)
	}
	if err != nil {
		s += err.Error()
	}
	if strings.Contains(s, "LEAKME") || strings.Contains(s, "nc-good") {
		t.Fatalf("leaked: %s", s)
	}
	return s
}

func TestNocoDB(t *testing.T) {
	m, f := setup(t, "secret://nc")
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || h.Message != "1 bases" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"bases", `{}`, `"title":"Ops"`},
		{"tables", `{"base":"pbase1"}`, `"id":"mtasks"`},
		{"fields", `{"table":"mtasks"}`, `"automatic":true,"primaryKey":false,"required":false,"title":"Total"`},
		{"list_records", `{"table":"mtasks","where":[{"field":"Title","op":"contains","value":"back up"},{"field":"Due date","op":"lte","value":"2026-12-01"},{"field":"Due date","op":"notempty"}],"sort":"-Due date"}`, `"Lead":[["Bo"]],"Owner":["Ana"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if out := noLeak(t, r, err); err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "_nc_m2m") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if f.where != "(Title,like,%back up%)~and(Due date,le,2026-12-01)~and(Due date,notblank)" || f.sort != "-Due date" {
		t.Fatal(f.where, f.sort)
	}

	r, err := invoke(m, "create_record", `{"table":"mtasks","data":{"Title":"New"}}`, true)
	if err != nil || r.Plan == nil || len(f.recs) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_record", `{"table":"mtasks","data":{"Title":"New"}}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_record" || string(r.Undo.Input) != `{"id":"2","table":"mtasks"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.recs["2"] != nil || f.last != `[{"Id":2}]` {
		t.Fatal(err, f.last)
	}
	if r, err := invoke(m, "update_record", `{"table":"mtasks","id":1,"data":{"Title":"Backup"}}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output), err)
	}
	r, err = invoke(m, "update_record", `{"table":"mtasks","id":"1","data":{"Title":"Backups"}}`, true)
	if err != nil || r.Plan == nil || string(r.Plan.Changes[0].Before) != `{"Title":"Backup"}` {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "update_record", `{"table":"mtasks","id":"1","data":{"Title":"Backups"}}`, false); err != nil || f.last != `[{"Id":1,"Title":"Backups"}]` {
		t.Fatal(err, f.last)
	}
	r, err = invoke(m, "delete_record", `{"table":"mtasks","id":"1"}`, true)
	if out := noLeak(t, r, err); err != nil || strings.Contains(out, "Backups") || f.recs["1"] == nil {
		t.Fatal(out, err)
	}
	if _, err := invoke(m, "delete_record", `{"table":"mtasks","id":"1"}`, false); err != nil || f.recs["1"] != nil {
		t.Fatal(err)
	}
}

func TestNocoDBWhere(t *testing.T) {
	cs := []records.Cond{{Field: "A", Op: "eq", Value: true}, {Field: "B", Op: "gt", Value: 2.5}, {Field: "C", Op: "empty"}}
	if got := Where(cs); got != "(A,eq,true)~and(B,gt,2.5)~and(C,blank)" {
		t.Fatal(got)
	}
}

func TestNocoDBValidation(t *testing.T) {
	m, f := setup(t, "secret://nc")
	for _, c := range []struct{ action, in string }{
		{"tables", `{"base":"../x"}`},
		{"list_records", `{"table":"mtasks/../x"}`},
		{"list_records", `{"table":"mtasks","where":[{"field":"Title","op":"eq","value":"x)~or(Id,gt,0"}]}`},
		{"list_records", `{"table":"mtasks","where":[{"field":"Title,eq,x)~or(Id","op":"eq","value":"0"}]}`},
		{"list_records", `{"table":"mtasks","where":[{"field":"Title","op":"eq","value":"a~b"}]}`},
		{"list_records", `{"table":"mtasks","where":[{"field":"Title","op":"eq","value":"a\\"}]}`},
		{"update_record", `{"table":"mtasks","id":"1/2","data":{"Title":"x"}}`},
		{"delete_record", `{"table":"mtasks","id":{"Id":1}}`},
		{"create_record", `{"table":"mtasks"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []struct{ action, in string }{
		{"list_records", `{"table":"mtasks","where":[{"field":"Owner","op":"contains","value":"@example.com"}]}`},
		{"list_records", `{"table":"mtasks","where":[{"field":"Nope","op":"eq","value":"x"}]}`},
		{"list_records", `{"table":"mtasks","sort":"CreatedBy"}`},
		{"list_records", `{"table":"mtasks","where":[{"field":"Lead","op":"contains","value":"@example.com"}]}`},
		{"create_record", `{"table":"mtasks","data":{"Id":5}}`},
		{"create_record", `{"table":"mtasks","data":{"Total":5}}`},
		{"create_record", `{"table":"mtasks","data":{"Owner":"x"}}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	for _, p := range f.seen {
		if p != "GET /api/v2/meta/tables/mtasks" {
			t.Fatalf("invalid input reached the server: %v", f.seen)
		}
	}
	if _, err := invoke(m, "list_records", `{"table":"mother"}`, false); err == nil || !strings.Contains(err.Error(), "another table") {
		t.Fatal(err)
	}
	for _, c := range []Config{{Token: "plain"}, {URL: "nocodb.example.com", Token: "secret://nc"}, {URL: "https://n.example.com/?a=1", Token: "secret://nc"}, {URL: "https://u:p@n.example.com", Token: "secret://nc"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" || h.Message != "NocoDB refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestNocoDBRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("xc-token") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://nc"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://nc": "nc-good"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
