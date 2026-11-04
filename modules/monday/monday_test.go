package monday

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

type fakeMonday struct {
	mu      sync.Mutex
	seen    []string
	queries []string
	status  string
	vars    map[string]any
}

func (f *fakeMonday) item(id string) string {
	return fmt.Sprintf(`{"id":%q,"name":"Launch page","state":"active","url":"https://acme.monday.com/boards/10/pulses/%s","updated_at":"2026-11-02T00:00:00Z","created_at":"2026-11-01T00:00:00Z",
		"board":{"id":"10","name":"Roadmap"},"group":{"id":"topics","title":"This week"},
		"column_values":[{"id":"status","type":"status","text":%q,"column":{"title":"Status"}},{"id":"email","type":"email","text":"kim@LEAKME.example","column":{"title":"Contact"}},
		{"id":"formula","type":"formula","text":"3","column":{"title":"Score"}},{"id":"person","type":"people","text":"Kim","column":{"title":"Owner"}}],
		"updates":[{"id":"70","text_body":"started","created_at":"2026-11-02T00:00:00Z","creator":{"id":"1","name":"Kim"}}]}`, id, id, f.status)
}

func (f *fakeMonday) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "mon_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"message":"Not Authenticated"}]}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, string(body))
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	json.Unmarshal(body, &req)
	f.queries = append(f.queries, req.Query)
	f.vars = req.Variables
	q := req.Query
	switch {
	case strings.Contains(q, "me {"):
		io.WriteString(w, `{"data":{"me":{"name":"Kim","email":"kim@LEAKME.example","account":{"name":"Acme"}}}}`)
	case strings.Contains(q, "boards(limit"):
		io.WriteString(w, `{"data":{"boards":[{"id":"10","name":"Roadmap","board_kind":"public","items_count":3,"url":"https://acme.monday.com/boards/10","workspace":{"id":"1","name":"Main"}}]}}`)
	case strings.Contains(q, "next_items_page"):
		fmt.Fprintf(w, `{"data":{"next_items_page":{"cursor":null,"items":[%s]}}}`, f.item("21"))
	case strings.Contains(q, "items_page"):
		fmt.Fprintf(w, `{"data":{"boards":[{"name":"Roadmap","items_page":{"cursor":"MSwxMCwi","items":[%s]}}]}}`, f.item("20"))
	case strings.Contains(q, "items(ids"):
		id := fmt.Sprint(req.Variables["ids"].([]any)[0])
		switch id {
		case "20", "21":
			fmt.Fprintf(w, `{"data":{"items":[%s]}}`, f.item(id))
		case "22": // answers with another item
			fmt.Fprintf(w, `{"data":{"items":[%s]}}`, f.item("20"))
		default:
			io.WriteString(w, `{"data":{"items":[]}}`)
		}
	case strings.Contains(q, "groups {"):
		io.WriteString(w, `{"data":{"boards":[{"name":"Roadmap","columns":[{"id":"status","title":"Status","type":"status"},{"id":"email","title":"Contact","type":"email"},{"id":"formula","title":"Score","type":"formula"}],"groups":[{"id":"topics","title":"This week"}]}]}}`)
	case strings.Contains(q, "create_item"):
		io.WriteString(w, `{"data":{"create_item":{"id":"30","name":"New"}}}`)
	case strings.Contains(q, "change_simple_column_value"):
		f.status = req.Variables["value"].(string)
		io.WriteString(w, `{"data":{"change_simple_column_value":{"id":"20"}}}`)
	case strings.Contains(q, "create_update"):
		io.WriteString(w, `{"data":{"create_update":{"id":"71"}}}`)
	case strings.Contains(q, "delete_update"):
		io.WriteString(w, `{"data":{"delete_update":{"id":"71"}}}`)
	case strings.Contains(q, "delete_item"):
		io.WriteString(w, `{"data":{"delete_item":{"id":"30"}}}`)
	default:
		io.WriteString(w, `{"errors":[{"message":"unknown query"}]}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeMonday) {
	f := &fakeMonday{status: "Working on it"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mo": "mon_good", "secret://bad": "mon_bad"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "m", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMonday(t *testing.T) {
	m, f := setup(t, "secret://mo")
	if h := m.Health(context.Background(), "m"); h.Status != "ok" || h.Message != "signed in as Kim in Acme" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"boards", `{}`, `"workspace":"Main"`},
		{"items", `{"board":"10"}`, `"cursor":"MSwxMCwi"`},
		{"items", `{"board":"10"}`, `"Status":"Working on it"`},
		{"items", `{"cursor":"MSwxMCwi"}`, `"id":"21"`},
		{"item", `{"item":"20"}`, `"text":"started"`},
		{"item", `{"item":"20"}`, `{"id":"email","title":"Contact","type":"email"}`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// Change a column: no-op, preview, real, undo.
	if r, err := invoke(m, "change_column_value", `{"item":"20","column":"status","value":"Working on it"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%+v %v", r, err)
	}
	r, err := invoke(m, "change_column_value", `{"item":"20","column":"status","value":"Done"}`, true)
	if err != nil || r.Plan == nil || string(r.Plan.Changes[0].Before) != `"Working on it"` || f.status != "Working on it" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "change_column_value", `{"item":"20","column":"status","value":"Done"}`, false)
	if err != nil || f.status != "Done" || f.vars["board"] != "10" || r.Undo == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status != "Working on it" {
		t.Fatal(err, f.status)
	}
	for _, col := range []string{"email", "formula"} {
		if _, err := invoke(m, "change_column_value", `{"item":"20","column":"`+col+`","value":"x"}`, false); err == nil {
			t.Fatalf("changed %s", col)
		}
	}

	// Create travels in variables only, whatever the name holds.
	name := `New"){ id } delete_item(item_id: 1`
	in, _ := json.Marshal(map[string]any{"board": "10", "name": name, "group": "topics", "columns": map[string]string{"status": "Done"}})
	r, err = invoke(m, "create_item", string(in), false)
	if err != nil || r.Undo == nil || string(r.Undo.Input) != `{"item":"30"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if strings.Contains(f.queries[len(f.queries)-1], "New") || f.vars["name"] != name || f.vars["values"] != `{"status":"Done"}` {
		t.Fatal(f.queries[len(f.queries)-1], f.vars)
	}
	if _, err := invoke(m, "create_item", `{"board":"10","name":"x","columns":{"email":"a@b.c"}}`, false); err == nil {
		t.Fatal("filled an email column")
	}
	if _, err := invoke(m, "create_item", `{"board":"10","name":"x","group":"nope"}`, false); err == nil {
		t.Fatal("accepted an unknown group")
	}

	// Update: escaped HTML, undo deletes it.
	r, err = invoke(m, "add_update", `{"item":"20","text":"<b>done</b>\nthanks"}`, false)
	if err != nil || f.vars["body"] != "&lt;b&gt;done&lt;/b&gt;<br>thanks" || r.Undo == nil || r.Undo.Action != "delete_update" {
		t.Fatalf("%+v %v %v", r, err, f.vars)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	r, err = invoke(m, "delete_item", `{"item":"20"}`, true)
	if err != nil || r.Plan == nil || strings.Contains(string(r.Plan.Changes[0].Before), "LEAKME") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "delete_item", `{"item":"99"}`, false); err == nil || !strings.Contains(err.Error(), "no item") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if strings.HasPrefix(a.Name, "delete_") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestMondayValidation(t *testing.T) {
	m, f := setup(t, "secret://mo")
	for _, c := range []struct{ action, in string }{
		{"items", `{}`},
		{"items", `{"board":"10 OR 1"}`},
		{"items", `{"cursor":"a b"}`},
		{"item", `{"item":"abc"}`},
		{"create_item", `{"board":"10"}`},
		{"create_item", `{"board":"10","name":"x","group":"Bad Group"}`},
		{"create_item", `{"board":"10","name":"x","columns":{"Status Col":"x"}}`},
		{"change_column_value", `{"item":"20","column":"status"}`},
		{"change_column_value", `{"item":"20","column":"$x","value":"y"}`},
		{"add_update", `{"item":"20","text":""}`},
		{"add_update", `{"item":"20","text":"@everyone heads up"}`},
		{"delete_update", `{"update":"x"}`},
		{"delete_item", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	if _, err := invoke(m, "change_column_value", `{"item":"22","column":"status","value":"Done"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("changed another item: %v %v", err, f.seen)
	}
	for _, c := range []Config{{Token: "plain"}, {}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "m"); h.Status != "down" || h.Message != "monday.com refused the API token" {
		t.Fatalf("%+v", h)
	}
}

func TestMondayRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://mo"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mo": "mon_good"}), "m", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "m"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
