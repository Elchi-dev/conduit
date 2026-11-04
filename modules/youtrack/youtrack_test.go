package youtrack

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

type fakeYouTrack struct {
	mu       sync.Mutex
	seen     []string
	lastBody map[string]any
	commands int
}

func issueJSON(id string) string {
	return fmt.Sprintf(`{"id":"2-15","idReadable":%q,"summary":"Login breaks","description":"steps","resolved":null,"created":1730000000000,"updated":1730500000000,
		"project":{"shortName":"PRJ","name":"Project"},"reporter":{"fullName":"Kim Lee","email":"kim@LEAKME.example"},
		"customFields":[{"name":"State","value":{"name":"Open"}},{"name":"Assignee","value":{"fullName":"Kim Lee","login":"kim","email":"kim@LEAKME.example"}},
		{"name":"Tags","value":[{"name":"ui"},{"name":"auth"}]},{"name":"Estimation","value":{"presentation":"2h"}},{"name":"Points","value":3},{"name":"Due","value":null}]}`, id)
}

func (f *fakeYouTrack) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer perm:good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Unauthorized","error_description":"You are not logged in."}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var b map[string]any
	json.Unmarshal(body, &b)
	switch r.Method + " " + r.URL.Path {
	case "GET /yt/api/users/me":
		io.WriteString(w, `{"fullName":"Kim Lee","login":"kim","email":"kim@LEAKME.example"}`)
	case "GET /yt/api/admin/projects":
		io.WriteString(w, `[{"id":"0-1","shortName":"PRJ","name":"Project","description":"main"},{"id":"0-2","shortName":"OLD","name":"Old","archived":true}]`)
	case "GET /yt/api/issues":
		fmt.Fprintf(w, `[%s]`, issueJSON("PRJ-12"))
	case "GET /yt/api/issues/PRJ-12", "GET /yt/api/issues/PRJ-40":
		io.WriteString(w, issueJSON(strings.TrimPrefix(r.URL.Path, "/yt/api/issues/")))
	case "GET /yt/api/issues/PRJ-13": // answers with another issue
		io.WriteString(w, strings.Replace(issueJSON("PRJ-12"), `"2-15"`, `"2-16"`, 1))
	case "GET /yt/api/issues/PRJ-12/comments":
		io.WriteString(w, `[{"id":"4-17","text":"seen it","created":1730600000000,"author":{"fullName":"Kim Lee","email":"kim@LEAKME.example"}}]`)
	case "POST /yt/api/issues":
		f.lastBody = b
		io.WriteString(w, `{"id":"2-40","idReadable":"PRJ-40","summary":"New"}`)
	case "POST /yt/api/issues/PRJ-12/comments":
		f.lastBody = b
		io.WriteString(w, `{"id":"4-18"}`)
	case "DELETE /yt/api/issues/PRJ-12/comments/4-18", "DELETE /yt/api/issues/PRJ-40":
		w.WriteHeader(200)
	case "POST /yt/api/commands/assist":
		if strings.Contains(fmt.Sprint(b["query"]), "Bogus") {
			io.WriteString(w, `{"commands":[{"description":"Unknown command Bogus","error":true}]}`)
			return
		}
		io.WriteString(w, `{"commands":[{"description":"Set State to In Progress","error":false}]}`)
	case "POST /yt/api/commands":
		f.lastBody = b
		f.commands++
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Not Found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeYouTrack) {
	f := &fakeYouTrack{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/yt/", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://yt": "perm:good", "secret://bad": "perm:bad"}), "y", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "y", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestYouTrack(t *testing.T) {
	m, f := setup(t, "secret://yt")
	if h := m.Health(context.Background(), "y"); h.Status != "ok" || h.Message != "signed in as Kim Lee" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"shortName":"PRJ"`},
		{"issues", `{"query":"for: me #Unresolved"}`, `"State":"Open"`},
		{"issues", `{}`, `"Tags":"ui, auth"`},
		{"issues", `{}`, `"Points":"3"`},
		{"issue", `{"issue":"PRJ-12"}`, `"reporter":"Kim Lee"`},
		{"issue", `{"issue":"prj-12"}`, `"text":"seen it"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if r, _ := invoke(m, "projects", `{}`, false); strings.Contains(string(r.Output), "OLD") {
		t.Fatal(string(r.Output))
	}
	if !strings.Contains(strings.Join(f.seen, "\n"), "query=for%3A+me+%23Unresolved") {
		t.Fatal(f.seen)
	}

	// Create; undo deletes.
	r, err := invoke(m, "create_issue", `{"project":"prj","summary":"New","description":"d"}`, false)
	if err != nil || r.Undo == nil || string(r.Undo.Input) != `{"issue":"PRJ-40"}` || fmt.Sprint(f.lastBody["project"]) != "map[id:0-1]" {
		t.Fatalf("%+v %v %v", r, err, f.lastBody)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "create_issue", `{"project":"OLD","summary":"x"}`, false); err == nil {
		t.Fatal("created in an archived project")
	}

	// Comment: the preview names who's mentioned; undo deletes.
	r, err = invoke(m, "comment", `{"issue":"PRJ-12","text":"@kim can you check?"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "mentions @kim") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "comment", `{"issue":"PRJ-12","text":"fixed"}`, false)
	if err != nil || r.Undo == nil || string(r.Undo.Input) != `{"comment":"4-18","issue":"PRJ-12"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}

	// Commands: the preview says what YouTrack will do; nothing runs until asked.
	r, err = invoke(m, "apply_command", `{"issue":"PRJ-12","command":"State In Progress"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "Set State to In Progress") || f.commands != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "apply_command", `{"issue":"PRJ-12","command":"Bogus thing"}`, false); err == nil || !strings.Contains(err.Error(), "Unknown command") || f.commands != 0 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "apply_command", `{"issue":"PRJ-12","command":"State In Progress","silent":true}`, false); err != nil || f.commands != 1 || f.lastBody["silent"] != true {
		t.Fatal(err, f.lastBody)
	}
	r, err = invoke(m, "delete_issue", `{"issue":"PRJ-12"}`, true)
	if err != nil || r.Plan == nil || strings.Contains(string(r.Plan.Changes[0].Before), "LEAKME") {
		t.Fatalf("%+v %v", r, err)
	}
	for _, a := range m.Manifest().Actions {
		if (strings.HasPrefix(a.Name, "delete_") || a.Name == "apply_command") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestYouTrackValidation(t *testing.T) {
	m, f := setup(t, "secret://yt")
	for _, c := range []struct{ action, in string }{
		{"issue", `{}`},
		{"issue", `{"issue":"../admin/users"}`},
		{"issue", `{"issue":"PRJ-12?fields=x"}`},
		{"issues", `{"skip":-1}`},
		{"issues", `{"query":"` + strings.Repeat("x", 3000) + `"}`},
		{"create_issue", `{"project":"PRJ"}`},
		{"create_issue", `{"project":"P/R","summary":"x"}`},
		{"comment", `{"issue":"PRJ-12","text":" "}`},
		{"comment", `{"issue":"PRJ-12","text":"@all heads up"}`},
		{"apply_command", `{"issue":"PRJ-12"}`},
		{"apply_command", `{"issue":"PRJ-12","command":"State Fixed\nremove"}`},
		{"apply_command", `{"issue":"PRJ-12","command":"State Fixed","comment":"@everyone fixed"}`},
		{"delete_comment", `{"issue":"PRJ-12","comment":"../x"}`},
		{"delete_issue", `{"issue":"PRJ"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	if _, err := invoke(m, "apply_command", `{"issue":"PRJ-13","command":"State Fixed"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("changed another issue: %v %v", err, f.seen)
	}
	for _, c := range []Config{
		{URL: "https://yt.example.com", Token: "perm:plain"},
		{Token: "secret://yt"},
		{URL: "yt.example.com", Token: "secret://yt"},
		{URL: "https://u:p@yt.example.com", Token: "secret://yt"},
		{URL: "https://yt.example.com/?a=1", Token: "secret://yt"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "y"); h.Status != "down" || h.Message != "YouTrack refused the token" {
		t.Fatalf("%+v", h)
	}
}

func TestYouTrackRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://yt"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://yt": "perm:good"}), "y", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "y"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
