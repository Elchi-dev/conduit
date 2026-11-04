package plane

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

const (
	pid   = "11111111-1111-1111-1111-111111111111"
	iid   = "22222222-2222-2222-2222-222222222222"
	other = "33333333-3333-3333-3333-333333333333"
	todo  = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	done  = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	cid   = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	newID = "dddddddd-dddd-dddd-dddd-dddddddddddd"
)

type fakePlane struct {
	mu       sync.Mutex
	seen     []string
	legacy   bool // only /issues/
	name     string
	state    string
	due      string
	lastBody map[string]any
}

func (f *fakePlane) issue(id string) string {
	due := "null"
	if f.due != "" {
		due = fmt.Sprintf("%q", f.due)
	}
	return fmt.Sprintf(`{"id":%q,"name":%q,"sequence_id":12,"state":%q,"priority":"high","start_date":null,"target_date":%s,"description_stripped":"text","description_html":"<p>text</p>",
		"assignees":["eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"],"labels":[],"created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-02T00:00:00Z","project":%q}`, id, f.name, f.state, due, pid)
}

func (f *fakePlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != "plane_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"detail":"Given API token is not valid"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	var b map[string]any
	json.Unmarshal(body, &b)
	path := r.URL.Path
	seg := "/work-items/"
	if f.legacy {
		seg = "/issues/"
	}
	proj := "/api/v1/workspaces/acme/projects/" + pid
	if strings.HasPrefix(path, proj) && strings.Contains(path, "/work-items/") && f.legacy || strings.Contains(path, "/issues/") && !f.legacy {
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not found."}`)
		return
	}
	switch r.Method + " " + strings.Replace(path, seg, "/ITEMS/", 1) {
	case "GET /api/v1/users/me/":
		io.WriteString(w, `{"id":"e","display_name":"kim","email":"kim@LEAKME.example"}`)
	case "GET /api/v1/workspaces/acme/projects/":
		fmt.Fprintf(w, `{"results":[{"id":%q,"name":"Web","identifier":"WEB","description":"site","archived_at":null,"total_members":3}],"next_page_results":false}`, pid)
	case "GET " + proj + "/":
		fmt.Fprintf(w, `{"id":%q,"name":"Web","identifier":"WEB"}`, pid)
	case "GET " + proj + "/states/":
		fmt.Fprintf(w, `[{"id":%q,"name":"Todo","group":"unstarted"},{"id":%q,"name":"Done","group":"completed"}]`, todo, done)
	case "GET " + proj + "/ITEMS/":
		fmt.Fprintf(w, `{"results":[%s],"next_cursor":"50:1:0","next_page_results":true}`, f.issue(iid))
	case "GET " + proj + "/ITEMS/" + iid + "/":
		io.WriteString(w, f.issue(iid))
	case "GET " + proj + "/ITEMS/" + other + "/": // answers with another item
		io.WriteString(w, f.issue(iid))
	case "GET " + proj + "/ITEMS/" + newID + "/":
		io.WriteString(w, f.issue(newID))
	case "PATCH " + proj + "/ITEMS/" + iid + "/":
		f.lastBody = b
		if v, ok := b["name"].(string); ok {
			f.name = v
		}
		if v, ok := b["state"].(string); ok {
			f.state = v
		}
		if v, ok := b["target_date"]; ok {
			f.due, _ = v.(string)
		}
		io.WriteString(w, f.issue(iid))
	case "POST " + proj + "/ITEMS/":
		f.lastBody = b
		io.WriteString(w, f.issue(newID))
	case "GET " + proj + "/ITEMS/" + iid + "/comments/":
		fmt.Fprintf(w, `{"results":[{"id":%q,"comment_html":"<p>hi</p>","comment_stripped":"hi","created_at":"2026-11-03T00:00:00Z","actor_detail":{"email":"kim@LEAKME.example"}}]}`, cid)
	case "POST " + proj + "/ITEMS/" + iid + "/comments/":
		f.lastBody = b
		fmt.Fprintf(w, `{"id":%q}`, cid)
	case "DELETE " + proj + "/ITEMS/" + iid + "/comments/" + cid + "/", "DELETE " + proj + "/ITEMS/" + newID + "/":
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"detail":"Not found."}`)
	}
}

func setup(t *testing.T, tok string, legacy bool) (*Module, *fakePlane) {
	f := &fakePlane{legacy: legacy, name: "Fix header", state: todo, due: "2026-12-01"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api/v1/", Workspace: "acme", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pl": "plane_good", "secret://bad": "plane_bad"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "p", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestPlane(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		m, f := setup(t, "secret://pl", legacy)
		if h := m.Health(context.Background(), "p"); h.Status != "ok" || h.Message != "signed in as kim, 1 projects" {
			t.Fatalf("%+v", h)
		}
		pi := `"project":"` + pid + `","issue":"` + iid + `"`
		for _, c := range []struct{ action, in, want string }{
			{"projects", `{}`, `"identifier":"WEB"`},
			{"states", `{"project":"` + pid + `"}`, `"group":"completed"`},
			{"issues", `{"project":"` + pid + `"}`, `"key":"WEB-12"`},
			{"issues", `{"project":"` + pid + `"}`, `"cursor":"50:1:0"`},
			{"issue", `{` + pi + `}`, `"state":"Todo"`},
			{"issue", `{` + pi + `}`, `"text":"hi"`},
		} {
			r, err := invoke(m, c.action, c.in, false)
			out := string(r.Output)
			if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
				t.Fatalf("legacy %v %s: %s %v", legacy, c.action, out, err)
			}
		}

		// Update: no-op, preview, real, undo.
		if r, err := invoke(m, "update_issue", `{`+pi+`,"state":"todo","due":"2026-12-01"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
			t.Fatalf("%+v %v", r, err)
		}
		r, err := invoke(m, "update_issue", `{`+pi+`,"state":"Done"}`, true)
		if err != nil || r.Plan == nil || string(r.Plan.Changes[0].Before) != `{"state":"Todo"}` || f.state != todo {
			t.Fatalf("%+v %v", r.Plan, err)
		}
		r, err = invoke(m, "update_issue", `{`+pi+`,"state":"Done","name":"Fix header now","due":""}`, false)
		if err != nil || f.state != done || f.name != "Fix header now" || f.due != "" || r.Undo == nil {
			t.Fatalf("%+v %v", r, err)
		}
		if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state != todo || f.name != "Fix header" || f.due != "2026-12-01" {
			t.Fatal(err, f.state, f.name, f.due)
		}
		if _, err := invoke(m, "update_issue", `{`+pi+`,"state":"Shipped"}`, false); err == nil || !strings.Contains(err.Error(), "Todo, Done") {
			t.Fatal(err)
		}

		// Create with escaped HTML; undo deletes.
		r, err = invoke(m, "create_issue", `{"project":"`+pid+`","name":"New","description":"<script>x</script>","state":"Todo","priority":"urgent"}`, false)
		if err != nil || r.Undo == nil || r.Undo.Action != "delete_issue" || f.lastBody["description_html"] != "<p>&lt;script&gt;x&lt;/script&gt;</p>" || f.lastBody["state"] != todo {
			t.Fatalf("%+v %v %v", r, err, f.lastBody)
		}
		if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
			t.Fatal(err)
		}

		// Comment; undo deletes it.
		r, err = invoke(m, "comment", `{`+pi+`,"text":"looks good"}`, false)
		if err != nil || r.Undo == nil || f.lastBody["comment_html"] != "<p>looks good</p>" {
			t.Fatalf("%+v %v", r, err)
		}
		if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
			t.Fatal(err)
		}
		r, err = invoke(m, "delete_issue", `{`+pi+`}`, true)
		if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Changes[0].Target, "WEB-12") {
			t.Fatalf("%+v %v", r, err)
		}
	}
	for _, a := range New().Manifest().Actions {
		if strings.HasPrefix(a.Name, "delete_") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestPlaneValidation(t *testing.T) {
	m, f := setup(t, "secret://pl", false)
	pi := `"project":"` + pid + `","issue":"` + iid + `"`
	for _, c := range []struct{ action, in string }{
		{"states", `{}`},
		{"issues", `{"project":"../../users"}`},
		{"issues", `{"project":"` + pid + `","cursor":"x&per_page=1000"}`},
		{"issue", `{"project":"` + pid + `"}`},
		{"issue", `{"project":"` + pid + `","issue":"WEB-12/../"}`},
		{"update_issue", `{` + pi + `}`},
		{"update_issue", `{` + pi + `,"priority":"p1"}`},
		{"update_issue", `{` + pi + `,"due":"soon"}`},
		{"create_issue", `{"project":"` + pid + `"}`},
		{"create_issue", `{"project":"` + pid + `","name":" "}`},
		{"comment", `{` + pi + `,"text":""}`},
		{"comment", `{` + pi + `,"text":"@all please review"}`},
		{"delete_comment", `{` + pi + `,"comment":"1"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	f.seen = nil
	if _, err := invoke(m, "update_issue", `{"project":"`+pid+`","issue":"`+other+`","name":"x"}`, false); err == nil || strings.Contains(strings.Join(f.seen, "\n"), "PATCH") {
		t.Fatalf("changed another item: %v %v", err, f.seen)
	}
	for _, c := range []Config{
		{Workspace: "acme", Token: "plain"},
		{Workspace: "Acme Corp", Token: "secret://pl"},
		{Token: "secret://pl"},
		{URL: "plane.example.com", Workspace: "acme", Token: "secret://pl"},
		{URL: "https://u:p@plane.example.com", Workspace: "acme", Token: "secret://pl"},
		{URL: "https://plane.example.com/#x", Workspace: "acme", Token: "secret://pl"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad", false)
	if h := bad.Health(context.Background(), "p"); h.Status != "down" || h.Message != "Plane refused the API key" {
		t.Fatalf("%+v", h)
	}
}

func TestPlaneRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-API-Key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Workspace: "acme", Token: "secret://pl"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://pl": "plane_good"}), "p", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "p"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
