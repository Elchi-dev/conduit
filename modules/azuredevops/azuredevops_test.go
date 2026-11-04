package azuredevops

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
	repoID = "11111111-2222-3333-4444-555555555555"
	projID = "99999999-2222-3333-4444-555555555555"
)

type fake struct {
	mu       sync.Mutex
	seen     []string
	prStatus string
	state    string
	rev      int
	deleted  bool
	queued   []string
	created  []string
	ctype    string
}

func (f *fake) pr() map[string]any {
	return map[string]any{"pullRequestId": 12, "title": "Fix login", "status": f.prStatus, "mergeStatus": "succeeded", "createdBy": map[string]any{"displayName": "Bo"},
		"sourceRefName": "refs/heads/fix/login", "targetRefName": "refs/heads/main", "lastMergeSourceCommit": map[string]any{"commitId": "abc123abc123abc123"},
		"repository": map[string]any{"id": repoID, "name": "web", "project": map[string]any{"id": projID, "name": "Web App"}},
		"reviewers":  []any{map[string]any{"displayName": "Ana", "vote": -10, "isRequired": true}, map[string]any{"displayName": "Cy", "vote": 10}}}
}

func (f *fake) wi() map[string]any {
	return map[string]any{"id": 5, "rev": f.rev, "fields": map[string]any{"System.WorkItemType": "Bug", "System.Title": "Crash on save", "System.State": f.state,
		"System.AssignedTo": map[string]any{"displayName": "Ana", "uniqueName": "ana@example.com"}, "System.Description": "<p>Steps &amp; more</p>"}}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "" || p != "pat" {
		// Azure DevOps answers a bad token with its sign-in page.
		w.WriteHeader(203)
		io.WriteString(w, `<html>sign in</html>`)
		return
	}
	if r.URL.Query().Get("api-version") == "" {
		w.WriteHeader(400)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	pp := "/acme/Web%20App/_apis"
	switch r.Method + " " + r.URL.EscapedPath() {
	case "GET /acme/_apis/projects":
		io.WriteString(w, `{"count":2,"value":[{"id":"`+projID+`","name":"Web App","state":"wellFormed","visibility":"private"}]}`)
	case "GET " + pp + "/git/repositories":
		io.WriteString(w, `{"value":[{"id":"`+repoID+`","name":"web","defaultBranch":"refs/heads/main"}]}`)
	case "GET " + pp + "/git/pullrequests", "GET " + pp + "/git/repositories/web/pullrequests":
		enc.Encode(map[string]any{"value": []any{f.pr()}})
	case "GET " + pp + "/git/pullrequests/12":
		enc.Encode(f.pr())
	case "GET " + pp + "/policy/evaluations":
		io.WriteString(w, `{"value":[{"status":"rejected","configuration":{"isBlocking":true,"type":{"displayName":"Build"}}},{"status":"approved","configuration":{"isBlocking":true,"type":{"displayName":"Minimum number of reviewers"}}}]}`)
	case "POST " + pp + "/git/repositories/" + repoID + "/pullRequests/12/threads":
		io.WriteString(w, `{"id":77}`)
	case "PATCH " + pp + "/git/repositories/" + repoID + "/pullrequests/12":
		f.prStatus = "completed"
		enc.Encode(f.pr())
	case "GET " + pp + "/build/definitions":
		io.WriteString(w, `{"value":[{"id":3,"name":"CI","path":"\\","repository":{"name":"web"}}]}`)
	case "GET " + pp + "/build/definitions/3":
		io.WriteString(w, `{"id":3,"name":"CI","repository":{"name":"web","defaultBranch":"refs/heads/main"}}`)
	case "GET " + pp + "/build/builds":
		io.WriteString(w, `{"value":[{"id":100,"buildNumber":"20261104.1","status":"completed","result":"failed","sourceBranch":"refs/heads/main","sourceVersion":"0123456789abcdef","definition":{"id":3,"name":"CI"}}]}`)
	case "GET " + pp + "/build/builds/100":
		io.WriteString(w, `{"id":100,"buildNumber":"20261104.1","status":"completed","result":"failed","definition":{"id":3,"name":"CI"}}`)
	case "GET " + pp + "/build/builds/101":
		io.WriteString(w, `{"id":101,"buildNumber":"20261104.2","status":"inProgress","definition":{"id":3,"name":"CI"},"sourceBranch":"refs/heads/main"}`)
	case "PATCH " + pp + "/build/builds/101":
		io.WriteString(w, `{"id":101,"status":"cancelling"}`)
	case "GET " + pp + "/build/builds/100/timeline":
		io.WriteString(w, `{"records":[{"type":"Stage","name":"Build","state":"completed","result":"failed","startTime":"1"},{"type":"Task","name":"npm test","result":"failed","errorCount":1,"log":{"id":7},"issues":[{"type":"error","message":"Tests failed"}],"startTime":"2"}]}`)
	case "GET " + pp + "/build/builds/100/logs":
		io.WriteString(w, `{"value":[{"id":6,"lineCount":3},{"id":7,"lineCount":500}]}`)
	case "GET " + pp + "/build/builds/100/logs/7":
		if r.URL.Query().Get("startLine") != "499" || r.URL.Query().Get("endLine") != "500" || r.Header.Get("Accept") != "text/plain" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, "\ufeff2026-11-04T10:00:00Z FAIL a.test.js\n2026-11-04T10:00:01Z ##[error]exit 1\n")
	case "POST " + pp + "/build/builds":
		f.queued = append(f.queued, string(body))
		io.WriteString(w, `{"id":102,"buildNumber":"20261104.3","status":"notStarted"}`)
	case "POST " + pp + "/wit/wiql":
		io.WriteString(w, `{"workItems":[{"id":5},{"id":6}]}`)
	case "GET " + pp + "/wit/workitems":
		if r.URL.Query().Get("ids") != "5,6" {
			w.WriteHeader(400)
			return
		}
		enc.Encode(map[string]any{"value": []any{f.wi()}})
	case "GET " + pp + "/wit/workitems/5":
		if f.deleted {
			w.WriteHeader(404)
			return
		}
		enc.Encode(f.wi())
	case "GET " + pp + "/wit/workitemtypes/Bug/states":
		io.WriteString(w, `{"value":[{"name":"New"},{"name":"Active"},{"name":"Resolved"},{"name":"Closed"}]}`)
	case "PATCH " + pp + "/wit/workitems/5":
		f.ctype = r.Header.Get("Content-Type")
		var ops []map[string]any
		json.Unmarshal(body, &ops)
		if ops[0]["op"] != "test" || int(ops[0]["value"].(float64)) != f.rev {
			w.WriteHeader(412)
			return
		}
		f.state = ops[1]["value"].(string)
		f.rev++
		enc.Encode(f.wi())
	case "POST " + pp + "/wit/workitems/$Bug":
		f.ctype = r.Header.Get("Content-Type")
		f.created = append(f.created, string(body))
		enc.Encode(f.wi())
	case "DELETE " + pp + "/wit/workitems/5":
		f.deleted = true
		io.WriteString(w, `{"id":5}`)
	case "GET " + pp + "/wit/recyclebin/5":
		if !f.deleted {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"id":5,"type":"Bug","name":"Crash on save"}`)
	case "PATCH " + pp + "/wit/recyclebin/5":
		f.deleted = false
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	f := &fake{prStatus: "active", state: "Active", rev: 3}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Organization: "acme", Project: "Web App", Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ado": "pat", "secret://bad": "nope"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestAzureDevOpsReads(t *testing.T) {
	m, _ := setup(t, "secret://ado")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || !strings.Contains(h.Message, "2 projects") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"name":"Web App"`},
		{"repositories", `{}`, `"defaultBranch":"main"`},
		{"pull_requests", `{"repo":"web"}`, `"vote":"rejected"`},
		{"pull_request", `{"id":12}`, `"policy":"Build","status":"rejected"`},
		{"pipelines", `{"search":"C"}`, `"name":"CI"`},
		{"builds", `{"pipeline":"CI","branch":"main"}`, `"result":"failed"`},
		{"build", `{"id":100}`, `"messages":["Tests failed"]`},
		{"build_log", `{"id":100,"lines":2}`, `"lines":["2026-11-04T10:00:00Z FAIL a.test.js","2026-11-04T10:00:01Z ##[error]exit 1"]`},
		{"query_work_items", `{"wiql":"select [System.Id] from WorkItems"}`, `"assignedTo":"Ana"`},
		{"work_item", `{"id":5}`, `"description":"Steps \u0026 more"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "ana@example.com") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "build_log" && !a.Sensitive {
			t.Fatal("logs must be sensitive")
		}
	}
}

func TestAzureDevOpsPullRequestsAndBuilds(t *testing.T) {
	m, f := setup(t, "secret://ado")
	if r, err := invoke(m, "comment_pull_request", `{"id":12,"text":"Looks good"}`, true); err != nil || r.Plan == nil {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "comment_pull_request", `{"id":12,"text":"Looks good"}`, false); err != nil || !strings.Contains(string(r.Output), `"thread":77`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err := invoke(m, "complete_pull_request", `{"id":12,"strategy":"squash","deleteSourceBranch":true}`, true)
	if err != nil || r.Plan == nil || f.prStatus != "active" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, want := range []string{"fix/login → main (squash)", "Ana voted REJECTED", "1 blocking polic(ies) not met", "source branch is deleted"} {
		if !strings.Contains(r.Plan.Summary, want) {
			t.Fatalf("preview lacks %q: %s", want, r.Plan.Summary)
		}
	}
	if _, err := invoke(m, "complete_pull_request", `{"id":12,"strategy":"squash"}`, false); err != nil || f.prStatus != "completed" {
		t.Fatal(err)
	}
	last := f.seen[len(f.seen)-1]
	if !strings.Contains(last, `"bypassPolicy":false`) || !strings.Contains(last, `"commitId":"abc123abc123abc123"`) {
		t.Fatal(last)
	}
	if _, err := invoke(m, "complete_pull_request", `{"id":12}`, false); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatal(err)
	}

	if r, err := invoke(m, "queue_build", `{"pipeline":3,"variables":{"ENV":"prod"},"parameters":{"region":"eu"}}`, true); err != nil || r.Plan == nil || len(f.queued) != 0 || !strings.Contains(r.Plan.Summary, "on main") {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "queue_build", `{"pipeline":"CI","branch":"release/1","variables":{"ENV":"prod"}}`, false); err != nil || len(f.queued) != 1 || !strings.Contains(string(r.Output), `"build":102`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if !strings.Contains(f.queued[0], `"sourceBranch":"refs/heads/release/1"`) || !strings.Contains(f.queued[0], `"parameters":"{\"ENV\":\"prod\"}"`) {
		t.Fatal(f.queued[0])
	}
	if _, err := invoke(m, "cancel_build", `{"id":100}`, false); err == nil || !strings.Contains(err.Error(), "already completed") {
		t.Fatal(err)
	}
	if r, err := invoke(m, "cancel_build", `{"id":101}`, false); err != nil || !strings.Contains(string(r.Output), "cancelling") {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestAzureDevOpsWorkItems(t *testing.T) {
	m, f := setup(t, "secret://ado")
	r, err := invoke(m, "update_work_item_state", `{"id":5,"state":"resolved"}`, true)
	if err != nil || r.Plan == nil || f.state != "Active" || !strings.Contains(r.Plan.Summary, "from Active to Resolved") {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "update_work_item_state", `{"id":5,"state":"Done"}`, false); err == nil || !strings.Contains(err.Error(), "can be New, Active") {
		t.Fatal(err)
	}
	r, err = invoke(m, "update_work_item_state", `{"id":5,"state":"resolved"}`, false)
	if err != nil || f.state != "Resolved" || r.Undo == nil || f.ctype != "application/json-patch+json" {
		t.Fatalf("%+v %v %s", r, err, f.ctype)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state != "Active" {
		t.Fatal(err)
	}

	if r, err := invoke(m, "create_work_item", `{"type":"Bug","title":"New bug","description":"<b>x</b>","tags":["ui","p1"],"areaPath":"Web App\\UI"}`, true); err != nil || r.Plan == nil || len(f.created) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "create_work_item", `{"type":"Bug","title":"New bug","description":"<b>x</b>","tags":["ui","p1"]}`, false)
	if err != nil || len(f.created) != 1 || r.Undo == nil || r.Undo.Action != "delete_work_item" {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.created[0], `"value":"`+jsonEsc("&lt;b&gt;x&lt;/b&gt;")+`"`) || !strings.Contains(f.created[0], `"value":"ui; p1"`) {
		t.Fatal(f.created[0])
	}
	if r, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || r.Plan == nil || f.deleted || !strings.Contains(r.Plan.Summary, "recycle bin") {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || !f.deleted || r.Undo == nil || r.Undo.Action != "restore_work_item" {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(f.seen[len(f.seen)-1], "destroy=false") {
		t.Fatal(f.seen[len(f.seen)-1])
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.deleted {
		t.Fatal(err)
	}
	risks := map[string]sdk.Risk{"complete_pull_request": sdk.RiskDestructive, "queue_build": sdk.RiskDestructive, "delete_work_item": sdk.RiskDestructive,
		"cancel_build": sdk.RiskWrite, "create_work_item": sdk.RiskWrite, "update_work_item_state": sdk.RiskWrite, "query_work_items": sdk.RiskRead}
	for _, a := range m.Manifest().Actions {
		if want, ok := risks[a.Name]; ok && a.Risk != want {
			t.Fatalf("%s: %s", a.Name, a.Risk)
		}
	}
}

func TestAzureDevOpsValidation(t *testing.T) {
	m, f := setup(t, "secret://ado")
	for _, c := range []struct{ action, in string }{
		{"repositories", `{"project":"../acme"}`},
		{"repositories", `{"project":"a/b"}`},
		{"repositories", `{"project":"x?y"}`},
		{"repositories", `{"project":".."}`},
		{"pull_requests", `{"repo":"we/b"}`},
		{"pull_requests", `{"status":"open"}`},
		{"pull_request", `{"id":0}`},
		{"build", `{"id":-1}`},
		{"builds", `{"branch":"../x"}`},
		{"builds", `{"pipeline":"C*"}`},
		{"queue_build", `{"pipeline":3,"variables":{"a b":"x"}}`},
		{"queue_build", `{"pipeline":3,"branch":"main..x"}`},
		{"complete_pull_request", `{"id":12,"strategy":"octopus"}`},
		{"query_work_items", `{"wiql":"DELETE FROM WorkItems"}`},
		{"query_work_items", `{"wiql":""}`},
		{"create_work_item", `{"type":"../Bug","title":"x"}`},
		{"create_work_item", `{"type":"Bug","title":""}`},
		{"create_work_item", `{"type":"Bug","title":"x","tags":["a;b"]}`},
		{"create_work_item", `{"type":"Bug","title":"x","areaPath":"a/b"}`},
		{"update_work_item_state", `{"id":5,"state":"<x>"}`},
		{"delete_work_item", `{"id":0}`},
		{"build_log", `{"id":100,"lines":0.5}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Organization: "acme", Token: "plain"}, {Organization: "ac/me", Token: "secret://ado"}, {Organization: "acme", Project: "a/../b", Token: "secret://ado"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || !strings.Contains(h.Message, "refused the token") {
		t.Fatalf("%+v", h)
	}
}

func TestAzureDevOpsRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Organization: "acme", Token: "secret://ado"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ado": "pat"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// jsonEsc is s as encoding/json writes it inside a string.
func jsonEsc(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}
