package jenkins

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

type fakeJenkins struct {
	mu       sync.Mutex
	posts    []string
	building bool
	crumbs   int
	session  string
}

func (f *fakeJenkins) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Jenkins", "2.479.1")
	if u, p, ok := r.BasicAuth(); !ok || u != "alice" || p != "tok" {
		w.WriteHeader(401)
		io.WriteString(w, `<html>Unauthorized</html>`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/ci")
	tree := r.URL.Query().Get("tree")
	if r.Method == "POST" {
		ck, _ := r.Cookie("JSESSIONID")
		if ck == nil || ck.Value != f.session || r.Header.Get("Jenkins-Crumb") != "crumb-"+f.session {
			w.WriteHeader(403)
			io.WriteString(w, `<html>No valid crumb was included in the request</html>`)
			return
		}
		r.ParseForm()
		f.posts = append(f.posts, path+" "+r.PostForm.Encode())
		switch path {
		case "/job/team/job/web%20app/buildWithParameters", "/job/hello/build":
			w.Header().Set("Location", "http://"+r.Host+"/ci/queue/item/77/")
			w.WriteHeader(201)
		case "/job/team/job/web%20app/12/stop":
			f.building = false
			http.Redirect(w, r, "/ci/job/team/job/web%20app/12/", http.StatusFound)
		case "/queue/cancelItem":
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
		return
	}
	switch path {
	case "/me/api/json":
		io.WriteString(w, `{"id":"alice","fullName":"Alice"}`)
	case "/api/json":
		if tree == "quietingDown" {
			io.WriteString(w, `{"quietingDown":false}`)
			return
		}
		io.WriteString(w, `{"jobs":[{"_class":"com.cloudbees.hudson.plugins.folder.Folder","name":"team","fullName":"team"},
			{"_class":"hudson.model.FreeStyleProject","name":"hello","fullName":"hello","color":"red","lastBuild":{"number":3,"result":"FAILURE","building":false,"timestamp":1762250000000,"duration":61000}}]}`)
	case "/crumbIssuer/api/json":
		f.crumbs++
		f.session = fmt.Sprintf("s%d", f.crumbs)
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: f.session, Path: "/"})
		io.WriteString(w, `{"crumb":"crumb-`+f.session+`","crumbRequestField":"Jenkins-Crumb"}`)
	case "/job/team/api/json":
		io.WriteString(w, `{"_class":"com.cloudbees.hudson.plugins.folder.Folder","name":"team","jobs":[{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","name":"web app","fullName":"team/web app","color":"blue_anime","lastBuild":{"number":12,"building":true,"timestamp":1762250000000}}]}`)
	case "/job/hello/api/json":
		io.WriteString(w, `{"_class":"hudson.model.FreeStyleProject","name":"hello","fullName":"hello","color":"red","buildable":true,"nextBuildNumber":4,"property":[]}`)
	case "/job/team/job/web%20app/api/json":
		if strings.HasPrefix(tree, "builds[") {
			io.WriteString(w, `{"builds":[{"number":12,"building":true,"timestamp":1762250000000},{"number":11,"result":"SUCCESS","building":false,"timestamp":1762240000000,"duration":120000}]}`)
			return
		}
		io.WriteString(w, `{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","name":"web app","fullName":"team/web app","color":"blue_anime","buildable":true,"inQueue":false,"nextBuildNumber":13,
			"description":"Deploys the web app","healthReport":[{"description":"Build stability: No recent builds failed.","score":100}],
			"property":[{"_class":"hudson.model.ParametersDefinitionProperty","parameterDefinitions":[
				{"_class":"hudson.model.ChoiceParameterDefinition","name":"ENV","type":"ChoiceParameterDefinition","choices":["staging","prod"],"defaultParameterValue":{"value":"staging"}},
				{"_class":"hudson.model.BooleanParameterDefinition","name":"DRY","type":"BooleanParameterDefinition","defaultParameterValue":{"value":true}},
				{"_class":"hudson.model.PasswordParameterDefinition","name":"DB_PASS","type":"PasswordParameterDefinition","defaultParameterValue":{"value":"LEAKME"}},
				{"_class":"hudson.model.StringParameterDefinition","name":"Api_Token","type":"StringParameterDefinition","defaultParameterValue":{"value":"LEAKME"}}]}],
			"lastBuild":{"number":12,"building":true,"timestamp":1762250000000},"builds":[{"number":12,"building":true,"timestamp":1762250000000}]}`)
	case "/job/team/job/web%20app/lastBuild/api/json", "/job/team/job/web%20app/12/api/json":
		io.WriteString(w, `{"number":12,"building":`+fmt.Sprint(f.building)+`,"result":null,"timestamp":1762250000000,"displayName":"#12","estimatedDuration":300000,
			"actions":[{"causes":[{"shortDescription":"Started by user Alice"}]},{"parameters":[{"_class":"hudson.model.StringParameterValue","name":"ENV","value":"prod"},{"_class":"hudson.model.PasswordParameterValue","name":"DB_PASS","value":"LEAKME"},{"_class":"hudson.model.StringParameterValue","name":"DEPLOY_KEY","value":"LEAKME"}]}],
			"changeSets":[{"items":[{"msg":"Fix login\n\nlong body","commitId":"0123456789abcdef0123","author":{"fullName":"Bob"}}]}],"artifacts":[{"relativePath":"dist/app.tar.gz"}]}`)
	case "/job/team/job/web%20app/12/consoleText":
		for i := 1; i <= 5000; i++ {
			fmt.Fprintf(w, "\x1b[32mline %d\x1b[0m\n", i)
		}
		io.WriteString(w, "Finished: no newline")
	case "/queue/api/json":
		io.WriteString(w, `{"items":[{"id":77,"why":"Waiting for next available executor","blocked":false,"stuck":false,"inQueueSince":1762250000000,"task":{"name":"hello","fullName":"hello"},"params":"\nTOKEN=LEAKME"}]}`)
	case "/queue/item/77/api/json":
		io.WriteString(w, `{"id":77,"task":{"name":"hello","fullName":"hello"},"cancelled":false}`)
	case "/queue/item/78/api/json":
		io.WriteString(w, `{"id":78,"task":{"name":"hello"},"executable":{"number":4}}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, token string) (*Module, *fakeJenkins) {
	f := &fakeJenkins{building: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/ci/", Username: "alice", Token: token})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "tok", "secret://bad": "nope"}), "j", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "j", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestJenkinsRead(t *testing.T) {
	m, _ := setup(t, "secret://t")
	if h := m.Health(context.Background(), "j"); h.Status != "ok" || h.Message != "signed in as alice · Jenkins 2.479.1" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"jobs", `{}`, `{"name":"team","type":"folder"}`},
		{"jobs", `{}`, `"lastBuild":{"durationSeconds":61,"number":3,"result":"FAILURE"`},
		{"jobs", `{"folder":"team"}`, `"status":"success, building"`},
		{"job", `{"job":"team/web app"}`, `{"choices":["staging","prod"],"default":"staging","name":"ENV","type":"Choice"}`},
		{"job", `{"job":"job/team/job/web app"}`, `"health":{"description":"Build stability`},
		{"builds", `{"job":"team/web app","limit":2}`, `{"durationSeconds":120,"number":11,"result":"SUCCESS"`},
		{"build", `{"job":"team/web app"}`, `{"name":"DB_PASS","value":"[hidden]"}`},
		// String parameters whose names look secret are hidden too.
		{"build", `{"job":"team/web app"}`, `{"name":"DEPLOY_KEY","value":"[hidden]"}`},
		{"job", `{"job":"team/web app"}`, `{"default":"[hidden]","name":"Api_Token","type":"String"}`},
		{"build", `{"job":"team/web app","number":12}`, `"changes":[{"author":"Bob","commit":"0123456789ab","message":"Fix login"}]`},
		{"queue", `{}`, `"why":"Waiting for next available executor"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "LEAKME") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	r, _ := invoke(m, "jobs", `{"problems":true}`, false)
	if strings.Contains(string(r.Output), "team") || !strings.Contains(string(r.Output), "hello") {
		t.Fatal(string(r.Output))
	}
	r, err := invoke(m, "console", `{"job":"team/web app","lines":3}`, false)
	var con struct {
		Lines     []string
		BytesRead int64
		Result    string
	}
	json.Unmarshal(r.Output, &con)
	if err != nil || len(con.Lines) != 3 || con.Lines[0] != "line 4999" || con.Lines[2] != "Finished: no newline" || con.Result != "RUNNING" {
		t.Fatalf("%s %v", r.Output, err)
	}
	if !m.Manifest().Actions[4].Sensitive || m.Manifest().Actions[4].Name != "console" {
		t.Fatal("console must be sensitive")
	}
	// Aborting a running build interrupts work in flight; removing a build
	// that hasn't started from the queue doesn't.
	for _, a := range m.Manifest().Actions {
		want, ok := map[string]sdk.Risk{"trigger_build": sdk.RiskDestructive, "stop_build": sdk.RiskDestructive, "cancel_queued": sdk.RiskDestructive}[a.Name]
		if ok && a.Risk != want {
			t.Fatalf("%s is %s, want %s", a.Name, a.Risk, want)
		}
	}
}

func TestJenkinsWrites(t *testing.T) {
	m, f := setup(t, "secret://t")
	p, err := invoke(m, "trigger_build", `{"job":"team/web app","parameters":{"ENV":"prod"}}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Start build #13 of team/web app with parameters" || len(f.posts) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	if after := string(p.Plan.Changes[0].After); !strings.Contains(after, `"ENV":"prod"`) || !strings.Contains(after, `"DRY":true`) || strings.Contains(after, "LEAKME") {
		t.Fatal(after)
	}
	r, err := invoke(m, "trigger_build", `{"job":"team/web app","parameters":{"ENV":"prod","DRY":false}}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"queueId":77`) || len(f.posts) != 1 || f.posts[0] != "/job/team/job/web%20app/buildWithParameters DRY=false&ENV=prod" {
		t.Fatalf("%s %v %v", r.Output, err, f.posts)
	}
	for _, in := range []string{
		`{"job":"team/web app","parameters":{"ENV":"dev"}}`,
		`{"job":"team/web app","parameters":{"DB_PASS":"x"}}`,
		`{"job":"team/web app","parameters":{"NOPE":"x"}}`,
		`{"job":"team/web app","parameters":{"DRY":"maybe"}}`,
		`{"job":"hello","parameters":{"X":"1"}}`,
		`{"job":"team"}`,
	} {
		if _, err := invoke(m, "trigger_build", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := invoke(m, "trigger_build", `{"job":"hello"}`, false); err != nil || f.posts[1] != "/job/hello/build " {
		t.Fatalf("%v %v", err, f.posts)
	}
	// An expired session: Jenkins refuses the cached crumb, a new one is fetched.
	f.session = "expired"
	if _, err := invoke(m, "trigger_build", `{"job":"hello"}`, false); err != nil || f.crumbs != 2 {
		t.Fatalf("%v %d", err, f.crumbs)
	}

	p, err = invoke(m, "stop_build", `{"job":"team/web app"}`, true)
	if err != nil || p.Plan == nil || !strings.HasPrefix(p.Plan.Summary, "Abort build #12 of team/web app") || !f.building {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, "stop_build", `{"job":"team/web app","number":12}`, false); err != nil || f.building {
		t.Fatal(err)
	}
	if _, err := invoke(m, "stop_build", `{"job":"team/web app","number":12}`, false); err == nil || !strings.Contains(err.Error(), "isn't running") {
		t.Fatal(err)
	}
	if p, err = invoke(m, "cancel_queued", `{"id":77}`, true); err != nil || p.Plan.Summary != "Remove the waiting build of hello from the queue" {
		t.Fatalf("%+v %v", p, err)
	}
	n := len(f.posts)
	if _, err := invoke(m, "cancel_queued", `{"id":77}`, false); err != nil || f.posts[n] != "/queue/cancelItem " {
		t.Fatalf("%v %v", err, f.posts)
	}
	if _, err := invoke(m, "cancel_queued", `{"id":78}`, false); err == nil || !strings.Contains(err.Error(), "isn't waiting") {
		t.Fatal(err)
	}
}

func TestJenkinsRefusals(t *testing.T) {
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "j"); h.Status != "down" || !strings.Contains(h.Message, "refused the username or API token") {
		t.Fatalf("%+v", h)
	}
	m, f := setup(t, "secret://t")
	for _, c := range []struct{ action, in string }{
		{"job", `{"job":"../../script"}`},
		{"job", `{"job":"a/../b"}`},
		{"job", `{"job":"a?b"}`},
		{"job", `{"job":""}`},
		{"builds", `{"job":"x","limit":500}`},
		{"build", `{"job":"x","number":-1}`},
		{"console", `{"job":"x","lines":99999}`},
		{"jobs", `{"folder":"a%2Fb"}`},
		{"cancel_queued", `{"id":0}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.posts) != 0 {
		t.Fatal(f.posts)
	}
	for _, c := range []Config{{URL: "http://t", Username: "a", Token: "plain"}, {URL: "http://t", Token: "secret://t"}, {URL: "ci:8080", Username: "a", Token: "secret://t"}, {URL: "http://t/#x", Username: "a", Token: "secret://t"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") + r.Header.Get("Jenkins-Crumb")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "alice", Token: "secret://t"})
	if err := rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "tok"}), "j", raw); err != nil {
		t.Fatal(err)
	}
	if h := rm.Health(context.Background(), "j"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
