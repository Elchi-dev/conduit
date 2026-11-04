package caprover

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
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeCapRover struct {
	mu        sync.Mutex
	seen      []string
	logins    int
	instances int
	deployed  int
	lastBody  map[string]any
	token     string
	attempts  int  // sign-ins tried
	noPatch   bool // a CapRover without the partial update
}

func (f *fakeCapRover) ok(w http.ResponseWriter, data string) {
	fmt.Fprintf(w, `{"status":100,"description":"OK","data":%s}`, data)
}

func (f *fakeCapRover) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("x-namespace") != "captain" {
		w.WriteHeader(400)
		return
	}
	if r.URL.Path == "/api/v2/login" {
		var b map[string]string
		json.Unmarshal(body, &b)
		f.attempts++
		if b["password"] != "good" {
			io.WriteString(w, `{"status":1105,"description":"Wrong password"}`)
			return
		}
		f.logins++
		f.token = fmt.Sprintf("tok%d", f.logins)
		f.ok(w, fmt.Sprintf(`{"token":%q}`, f.token))
		return
	}
	if r.Header.Get("x-captain-auth") != f.token || f.token == "" {
		io.WriteString(w, `{"status":1106,"description":"Auth token corrupted"}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v2/user/system/versioninfo":
		f.ok(w, `{"currentVersion":"1.13.2","latestVersion":"1.13.2","canUpdate":false}`)
	case "GET /api/v2/user/apps/appDefinitions":
		f.ok(w, fmt.Sprintf(`{"rootDomain":"apps.example.com","appDefinitions":[
			{"appName":"shop","instanceCount":%d,"hasPersistentData":false,"containerHttpPort":3000,"hasDefaultSubDomainSsl":true,"forceSsl":true,"deployedVersion":%d,
			 "customDomain":[{"publicDomain":"shop.example.com","hasSsl":true}],"envVars":[{"key":"DB","value":"LEAKME"}],"volumes":[],
			 "appPushWebhook":{"tokenVersion":"x","pushWebhookToken":"LEAKME","repoInfo":{"repo":"https://bob:LEAKME@github.com/acme/shop","branch":"main","user":"LEAKME","password":"LEAKME","sshKey":"LEAKME"}},
			 "versions":[{"version":0,"deployedImageName":"img-captain--shop:0","gitHash":"abc","timeStamp":"2026-11-01"},{"version":1,"deployedImageName":"img-captain--shop:1","gitHash":"def","timeStamp":"2026-11-02"}]},
			{"appName":"worker","instanceCount":0,"notExposeAsWebApp":true,"deployedVersion":0,"versions":[]}]}`, f.instances, f.deployed))
	case "GET /api/v2/user/apps/appData/shop":
		f.ok(w, `{"isAppBuilding":false,"isBuildFailed":true,"logs":{"lines":["DB=LEAKME"]}}`)
	case "POST /api/v2/user/apps/appData/shop":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.lastBody = b
		f.deployed = 2
		io.WriteString(w, `{"status":101,"description":"Deploy is started"}`)
	case "PATCH /api/v2/user/apps/appDefinitions/update":
		if f.noPatch {
			w.WriteHeader(404)
			return
		}
		var b map[string]any
		json.Unmarshal(body, &b)
		f.lastBody = b
		f.instances = int(b["instanceCount"].(float64))
		f.ok(w, `{}`)
	case "POST /api/v2/user/apps/appDefinitions/update":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.lastBody = b
		f.instances = int(b["instanceCount"].(float64))
		f.ok(w, `{}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, pass string) (*Module, *fakeCapRover) {
	f := &fakeCapRover{instances: 2, deployed: 1}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: pass})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "good", "secret://bad": "wrong"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "c", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestCapRover(t *testing.T) {
	m, f := setup(t, "secret://c")
	if h := m.Health(context.Background(), "c"); h.Status != "ok" || h.Message != "2 apps, 1 scaled to 0 · CapRover 1.13.2" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"apps", `{}`, `"gitRepository":"https://github.com/acme/shop"`},
		{"apps", `{}`, `{"domain":"shop.apps.example.com","https":true}`},
		{"apps", `{}`, `"image":"img-captain--shop:1"`},
		{"apps", `{}`, `"webApp":false`},
		{"app", `{"app":"shop"}`, `"lastBuildFailed":true`},
		{"app", `{"app":"shop"}`, `"versions":[{"gitCommit":"def","image":"img-captain--shop:1"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}

	// Scale: preview, real (with every other setting sent back), undo, no-op.
	r, err := invoke(m, "scale_app", `{"app":"shop","instances":0}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "stops it") || f.instances != 2 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "scale_app", `{"app":"shop","instances":0}`, false)
	if err != nil || f.instances != 0 || r.Undo == nil || r.Undo.Action != "scale_app" || string(r.Undo.Input) != `{"app":"shop","instances":2}` {
		t.Fatalf("%+v %v", r, err)
	}
	// Only the count is sent: no settings come back to CapRover.
	if len(f.lastBody) != 2 || f.lastBody["appName"] != "shop" || !strings.HasPrefix(f.seen[len(f.seen)-1], "PATCH ") {
		t.Fatal(f.lastBody)
	}
	if strings.Contains(string(r.Output), "LEAKME") {
		t.Fatal(string(r.Output))
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.instances != 2 {
		t.Fatal(err)
	}
	if r, err := invoke(m, "scale_app", `{"app":"shop","instances":2}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%+v %v", r, err)
	}

	// Deploy an image; undo deploys the version that ran before.
	if r, err := invoke(m, "deploy_app", `{"app":"shop","image":"nginx:1.27"}`, true); err != nil || r.Plan == nil || !strings.HasPrefix(r.Plan.Summary, "Deploy image nginx:1.27 to app shop") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "deploy_app", `{"app":"shop","image":"nginx:1.27"}`, false)
	if err != nil || r.Undo == nil || string(r.Undo.Input) != `{"app":"shop","version":1}` {
		t.Fatalf("%+v %v", r, err)
	}
	if f.lastBody["captainDefinitionContent"] != `{"imageName":"nginx:1.27","schemaVersion":2}` {
		t.Fatal(f.lastBody)
	}
	if last := f.seen[len(f.seen)-1]; !strings.HasPrefix(last, "POST /api/v2/user/apps/appData/shop?detached=1 ") {
		t.Fatal(last)
	}
	f.deployed = 1
	if r, err := invoke(m, "deploy_app", `{"app":"shop","version":0}`, false); err != nil || f.lastBody["captainDefinitionContent"] != `{"imageName":"img-captain--shop:0","schemaVersion":2}` {
		t.Fatalf("%+v %v", r, err)
	}
	f.deployed = 1
	if r, err := invoke(m, "deploy_app", `{"app":"shop","version":1}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "deploy_app", `{"app":"shop","version":9}`, false); err == nil || !strings.Contains(err.Error(), "no version 9") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "scale_app", `{"app":"nope","instances":1}`, false); err == nil || !strings.Contains(err.Error(), "no app nope") {
		t.Fatal(err)
	}

	// A revoked token signs in again once.
	f.token = "revoked"
	if _, err := invoke(m, "apps", `{}`, false); err != nil || f.logins != 2 {
		t.Fatal(err, f.logins)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestCapRoverScaleWithoutPartialUpdate(t *testing.T) {
	m, f := setup(t, "secret://c")
	f.noPatch = true
	if _, err := invoke(m, "scale_app", `{"app":"shop","instances":3}`, false); err != nil || f.instances != 3 {
		t.Fatal(err)
	}
	// The full update gets every setting back, with only the count changed.
	if envs, _ := f.lastBody["envVars"].([]any); len(envs) != 1 || f.lastBody["forceSsl"] != true || f.lastBody["appName"] != "shop" || f.lastBody["containerHttpPort"] != float64(3000) {
		t.Fatal(f.lastBody)
	}
	if last := f.seen[len(f.seen)-1]; !strings.HasPrefix(last, "POST /api/v2/user/apps/appDefinitions/update ") {
		t.Fatal(last)
	}
}

func TestCapRoverPausesAfterRefusedPassword(t *testing.T) {
	m, f := setup(t, "secret://bad")
	c, _ := m.set.Get("c")
	now := time.Now()
	c.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if h := m.Health(context.Background(), "c"); h.Status != "down" || h.Message != "CapRover refused the password" {
			t.Fatalf("%+v", h)
		}
	}
	if f.attempts != 1 {
		t.Fatalf("signed in %d times", f.attempts)
	}
	now = now.Add(loginPause + time.Second)
	m.Health(context.Background(), "c")
	if f.attempts != 2 {
		t.Fatalf("signed in %d times", f.attempts)
	}
}

func TestCapRoverValidation(t *testing.T) {
	m, f := setup(t, "secret://c")
	for _, c := range []struct{ action, in string }{
		{"app", `{}`}, {"app", `{"app":"../login"}`}, {"deploy_app", `{"app":"shop"}`}, {"deploy_app", `{"app":"shop","image":"x","version":1}`},
		{"deploy_app", `{"app":"shop","image":"nginx latest"}`}, {"deploy_app", `{"app":"shop","image":"a\",\"x\":\"y"}`}, {"deploy_app", `{"app":"shop","version":-1}`},
		{"scale_app", `{"app":"shop"}`}, {"scale_app", `{"app":"shop","instances":-1}`}, {"scale_app", `{"app":"shop","instances":500}`}, {"scale_app", `{"app":"Shop?x=1","instances":1}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.logins != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://c.example.com", Password: "plain"}, {Password: "secret://c"}, {URL: "https://u:p@c.example.com", Password: "secret://c"},
		{URL: "https://c.example.com/#x", Password: "secret://c"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "c"); h.Status != "down" || h.Message != "CapRover refused the password" {
		t.Fatalf("%+v", h)
	}
}

func TestCapRoverRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = r.Header.Get("x-captain-auth") + string(b)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/login" {
			io.WriteString(w, `{"status":100,"data":{"token":"tok"}}`)
			return
		}
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Password: "secret://c"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://c": "good"}), "c", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "c"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
