package amp

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

const mcID = "0f1e2d3c-4b5a-4968-8776-655443322110"

type fakeAMP struct {
	mu       sync.Mutex
	seen     []string
	sessions map[string]string // session -> prefix it's valid for
	n        int
	state    int  // the Minecraft instance's AppState
	running  bool // the Minecraft instance itself
	logins   int
}

func (f *fakeAMP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	var b map[string]any
	_ = json.Unmarshal(body, &b)
	path := strings.TrimPrefix(r.URL.Path, "/API/")
	prefix, method := "", path
	if strings.HasPrefix(path, "ADSModule/Servers/") {
		parts := strings.SplitN(path, "/API/", 2)
		prefix, method = parts[0]+"/API/", parts[1]
	}
	if method == "Core/Login" {
		f.logins++
		if b["username"] != "admin" || b["password"] != "hunter2" {
			io.WriteString(w, `{"success":false,"resultReason":"Incorrect username or password"}`)
			return
		}
		f.n++
		sid := "sess-" + string(rune('a'+f.n))
		f.sessions[sid] = prefix
		io.WriteString(w, `{"success":true,"sessionID":"`+sid+`","permissions":[]}`)
		return
	}
	sid, _ := b["SESSIONID"].(string)
	if p, ok := f.sessions[sid]; !ok || p != prefix {
		w.WriteHeader(401)
		io.WriteString(w, `{"Title":"Unauthorized Access","Message":"You do not have permission to access this method.","StackTrace":""}`)
		return
	}
	delete(b, "SESSIONID")
	rest, _ := json.Marshal(b)
	f.seen = append(f.seen, prefix+method+" "+string(rest))
	mc := "ADSModule/Servers/" + mcID + "/API/"
	switch prefix + method {
	case "ADSModule/GetInstances":
		run := map[bool]string{true: "true", false: "false"}[f.running]
		io.WriteString(w, `{"result":[{"FriendlyName":"Local","AvailableInstances":[
			{"InstanceID":"00000000-0000-4000-8000-000000000000","InstanceName":"ADS01","FriendlyName":"ADS","Module":"ADS","Running":true},
			{"InstanceID":"`+mcID+`","InstanceName":"Minecraft01","FriendlyName":"Survival","Module":"MinecraftModule","ModuleDisplayName":"Minecraft","Running":`+run+`,"AppState":`+itoa(f.state)+`,"Metrics":{"CPU Usage":{"RawValue":15,"MaxValue":100,"Percent":15,"Units":"%"},"Memory Usage":{"RawValue":2048,"MaxValue":4096,"Percent":50,"Units":"MB"},"Active Users":{"RawValue":3,"MaxValue":20,"Percent":15,"Units":"Users"}}}]}]}`)
	case mc + "Core/GetStatus":
		io.WriteString(w, `{"State":`+itoa(f.state)+`,"Uptime":"01:02:03","Metrics":{"CPU Usage":{"RawValue":15,"MaxValue":100,"Percent":15,"Units":"%"},"Active Users":{"RawValue":3,"MaxValue":20,"Percent":15,"Units":"Users"}}}`)
	case mc + "Core/Start":
		f.state = 20
		io.WriteString(w, `{"result":{"Status":true,"Reason":""}}`)
	case mc + "Core/Stop":
		f.state = 0
		io.WriteString(w, `{}`)
	case mc + "Core/Restart", mc + "Core/SendConsoleMessage":
		io.WriteString(w, `{}`)
	case mc + "Core/UpdateApplication":
		io.WriteString(w, `{"Status":false,"Reason":"Update already in progress"}`)
	case mc + "Core/GetUpdates":
		io.WriteString(w, `{"ConsoleEntries":[{"Timestamp":"/Date(1762250400000)/","Source":"Server","Type":"Console","Contents":"Done (3.1s)!"}]}`)
	case "ADSModule/StartInstance":
		f.running, f.state = true, 20
		io.WriteString(w, `{"result":{"Status":true}}`)
	default:
		w.WriteHeader(404)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func setup(t *testing.T, pw string) (*Module, *fakeAMP) {
	f := &fakeAMP{sessions: map[string]string{}, state: 0, running: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", Username: "admin", Password: pw})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://amp": "hunter2", "secret://bad": "wrong"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "a", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestAMP(t *testing.T) {
	m, f := setup(t, "secret://amp")
	if h := m.Health(context.Background(), "a"); h.Status != "ok" || h.Message != "1 instances" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "instances", `{}`, false)
	if err != nil || strings.Contains(string(r.Output), "ADS01") || !strings.Contains(string(r.Output), `"players":3`) || !strings.Contains(string(r.Output), `"game":"Minecraft"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	in := `{"instance":"Survival"}`
	r, err = invoke(m, "start", in, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Start Survival" || f.state != 0 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "start", in, false)
	if err != nil || f.state != 20 || r.Undo == nil || r.Undo.Action != "stop" || string(r.Undo.Input) != in {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "start", `{"instance":"minecraft01"}`, false); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatal(err)
	}
	if r, err := invoke(m, "status", `{"instance":"`+mcID+`"}`, false); err != nil || !strings.Contains(string(r.Output), `"uptime":"01:02:03"`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// An expired session is replaced by logging in again.
	for s := range f.sessions {
		delete(f.sessions, s)
	}
	logins := f.logins
	cmd := `{"instance":"Survival","command":"say hi"}`
	if r, err := invoke(m, "command", cmd, true); err != nil || !strings.Contains(r.Plan.Summary, "say hi") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "command", cmd, false); err != nil || f.seen[len(f.seen)-1] != "ADSModule/Servers/"+mcID+`/API/Core/SendConsoleMessage {"message":"say hi"}` {
		t.Fatal(err, f.seen)
	}
	if f.logins != logins+2 {
		t.Fatalf("logged in %d times", f.logins-logins)
	}
	if r, err := invoke(m, "console", in, false); err != nil || !strings.Contains(string(r.Output), `"time":"2025-11-04T10:00:00Z"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err := invoke(m, "update", in, true); err != nil || !strings.Contains(r.Plan.Summary, "3 players are disconnected") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "update", in, false); err == nil || !strings.Contains(err.Error(), "Update already in progress") {
		t.Fatal(err)
	}
	r, err = invoke(m, "stop", in, false)
	if err != nil || f.state != 0 || r.Undo == nil || r.Undo.Action != "start" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "command", cmd, false); err == nil || !strings.Contains(err.Error(), "can't take commands") {
		t.Fatal(err)
	}

	// An instance that's off is started through the controller.
	f.running = false
	if _, err := invoke(m, "stop", in, false); err == nil || !strings.Contains(err.Error(), "is off") {
		t.Fatal(err)
	}
	if r, err := invoke(m, "start", in, true); err != nil || !strings.Contains(r.Plan.Summary, "Start instance Survival") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, "start", in, false); err != nil || !f.running || f.seen[len(f.seen)-1] != `ADSModule/StartInstance {"InstanceName":"Minecraft01"}` {
		t.Fatal(err, f.seen[len(f.seen)-1])
	}
	if _, err := invoke(m, "status", `{"instance":"Creative"}`, false); err == nil || !strings.Contains(err.Error(), "no instance") {
		t.Fatal(err)
	}
}

func TestAMPValidation(t *testing.T) {
	m, f := setup(t, "secret://amp")
	for _, c := range []struct{ action, in string }{
		{"status", `{"instance":"../Core/Login"}`},
		{"start", `{"instance":"a/b"}`},
		{"command", `{"instance":"Survival","command":"say a\nstop"}`},
		{"command", `{"instance":"Survival"}`},
		{"command", `{"instance":"Survival","command":"` + strings.Repeat("x", 501) + `"}`},
		{"stop", `{"instance":5}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.logins != 0 {
		t.Fatalf("invalid input reached AMP: %v", f.seen)
	}
	for _, c := range []Config{
		{URL: "https://amp", Username: "admin", Password: "hunter2"},
		{URL: "amp:8080", Username: "admin", Password: "secret://amp"},
		{URL: "https://amp", Username: "", Password: "secret://amp"},
		{URL: "https://amp", Username: "a\"b", Password: "secret://amp"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "a"); h.Status != "down" || !strings.Contains(h.Message, "refused the login") || strings.Contains(h.Message, "wrong") {
		t.Fatalf("%+v", h)
	}
}

// A redirect to another host must not carry the login there.
func TestAMPRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = string(b)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect) // 307 resends the body
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Username: "admin", Password: "secret://amp"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://amp": "hunter2"}), "a", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "a"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
