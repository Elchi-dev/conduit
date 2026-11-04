package upcloud

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

const uuid = "00af0f73-7082-4283-b925-811d1585774b"

type fake struct {
	mu     sync.Mutex
	state  string
	hits   int
	bodies []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	if u, p, ok := r.BasicAuth(); !ok || u != "conduit-api" || p != "pa:ss word" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"error_code":"AUTHENTICATION_FAILED","error_message":"Authentication failed using the given username and password."}}`)
		return
	}
	s := `{"uuid":"` + uuid + `","hostname":"web.example.com","title":"web","state":"` + f.state + `","zone":"fi-hel1","plan":"1xCPU-2GB","core_number":"1","memory_amount":"2048","tags":{"tag":["prod"]}}`
	switch r.Method + " " + r.URL.Path {
	case "GET /server":
		io.WriteString(w, `{"servers":{"server":[`+s+`]}}`)
	case "GET /server/" + uuid:
		io.WriteString(w, `{"server":`+s+`}`)
	case "POST /server/" + uuid + "/stop", "POST /server/" + uuid + "/start", "POST /server/" + uuid + "/restart":
		b, _ := io.ReadAll(r.Body)
		f.bodies = append(f.bodies, string(b))
		if strings.HasSuffix(r.URL.Path, "/stop") {
			f.state = "stopped"
		} else {
			f.state = "started"
		}
		io.WriteString(w, `{"server":`+s+`}`)
	case "GET /storage/private":
		io.WriteString(w, `{"storages":{"storage":[{"uuid":"01d4fcd4-e446-433b-8a9c-551a1284952e","title":"web disk","type":"normal","size":25,"state":"online","tier":"maxiops","zone":"fi-hel1","access":"private"}]}}`)
	case "GET /account":
		io.WriteString(w, `{"account":{"credits":9972.2324,"username":"main-owner","resource_limits":{"cores":200}}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"error_code":"NOT_FOUND","error_message":"not found"}}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fake) {
	t.Helper()
	f := &fake{state: "started"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Username: "conduit-api", Password: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://up": "pa:ss word\n", "secret://bad": "nope"}), "u", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "u", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestUpCloudReads(t *testing.T) {
	m, _ := setup(t, "secret://up")
	if h := m.Health(context.Background(), "u"); h.Status != "ok" || h.Message != "1 servers" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, want string }{
		{"servers", `"name":"web","hostname":"web.example.com","state":"started","zone":"fi-hel1","plan":"1xCPU-2GB","cores":1,"memoryMb":2048`},
		{"storages", `"sizeGb":25,"state":"online","tier":"maxiops"`},
		{"credits", `"amount":99.72,"credits":9972.2324`},
	} {
		r, err := invoke(m, c.action, `{}`, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
		if strings.Contains(out, "main-owner") || strings.Contains(out, "pa:ss") {
			t.Fatalf("%s leaked: %s", c.action, out)
		}
	}
}

func TestUpCloudPower(t *testing.T) {
	m, f := setup(t, "secret://up")
	one := `{"server":"` + uuid + `"}`
	if r, err := invoke(m, "stop", one, true); err != nil || r.Plan == nil || len(f.bodies) != 0 {
		t.Fatalf("dry run %+v %v", r, err)
	}
	r, err := invoke(m, "stop", one, false)
	if err != nil || f.state != "stopped" || r.Undo == nil || r.Undo.Action != "start" || !strings.Contains(f.bodies[0], `"stop_type":"soft"`) {
		t.Fatalf("stop %+v %v %v", r, err, f.bodies)
	}
	if _, err := invoke(m, "restart", one, false); err == nil {
		t.Fatal("restarted a stopped server")
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state != "started" {
		t.Fatalf("undo %v", err)
	}
	if _, err := invoke(m, "start", one, false); err == nil {
		t.Fatal("started a started server")
	}
	if _, err := invoke(m, "restart", one, false); err != nil || !strings.Contains(f.bodies[2], `"timeout_action":"ignore"`) {
		t.Fatalf("restart %v %v", err, f.bodies)
	}
	for _, a := range m.Manifest().Actions {
		want := sdk.RiskRead
		switch a.Name {
		case "start":
			want = sdk.RiskWrite
		case "stop", "restart":
			want = sdk.RiskDestructive
		}
		if a.Risk != want || a.Sensitive != (a.Name == "credits") {
			t.Errorf("%s is %s sensitive=%v", a.Name, a.Risk, a.Sensitive)
		}
	}
}

func TestUpCloudBadInputNeverSent(t *testing.T) {
	m, f := setup(t, "secret://up")
	for _, in := range []string{`{}`, `{"server":"../account"}`, `{"server":"` + uuid + `/stop"}`, `{"server":"` + strings.ToUpper(uuid) + `"}`, `{"server":7}`} {
		if _, err := invoke(m, "stop", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if f.hits != 0 {
		t.Fatalf("%d requests for bad input", f.hits)
	}
}

func TestUpCloudSettingsAndBadPassword(t *testing.T) {
	for _, raw := range []string{
		`{"username":"api","password":"hunter2"}`,
		`{"username":"","password":"secret://up"}`,
		`{"username":"a:b","password":"secret://up"}`,
		`{"username":"secret://user","password":"secret://up"}`,
		`{}`,
	} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "u", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	m, _ := setup(t, "secret://bad")
	if h := m.Health(context.Background(), "u"); h.Status != "down" || !strings.Contains(h.Message, "refused the user name and password") {
		t.Fatalf("%+v", h)
	}
}

func TestUpCloudRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Username: "conduit-api", Password: "secret://up"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://up": "pw"}), "u", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "u"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
