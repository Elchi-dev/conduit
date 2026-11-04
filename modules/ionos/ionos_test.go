package ionos

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
	dcID  = "11111111-2222-3333-4444-555555555555"
	srvID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

type fakeIONOS struct {
	mu    sync.Mutex
	seen  []string
	state string
}

func (f *fakeIONOS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer ion-good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"httpStatus":401,"messages":[{"errorCode":"315","message":"Unauthorized"}]}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	sp := "/cloudapi/v6/datacenters/" + dcID + "/servers/" + srvID
	srv := func() string {
		return fmt.Sprintf(`{"id":%q,"properties":{"name":"web","type":"ENTERPRISE","vmState":%q,"cores":2,"ram":4096,"availabilityZone":"AUTO","cpuFamily":"INTEL_ICELAKE"},"metadata":{"state":"AVAILABLE","createdBy":"LEAKME"}}`, srvID, f.state)
	}
	switch {
	case r.URL.Path == "/cloudapi/v6/datacenters":
		fmt.Fprintf(w, `{"items":[{"id":%q,"properties":{"name":"prod","location":"de/fra","secAuthProtection":false},"metadata":{"state":"AVAILABLE","createdByUserId":"LEAKME"}}]}`, dcID)
	case r.URL.Path == "/cloudapi/v6/datacenters/"+dcID+"/servers":
		fmt.Fprintf(w, `{"items":[%s]}`, srv())
	case r.URL.Path == "/cloudapi/v6/datacenters/"+dcID+"/volumes":
		io.WriteString(w, `{"items":[{"id":"v1","properties":{"name":"root","type":"SSD","size":50,"licenceType":"LINUX","availabilityZone":"AUTO","bootServer":"`+srvID+`",
			"userData":"LEAKME","sshKeys":["LEAKME"],"imagePassword":"LEAKME"},"metadata":{"state":"AVAILABLE"}}]}`)
	case r.Method == "GET" && r.URL.Path == sp:
		io.WriteString(w, srv())
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, sp+"/"):
		f.state = map[string]string{"start": "RUNNING", "stop": "SHUTOFF", "reboot": "RUNNING"}[strings.TrimPrefix(r.URL.Path, sp+"/")]
		w.WriteHeader(202)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"httpStatus":404,"messages":[{"errorCode":"309","message":"Resource does not exist"}]}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeIONOS) {
	f := &fakeIONOS{state: "RUNNING"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL + "/cloudapi/v6"
	raw, _ := json.Marshal(Config{Token: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ion": "ion-good\n", "secret://bad": "nope"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "i", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestIONOS(t *testing.T) {
	m, f := setup(t, "secret://ion")
	if h := m.Health(context.Background(), "i"); h.Status != "ok" || h.Message != "1 data centers" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"datacenters", `{}`, `"location":"de/fra"`},
		{"servers", `{}`, `"datacenterName":"prod"`},
		{"servers", `{"datacenter":"` + dcID + `"}`, `"vmState":"RUNNING"`},
		{"volumes", `{"datacenter":"` + dcID + `"}`, `"sizeGb":50`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "ion-good") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if !strings.Contains(f.seen[0], "depth=1") {
		t.Fatal(f.seen)
	}
	in := `{"datacenter":"` + dcID + `","server":"` + srvID + `"}`
	if r, _ := invoke(m, "start_server", in, false); !strings.Contains(string(r.Output), "nothing to change") || r.Undo != nil {
		t.Fatal(string(r.Output))
	}
	r, err := invoke(m, "stop_server", in, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Stop web ("+srvID+")" || f.state != "RUNNING" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "stop_server", in, false)
	if err != nil || f.state != "SHUTOFF" || r.Undo == nil || r.Undo.Action != "start_server" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "reboot_server", in, false); err == nil || !strings.Contains(err.Error(), "only a running") {
		t.Fatal(err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state != "RUNNING" {
		t.Fatal(err)
	}
	if _, err := invoke(m, "reboot_server", `{"datacenter":"`+dcID+`","server":"00000000-0000-0000-0000-000000000000"}`, false); err == nil || !strings.Contains(err.Error(), "there's no server") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		destructive := a.Name == "stop_server" || a.Name == "reboot_server"
		if destructive != (a.Risk == sdk.RiskDestructive) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestIONOSValidation(t *testing.T) {
	m, f := setup(t, "secret://ion")
	for _, c := range []struct{ action, in string }{
		{"start_server", `{"server":"` + srvID + `"}`},
		{"start_server", `{"datacenter":"` + dcID + `","server":"../x"}`},
		{"stop_server", `{"datacenter":"x/y","server":"` + srvID + `"}`},
		{"volumes", `{}`},
		{"servers", `{"datacenter":"a?b"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, raw := range []string{`{"token":"plain"}`, `{}`, `[]`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "i"); h.Status != "down" || h.Message != "IONOS refused the API token (wrong or expired)" {
		t.Fatalf("%+v", h)
	}
}

func TestIONOSRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://ion"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ion": "ion-good"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "i"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
