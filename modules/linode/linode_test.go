package linode

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

type fake struct {
	mu     sync.Mutex
	state  string
	hits   int
	posted []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	if r.Header.Get("Authorization") != "Bearer lintok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"reason":"Invalid Token"}]}`)
		return
	}
	inst := `{"id":42,"label":"web-1","status":"` + f.state + `","region":"eu-central","type":"g6-standard-2","ipv4":["192.0.2.7"],"ipv6":"2001:db8::7/128","specs":{"vcpus":2,"memory":4096,"disk":81920},"created":"2026-01-02T03:04:05"}`
	switch r.Method + " " + r.URL.Path {
	case "GET /linode/instances":
		io.WriteString(w, `{"data":[`+inst+`],"page":1,"pages":1,"results":1}`)
	case "GET /linode/instances/42":
		io.WriteString(w, inst)
	case "POST /linode/instances/42/shutdown":
		f.state = "offline"
		f.posted = append(f.posted, "shutdown")
		io.WriteString(w, `{}`)
	case "POST /linode/instances/42/boot":
		f.state = "running"
		f.posted = append(f.posted, "boot")
		io.WriteString(w, `{}`)
	case "POST /linode/instances/42/reboot":
		f.posted = append(f.posted, "reboot")
		io.WriteString(w, `{}`)
	case "GET /volumes":
		io.WriteString(w, `{"data":[{"id":5,"label":"data","status":"active","size":40,"region":"eu-central","linode_id":42,"linode_label":"web-1"}],"pages":1}`)
	case "GET /networking/firewalls":
		io.WriteString(w, `{"data":[{"id":8,"label":"edge","status":"enabled","rules":{"inbound_policy":"DROP","outbound_policy":"ACCEPT","inbound":[{"action":"ACCEPT","protocol":"TCP","ports":"22,443","addresses":{"ipv4":["0.0.0.0/0"]},"label":"web"}],"outbound":[]},"entities":[{"id":42,"type":"linode","label":"web-1"}]}],"pages":1}`)
	case "GET /account":
		io.WriteString(w, `{"email":"owner@example.com","address_1":"1 Main St","credit_card":{"last_four":"1111"},"balance":12.5,"balance_uninvoiced":3.25}`)
	case "GET /account/invoices":
		io.WriteString(w, `{"data":[{"id":1001,"date":"2026-10-01T00:00:00","label":"Invoice","subtotal":10,"tax":2,"total":12},{"id":1000,"date":"2026-09-01T00:00:00","label":"Invoice","subtotal":10,"tax":2,"total":12}],"pages":1}`)
	case "GET /account/transfer":
		io.WriteString(w, `{"used":120,"quota":4000,"billable":0}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[{"reason":"Not found"}]}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fake) {
	t.Helper()
	f := &fake{state: "running"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://lin": "lintok\n", "secret://bad": "nope"}), "l", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "l", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestLinodeReads(t *testing.T) {
	m, _ := setup(t, "secret://lin")
	if h := m.Health(context.Background(), "l"); h.Status != "ok" || h.Message != "1 instances" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"instances", `{}`, `"region":"eu-central","type":"g6-standard-2"`},
		{"volumes", `{}`, `"attachedTo":"web-1"`},
		{"firewalls", `{}`, `"inboundPolicy":"DROP"`},
		{"network_transfer", `{}`, `"usedGb":120`},
		{"balance", `{}`, `"balance":12.5,"currency":"USD","uninvoiced":3.25`},
		{"invoices", `{"limit":1}`, `"id":1001`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
		for _, leak := range []string{"owner@", "Main St", "1111", "1000"} {
			if strings.Contains(out, leak) {
				t.Fatalf("%s leaked %s: %s", c.action, leak, out)
			}
		}
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "balance" || a.Name == "invoices") != a.Sensitive {
			t.Errorf("%s sensitive=%v", a.Name, a.Sensitive)
		}
	}
}

func TestLinodePower(t *testing.T) {
	m, f := setup(t, "secret://lin")
	r, err := invoke(m, "shutdown", `{"instance":42}`, true)
	if err != nil || r.Plan == nil || f.state != "running" || len(f.posted) != 0 {
		t.Fatalf("dry run %+v %v", r, err)
	}
	r, err = invoke(m, "shutdown", `{"instance":42}`, false)
	if err != nil || f.state != "offline" || r.Undo == nil || r.Undo.Action != "power_on" {
		t.Fatalf("shutdown %+v %v", r, err)
	}
	if _, err := invoke(m, "shutdown", `{"instance":42}`, false); err == nil {
		t.Fatal("shut down an offline instance")
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state != "running" || r.Undo == nil || r.Undo.Action != "shutdown" {
		t.Fatalf("undo %+v %v", r, err)
	}
	if _, err := invoke(m, "power_on", `{"instance":42}`, false); err == nil {
		t.Fatal("powered on a running instance")
	}
	if r, err := invoke(m, "reboot", `{"instance":42}`, false); err != nil || r.Undo != nil {
		t.Fatalf("reboot %+v %v", r, err)
	}
	if strings.Join(f.posted, ",") != "shutdown,boot,reboot" {
		t.Fatalf("posted %v", f.posted)
	}
	if _, err := invoke(m, "reboot", `{"instance":7}`, false); err == nil || !strings.Contains(err.Error(), "no such instance") {
		t.Fatalf("missing instance: %v", err)
	}
	for _, a := range m.Manifest().Actions {
		want := sdk.RiskRead
		switch a.Name {
		case "power_on":
			want = sdk.RiskWrite
		case "shutdown", "reboot":
			want = sdk.RiskDestructive
		}
		if a.Risk != want {
			t.Errorf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestLinodeBadInputNeverSent(t *testing.T) {
	m, f := setup(t, "secret://lin")
	for _, c := range []struct{ action, in string }{
		{"reboot", `{}`},
		{"reboot", `{"instance":0}`},
		{"shutdown", `{"instance":-3}`},
		{"power_on", `{"instance":"../account"}`},
		{"invoices", `{"limit":500}`},
		{"invoices", `{"limit":-1}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s %s accepted", c.action, c.in)
		}
	}
	if f.hits != 0 {
		t.Fatalf("%d requests for bad input", f.hits)
	}
}

func TestLinodeSettings(t *testing.T) {
	m := New()
	for _, raw := range []string{`{"token":"plain-token"}`, `{}`, `not json`} {
		if err := m.Configure(context.Background(), fakehost.New(nil), "l", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if h := m.Health(context.Background(), "l"); h.Status != "unconfigured" {
		t.Fatalf("%+v", h)
	}
}

func TestLinodeBadToken(t *testing.T) {
	m, _ := setup(t, "secret://bad")
	h := m.Health(context.Background(), "l")
	if h.Status != "down" || !strings.Contains(h.Message, "refused the access token") || strings.Contains(h.Message, "nope") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "instances", `{}`, false); err == nil {
		t.Fatal("bad token worked")
	}
}

func TestLinodeRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://lin"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://lin": "lintok"}), "l", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "l"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
	if _, err := invoke(m, "reboot", `{"instance":42}`, false); err == nil || hit {
		t.Fatal("followed the redirect")
	}
}
