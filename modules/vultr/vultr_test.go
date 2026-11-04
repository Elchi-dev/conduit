package vultr

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
	vm   = "cb676a46-66fd-4dfb-b839-443f2e6c0b60"
	snap = "5359435d-28b6-4aa9-a2ee-d0fa3e1a6e47"
)

type fake struct {
	mu        sync.Mutex
	power     string
	hits      int
	posted    []string
	snapshots map[string]string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	if r.Header.Get("Authorization") != "Bearer vtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"Invalid API token.","status":401}`)
		return
	}
	in := `{"id":"` + vm + `","label":"app","hostname":"app.example.com","os":"Debian 12 x64","region":"ams","plan":"vc2-1c-1gb","vcpu_count":1,"ram":1024,"disk":25,"main_ip":"192.0.2.9","v6_main_ip":"2001:db8::9","status":"active","power_status":"` + f.power + `","server_status":"ok","date_created":"2026-01-01T00:00:00+00:00"}`
	switch r.Method + " " + r.URL.Path {
	case "GET /instances":
		if r.URL.Query().Get("cursor") == "" {
			io.WriteString(w, `{"instances":[`+in+`],"meta":{"total":2,"links":{"next":"bmV4dA==","prev":""}}}`)
			return
		}
		io.WriteString(w, `{"instances":[{"id":"11111111-2222-3333-4444-555555555555","label":"","hostname":"db","power_status":"running"}],"meta":{"total":2,"links":{"next":"","prev":"x"}}}`)
	case "GET /instances/" + vm:
		io.WriteString(w, `{"instance":`+in+`}`)
	case "POST /instances/" + vm + "/halt":
		f.power = "stopped"
		f.posted = append(f.posted, "halt")
		w.WriteHeader(204)
	case "POST /instances/" + vm + "/start":
		f.power = "running"
		f.posted = append(f.posted, "start")
		w.WriteHeader(204)
	case "POST /instances/" + vm + "/reboot":
		f.posted = append(f.posted, "reboot")
		w.WriteHeader(204)
	case "GET /instances/" + vm + "/bandwidth":
		io.WriteString(w, `{"bandwidth":{"2026-11-01":{"incoming_bytes":100,"outgoing_bytes":200},"2026-11-02":{"incoming_bytes":10,"outgoing_bytes":20},"2026-11-03":{"incoming_bytes":1,"outgoing_bytes":2}}}`)
	case "GET /snapshots":
		io.WriteString(w, `{"snapshots":[{"id":"`+snap+`","description":"nightly","status":"complete","size":2147483648,"date_created":"2026-11-01T00:00:00+00:00"}]}`)
	case "POST /snapshots":
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		if b["instance_id"] != vm {
			w.WriteHeader(400)
			return
		}
		f.snapshots[snap] = b["description"]
		w.WriteHeader(201)
		io.WriteString(w, `{"snapshot":{"id":"`+snap+`","status":"pending"}}`)
	case "GET /snapshots/" + snap:
		io.WriteString(w, `{"snapshot":{"id":"`+snap+`","description":"nightly","size":10}}`)
	case "DELETE /snapshots/" + snap:
		delete(f.snapshots, snap)
		w.WriteHeader(204)
	case "GET /account":
		io.WriteString(w, `{"account":{"name":"Owner Name","email":"owner@example.com","acls":["manage_users"],"balance":-25.5,"pending_charges":4.2,"last_payment_date":"2026-10-01T00:00:00+00:00","last_payment_amount":-50}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"Not found","status":404}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fake) {
	t.Helper()
	f := &fake{power: "running", snapshots: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://v": "vtok", "secret://bad": "nope"}), "v", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "v", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestVultrReads(t *testing.T) {
	m, _ := setup(t, "secret://v")
	if h := m.Health(context.Background(), "v"); h.Status != "ok" || h.Message != "2 instances" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"instances", `{}`, `"name":"app","status":"active","power":"running"`},
		{"instances", `{}`, `"name":"db"`},
		{"snapshots", `{}`, `"sizeGb":2`},
		{"bandwidth", `{"instance":"` + vm + `","days":2}`, `"totalInBytes":11,"totalOutBytes":22`},
		{"balance", `{}`, `"balance":-25.5`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
		for _, leak := range []string{"owner@", "Owner Name", "manage_users", "2026-11-01\""} {
			if strings.Contains(out, leak) {
				t.Fatalf("%s leaked %s: %s", c.action, leak, out)
			}
		}
	}
}

func TestVultrPowerAndSnapshots(t *testing.T) {
	m, f := setup(t, "secret://v")
	one := `{"instance":"` + vm + `"}`
	if r, err := invoke(m, "halt", one, true); err != nil || r.Plan == nil || len(f.posted) != 0 {
		t.Fatalf("dry run %+v %v", r, err)
	}
	r, err := invoke(m, "halt", one, false)
	if err != nil || f.power != "stopped" || r.Undo == nil || r.Undo.Action != "start" {
		t.Fatalf("halt %+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.power != "running" {
		t.Fatalf("undo %v", err)
	}
	if _, err := invoke(m, "start", one, false); err == nil {
		t.Fatal("started a running instance")
	}
	if _, err := invoke(m, "reboot", one, false); err != nil {
		t.Fatal(err)
	}
	if r, err := invoke(m, "snapshot", one, true); err != nil || r.Plan == nil || len(f.snapshots) != 0 || !strings.Contains(r.Plan.Summary, "billed") {
		t.Fatalf("snapshot dry run %+v %v", r, err)
	}
	r, err = invoke(m, "snapshot", `{"instance":"`+vm+`","description":"before upgrade"}`, false)
	if err != nil || f.snapshots[snap] != "before upgrade" || r.Undo == nil || r.Undo.Action != "delete_snapshot" {
		t.Fatalf("snapshot %+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.snapshots) != 0 {
		t.Fatalf("undo snapshot %v", err)
	}
	if strings.Join(f.posted, ",") != "halt,start,reboot" {
		t.Fatalf("posted %v", f.posted)
	}
	for _, a := range m.Manifest().Actions {
		want := sdk.RiskRead
		switch a.Name {
		case "start":
			want = sdk.RiskWrite
		case "halt", "reboot", "snapshot", "delete_snapshot":
			want = sdk.RiskDestructive
		}
		if a.Risk != want || a.Sensitive != (a.Name == "balance") {
			t.Errorf("%s is %s sensitive=%v", a.Name, a.Risk, a.Sensitive)
		}
	}
}

func TestVultrBadInputNeverSent(t *testing.T) {
	m, f := setup(t, "secret://v")
	for _, c := range []struct{ action, in string }{
		{"halt", `{}`},
		{"halt", `{"instance":"../account"}`},
		{"reboot", `{"instance":"` + strings.ToUpper(vm) + `"}`},
		{"start", `{"instance":"` + vm + `/halt"}`},
		{"bandwidth", `{"instance":"` + vm + `","days":90}`},
		{"snapshot", `{"instance":"` + vm + `","description":"two\nlines"}`},
		{"delete_snapshot", `{"snapshot":"../instances"}`},
		{"start", `{"instance":42}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s %s accepted", c.action, c.in)
		}
	}
	if f.hits != 0 {
		t.Fatalf("%d requests for bad input", f.hits)
	}
}

func TestVultrSettingsAndBadKey(t *testing.T) {
	m := New()
	for _, raw := range []string{`{"apiKey":"ABCDEF"}`, `{}`, `[`} {
		if err := m.Configure(context.Background(), fakehost.New(nil), "v", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	m, _ = setup(t, "secret://bad")
	if h := m.Health(context.Background(), "v"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
		t.Fatalf("%+v", h)
	}
}

func TestVultrRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusPermanentRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{APIKey: "secret://v"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://v": "vtok"}), "v", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "v"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
