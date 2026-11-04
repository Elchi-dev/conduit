package scaleway

import (
	"context"
	"encoding/json"
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

const (
	srvID   = "0a3b1f7e-4d0c-4b9a-9f43-1c2d3e4f5a6b"
	project = "11111111-2222-4333-8444-555555555555"
	access  = "SCWABCDEFGHIJ0123456"
)

type fake struct {
	mu      sync.Mutex
	state   string
	hits    int
	actions []string
	query   string
	s3Auth  string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	if r.Header.Get("X-Auth-Token") != "scwsecret" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"authentication is denied","method":"api_key","reason":"invalid_argument","type":"denied_authentication"}`)
		return
	}
	s := `{"id":"` + srvID + `","name":"edge","state":"` + f.state + `","commercial_type":"DEV1-S","arch":"x86_64","public_ip":{"address":"192.0.2.44"},"public_ips":[{"address":"192.0.2.44"},{"address":"2001:db8::44"}],"private_ip":null,"zone":"nl-ams-1","tags":["web"],"creation_date":"2026-02-01T00:00:00Z","project":"` + project + `"}`
	switch r.Method + " " + r.URL.Path {
	case "GET /instance/v1/zones/nl-ams-1/servers":
		f.query = r.URL.RawQuery
		w.Header().Set("X-Total-Count", "1")
		io.WriteString(w, `{"servers":[`+s+`]}`)
	case "GET /instance/v1/zones/nl-ams-1/servers/" + srvID:
		io.WriteString(w, `{"server":`+s+`}`)
	case "POST /instance/v1/zones/nl-ams-1/servers/" + srvID + "/action":
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		f.actions = append(f.actions, b["action"])
		switch b["action"] {
		case "poweroff":
			f.state = "stopped"
		case "poweron":
			f.state = "running"
		}
		w.WriteHeader(202)
		io.WriteString(w, `{"task":{"id":"t","status":"pending"}}`)
	case "GET /k8s/v1/regions/nl-ams/clusters":
		if r.URL.Query().Get("project_id") != project {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"clusters":[{"id":"c1","name":"prod","status":"ready","version":"1.31.2","type":"kapsule","cni":"cilium","region":"nl-ams","upgrade_available":true,"cluster_url":"https://c1.api.k8s.nl-ams.scw.cloud:6443","created_at":"2026-03-01T00:00:00Z"}],"total_count":1}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"resource is not found","type":"not_found"}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fake) {
	t.Helper()
	f := &fake{state: "running"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.s3Auth = r.Header.Get("Authorization")
		f.mu.Unlock()
		if r.Header.Get("X-Auth-Token") != "" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult><Owner><ID>o</ID></Owner><Buckets><Bucket><Name>backups</Name><CreationDate>2026-04-01T00:00:00.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>`)
	}))
	t.Cleanup(s3.Close)
	m := New()
	m.Base = srv.URL
	m.S3Base = s3.URL
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{SecretKey: ref, AccessKey: access, ProjectID: project, Zone: "nl-ams-1"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://scw": "scwsecret", "secret://bad": "nope"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestScalewayReads(t *testing.T) {
	m, f := setup(t, "secret://scw")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "1 servers in nl-ams-1" {
		t.Fatalf("%+v", h)
	}
	if !strings.Contains(f.query, "project="+project) {
		t.Fatalf("no project filter: %s", f.query)
	}
	for _, c := range []struct{ action, want string }{
		{"servers", `"publicIps":["192.0.2.44","2001:db8::44"]`},
		{"clusters", `"status":"ready","version":"1.31.2","type":"kapsule","cni":"cilium","region":"nl-ams","upgradeAvailable":true`},
		{"buckets", `[{"name":"backups","region":"nl-ams","created":"2026-04-01T00:00:00.000Z"}]`},
	} {
		r, err := invoke(m, c.action, `{}`, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
		if strings.Contains(out, "6443") || strings.Contains(out, "scwsecret") {
			t.Fatalf("%s leaked: %s", c.action, out)
		}
	}
	if !strings.HasPrefix(f.s3Auth, "AWS4-HMAC-SHA256 Credential="+access+"/20261104/nl-ams/s3/aws4_request") {
		t.Fatalf("s3 auth %q", f.s3Auth)
	}
	for _, a := range m.Manifest().Actions {
		if strings.Contains(a.Name, "kubeconfig") {
			t.Fatal("kubeconfig action")
		}
	}
}

func TestScalewayPower(t *testing.T) {
	m, f := setup(t, "secret://scw")
	one := `{"server":"` + srvID + `"}`
	if r, err := invoke(m, "power_off", one, true); err != nil || r.Plan == nil || len(f.actions) != 0 {
		t.Fatalf("dry run %+v %v", r, err)
	}
	r, err := invoke(m, "power_off", one, false)
	if err != nil || f.state != "stopped" || r.Undo == nil || r.Undo.Action != "power_on" {
		t.Fatalf("power_off %+v %v", r, err)
	}
	if _, err := invoke(m, "reboot", one, false); err == nil {
		t.Fatal("rebooted a stopped server")
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state != "running" {
		t.Fatalf("undo %v", err)
	}
	if _, err := invoke(m, "reboot", one, false); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.actions, ",") != "poweroff,poweron,reboot" {
		t.Fatalf("actions %v", f.actions)
	}
	for _, a := range m.Manifest().Actions {
		want := sdk.RiskRead
		switch a.Name {
		case "power_on":
			want = sdk.RiskWrite
		case "power_off", "reboot":
			want = sdk.RiskDestructive
		}
		if a.Risk != want {
			t.Errorf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestScalewayBadInputNeverSent(t *testing.T) {
	m, f := setup(t, "secret://scw")
	for _, in := range []string{`{}`, `{"server":"../../servers"}`, `{"server":"` + srvID + `/action"}`, `{"server":1}`} {
		if _, err := invoke(m, "power_off", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if f.hits != 0 {
		t.Fatalf("%d requests for bad input", f.hits)
	}
}

func TestScalewaySettings(t *testing.T) {
	h := fakehost.New(map[string]string{"secret://scw": "scwsecret"})
	for _, raw := range []string{
		`{"secretKey":"plain-secret"}`,
		`{}`,
		`{"secretKey":"secret://scw","zone":"fr-par-1/../x"}`,
		`{"secretKey":"secret://scw","zone":"mars"}`,
		`{"secretKey":"secret://scw","projectId":"not-a-uuid"}`,
		`{"secretKey":"secret://scw","accessKey":"secret://ak"}`,
		`{"secretKey":"secret://scw","accessKey":"AKIA123"}`,
	} {
		if err := New().Configure(context.Background(), h, "s", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	m := New()
	if err := m.Configure(context.Background(), h, "s", json.RawMessage(`{"secretKey":"secret://scw"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "buckets", `{}`, false); err == nil || !strings.Contains(err.Error(), "access key") {
		t.Fatalf("buckets without access key: %v", err)
	}
}

func TestScalewayBadKey(t *testing.T) {
	m, _ := setup(t, "secret://bad")
	if h := m.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "refused the secret key") {
		t.Fatalf("%+v", h)
	}
}

func TestScalewayRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	m.S3Base = srv.URL
	raw, _ := json.Marshal(Config{SecretKey: "secret://scw", AccessKey: access})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://scw": "scwsecret"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "s"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
	if _, err := invoke(m, "buckets", `{}`, false); err == nil || hit {
		t.Fatal("followed the redirect")
	}
}
