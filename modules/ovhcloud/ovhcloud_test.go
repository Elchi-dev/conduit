package ovhcloud

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	appKey  = "7kbG7Bk7S9Nt7ZSV"
	project = "0123456789abcdef0123456789abcdef"
	instID  = "aaaaaaaa-1111-2222-3333-444444444444"
)

type fakeOVH struct {
	mu      sync.Mutex
	seen    []string
	times   int
	clock   int64
	vps     map[string]string
	inst    string
	granted bool
}

// verify checks the signature as OVHcloud does.
func (f *fakeOVH) verify(r *http.Request, body []byte) string {
	ts := r.Header.Get("X-Ovh-Timestamp")
	if r.Header.Get("X-Ovh-Application") != appKey || r.Header.Get("X-Ovh-Consumer") != "ck-good" {
		return `{"message":"Invalid application key","errorCode":"INVALID_CREDENTIAL"}`
	}
	if n, _ := strconv.ParseInt(ts, 10, 64); n < f.clock-5 || n > f.clock+5 {
		return `{"message":"Invalid timestamp"}`
	}
	sum := sha1.Sum([]byte("as-good+ck-good+" + r.Method + "+http://" + r.Host + r.URL.RequestURI() + "+" + string(body) + "+" + ts))
	if r.Header.Get("X-Ovh-Signature") != "$1$"+hex.EncodeToString(sum[:]) {
		return `{"message":"Invalid signature","errorCode":"INVALID_SIGNATURE"}`
	}
	return ""
}

func (f *fakeOVH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/1.0/auth/time" {
		f.times++
		fmt.Fprint(w, f.clock)
		return
	}
	body, _ := io.ReadAll(r.Body)
	if msg := f.verify(r, body); msg != "" {
		if strings.Contains(msg, "CREDENTIAL") {
			w.WriteHeader(403)
		} else {
			w.WriteHeader(400)
		}
		io.WriteString(w, msg)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	p := strings.TrimPrefix(r.URL.Path, "/1.0")
	ip := "/cloud/project/" + project + "/instance/" + instID
	switch {
	case p == "/auth/currentCredential":
		io.WriteString(w, `{"status":"validated","expiration":"2099-01-01T00:00:00+01:00","rules":[{"method":"GET","path":"/*"}],"credentialId":1}`)
	case p == "/dedicated/server":
		// A name Conduit won't put in a path is skipped, not the end of the list.
		io.WriteString(w, `["ns1.ip-1-2-3.eu","-bad/name"]`)
	case p == "/dedicated/server/ns1.ip-1-2-3.eu":
		io.WriteString(w, `{"name":"ns1.ip-1-2-3.eu","ip":"1.2.3.4","reverse":"ns1.ip-1-2-3.eu","datacenter":"gra3","state":"ok","powerState":"poweron","commercialRange":"rise","os":"debian12_64","rootDevice":"LEAKME"}`)
	case p == "/dedicated/server/ns1.ip-1-2-3.eu/reboot" && r.Method == "POST":
		io.WriteString(w, `{"taskId":1}`)
	case p == "/vps":
		if !f.granted {
			w.WriteHeader(403)
			io.WriteString(w, `{"message":"This call has not been granted","errorCode":"NOT_GRANTED_CALL"}`)
			return
		}
		io.WriteString(w, `["vps-1.vps.ovh.net"]`)
	case p == "/vps/vps-1.vps.ovh.net" && r.Method == "GET":
		fmt.Fprintf(w, `{"name":"vps-1.vps.ovh.net","displayName":"web","state":%q,"zone":"Region OpenStack: os-gra7","vcore":2,"memoryLimit":4096,"offerType":"ssd","model":{"name":"vps-value-1-2-40"}}`, f.vps["vps-1.vps.ovh.net"])
	case strings.HasPrefix(p, "/vps/vps-1.vps.ovh.net/") && r.Method == "POST":
		op := strings.TrimPrefix(p, "/vps/vps-1.vps.ovh.net/")
		f.vps["vps-1.vps.ovh.net"] = map[string]string{"start": "running", "stop": "stopped", "reboot": "running"}[op]
	case p == "/cloud/project":
		fmt.Fprintf(w, `[%q]`, project)
	case p == "/cloud/project/"+project:
		fmt.Fprintf(w, `{"project_id":%q,"projectName":"prod","description":"Production","status":"ok","creationDate":"2024-01-01"}`, project)
	case p == "/cloud/project/"+project+"/instance":
		fmt.Fprintf(w, `[{"id":%q,"name":"app-1","status":%q,"region":"GRA11","flavorId":"b3-8","sshKey":{"publicKey":"LEAKME"},"ipAddresses":[{"ip":"51.1.2.3","type":"public","version":4}]}]`, instID, f.inst)
	case p == ip && r.Method == "GET":
		fmt.Fprintf(w, `{"id":%q,"name":"app-1","status":%q,"region":"GRA11"}`, instID, f.inst)
	case strings.HasPrefix(p, ip+"/") && r.Method == "POST":
		f.inst = map[string]string{"start": "ACTIVE", "stop": "SHUTOFF", "reboot": "ACTIVE"}[strings.TrimPrefix(p, ip+"/")]
	case p == "/domain":
		io.WriteString(w, `["b.example","a.example"]`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"The requested object does not exist"}`)
	}
}

func setup(t *testing.T, ck string) (*Module, *fakeOVH) {
	f := &fakeOVH{clock: time.Now().Unix() + 3600, vps: map[string]string{"vps-1.vps.ovh.net": "running"}, inst: "SHUTOFF", granted: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL + "/1.0"
	raw, _ := json.Marshal(Config{ApplicationKey: appKey, ApplicationSecret: "secret://as", ConsumerKey: ck})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://as": "as-good\n", "secret://ck": "ck-good", "secret://bad": "ck-bad"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestOVHcloud(t *testing.T) {
	m, f := setup(t, "secret://ck")
	if h := m.Health(context.Background(), "o"); h.Status != "ok" || !strings.Contains(h.Message, "validated, expires 2099") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"dedicated_servers", `{}`, `"powerState":"poweron"`},
		{"vps", `{}`, `"model":"vps-value-1-2-40"`},
		{"cloud_projects", `{}`, `"name":"prod"`},
		{"cloud_instances", `{"project":"` + project + `"}`, `"addresses":["51.1.2.3 (public)"]`},
		{"domains", `{}`, `["a.example","b.example"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "ck-good") || strings.Contains(out, "as-good") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if f.times != 1 {
		t.Fatalf("server time asked %d times", f.times)
	}

	v := `{"vps":"vps-1.vps.ovh.net"}`
	if r, _ := invoke(m, "start_vps", v, false); !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output))
	}
	r, err := invoke(m, "stop_vps", v, true)
	if err != nil || r.Plan == nil || f.vps["vps-1.vps.ovh.net"] != "running" {
		t.Fatal(err)
	}
	r, err = invoke(m, "stop_vps", v, false)
	if err != nil || f.vps["vps-1.vps.ovh.net"] != "stopped" || r.Undo == nil || r.Undo.Action != "start_vps" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.vps["vps-1.vps.ovh.net"] != "running" {
		t.Fatal(err)
	}

	ci := `{"project":"` + project + `","instance":"` + instID + `"}`
	if _, err := invoke(m, "reboot_instance", ci, false); err == nil || !strings.Contains(err.Error(), "only an active") {
		t.Fatal(err)
	}
	r, err = invoke(m, "start_instance", ci, false)
	if err != nil || f.inst != "ACTIVE" || r.Undo == nil || r.Undo.Action != "stop_instance" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "reboot_instance", ci, false); err != nil || !strings.Contains(f.seen[len(f.seen)-1], `{"type":"soft"}`) {
		t.Fatal(err, f.seen)
	}
	if r, err := invoke(m, "reboot_dedicated", `{"server":"ns1.ip-1-2-3.eu"}`, true); err != nil || r.Plan == nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "reboot_dedicated", `{"server":"ns1.ip-1-2-3.eu"}`, false); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "start_vps", `{"vps":"gone.ovh.net"}`, false); err == nil || !strings.Contains(err.Error(), "there's no VPS gone.ovh.net") {
		t.Fatal(err)
	}
	f.granted = false
	if _, err := invoke(m, "vps", `{}`, false); err == nil || !strings.Contains(err.Error(), "rules don't allow") {
		t.Fatal(err)
	}

	for _, a := range m.Manifest().Actions {
		destructive := strings.HasPrefix(a.Name, "stop_") || strings.HasPrefix(a.Name, "reboot_")
		if destructive != (a.Risk == sdk.RiskDestructive) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestOVHcloudValidation(t *testing.T) {
	m, f := setup(t, "secret://ck")
	for _, c := range []struct{ action, in string }{
		{"start_vps", `{}`},
		{"start_vps", `{"vps":"../me"}`},
		{"stop_vps", `{"vps":"a/b"}`},
		{"reboot_dedicated", `{"server":"x?y"}`},
		{"reboot_dedicated", `{"server":"a..b"}`},
		{"cloud_instances", `{"project":"../../me"}`},
		{"start_instance", `{"project":"` + project + `","instance":"x"}`},
		{"stop_instance", `{"project":"nope","instance":"` + instID + `"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.times != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{
		{ApplicationKey: appKey, ApplicationSecret: "plain", ConsumerKey: "secret://ck"},
		{ApplicationKey: appKey, ApplicationSecret: "secret://as", ConsumerKey: "plain"},
		{ApplicationKey: "secret://ak", ApplicationSecret: "secret://as", ConsumerKey: "secret://ck"},
		{ApplicationKey: appKey, ApplicationSecret: "secret://as", ConsumerKey: "secret://ck", Endpoint: "https://evil.example"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "o"); h.Status != "down" || strings.Contains(h.Message, "ck-") || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
	// A wrong application secret makes a signature OVHcloud rejects.
	ws, _ := setup(t, "secret://ck")
	raw, _ := json.Marshal(Config{ApplicationKey: appKey, ApplicationSecret: "secret://wrong", ConsumerKey: "secret://ck"})
	ws.Configure(context.Background(), fakehost.New(map[string]string{"secret://wrong": "as-bad", "secret://ck": "ck-good"}), "o", raw)
	if h := ws.Health(context.Background(), "o"); h.Status != "down" || !strings.Contains(h.Message, "signature") {
		t.Fatalf("%+v", h)
	}
}

func TestOVHcloudRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("X-Ovh-Consumer") + r.Header.Get("X-Ovh-Signature")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/auth/time") {
			fmt.Fprint(w, time.Now().Unix())
			return
		}
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL + "/1.0"
	raw, _ := json.Marshal(Config{ApplicationKey: appKey, ApplicationSecret: "secret://as", ConsumerKey: "secret://ck"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://as": "a", "secret://ck": "c"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "o"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
