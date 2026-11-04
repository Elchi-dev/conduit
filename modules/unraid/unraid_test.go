package unraid

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

type fakeUnraid struct {
	mu        sync.Mutex
	plex      string // container state
	vm        string
	parity    string
	mutations []string
}

func (f *fakeUnraid) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/graphql" || r.Method != "POST" {
		w.WriteHeader(404)
		return
	}
	if r.Header.Get("X-Api-Key") != "key1" {
		// Unraid answers a bad key with a GraphQL error.
		io.WriteString(w, `{"errors":[{"message":"Unauthorized","extensions":{"code":"UNAUTHENTICATED"}}],"data":null}`)
		return
	}
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	defer f.mu.Unlock()
	q := req.Query
	if strings.HasPrefix(strings.TrimSpace(q), "mutation") {
		f.mutations = append(f.mutations, strings.Join(strings.Fields(q), " ")+" "+mustString(req.Variables))
	}
	switch {
	case strings.Contains(q, "vars {"):
		io.WriteString(w, `{"data":{"vars":{"name":"Tower","version":"7.2.0"}}}`)
	case strings.Contains(q, "parityCheck { start"):
		f.parity = "RUNNING"
		io.WriteString(w, `{"data":{"parityCheck":{"start":{}}}}`)
	case strings.Contains(q, "parityCheck { pause"):
		f.parity = "PAUSED"
		io.WriteString(w, `{"data":{"parityCheck":{"pause":{}}}}`)
	case strings.Contains(q, "parityCheck { resume"):
		f.parity = "RUNNING"
		io.WriteString(w, `{"data":{"parityCheck":{"resume":{}}}}`)
	case strings.Contains(q, "parityCheck { cancel"):
		f.parity = "CANCELLED"
		io.WriteString(w, `{"data":{"parityCheck":{"cancel":{}}}}`)
	case strings.Contains(q, "array { parityCheckStatus"):
		io.WriteString(w, `{"data":{"array":{"parityCheckStatus":{"status":"`+f.parity+`","running":`+boolStr(f.parity == "RUNNING")+`,"paused":`+boolStr(f.parity == "PAUSED")+`,"correcting":false,"progress":42,"errors":0,"speed":"180 MB/s","duration":3600,"date":"2026-11-01T02:00:00Z"}}}}`)
	case strings.Contains(q, "array {"):
		io.WriteString(w, `{"data":{"array":{"state":"STARTED","capacity":{"kilobytes":{"free":"1000","used":"3000","total":"4000"},"disks":{"free":"1","used":"3","total":"4"}},
			"boot":{"id":"s:boot","name":"flash","device":"sda","type":"Flash","status":"DISK_OK","temp":null,"numErrors":0,"size":"15000000"},
			"parities":[{"id":"s:p","idx":0,"name":"parity","device":"sdb","type":"Parity","status":"DISK_OK","temp":34,"numErrors":0,"numReads":10,"numWrites":5,"size":8000000000}],
			"disks":[{"id":"s:d1","idx":1,"name":"disk1","device":"sdc","type":"Data","status":"DISK_OK","temp":57,"numErrors":"3","size":8000000000,"fsSize":7800000000,"fsUsed":3900000000,"fsFree":3900000000,"fsType":"xfs","isSpinning":true,"warning":null,"critical":null},
				{"id":"s:d2","idx":2,"name":"disk2","device":"","type":"Data","status":"DISK_NP","temp":null,"numErrors":0}],
			"caches":[{"id":"s:c","name":"cache","device":"nvme0n1","type":"Cache","status":"DISK_OK","temp":40,"numErrors":0,"warning":60,"critical":70}],
			"parityCheckStatus":{"status":"`+f.parity+`","running":false,"paused":false,"progress":0}}}}`)
	case strings.Contains(q, "docker { start"), strings.Contains(q, "docker { stop"):
		if req.Variables["id"] != "s:abc123" {
			io.WriteString(w, `{"errors":[{"message":"No such container"}]}`)
			return
		}
		m := "start"
		f.plex = "RUNNING"
		if strings.Contains(q, "docker { stop") {
			m, f.plex = "stop", "EXITED"
		}
		io.WriteString(w, `{"data":{"docker":{"`+m+`":{"id":"s:abc123","names":["/plex"],"image":"plexinc/pms-docker","state":"`+f.plex+`","status":"x"}}}}`)
	case strings.Contains(q, "docker {"):
		io.WriteString(w, `{"data":{"docker":{"containers":[
			{"id":"s:abc123","names":["/plex"],"image":"plexinc/pms-docker","state":"`+f.plex+`","status":"Up 2 hours","autoStart":true,"ports":[{"ip":"0.0.0.0","privatePort":32400,"publicPort":32400,"type":"TCP"}],"labels":{"secret":"LEAKME"}},
			{"id":"s:def456","names":["/sonarr"],"image":"linuxserver/sonarr","state":"EXITED","status":"Exited (0)","autoStart":false,"ports":[]}]}}}`)
	case strings.Contains(q, "vm { start"), strings.Contains(q, "vm { stop"):
		f.vm = "RUNNING"
		m := "start"
		if strings.Contains(q, "vm { stop") {
			f.vm, m = "SHUTOFF", "stop"
		}
		io.WriteString(w, `{"data":{"vm":{"`+m+`":true}}}`)
	case strings.Contains(q, "vms {"):
		io.WriteString(w, `{"data":{"vms":{"domains":[{"id":"s:4f1c-uuid","name":"Home Assistant","state":"`+f.vm+`"}]}}}`)
	case strings.Contains(q, "notifications {"):
		if strings.Contains(q, "list(") && (req.Variables["type"] != "UNREAD" || req.Variables["limit"] != float64(5) || req.Variables["importance"] != "ALERT") {
			w.WriteHeader(400)
			io.WriteString(w, `{"errors":[{"message":"bad filter"}]}`)
			return
		}
		io.WriteString(w, `{"data":{"notifications":{"overview":{"unread":{"info":1,"warning":2,"alert":1,"total":4},"archive":{"info":0,"warning":0,"alert":0,"total":9}},
			"list":[{"id":"n1","title":"Unraid Status","subject":"Disk 1 temperature","description":"disk1 is hot (57 C)","importance":"ALERT","timestamp":"2026-11-04T09:00:00Z"},
			{"id":"n2","title":"Parity","subject":"Parity check finished","description":"0 errors","importance":"ALERT","timestamp":"2026-11-04T10:00:00Z"}]}}}`)
	default:
		w.WriteHeader(400)
		io.WriteString(w, `{"errors":[{"message":"Cannot query field"}]}`)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func mustString(v any) string { b, _ := json.Marshal(v); return string(b) }

func setup(t *testing.T, key string) (*Module, *fakeUnraid) {
	f := &fakeUnraid{plex: "RUNNING", vm: "SHUTOFF", parity: "COMPLETED"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "key1", "secret://bad": "nope"}), "u", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "u", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestUnraidRead(t *testing.T) {
	m, _ := setup(t, "secret://k")
	if h := m.Health(context.Background(), "u"); h.Status != "degraded" || !strings.Contains(h.Message, "Tower · Unraid 7.2.0 · 1 disks need attention") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"overview", `{}`, `"containers":{"running":1,"total":2}`},
		{"overview", `{}`, `"unreadNotifications":{"info":1,"warning":2,"alert":1,"total":4}`},
		{"array", `{}`, `"issues":["3 errors","57 °C (critical ≥ 55)"]`},
		{"array", `{}`, `"usedPercent":75`},
		{"containers", `{"state":"running"}`, `"ports":["32400→32400/tcp"]`},
		{"vms", `{}`, `"name":"Home Assistant","state":"shutoff"`},
		{"notifications", `{"importance":"alert","limit":5}`, `"unread":{"info":1`},
		{"parity_status", `{}`, `"status":"COMPLETED"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) || strings.Contains(string(r.Output), "LEAKME") {
			t.Fatalf("%s: %s %v", c.action, r.Output, err)
		}
	}
	r, _ := invoke(m, "array", `{}`, false)
	if strings.Contains(string(r.Output), "disk2") || strings.Count(string(r.Output), `"issues"`) != 2 {
		t.Fatalf("empty slot or cache shown as a problem: %s", r.Output)
	}
	r, _ = invoke(m, "notifications", `{"importance":"alert","limit":5}`, false)
	if i, j := strings.Index(string(r.Output), "n2"), strings.Index(string(r.Output), "n1"); i < 0 || i > j {
		t.Fatalf("not newest first: %s", r.Output)
	}
	r, _ = invoke(m, "containers", `{"search":"son"}`, false)
	if strings.Contains(string(r.Output), "plex") || !strings.Contains(string(r.Output), "sonarr") {
		t.Fatal(string(r.Output))
	}
}

func TestUnraidContainersAndVMs(t *testing.T) {
	m, f := setup(t, "secret://k")
	p, err := invoke(m, "stop_container", `{"container":"plex"}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Stop container plex (plexinc/pms-docker)" || len(f.mutations) != 0 {
		t.Fatalf("plan %+v %v %v", p.Plan, err, f.mutations)
	}
	r, err := invoke(m, "stop_container", `{"container":"plex"}`, false)
	if err != nil || f.plex != "EXITED" || r.Undo == nil || r.Undo.Action != "start_container" || string(r.Undo.Input) != `{"container":"s:abc123"}` {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || f.plex != "RUNNING" || r.Undo.Action != "stop_container" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, "start_container", `{"container":"plex"}`, false); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatal(err)
	}
	f.mutations = nil
	r, err = invoke(m, "restart_container", `{"container":"PLEX"}`, false)
	if err != nil || r.Undo != nil || len(f.mutations) != 2 || !strings.Contains(f.mutations[0], "stop(id: $id)") || !strings.Contains(f.mutations[1], "start(id: $id)") {
		t.Fatalf("%+v %v %v", r, err, f.mutations)
	}
	if _, err := invoke(m, "stop_container", `{"container":"nope"}`, false); err == nil || !strings.Contains(err.Error(), "no container") {
		t.Fatal(err)
	}

	r, err = invoke(m, "start_vm", `{"vm":"home assistant"}`, false)
	if err != nil || f.vm != "RUNNING" || r.Undo == nil || r.Undo.Action != "stop_vm" {
		t.Fatalf("%+v %v", r, err)
	}
	p, err = invoke(m, "stop_vm", string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, "Shut down VM Home Assistant") || f.vm != "RUNNING" {
		t.Fatalf("%+v %v", p, err)
	}
	if r, err = invoke(m, "stop_vm", string(r.Undo.Input), false); err != nil || f.vm != "SHUTOFF" || r.Undo.Action != "start_vm" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestUnraidParity(t *testing.T) {
	m, f := setup(t, "secret://k")
	if _, err := invoke(m, "pause_parity_check", `{}`, false); err == nil {
		t.Fatal("paused a check that isn't running")
	}
	p, err := invoke(m, "start_correcting_parity_check", `{}`, true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, "correcting") || len(f.mutations) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, "start_parity_check", `{}`, false); err != nil || f.parity != "RUNNING" || !strings.Contains(f.mutations[0], `{"correct":false}`) {
		t.Fatalf("%v %v", err, f.mutations)
	}
	if _, err := invoke(m, "start_parity_check", `{}`, false); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatal(err)
	}
	r, err := invoke(m, "pause_parity_check", `{}`, false)
	if err != nil || f.parity != "PAUSED" || r.Undo == nil || r.Undo.Action != "resume_parity_check" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.parity != "RUNNING" || r.Undo.Action != "pause_parity_check" {
		t.Fatalf("%+v %v", r, err)
	}
	p, err = invoke(m, "cancel_parity_check", `{}`, true)
	if err != nil || p.Plan.Summary != "Cancel the parity check at 42%; its progress is lost" || f.parity != "RUNNING" {
		t.Fatalf("%+v %v", p, err)
	}
	if r, err = invoke(m, "cancel_parity_check", `{}`, false); err != nil || f.parity != "CANCELLED" || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestUnraidRefusals(t *testing.T) {
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "u"); h.Status != "down" || !strings.Contains(h.Message, "refused the API key") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "containers", `{}`, false); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
	m, f := setup(t, "secret://k")
	for _, c := range []struct{ action, in string }{
		{"stop_container", `{"container":""}`},
		{"stop_container", `{"container":"a\nb"}`},
		{"start_vm", `{"vm":""}`},
		{"notifications", `{"limit":1000}`},
		{"notifications", `{"importance":"loud"}`},
		{"containers", `{"state":"paused"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.mutations) != 0 {
		t.Fatal(f.mutations)
	}
	for _, c := range []Config{{URL: "http://t", APIKey: "plainkey"}, {URL: "tower:80", APIKey: "secret://k"}, {URL: "http://u:p@t", APIKey: "secret://k"}, {URL: "http://t?x=1", APIKey: "secret://k"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Api-Key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://k"})
	if err := rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "key1"}), "u", raw); err != nil {
		t.Fatal(err)
	}
	if h := rm.Health(context.Background(), "u"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
