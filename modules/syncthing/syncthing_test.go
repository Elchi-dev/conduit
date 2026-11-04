package syncthing

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
	self   = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA"
	laptop = "BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB-BBBBBBB"
	phone  = "CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC-CCCCCCC"
)

type fakeST struct {
	mu      sync.Mutex
	paused  map[string]bool
	writes  []string
	queried []string
}

func (f *fakeST) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != "key" {
		w.WriteHeader(403)
		io.WriteString(w, "CSRF Error")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.Method != "GET" {
		f.writes = append(f.writes, r.Method+" "+r.URL.EscapedPath()+"?"+r.URL.RawQuery+" "+string(body))
	} else if q := r.URL.RawQuery; q != "" {
		f.queried = append(f.queried, r.URL.Path+"?"+q)
	}
	q := r.URL.Query()
	switch r.Method + " " + r.URL.EscapedPath() {
	case "GET /rest/system/ping":
		io.WriteString(w, `{"ping":"pong"}`)
	case "GET /rest/system/version":
		io.WriteString(w, `{"version":"v1.29.2","os":"linux","arch":"amd64","longVersion":"syncthing v1.29.2"}`)
	case "GET /rest/system/status":
		io.WriteString(w, `{"myID":"`+self+`","uptime":3600,"startTime":"2026-11-04T08:00:00Z","discoveryEnabled":true,"alloc":1048576,"guiAddressUsed":"127.0.0.1:8384",
			"connectionServiceStatus":{"tcp://0.0.0.0:22000":{"error":null},"quic://0.0.0.0:22000":{"error":"bind failed"}}}`)
	case "GET /rest/system/error":
		io.WriteString(w, `{"errors":[{"when":"2026-11-04T09:00:00Z","message":"Listen (BEP/quic): bind failed"}]}`)
	case "GET /rest/config/folders":
		b, _ := json.Marshal([]map[string]any{
			{"id": "abcde-12345", "label": "Photos", "path": "/data/photos", "type": "sendreceive", "paused": f.paused["abcde-12345"],
				"devices": []map[string]any{{"deviceID": self}, {"deviceID": phone, "encryptionPassword": "LEAKME-ENC"}}},
			{"id": "docs", "label": "", "path": "/data/docs", "type": "sendonly", "paused": f.paused["docs"], "devices": []map[string]any{{"deviceID": self}}},
		})
		w.Write(b)
	case "GET /rest/config/devices":
		b, _ := json.Marshal([]map[string]any{
			{"deviceID": self, "name": "nas", "addresses": []string{"dynamic"}, "paused": false},
			{"deviceID": laptop, "name": "Laptop", "addresses": []string{"dynamic"}, "paused": f.paused[laptop]},
			{"deviceID": phone, "name": "Phone", "addresses": []string{"tcp://10.0.0.5:22000"}, "paused": f.paused[phone]},
		})
		w.Write(b)
	case "GET /rest/config/gui", "GET /rest/config":
		io.WriteString(w, `{"apiKey":"LEAKME-KEY","password":"LEAKME-PW"}`)
	case "GET /rest/db/status":
		if q.Get("folder") == "abcde-12345" {
			io.WriteString(w, `{"state":"syncing","stateChanged":"2026-11-04T10:00:00Z","globalBytes":1000,"globalFiles":10,"localBytes":800,"needBytes":200,"needFiles":2,"needDeletes":0,"pullErrors":1,"errors":0}`)
			return
		}
		io.WriteString(w, `{"state":"idle","stateChanged":"2026-11-04T09:00:00Z","globalBytes":50,"globalFiles":1,"localBytes":50}`)
	case "GET /rest/db/completion":
		switch {
		case q.Get("folder") == "abcde-12345":
			io.WriteString(w, `{"completion":99.99,"needBytes":200}`)
		case q.Get("device") == laptop:
			io.WriteString(w, `{"completion":100,"needBytes":0}`)
		default:
			io.WriteString(w, `{"completion":42.55,"needBytes":5000}`)
		}
	case "GET /rest/folder/errors":
		io.WriteString(w, `{"folder":"abcde-12345","errors":[{"path":"IMG_1.jpg","error":"permission denied"}],"page":1,"perpage":10}`)
	case "GET /rest/system/connections":
		io.WriteString(w, `{"total":{},"connections":{"`+laptop+`":{"connected":true,"paused":false,"address":"192.168.1.20:22000","clientVersion":"v1.29.2","type":"tcp-client","inBytesTotal":10,"outBytesTotal":20},
			"`+phone+`":{"connected":false,"address":"","clientVersion":""}}}`)
	case "GET /rest/stats/device":
		io.WriteString(w, `{"`+phone+`":{"lastSeen":"2026-11-01T12:00:00Z"},"`+laptop+`":{"lastSeen":"2026-11-04T11:00:00Z"}}`)
	case "GET /rest/cluster/pending/devices":
		io.WriteString(w, `{"DDDDDDD-DDDDDDD-DDDDDDD-DDDDDDD-DDDDDDD-DDDDDDD-DDDDDDD-DDDDDDD":{"time":"2026-11-04T07:00:00Z","name":"New phone","address":"10.0.0.9:22000"}}`)
	case "GET /rest/cluster/pending/folders":
		io.WriteString(w, `{"music":{"offeredBy":{"`+laptop+`":{"time":"2026-11-03T07:00:00Z","label":"Music","receiveEncrypted":false,"remoteEncrypted":false}}}}`)
	case "PATCH /rest/config/folders/abcde-12345", "PATCH /rest/config/folders/docs", "PATCH /rest/config/devices/" + laptop, "PATCH /rest/config/devices/" + phone:
		var b struct{ Paused bool }
		json.Unmarshal(body, &b)
		parts := strings.Split(r.URL.Path, "/")
		f.paused[parts[len(parts)-1]] = b.Paused
	case "POST /rest/db/scan":
	default:
		w.WriteHeader(404)
		io.WriteString(w, "404 page not found")
	}
}

func setup(t *testing.T, key string) (*Module, *fakeST) {
	f := &fakeST{paused: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/", APIKey: key})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "key", "secret://bad": "nope"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestSyncthingRead(t *testing.T) {
	m, _ := setup(t, "secret://k")
	if h := m.Health(context.Background(), "s"); h.Status != "degraded" || h.Message != "Syncthing v1.29.2 · 1 recent error(s)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, want string }{
		{"status", `"deviceId":"` + self + `"`},
		{"status", `"listeners":{"quic://0.0.0.0:22000":"bind failed","tcp://0.0.0.0:22000":"ok"}`},
		{"status", `"errors":[{"message":"Listen (BEP/quic): bind failed","when":"2026-11-04T09:00:00Z"}]`},
		{"folders", `{"completion":99.9,"devices":2,"fileErrorCount":1,"fileErrors":[{"error":"permission denied","path":"IMG_1.jpg"}],"globalBytes":1000,"globalFiles":10,"id":"abcde-12345","label":"Photos","localBytes":800,"needBytes":200,"needDeletes":0,"needFiles":2,"path":"/data/photos","paused":false,"since":"2026-11-04T10:00:00Z","state":"syncing","type":"sendreceive"}`},
		{"folders", `"id":"docs"`},
		{"devices", `{"address":"192.168.1.20:22000","clientVersion":"v1.29.2","completion":100,"connected":true,"connectionType":"tcp-client","id":"` + laptop + `","inBytes":10,"lastSeen":"2026-11-04T11:00:00Z","name":"Laptop","outBytes":20,"paused":false}`},
		{"devices", `{"completion":42.5,"connected":false,"id":"` + phone + `","lastSeen":"2026-11-01T12:00:00Z","name":"Phone","needBytes":5000,"paused":false}`},
		{"pending", `{"devices":[{"address":"10.0.0.9:22000","deviceId":"DDDDDDD-DDDDDDD-DDDDDDD-DDDDDDD-DDDDDDD-DDDDDDD-DDDDDDD-DDDDDDD","name":"New phone","since":"2026-11-04T07:00:00Z"}],"folders":[{"folderId":"music","label":"Music","offeredBy":"` + laptop + `","since":"2026-11-03T07:00:00Z"}]}`},
	} {
		r, err := invoke(m, c.action, `{}`, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, `"name":"nas"`) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
}

func TestSyncthingPause(t *testing.T) {
	m, f := setup(t, "secret://k")
	p, err := invoke(m, "pause", `{"folder":"photos"}`, true)
	if err != nil || p.Plan == nil || p.Plan.Summary != "Pause folder Photos" || len(f.writes) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := invoke(m, "pause", `{"folder":"photos"}`, false)
	if err != nil || !f.paused["abcde-12345"] || r.Undo == nil || r.Undo.Action != "resume" || string(r.Undo.Input) != `{"folder":"abcde-12345"}` ||
		f.writes[0] != `PATCH /rest/config/folders/abcde-12345? {"paused":true}` {
		t.Fatalf("%s %+v %v %v", r.Output, r.Undo, err, f.writes)
	}
	if r2, err := invoke(m, "pause", `{"folder":"abcde-12345"}`, false); err != nil || r2.Undo != nil || !strings.Contains(string(r2.Output), `"changed":false`) {
		t.Fatalf("%s %v", r2.Output, err)
	}
	if _, err := invoke(m, "rescan", `{"folder":"Photos"}`, false); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatal(err)
	}
	if r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.paused["abcde-12345"] || r.Undo.Action != "pause" {
		t.Fatalf("%+v %v", r, err)
	}

	r, err = invoke(m, "pause", `{"device":"laptop"}`, false)
	if err != nil || !f.paused[laptop] || string(r.Undo.Input) != `{"device":"`+laptop+`"}` {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "resume", `{"device":"`+strings.ToLower(laptop)+`"}`, false); err != nil || f.paused[laptop] {
		t.Fatal(err)
	}
	if _, err := invoke(m, "pause", `{"device":"nas"}`, false); err == nil || !strings.Contains(err.Error(), "no device nas") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "pause", `{"device":"`+self+`"}`, false); err == nil || !strings.Contains(err.Error(), "this device") {
		t.Fatal(err)
	}

	n := len(f.writes)
	if p, err := invoke(m, "rescan", `{}`, true); err != nil || p.Plan.Summary != "Rescan every folder" || len(f.writes) != n {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := invoke(m, "rescan", `{"folder":"docs"}`, false); err != nil || f.writes[len(f.writes)-1] != "POST /rest/db/scan?folder=docs " {
		t.Fatal(err, f.writes)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "pause" || a.Name == "resume") != a.Reversible {
			t.Fatal(a.Name)
		}
	}
}

func TestSyncthingRefusals(t *testing.T) {
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "s"); h.Status != "down" || h.Message != "Syncthing refused the API key" {
		t.Fatalf("%+v", h)
	}
	m, f := setup(t, "secret://k")
	for _, c := range []struct{ action, in string }{
		{"pause", `{}`},
		{"pause", `{"folder":"docs","device":"Laptop"}`},
		{"pause", `{"folder":"../config/gui"}`},
		{"pause", `{"folder":"docs\u0000"}`},
		{"resume", `{"device":"Tablet"}`},
		{"resume", `{"device":"../../config"}`},
		{"rescan", `{"folder":"nope"}`},
		{"rescan", `{"folder":"docs&folder=x"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.writes) != 0 || len(f.queried) != 0 {
		t.Fatalf("refused input reached Syncthing: %v %v", f.writes, f.queried)
	}
	for _, c := range []Config{{URL: "https://nas:8384", APIKey: "plainkey"}, {URL: "nas:8384", APIKey: "secret://k"}, {URL: "https://a:b@nas:8384", APIKey: "secret://k"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-API-Key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	rm := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://k"})
	if err := rm.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "key"}), "s", raw); err != nil {
		t.Fatal(err)
	}
	if h := rm.Health(context.Background(), "s"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
