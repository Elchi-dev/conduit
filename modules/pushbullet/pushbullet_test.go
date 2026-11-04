package pushbullet

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

const goodTok = "o.LEAKMEaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fake struct {
	mu       sync.Mutex
	seen     []string
	pushes   map[string]string // iden -> direction
	lastBody map[string]any
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Access-Token") != goodTok {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":"invalid_access_token","type":"invalid_request","message":"Access token is missing or invalid.","cat":"(=^ ◡ ^=)"}}`)
		return
	}
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	switch {
	case r.Method == "GET" && r.URL.Path == "/users/me":
		io.WriteString(w, `{"iden":"ujpah72o0","email":"me@example.com","name":"Elon","created":1381092887.398433}`)
	case r.Method == "GET" && r.URL.Path == "/devices":
		io.WriteString(w, `{"devices":[{"iden":"ujpah72o0sjAoRtnM0jc","active":true,"nickname":"Pixel","manufacturer":"Google","model":"Pixel 9","app_version":8623,"push_token":"PTLEAKME","key_fingerprint":"KFLEAKME","has_sms":true}]}`)
	case r.Method == "GET" && r.URL.Path == "/pushes":
		ps := []string{}
		for iden, dir := range f.pushes {
			ps = append(ps, fmt.Sprintf(`{"iden":%q,"active":true,"created":1730714400.5,"type":"note","direction":%q,"sender_name":"Elon","sender_email":"me@example.com","title":"t","body":"secret note"}`, iden, dir))
		}
		fmt.Fprintf(w, `{"pushes":[%s],"cursor":"next1"}`, strings.Join(ps, ","))
	case r.Method == "POST" && r.URL.Path == "/pushes":
		json.Unmarshal(body, &f.lastBody)
		f.pushes["ujnew1"] = "self"
		io.WriteString(w, `{"iden":"ujnew1","active":true,"type":"note","direction":"self","created":1730714400}`)
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/pushes/"):
		iden := strings.TrimPrefix(r.URL.Path, "/pushes/")
		if _, ok := f.pushes[iden]; !ok {
			w.WriteHeader(404)
			return
		}
		delete(f.pushes, iden)
		io.WriteString(w, `{}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, tok string) (*Module, *fake) {
	t.Helper()
	f := &fake{pushes: map[string]string{"ujin1": "incoming", "ujout1": "outgoing"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": goodTok, "secret://bad": "nope"}), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestPushbullet(t *testing.T) {
	m, f := setup(t, "secret://t")
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || h.Message != "Pushbullet · Elon · 1 devices" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "devices", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"nickname":"Pixel"`) || strings.Contains(string(r.Output), "LEAKME") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "pushes", `{"limit":5}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"body":"secret note"`) || !strings.Contains(string(r.Output), `"cursor":"next1"`) || strings.Contains(string(r.Output), "me@example.com") {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "pushes") != a.Sensitive || (a.Name == "delete_push") != (a.Risk == sdk.RiskDestructive) {
			t.Fatal(a.Name)
		}
	}

	n := len(f.seen)
	r, err = invoke(m, "push_note", `{"title":"Deploy","body":"done","device":"ujpah72o0sjAoRtnM0jc"}`, true)
	if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, "your device Pixel") || f.pushes["ujnew1"] != "" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if len(f.seen) != n+1 { // only the device lookup
		t.Fatal(f.seen[n:])
	}
	r, err = invoke(m, "push_note", `{"title":"Deploy","body":"done","device":"ujpah72o0sjAoRtnM0jc"}`, false)
	if err != nil || r.Undo == nil || string(r.Undo.Input) != `{"push":"ujnew1"}` || f.lastBody["device_iden"] != "ujpah72o0sjAoRtnM0jc" || f.lastBody["email"] != nil {
		t.Fatalf("%+v %v %v", r, err, f.lastBody)
	}
	if r, err := invoke(m, r.Undo.Action, string(r.Undo.Input), true); err != nil || r.Plan == nil || strings.Contains(string(r.Plan.Changes[0].Before), "secret note") || f.pushes["ujnew1"] == "" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.pushes["ujnew1"] != "" {
		t.Fatal(err)
	}
	if r, err := invoke(m, "delete_push", `{"push":"ujnew1"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_push", `{"push":"ujout1"}`, false); err != nil || f.pushes["ujout1"] != "" {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_push", `{"push":"ujin1"}`, false); err == nil || f.pushes["ujin1"] == "" {
		t.Fatal("deleted someone else's push")
	}
	if _, err := invoke(m, "push_note", `{"body":"x","device":"ujother"}`, false); err == nil || !strings.Contains(err.Error(), "no active device") {
		t.Fatal(err)
	}
}

func TestPushbulletValidation(t *testing.T) {
	m, f := setup(t, "secret://t")
	for _, c := range []struct{ action, in string }{
		{"push_note", `{}`}, {"push_note", `{"body":"  "}`}, {"push_note", `{"body":"` + strings.Repeat("x", maxBody+1) + `"}`},
		{"push_note", `{"body":"x","title":"` + strings.Repeat("t", maxTitle+1) + `"}`}, {"push_note", `{"body":"x","device":"../users"}`},
		{"pushes", `{"limit":500}`}, {"pushes", `{"cursor":"a&b"}`}, {"delete_push", `{}`}, {"delete_push", `{"push":"x/../y"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{}, {Token: goodTok}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "b"); h.Status != "down" || h.Message != "Pushbullet refused the access token" {
		t.Fatalf("%+v", h)
	}
}

func TestPushbulletRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Access-Token") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://t"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": goodTok}), "b", raw); err != nil {
		t.Fatal(err)
	}
	h := m.Health(context.Background(), "b")
	if h.Status != "down" || leaked != "" || strings.Contains(h.Message, "LEAKME") {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
