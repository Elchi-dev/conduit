package victron

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

type fakeVRM struct {
	mu    sync.Mutex
	seen  []string
	sites string
}

const oneSite = `[{"idSite":4242,"name":"Boat","timezone":"Europe/Amsterdam","alarm":true,"hasMains":1,"hasGenerator":0,"last_timestamp":1793800000,"device_icon":"boat","geofence":"LEAKME","phonenumber":"LEAKME","identifier":"b827eb000000"}]`

func (f *fakeVRM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Authorization") != "Token vrm_good" {
		w.WriteHeader(401)
		io.WriteString(w, `{"success":false,"errors":"Invalid token","error_code":"invalid_token"}`)
		return
	}
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.RequestURI())
	f.mu.Unlock()
	switch r.URL.Path {
	case "/users/me":
		io.WriteString(w, `{"success":true,"user":{"id":77,"name":"LEAKME","email":"leakme@example.com","country":"NL"}}`)
	case "/users/77/installations":
		io.WriteString(w, `{"success":true,"records":`+f.sites+`}`)
	case "/installations/4242/diagnostics":
		if r.URL.Query().Get("count") != "1000" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"success":true,"records":[
			{"idSite":4242,"timestamp":1793800100,"Device":"Gateway","instance":0,"description":"Battery SOC","dbusServiceType":"system","dbusPath":"/Dc/Battery/Soc","code":"bs","formattedValue":"84.0 %","rawValue":84.04},
			{"idSite":4242,"timestamp":1793800100,"Device":"Gateway","instance":0,"description":"Battery Power","dbusServiceType":"system","dbusPath":"/Dc/Battery/Power","code":"bp","formattedValue":"-120 W","rawValue":"-120"},
			{"idSite":4242,"timestamp":1793800100,"Device":"Gateway","instance":0,"description":"Battery state","dbusServiceType":"system","dbusPath":"/Dc/Battery/State","code":"bst","formattedValue":"Discharging","rawValue":2},
			{"idSite":4242,"timestamp":1793800100,"Device":"Gateway","instance":0,"description":"PV - DC-coupled","dbusServiceType":"system","dbusPath":"/Dc/Pv/Power","code":"Pdc","formattedValue":"1500 W","rawValue":1500},
			{"idSite":4242,"timestamp":1793800100,"Device":"Gateway","instance":0,"description":"PV - AC-coupled on grid L1","dbusServiceType":"system","dbusPath":"/Ac/PvOnGrid/L1/Power","code":"pg1","formattedValue":"300 W","rawValue":300},
			{"idSite":4242,"timestamp":1793800100,"Device":"Gateway","instance":0,"description":"Grid L1","dbusServiceType":"system","dbusPath":"/Ac/Grid/L1/Power","code":"g1","formattedValue":"-200 W","rawValue":-200},
			{"idSite":4242,"timestamp":1793800100,"Device":"Gateway","instance":0,"description":"Grid L2","dbusServiceType":"system","dbusPath":"/Ac/Grid/L2/Power","code":"g2","formattedValue":"50 W","rawValue":50},
			{"idSite":4242,"timestamp":1793800050,"Device":"Gateway","instance":0,"description":"AC Consumption L1","dbusServiceType":"system","dbusPath":"/Ac/Consumption/L1/Power","code":"a1","formattedValue":"900 W","rawValue":900},
			{"idSite":4242,"timestamp":1793800100,"Device":"Battery Monitor","instance":279,"description":"Voltage","dbusServiceType":"battery","dbusPath":"/Dc/0/Voltage","code":"V","formattedValue":"52.1 V","rawValue":52.1}]}`)
	case "/installations/4242/alarms":
		io.WriteString(w, `{"success":true,"alarms":[{"idDataAttribute":51,"instance":0,"lowAlarm":"20","highAlarm":null,"enabled":1,"notifyAfterSeconds":60}],
			"attributes":[{"idDataAttribute":51,"code":"bs","description":"Battery SOC"}],"users":[{"idUser":77,"email":"leakme@example.com","name":"LEAKME"}],"devices":[]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"success":false,"errors":"not found"}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeVRM) {
	f := &fakeVRM{sites: oneSite}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://v": "vrm_good", "secret://bad": "vrm_bad"}), "v", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "v", Action: action, Input: json.RawMessage(in)})
}

func TestVictron(t *testing.T) {
	m, f := setup(t, "secret://v")
	if h := m.Health(context.Background(), "v"); h.Status != "degraded" || h.Message != "1 installation(s), 1 with an active alarm" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"installations", `{}`, `[{"alarm":true,"generator":false,"kind":"boat","lastReport":"2026-11-04T13:46:40Z","mains":true,"name":"Boat","site":4242,"timezone":"Europe/Amsterdam"}]`},
		{"summary", `{}`, `{"battery":{"powerW":-120,"socPercent":84,"state":"discharging"},"consumptionW":900,"gridW":-150,"loggedAt":"2026-11-04T13:48:20Z","pv":{"acW":300,"dcW":1500,"totalW":1800},"site":4242}`},
		{"summary", `{"site":4242,"all":true}`, `{"code":"V","description":"Voltage","device":"Battery Monitor","instance":279,"value":"52.1 V"}`},
		{"alarms", `{}`, `{"active":true,"rules":[{"attribute":51,"enabled":true,"instance":0,"low":20,"notifyAfterSeconds":60,"watches":"Battery SOC"}],"site":4242}`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(strings.ToLower(out), "leakme") || strings.Contains(out, "vrm_good") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	// Several installations: the site must be named.
	f.sites = `[{"idSite":4242,"name":"Boat"},{"idSite":5,"name":"Cabin"}]`
	if _, err := invoke(m, "summary", `{}`); err == nil || !strings.Contains(err.Error(), "say which") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "summary", `{"site":9}`); err == nil || err.Error() != "VRM doesn't know this installation" {
		t.Fatal(err)
	}
}

func TestVictronValidation(t *testing.T) {
	m, f := setup(t, "secret://v")
	for _, c := range []struct{ action, in string }{
		{"summary", `{"site":0}`},
		{"summary", `{"site":-1}`},
		{"alarms", `{"site":"../users/77"}`},
		{"alarms", `{"site":1.5}`},
		{"summary", `{"site":99999999999}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, raw := range []string{`{"token":"vrm_plain"}`, `{}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "v"); h.Status != "down" || h.Message != "VRM refused the access token" {
		t.Fatalf("%+v", h)
	}
}

func TestVictronRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("X-Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	m.Configure(context.Background(), fakehost.New(map[string]string{"secret://v": "vrm_good"}), "v", json.RawMessage(`{"token":"secret://v"}`))
	if h := m.Health(context.Background(), "v"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
