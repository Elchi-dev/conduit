package hue

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
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
	bid   = "001788fffe123456"
	l1    = "11111111-1111-4111-8111-111111111111" // colour, living room
	l2    = "22222222-2222-4222-8222-222222222222" // white ambiance, living room
	d1    = "d1111111-1111-4111-8111-111111111111"
	d2    = "d2222222-2222-4222-8222-222222222222"
	d3    = "d3333333-3333-4333-8333-333333333333" // motion sensor
	room  = "a0000000-0000-4000-8000-000000000001"
	zone  = "a0000000-0000-4000-8000-000000000002"
	gl    = "b0000000-0000-4000-8000-000000000001"
	scn   = "c0000000-0000-4000-8000-000000000001"
	scn2  = "c0000000-0000-4000-8000-000000000002"
	appKy = "the-app-key"
)

type lamp struct {
	On     bool
	Bri    float64
	X, Y   float64
	Mirek  int // 0: in xy mode
	Colour bool
}

type fakeBridge struct {
	mu     sync.Mutex
	lamps  map[string]*lamp
	writes []string
}

func newBridge() *fakeBridge {
	return &fakeBridge{lamps: map[string]*lamp{
		l1: {On: true, Bri: 80, X: 0.3, Y: 0.3, Colour: true},
		l2: {On: false, Bri: 40, Mirek: 366},
	}}
}

func (f *fakeBridge) lightJSON(id, name, owner string) map[string]any {
	l := f.lamps[id]
	e := map[string]any{"id": id, "type": "light", "owner": map[string]string{"rid": owner, "rtype": "device"},
		"metadata": map[string]string{"name": name, "archetype": "sultan_bulb"}, "on": map[string]bool{"on": l.On},
		"dimming": map[string]float64{"brightness": l.Bri}}
	ct := map[string]any{"mirek_valid": l.Mirek > 0, "mirek_schema": map[string]int{"mirek_minimum": 153, "mirek_maximum": 454}, "mirek": nil}
	if l.Mirek > 0 {
		ct["mirek"] = l.Mirek
	}
	e["color_temperature"] = ct
	if l.Colour {
		e["color"] = map[string]any{"xy": map[string]float64{"x": l.X, "y": l.Y}, "gamut_type": "C"}
	}
	return e
}

func (f *fakeBridge) apply(id string, body map[string]any) {
	l := f.lamps[id]
	if on, ok := body["on"].(map[string]any); ok {
		l.On = on["on"].(bool)
	}
	if d, ok := body["dimming"].(map[string]any); ok {
		l.Bri = d["brightness"].(float64)
	}
	if c, ok := body["color"].(map[string]any); ok {
		xy := c["xy"].(map[string]any)
		l.X, l.Y, l.Mirek = xy["x"].(float64), xy["y"].(float64), 0
	}
	if c, ok := body["color_temperature"].(map[string]any); ok {
		l.Mirek = int(c["mirek"].(float64))
	}
}

func (f *fakeBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("hue-application-key") != appKy {
		w.WriteHeader(403)
		io.WriteString(w, `{"errors":[{"description":"unauthorized user"}],"data":[]}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	data := func(v any) {
		b, _ := json.Marshal(map[string]any{"errors": []any{}, "data": v})
		w.Write(b)
	}
	path := strings.TrimPrefix(r.URL.Path, "/clip/v2/resource/")
	if r.Method == http.MethodPut {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		raw, _ := json.Marshal(body)
		f.writes = append(f.writes, path+" "+string(raw))
		typ, id, _ := strings.Cut(path, "/")
		switch {
		case typ == "light" && f.lamps[id] != nil:
			f.apply(id, body)
		case typ == "grouped_light" && id == gl:
			f.apply(l1, body)
			f.apply(l2, body)
		case typ == "scene" && id == scn:
			f.apply(l1, map[string]any{"on": map[string]any{"on": true}, "dimming": map[string]any{"brightness": 30.0}, "color": map[string]any{"xy": map[string]any{"x": 0.5, "y": 0.4}}})
			f.apply(l2, map[string]any{"on": map[string]any{"on": true}, "color_temperature": map[string]any{"mirek": 454.0}})
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"errors":[{"description":"not found"}],"data":[]}`)
			return
		}
		data([]map[string]string{{"rid": id, "rtype": typ}})
		return
	}
	switch path {
	case "bridge":
		data([]map[string]string{{"id": "x", "bridge_id": bid}})
	case "light":
		data([]any{f.lightJSON(l1, "Sofa lamp", d1), f.lightJSON(l2, "Ceiling", d2)})
	case "device":
		data([]map[string]any{
			{"id": d1, "metadata": map[string]string{"name": "Sofa lamp"}, "product_data": map[string]string{"product_name": "Hue color lamp"}, "services": []map[string]string{{"rid": l1, "rtype": "light"}}},
			{"id": d2, "metadata": map[string]string{"name": "Ceiling"}, "product_data": map[string]string{"product_name": "Hue ambiance"}, "services": []map[string]string{{"rid": l2, "rtype": "light"}}},
			{"id": d3, "metadata": map[string]string{"name": "Hall sensor"}, "product_data": map[string]string{"product_name": "Hue motion sensor"}},
		})
	case "zigbee_connectivity":
		data([]map[string]any{{"owner": map[string]string{"rid": d1}, "status": "connected"}, {"owner": map[string]string{"rid": d2}, "status": "connectivity_issue"}})
	case "room":
		data([]map[string]any{{"id": room, "metadata": map[string]string{"name": "Living room", "archetype": "living_room"},
			"children": []map[string]string{{"rid": d1, "rtype": "device"}, {"rid": d2, "rtype": "device"}}, "services": []map[string]string{{"rid": gl, "rtype": "grouped_light"}}}})
	case "zone":
		data([]map[string]any{{"id": zone, "metadata": map[string]string{"name": "Reading"}, "children": []map[string]string{{"rid": l1, "rtype": "light"}}}})
	case "grouped_light":
		data([]map[string]any{{"id": gl, "on": map[string]bool{"on": f.lamps[l1].On || f.lamps[l2].On}, "dimming": map[string]float64{"brightness": 60}}})
	case "scene":
		data([]map[string]any{
			{"id": scn, "metadata": map[string]string{"name": "Relax"}, "group": map[string]string{"rid": room, "rtype": "room"}, "status": map[string]string{"active": "inactive"},
				"actions": []map[string]any{
					{"target": map[string]string{"rid": l1, "rtype": "light"}, "action": map[string]any{"on": map[string]bool{"on": true}, "dimming": map[string]float64{"brightness": 30}, "color": map[string]any{"xy": map[string]float64{"x": 0.5, "y": 0.4}}}},
					{"target": map[string]string{"rid": l2, "rtype": "light"}, "action": map[string]any{"on": map[string]bool{"on": true}, "color_temperature": map[string]int{"mirek": 454}}},
				}},
			{"id": scn2, "metadata": map[string]string{"name": "Relax"}, "group": map[string]string{"rid": zone, "rtype": "zone"}, "status": map[string]string{"active": "static"}},
		})
	case "device_power":
		data([]map[string]any{{"owner": map[string]string{"rid": d3}, "power_state": map[string]any{"battery_state": "low", "battery_level": 12}},
			{"owner": map[string]string{"rid": d1}, "power_state": map[string]any{}}})
	case "motion":
		data([]map[string]any{{"owner": map[string]string{"rid": d3}, "enabled": true, "motion": map[string]any{"motion": true, "motion_valid": true,
			"motion_report": map[string]any{"changed": "2026-11-04T10:00:00Z", "motion": true}}}})
	case "temperature":
		data([]map[string]any{{"owner": map[string]string{"rid": d3}, "temperature": map[string]any{"temperature": 21.34, "temperature_valid": true}}})
	case "light_level":
		data([]map[string]any{{"owner": map[string]string{"rid": d3}, "light": map[string]any{"light_level": 20001, "light_level_valid": true}}})
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[{"description":"not found"}],"data":[]}`)
	}
}

func cert(t *testing.T, cn string) (tls.Certificate, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:])
}

// testCA stands in for the Hue bridge root CA: it's added to bridgeRoots,
// next to the real roots, so caServer can play a genuine bridge.
var testCA, testCAKey = func() (*x509.Certificate, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "test root-bridge", Organization: []string{"Philips Hue"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	bridgeRoots.AddCert(c)
	return c, key
}()

// caServer is a bridge whose certificate (CN = cn) the test CA signed, like
// a real bridge's.
func caServer(t *testing.T, h http.Handler, cn string) *httptest.Server {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn, Organization: []string{"Philips Hue"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, testCA, &key.PublicKey, testCAKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// tlsServer is a server with a self-signed certificate (CN = cn): an old
// bridge, or someone on the network playing one.
func tlsServer(t *testing.T, h http.Handler, cn string) (*httptest.Server, string) {
	c, fp := cert(t, cn)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{c}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, fp
}

var secrets = map[string]string{"secret://hue": appKy, "secret://bad": "nope"}

func configure(t *testing.T, c Config) (*Module, error) {
	m := New()
	raw, _ := json.Marshal(c)
	return m, m.Configure(context.Background(), fakehost.New(secrets), "h", raw)
}

// critical is what setup puts in criticalLights (nothing unless a test sets it).
var critical []string

func setup(t *testing.T) (*Module, *fakeBridge) {
	t.Helper()
	pace = 0
	f := newBridge()
	srv := caServer(t, f, bid)
	m, err := configure(t, Config{URL: srv.URL, ApplicationKey: "secret://hue", BridgeID: strings.ToUpper(bid), CriticalLights: critical})
	if err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "h", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestHueRead(t *testing.T) {
	m, _ := setup(t)
	if h := m.Health(context.Background(), "h"); h.Status != "ok" || h.Message != "bridge "+bid+" · 2 lights" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"lights", `{}`, `[{"id":"` + l2 + `","kelvin":2732,"name":"Ceiling","on":false,"product":"Hue ambiance","reachable":false,"room":"Living room","type":"sultan_bulb","brightness":40},` +
			`{"brightness":80,"id":"` + l1 + `","name":"Sofa lamp","on":true,"product":"Hue color lamp","reachable":true,"room":"Living room","type":"sultan_bulb","xy":{"x":0.3,"y":0.3}}]`},
		{"lights", `{"room":"reading"}`, `"name":"Sofa lamp"`},
		{"rooms", `{}`, `[{"archetype":"living_room","brightness":60,"id":"` + room + `","kind":"room","lights":["Ceiling","Sofa lamp"],"lightsOn":1,"name":"Living room","on":true},{"id":"` + zone + `","kind":"zone","lights":["Sofa lamp"],"lightsOn":1,"name":"Reading"}]`},
		{"scenes", `{"room":"Living room"}`, `[{"active":"inactive","id":"` + scn + `","lights":2,"name":"Relax","room":"Living room"}]`},
		{"sensors", `{}`, `[{"battery":12,"batteryState":"low","device":"` + d3 + `","lux":100,"motion":true,"motionChanged":"2026-11-04T10:00:00Z","name":"Hall sensor","product":"Hue motion sensor","temperatureC":21.3}]`},
		{"batteries", `{}`, `[{"battery":12,"batteryState":"low","device":"` + d3 + `","name":"Hall sensor","product":"Hue motion sensor"}]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil {
			t.Fatalf("%s: %v", c.action, err)
		}
		got := string(r.Output)
		if c.action == "lights" && c.in == `{}` {
			// Map keys are sorted by encoding/json; compare as values.
			var a, b any
			json.Unmarshal(r.Output, &a)
			json.Unmarshal([]byte(c.want), &b)
			if mustJSONs(a) != mustJSONs(b) {
				t.Fatalf("%s:\n%s\n%s", c.action, got, c.want)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Fatalf("%s %s:\n%s\nwant %s", c.action, c.in, got, c.want)
		}
	}
}

func mustJSONs(v any) string { return string(mustJSON(v)) }

func TestHueWrite(t *testing.T) {
	m, f := setup(t)
	p, err := invoke(m, "set_light", `{"light":"sofa lamp","color":"#ff0000","brightness":50}`, true)
	if err != nil || p.Plan == nil || len(f.writes) != 0 || p.Plan.Summary != "Turn on Sofa lamp at brightness 50%, colour xy 0.7006,0.2993" ||
		string(p.Plan.Changes[0].Before) != `{"brightness":80,"on":true,"xy":{"x":0.3,"y":0.3}}` {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err := invoke(m, "set_light", `{"light":"sofa lamp","color":"#ff0000","brightness":50,"transitionMs":400}`, false)
	if err != nil || len(f.writes) != 1 || f.writes[0] != `light/`+l1+` {"color":{"xy":{"x":0.7006,"y":0.2993}},"dimming":{"brightness":50},"dynamics":{"duration":400},"on":{"on":true}}` {
		t.Fatalf("%v %q", err, f.writes)
	}
	if r.Undo == nil || r.Undo.Action != "restore_lights" {
		t.Fatalf("%+v", r.Undo)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	if l := f.lamps[l1]; !l.On || l.Bri != 80 || l.X != 0.3 || l.Mirek != 0 {
		t.Fatalf("not restored: %+v", l)
	}

	// The white lamp in colour-temperature mode comes back by mirek.
	r, err = invoke(m, "set_light", `{"light":"`+l2+`","kelvin":4000}`, false)
	if err != nil || f.lamps[l2].Mirek != 250 || !f.lamps[l2].On {
		t.Fatalf("%v %+v", err, f.lamps[l2])
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.lamps[l2].Mirek != 366 || f.lamps[l2].On {
		t.Fatalf("%v %+v", err, f.lamps[l2])
	}

	// A scene: preview per light, undo puts both back.
	f.writes = nil
	p, err = invoke(m, "activate_scene", `{"scene":"Relax","room":"Living room"}`, true)
	if err != nil || len(p.Plan.Changes) != 2 || len(f.writes) != 0 || string(p.Plan.Changes[1].After) != `{"brightness":40,"kelvin":2202,"on":true}` {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := invoke(m, "activate_scene", `{"scene":"Relax"}`, false); err == nil || !strings.Contains(err.Error(), "2 scenes are named") {
		t.Fatal(err)
	}
	r, err = invoke(m, "activate_scene", `{"scene":"`+scn+`"}`, false)
	if err != nil || f.writes[0] != `scene/`+scn+` {"recall":{"action":"active"}}` || f.lamps[l1].Bri != 30 {
		t.Fatalf("%v %q", err, f.writes)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil {
		t.Fatal(err)
	}
	if a, b := f.lamps[l1], f.lamps[l2]; a.Bri != 80 || a.X != 0.3 || !a.On || b.On || b.Mirek != 366 {
		t.Fatalf("not restored: %+v %+v", a, b)
	}

	// A room off, and back.
	r, err = invoke(m, "set_group", `{"group":"Living room","on":false}`, false)
	if err != nil || f.lamps[l1].On || r.Undo == nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || !f.lamps[l1].On || f.lamps[l2].On {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		write := strings.HasPrefix(a.Name, "set_") || a.Name == "activate_scene" || a.Name == "restore_lights"
		if a.Name == "light_off_critical" {
			if a.Risk != sdk.RiskDestructive || !a.DryRun || !a.Reversible {
				t.Fatalf("%s: %+v", a.Name, a)
			}
			continue
		}
		if write && (a.Risk != sdk.RiskWrite || !a.DryRun || !a.Reversible) || !write && a.Risk != sdk.RiskRead {
			t.Fatalf("%s: %+v", a.Name, a)
		}
	}
}

func TestHueRefusals(t *testing.T) {
	m, f := setup(t)
	for _, c := range []struct{ action, in string }{
		{"set_light", `{"light":"Sofa lamp","brightness":101}`},
		{"set_light", `{"light":"Sofa lamp","brightness":-1}`},
		{"set_light", `{"light":"Sofa lamp","color":"red"}`},
		{"set_light", `{"light":"Sofa lamp","color":"#000000"}`},
		{"set_light", `{"light":"Sofa lamp","color":"#ff0000","kelvin":3000}`},
		{"set_light", `{"light":"Sofa lamp","kelvin":9000}`},
		{"set_light", `{"light":"Sofa lamp","xy":{"x":2,"y":0.1}}`},
		{"set_light", `{"light":"Sofa lamp","transitionMs":70000,"on":true}`},
		{"set_light", `{"light":"Sofa lamp"}`},
		{"set_light", `{"light":"Ceiling","color":"#00ff00"}`}, // no colour
		{"set_light", `{"light":"Ceiling","mirek":480}`},       // outside its range
		{"set_light", `{"light":"../bridge","on":true}`},
		{"set_light", `{"light":"` + l1 + `/../../bridge","on":true}`},
		{"set_light", `{"light":"33333333-3333-4333-8333-333333333333","on":true}`},
		{"set_light", `{"on":true}`},
		{"set_group", `{"group":"Living room","color":"#ff0000"}`},
		{"set_group", `{"group":"Kitchen","on":true}`},
		{"activate_scene", `{"scene":"Nope"}`},
		{"activate_scene", `{"scene":"Relax","room":"Garage"}`},
		{"restore_lights", `{"lights":[]}`},
		{"restore_lights", `{"lights":[{"id":"x/../y","on":true}]}`},
		{"restore_lights", `{"lights":[{"id":"33333333-3333-4333-8333-333333333333","on":true}]}`},
		{"restore_lights", `{"lights":[{"id":"` + l1 + `","on":true},{"id":"` + l1 + `","on":false}]}`},
		{"restore_lights", `{"lights":[{"id":"` + l2 + `","xy":{"x":0.3,"y":0.3}}]}`},
		{"restore_lights", `{"lights":[{"id":"` + l1 + `","xy":{"x":0.3,"y":0.3},"mirek":300}]}`},
		{"nope", `{}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.writes) != 0 {
		t.Fatalf("refused input reached the bridge: %q", f.writes)
	}

	srv, fp := tlsServer(t, newBridge(), bid)
	bad, err := configure(t, Config{URL: caServer(t, newBridge(), bid).URL, ApplicationKey: "secret://bad", BridgeID: bid})
	if err != nil {
		t.Fatal(err)
	}
	if h := bad.Health(context.Background(), "h"); h.Status != "down" || !strings.Contains(h.Message, "refused the application key") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct {
		cfg  Config
		want string
	}{
		{Config{URL: srv.URL, ApplicationKey: "secret://hue", Fingerprint: fp}, "ok"},
		{Config{URL: srv.URL, ApplicationKey: "secret://hue", Fingerprint: fp, BridgeID: bid}, "ok"},
		{Config{URL: srv.URL, ApplicationKey: "secret://hue", Fingerprint: strings.Repeat("ab", 32)}, "down"},
		{Config{URL: srv.URL, ApplicationKey: "secret://hue", BridgeID: "001788fffe000000"}, "down"}, // another bridge's name
	} {
		m, err := configure(t, c.cfg)
		if err != nil {
			t.Fatal(err)
		}
		if h := m.Health(context.Background(), "h"); h.Status != c.want {
			t.Fatalf("%+v: %+v", c.cfg, h)
		}
	}
	for _, c := range []Config{
		{URL: "http://192.168.1.20", ApplicationKey: "secret://hue", BridgeID: bid},
		{URL: "https://192.168.1.20", ApplicationKey: "plain-key", BridgeID: bid},
		{URL: "https://192.168.1.20", ApplicationKey: "secret://hue"},
		{URL: "https://192.168.1.20", ApplicationKey: "secret://hue", BridgeID: "bridge-1"},
		{URL: "https://192.168.1.20", ApplicationKey: "secret://hue", Fingerprint: "abcd"},
		{URL: "https://192.168.1.20/api", ApplicationKey: "secret://hue", BridgeID: bid},
		{URL: "https://u:p@192.168.1.20", ApplicationKey: "secret://hue", BridgeID: bid},
	} {
		if _, err := configure(t, c); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}

	// The key is in its own header, which Go would carry to another host.
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("hue-application-key") }))
	defer evil.Close()
	rd := caServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}), bid)
	rm, err := configure(t, Config{URL: rd.URL, ApplicationKey: "secret://hue", BridgeID: bid})
	if err != nil {
		t.Fatal(err)
	}
	if h := rm.Health(context.Background(), "h"); h.Status != "down" || !strings.Contains(h.Message, "another host") || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

func TestRGBToXY(t *testing.T) {
	for in, want := range map[string]xy{"#ffffff": {0.3227, 0.329}, "00ff00": {0.1724, 0.7468}, "#0000FF": {0.1355, 0.0399}} {
		if got, err := rgbToXY(in); err != nil || got != want {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
}

// The bridge id isn't a secret (the bridge announces it), so with the id
// alone the certificate must chain to the Hue root CA: a self-signed one
// carrying the id gets nothing, least of all the application key.
func TestHueBridgeIDNeedsRootCA(t *testing.T) {
	var mu sync.Mutex
	var got string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got += r.Header.Get("hue-application-key")
		mu.Unlock()
		w.Write([]byte(`{"errors":[],"data":[{"id":"x","bridge_id":"` + bid + `"}]}`))
	})
	srv, fp := tlsServer(t, h, bid)
	m, err := configure(t, Config{URL: srv.URL, ApplicationKey: "secret://hue", BridgeID: bid})
	if err != nil {
		t.Fatal(err)
	}
	if hl := m.Health(context.Background(), "h"); hl.Status != "down" || !strings.Contains(hl.Message, "root CA") {
		t.Fatalf("%+v", hl)
	}
	mu.Lock()
	if got != "" {
		t.Fatalf("the key went to a self-signed server: %q", got)
	}
	mu.Unlock()
	// With the fingerprint pinned, the same self-signed bridge is fine.
	if m, _ = configure(t, Config{URL: srv.URL, ApplicationKey: "secret://hue", BridgeID: bid, Fingerprint: fp}); m.Health(context.Background(), "h").Status == "down" {
		t.Fatal("refused the pinned fingerprint")
	}
	mu.Lock()
	if !strings.HasPrefix(got, appKy) {
		t.Fatalf("the pinned bridge got no key: %q", got)
	}
	mu.Unlock()
	// Signed by the CA, but for another bridge.
	other := caServer(t, newBridge(), "001788fffe000000")
	if m, _ = configure(t, Config{URL: other.URL, ApplicationKey: "secret://hue", BridgeID: bid}); m.Health(context.Background(), "h").Status != "down" {
		t.Fatal("took another bridge's certificate")
	}
	// The embedded roots are the two Hue roots.
	n := 0
	for rest := []byte(hueRoots); ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil || !c.IsCA || c.CheckSignatureFrom(c) != nil {
			t.Fatalf("%v %+v", err, c.Subject)
		}
		n++
	}
	if n != 2 {
		t.Fatal(n)
	}
}

func TestHueCriticalLights(t *testing.T) {
	critical = []string{"ceiling"} // by name, any case
	defer func() { critical = nil }()
	m, f := setup(t)
	for _, c := range []struct{ action, in string }{
		{"set_light", `{"light":"Ceiling","on":false}`},
		{"set_light", `{"light":"` + l2 + `","on":false}`},
		{"restore_lights", `{"lights":[{"id":"` + l2 + `","on":false}]}`},
		{"restore_lights", `{"lights":[{"id":"` + l1 + `","on":false},{"id":"` + l2 + `","on":false}]}`},
		{"light_off_critical", `{"light":"Sofa lamp"}`}, // not critical
		{"light_off_critical", `{"light":"Ceiling","lights":[{"id":"` + l2 + `","on":false}]}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.writes) != 0 {
		t.Fatal(f.writes)
	}
	// Turning a critical light on is fine; undo turns it off again, so it's
	// light_off_critical.
	r, err := invoke(m, "set_light", `{"light":"Ceiling","on":true}`, false)
	if err != nil || !f.lamps[l2].On || r.Undo == nil || r.Undo.Action != "light_off_critical" {
		t.Fatalf("%+v %v", r.Undo, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.lamps[l2].On {
		t.Fatal(err)
	}
	f.lamps[l2].On = true

	// A room off: the others light by light, the critical one stays on.
	f.writes = nil
	p, err := invoke(m, "set_group", `{"group":"Living room","on":false}`, true)
	if err != nil || len(p.Plan.Changes) != 1 || !strings.Contains(p.Plan.Summary, "leaving Ceiling on") || len(f.writes) != 0 {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err = invoke(m, "set_group", `{"group":"Living room","on":false}`, false)
	if err != nil || f.lamps[l1].On || !f.lamps[l2].On || len(f.writes) != 1 || !strings.HasPrefix(f.writes[0], "light/"+l1+" ") {
		t.Fatalf("%v %q", err, f.writes)
	}
	if !strings.Contains(string(r.Output), `"skippedCritical":["Ceiling"]`) || r.Undo.Action != "restore_lights" {
		t.Fatalf("%s %+v", r.Output, r.Undo)
	}
	// Turning a room on still goes to the grouped light.
	f.writes = nil
	if _, err := invoke(m, "set_group", `{"group":"Living room","on":true}`, false); err != nil || len(f.writes) != 1 || !strings.HasPrefix(f.writes[0], "grouped_light/") {
		t.Fatalf("%v %q", err, f.writes)
	}

	// The destructive action does turn it off, and undo turns it back on.
	f.writes = nil
	p, err = invoke(m, "light_off_critical", `{"light":"Ceiling"}`, true)
	if err != nil || !strings.HasPrefix(p.Plan.Summary, "Turn off critical Ceiling") || len(f.writes) != 0 {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	r, err = invoke(m, "light_off_critical", `{"light":"Ceiling"}`, false)
	if err != nil || f.lamps[l2].On || r.Undo == nil || r.Undo.Action != "restore_lights" {
		t.Fatalf("%+v %v", r.Undo, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || !f.lamps[l2].On {
		t.Fatal(err)
	}
}

// A scene whose action turns a critical light off is refused.
func TestHueCriticalScene(t *testing.T) {
	critical = []string{l1}
	defer func() { critical = nil }()
	m, f := setup(t)
	srv := caServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/resource/scene") {
			w.Write([]byte(`{"errors":[],"data":[{"id":"` + scn + `","metadata":{"name":"Night"},"group":{"rid":"` + room + `","rtype":"room"},"status":{"active":"inactive"},` +
				`"actions":[{"target":{"rid":"` + l1 + `","rtype":"light"},"action":{"on":{"on":false}}},{"target":{"rid":"` + l2 + `","rtype":"light"},"action":{"on":{"on":true}}}]}]}`))
			return
		}
		f.ServeHTTP(w, r)
	}), bid)
	m, err := configure(t, Config{URL: srv.URL, ApplicationKey: "secret://hue", BridgeID: bid, CriticalLights: critical})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "activate_scene", `{"scene":"Night"}`, false); err == nil || !strings.Contains(err.Error(), "Sofa lamp") {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatal(f.writes)
	}
}
