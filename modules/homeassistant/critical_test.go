package homeassistant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func st(id, state string, attrs map[string]any) haState {
	if attrs == nil {
		attrs = map[string]any{}
	}
	return haState{EntityID: id, State: state, Attributes: attrs}
}

// broken answers 500 for one entity's state, like a Home Assistant that
// can't read it.
type broken struct {
	*fakeHA
	entity string
}

func (b broken) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/states/"+b.entity {
		w.WriteHeader(500)
		return
	}
	b.fakeHA.ServeHTTP(w, r)
}

func setupCritical(t *testing.T, critical ...string) (*Module, *fakeHA) {
	f := &fakeHA{state: map[string]haState{
		"light.desk":            st("light.desk", "on", map[string]any{"friendly_name": "Desk"}),
		"light.garage":          st("light.garage", "off", map[string]any{"friendly_name": "Garage light"}),
		"light.outdoor":         st("light.outdoor", "off", map[string]any{"friendly_name": "Outdoor lamp"}),
		"switch.kettle":         st("switch.kettle", "off", map[string]any{"friendly_name": "Kettle", "device_class": "outlet"}),
		"switch.motor":          st("switch.motor", "off", map[string]any{"friendly_name": "Motor"}),
		"switch.garage_door":    st("switch.garage_door", "off", map[string]any{"friendly_name": "Garage Door"}),
		"switch.hoftor":         st("switch.hoftor", "off", map[string]any{"friendly_name": "Hoftor"}),
		"switch.relay_3":        st("switch.relay_3", "off", map[string]any{"friendly_name": "Relay 3", "device_class": "gate"}),
		"switch.rack":           st("switch.rack", "on", map[string]any{"friendly_name": "Rack"}),
		"switch.gone":           st("switch.gone", "unavailable", nil),
		"switch.unread":         st("switch.unread", "off", nil),
		"cover.garage_door":     st("cover.garage_door", "closed", map[string]any{"friendly_name": "Garage Door", "device_class": "garage"}),
		"cover.moving":          st("cover.moving", "opening", map[string]any{"device_class": "gate"}),
		"valve.garden":          st("valve.garden", "closed", map[string]any{"friendly_name": "Garden"}),
		"climate.living":        st("climate.living", "heat", map[string]any{"friendly_name": "Living room"}),
		"siren.hall":            st("siren.hall", "off", map[string]any{"friendly_name": "Hall"}),
		"lock.front":            st("lock.front", "locked", map[string]any{"friendly_name": "Front"}),
		"alarm_control_panel.h": st("alarm_control_panel.h", "armed_away", nil),
	}}
	srv := httptest.NewServer(broken{f, "switch.unread"})
	t.Cleanup(srv.Close)
	m := New()
	cfg, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://ha", CriticalEntities: critical})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://ha": "ha"}), "ha", cfg); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func call(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "ha", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestCriticalWhy(t *testing.T) {
	h := &home{critical: []string{"switch.rack", "switch.garden_*", "input_boolean.?ump"}}
	for _, c := range []struct {
		s    haState
		want bool
	}{
		// Domains.
		{st("lock.front", "locked", nil), true}, {st("cover.blinds", "open", nil), true},
		{st("alarm_control_panel.home", "armed_away", nil), true}, {st("valve.main", "closed", nil), true},
		{st("climate.living", "heat", nil), true}, {st("water_heater.boiler", "eco", nil), true},
		{st("camera.drive", "idle", nil), true}, {st("siren.hall", "off", nil), true},
		{st("humidifier.bed", "off", nil), true}, {st("script.open_up", "off", nil), true},
		// Device classes: outlet and switch aren't critical.
		{st("switch.relay_1", "off", map[string]any{"device_class": "garage"}), true},
		{st("switch.relay_2", "off", map[string]any{"device_class": "gate"}), true},
		{st("switch.relay_3", "off", map[string]any{"device_class": "door"}), true},
		{st("switch.relay_4", "off", map[string]any{"device_class": "window"}), true},
		{st("switch.relay_5", "off", map[string]any{"device_class": "lock"}), true},
		{st("switch.relay_6", "off", map[string]any{"device_class": "shutter"}), true},
		{st("switch.relay_7", "off", map[string]any{"device_class": "outlet"}), false},
		{st("switch.relay_8", "off", map[string]any{"device_class": "switch"}), false},
		// Names, by id and by friendly name.
		{st("switch.garage_door", "off", nil), true}, {st("switch.relay_9", "off", map[string]any{"friendly_name": "Front gate"}), true},
		{st("switch.hoftor", "off", nil), true}, {st("switch.x", "off", map[string]any{"friendly_name": "Haustür Riegel"}), true},
		{st("switch.heating_pump", "off", nil), true}, {st("input_boolean.alarm_armed", "off", nil), true},
		{st("switch.tor_2", "off", nil), true}, {st("switch.einfahrt_tor", "off", nil), true},
		{st("switch.motor", "off", nil), false}, {st("switch.monitor", "off", nil), false},
		{st("switch.kettle", "off", map[string]any{"friendly_name": "Kettle"}), false},
		{st("fan.bedroom", "off", nil), false},
		// A light only lights, whatever it's called.
		{st("light.garage", "off", nil), false}, {st("light.front_door", "off", map[string]any{"friendly_name": "Front door"}), false},
		// criticalEntities, with globs.
		{st("switch.rack", "on", nil), true}, {st("switch.garden_pump", "on", nil), true}, {st("switch.gardenx", "on", nil), false},
		{st("input_boolean.pump", "on", nil), true}, {st("light.rack", "on", nil), false},
		// An unknown state can't be judged.
		{st("switch.kettle", "unavailable", nil), true}, {st("light.desk", "unknown", nil), true},
	} {
		if got := h.why(c.s) != ""; got != c.want {
			t.Errorf("%s %v: critical %v, want %v (%s)", c.s.EntityID, c.s.Attributes, got, c.want, h.why(c.s))
		}
	}
}

// The same German names openHAB and Homebridge test, as friendly names.
func TestCriticalGermanNames(t *testing.T) {
	h := &home{}
	for _, c := range []struct {
		name string
		want bool
	}{
		{"Hoftor", true}, {"Haustür Riegel", true}, {"Haustuer", true}, {"Garagentor", true}, {"Einfahrtstor", true},
		{"Tor 2", true}, {"Torantrieb", true}, {"Türe Keller", true}, {"Schloss Eingang", true}, {"Türöffner", true},
		{"Oeffner", true}, {"Fenster Bad", true}, {"Heizung", true}, {"Sirene", true}, {"Ventil Garten", true},
		{"Kamera Einfahrt", true}, {"Rauchmelder", true}, {"Sicherheit", true}, {"Bewässerung", true}, {"Bewaesserung", true},
		{"Motor", false}, {"Monitor", false}, {"Rotor", false}, {"Traktor", false}, {"Faktor", false}, {"Indikator", false},
		{"Stehlampe", false},
	} {
		if got := h.why(st("switch.x", "off", map[string]any{"friendly_name": c.name})) != ""; got != c.want {
			t.Errorf("%q: critical %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPlainWritesRefuseCritical(t *testing.T) {
	m, f := setupCritical(t, "switch.ra*")
	for _, c := range []struct{ action, entity, want string }{
		{"turn_on", "switch.garage_door", "use turn_critical with entity switch.garage_door and action on"},
		{"turn_off", "switch.rack", "listed in criticalEntities): use turn_critical with entity switch.rack and action off"},
		{"toggle", "switch.hoftor", "action toggle"},
		{"turn_on", "switch.relay_3", "device class is gate"},
		{"turn_on", "cover.garage_door", "a cover"},
		{"turn_on", "climate.living", "heating or cooling"},
		{"turn_on", "siren.hall", "turn_critical"},
		{"turn_off", "lock.front", "use call_service with lock.lock or lock.unlock"},
		{"turn_off", "alarm_control_panel.h", "alarm_disarm"},
		// Fail closed: an unknown or unreadable state counts as critical.
		{"turn_on", "switch.gone", "its state is unavailable"},
		{"turn_on", "switch.unread", "couldn't be read"},
	} {
		_, err := call(m, c.action, `{"entity":"`+c.entity+`"}`, false)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "is critical") {
			t.Errorf("%s %s: %v", c.action, c.entity, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("a critical entity was changed: %v", f.calls)
	}
	// Ordinary lights and switches still work as writes, with undo.
	for _, e := range []string{"light.desk", "light.garage", "light.outdoor", "switch.kettle", "switch.motor"} {
		was := f.state[e].State
		r, err := call(m, "toggle", `{"entity":"`+e+`"}`, false)
		if err != nil || f.state[e].State == was || r.Undo == nil || r.Undo.Action != "turn_"+was {
			t.Fatalf("%s: %+v %v", e, r, err)
		}
		if _, err := call(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state[e].State != was {
			t.Fatalf("%s undo: %v", e, err)
		}
	}
	if _, err := call(m, "turn_on", `{"entity":"switch.nope"}`, false); err == nil || !strings.Contains(err.Error(), "no entity") {
		t.Fatal(err)
	}
	// Listings say what's critical.
	r, err := call(m, "state", `{"entity":"switch.hoftor"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"criticalBecause":"its name says`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, _ = call(m, "entities", `{"search":"kettle"}`, false)
	if strings.Contains(string(r.Output), "critical") {
		t.Fatal(string(r.Output))
	}
	r, _ = call(m, "entities", `{"domain":"cover"}`, false)
	if !strings.Contains(string(r.Output), `"critical":true`) {
		t.Fatal(string(r.Output))
	}
}

func TestTurnCritical(t *testing.T) {
	m, f := setupCritical(t, "switch.rack")
	for _, a := range m.Manifest().Actions {
		switch a.Name {
		case "turn_critical", "call_service":
			if a.Risk != sdk.RiskDestructive {
				t.Fatal(a.Name, a.Risk)
			}
		case "turn_on", "turn_off", "toggle":
			if a.Risk != sdk.RiskWrite {
				t.Fatal(a.Name, a.Risk)
			}
		}
	}

	// Preview: says what it does, changes nothing.
	for _, c := range []struct{ entity, action, want string }{
		{"cover.garage_door", "on", "Open Garage Door (cover.garage_door) (closed → open); this opens the garage door (a cover"},
		{"cover.garage_door", "toggle", "(closed → open); this opens the garage door"},
		{"switch.garage_door", "toggle", "Turn on Garage Door (switch.garage_door) (off → on); this turns it on, which may open, unlock or start the garage door (its name says"},
		{"switch.hoftor", "on", "(off → on); this turns it on, which may open, unlock or start the gate"},
		{"switch.rack", "toggle", "Turn off Rack (switch.rack) (on → off); this turns it off (listed in criticalEntities)"},
		{"valve.garden", "on", "Open Garden (valve.garden) (closed → open); this opens the valve"},
		{"climate.living", "toggle", "Turn off Living room (climate.living) (heat → off); this turns the heating or cooling off"},
		{"siren.hall", "on", "this sounds the siren"},
		{"switch.unread", "on", "(state unknown → on)"},
	} {
		r, err := call(m, "turn_critical", `{"entity":"`+c.entity+`","action":"`+c.action+`"}`, true)
		if err != nil || r.Plan == nil || !strings.Contains(r.Plan.Summary, c.want) {
			t.Errorf("%s %s: %+v %v", c.entity, c.action, r.Plan, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("a preview changed something: %v", f.calls)
	}

	// Refusals.
	for _, c := range []struct{ entity, action, want string }{
		{"switch.kettle", "on", "isn't critical; use turn_on"},
		{"light.desk", "toggle", "isn't critical; use toggle"},
		{"switch.unread", "toggle", "not known on or off"},
		{"switch.gone", "toggle", "unavailable, not known on or off"},
		{"cover.moving", "toggle", "opening, not known on or off"},
		{"lock.front", "off", "call_service"},
		{"cover.garage_door", "open", "on, off or toggle"},
		{"switch.nope", "on", "no entity"},
		{"../x", "on", "isn't an entity id"},
	} {
		if _, err := call(m, "turn_critical", `{"entity":"`+c.entity+`","action":"`+c.action+`"}`, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s: %v", c.entity, c.action, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("a refusal changed something: %v", f.calls)
	}

	// Act, read back, undo.
	r, err := call(m, "turn_critical", `{"entity":"cover.garage_door","action":"on"}`, false)
	if err != nil || f.state["cover.garage_door"].State != "open" || !strings.Contains(string(r.Output), `"now":"open"`) || !strings.Contains(string(r.Output), `"was":"closed"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r.Undo == nil || r.Undo.Action != "turn_critical" || string(r.Undo.Input) != `{"action":"off","entity":"cover.garage_door"}` {
		t.Fatalf("%+v", r.Undo)
	}
	if _, err := call(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.state["cover.garage_door"].State != "closed" {
		t.Fatal(err)
	}
	if got := strings.Join(f.calls, "; "); !strings.Contains(got, "cover/open_cover") || !strings.Contains(got, "cover/close_cover") {
		t.Fatal(got)
	}
	r, err = call(m, "turn_critical", `{"entity":"switch.hoftor","action":"toggle"}`, false)
	if err != nil || f.state["switch.hoftor"].State != "on" || r.Undo == nil || string(r.Undo.Input) != `{"action":"off","entity":"switch.hoftor"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.HasSuffix(f.calls[len(f.calls)-1], "switch/turn_on map[entity_id:switch.hoftor]") {
		t.Fatalf("toggle must send the explicit service: %v", f.calls)
	}
	// Nothing to change.
	if r, err := call(m, "turn_critical", `{"entity":"switch.hoftor","action":"on"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%+v %v", r, err)
	}
	// Heat → off can't be put back exactly (the mode may differ), so no undo.
	r, err = call(m, "turn_critical", `{"entity":"climate.living","action":"off"}`, false)
	if err != nil || f.state["climate.living"].State != "off" || r.Undo != nil {
		t.Fatalf("%+v %v", r, err)
	}
	// Off → on can: undo turns it off again.
	r, err = call(m, "turn_critical", `{"entity":"climate.living","action":"on"}`, false)
	if err != nil || r.Undo == nil || string(r.Undo.Input) != `{"action":"off","entity":"climate.living"}` {
		t.Fatalf("%+v %v", r, err)
	}
	// An unreadable state: on or off with approval, but no undo.
	r, err = call(m, "turn_critical", `{"entity":"switch.unread","action":"on"}`, false)
	if err != nil || r.Undo != nil || !strings.Contains(string(r.Output), `"now":"couldn't be read back"`) {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestCriticalEntitiesConfig(t *testing.T) {
	for _, list := range [][]string{{""}, {"garage"}, {"switch.[a"}, {"switch/x.y"}, {"switch.a b"}, make([]string, 201)} {
		raw, _ := json.Marshal(Config{URL: "http://ha.local:8123", Token: "secret://ha", CriticalEntities: list})
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Errorf("accepted %q", list)
		}
	}
	raw, _ := json.Marshal(Config{URL: "http://ha.local:8123", Token: "secret://ha", CriticalEntities: []string{" Switch.Garage_* ", "switch.rack", "*.pump"}})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
		t.Fatal(err)
	}
}
