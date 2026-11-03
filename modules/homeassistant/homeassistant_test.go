package homeassistant

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

type fakeHA struct {
	mu    sync.Mutex
	state map[string]haState
	calls []string
}

func (f *fakeHA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer ha" {
		w.WriteHeader(401)
		return
	}
	switch {
	case r.URL.Path == "/api/config":
		io.WriteString(w, `{"version":"2026.10.1","location_name":"Home"}`)
	case r.URL.Path == "/api/states":
		var out []haState
		for _, s := range f.state {
			out = append(out, s)
		}
		json.NewEncoder(w).Encode(out)
	case strings.HasPrefix(r.URL.Path, "/api/states/"):
		s, ok := f.state[strings.TrimPrefix(r.URL.Path, "/api/states/")]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Entity not found."}`)
			return
		}
		json.NewEncoder(w).Encode(s)
	case strings.HasPrefix(r.URL.Path, "/api/services/"):
		var d map[string]any
		json.NewDecoder(r.Body).Decode(&d)
		svc := strings.TrimPrefix(r.URL.Path, "/api/services/")
		f.calls = append(f.calls, fmt.Sprintf("%s %v", svc, d))
		id, _ := d["entity_id"].(string)
		s := f.state[id]
		switch {
		case strings.HasSuffix(svc, "/turn_on"):
			s.State = "on"
			if rgb, ok := d["rgb_color"].([]any); ok {
				s.Attributes["rgb_color"] = rgb
			}
		case strings.HasSuffix(svc, "/turn_off"):
			s.State = "off"
		case strings.HasSuffix(svc, "/toggle"):
			s.State = map[string]string{"on": "off", "off": "on"}[s.State]
		}
		f.state[id] = s
		io.WriteString(w, `[]`)
	default:
		w.WriteHeader(404)
	}
}

func TestHomeAssistant(t *testing.T) {
	f := &fakeHA{state: map[string]haState{
		"light.desk":  {EntityID: "light.desk", State: "on", Attributes: map[string]any{"friendly_name": "Desk", "rgb_color": []any{255.0, 255.0, 255.0}, "brightness": 200.0}},
		"sensor.temp": {EntityID: "sensor.temp", State: "21.5", Attributes: map[string]any{"unit_of_measurement": "°C"}},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	m := New()
	ctx := context.Background()
	cfg, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://ha"})
	m.Configure(ctx, fakehost.New(map[string]string{"secret://ha": "ha"}), "ha", cfg)
	if h := m.Health(ctx, "ha"); h.Status != "ok" || h.Message != "Home, Home Assistant 2026.10.1" {
		t.Fatalf("health %+v", h)
	}
	do := func(action string, in any) sdk.Result {
		b, _ := json.Marshal(in)
		r, err := m.Invoke(ctx, sdk.Call{Instance: "ha", Action: action, Input: b})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return r
	}
	var ents []State
	json.Unmarshal(do("entities", map[string]string{"domain": "sensor"}).Output, &ents)
	if len(ents) != 1 || ents[0].Unit != "°C" {
		t.Fatalf("entities %+v", ents)
	}
	r := do("toggle", map[string]string{"entity": "light.desk"})
	if f.state["light.desk"].State != "off" || r.Undo.Action != "turn_on" {
		t.Fatalf("toggle: %s %+v", f.state["light.desk"].State, r.Undo)
	}
	do(r.Undo.Action, json.RawMessage(r.Undo.Input))
	if f.state["light.desk"].State != "on" {
		t.Fatal("undo didn't turn it back on")
	}
	r = do("set_light", map[string]any{"entity": "light.desk", "color": "red"})
	if fmt.Sprint(f.state["light.desk"].Attributes["rgb_color"]) != "[230 40 40]" {
		t.Fatalf("colour %v", f.state["light.desk"].Attributes["rgb_color"])
	}
	do(r.Undo.Action, json.RawMessage(r.Undo.Input))
	if fmt.Sprint(f.state["light.desk"].Attributes["rgb_color"]) != "[255 255 255]" {
		t.Fatalf("undo must restore the colour: %v", f.state["light.desk"].Attributes["rgb_color"])
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "ha", Action: "state", Input: json.RawMessage(`{"entity":"light.nope"}`)}); err == nil || !strings.Contains(err.Error(), "no entity") {
		t.Fatalf("missing entity: %v", err)
	}
	if _, err := parseColor("#12zz34"); err == nil {
		t.Fatal("bad colour accepted")
	}
}
