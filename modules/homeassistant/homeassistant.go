// Package homeassistant controls a Home Assistant installation: entities,
// lights and switches, scenes and services. Toggles and light changes can be
// undone.
package homeassistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Home Assistant's settings.
type Config struct {
	URL   string `json:"url"`   // e.g. http://homeassistant.local:8123
	Token string `json:"token"` // secret:// long-lived access token
}

type home struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[home]
	HTTP *http.Client
}

// New returns the Home Assistant module.
func New() *Module { return &Module{} }

var entityRe = regexp.MustCompile(`^[a-z_]+\.[a-z0-9_]+$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	ent := `"entity":{"type":"string","description":"Entity id, e.g. light.desk"}`
	return sdk.Manifest{
		ID: "homeassistant", Name: "Home Assistant", Version: "0.1.0", Category: "Smart home", Icon: "home",
		Description: "Lights, switches, scenes and anything else in your Home Assistant.",
		Presets:     []string{"homelab", "gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Home Assistant's address, e.g. http://homeassistant.local:8123"},
			"token":{"type":"string","x-secret":true,"description":"A long-lived access token (your profile, Security)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "entities", Title: "Entities", Description: "Everything Home Assistant knows, with its state.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"domain":{"type":"string","description":"e.g. light, switch, sensor"},"search":{"type":"string"}}}`)},
			{Name: "state", Title: "State of one entity", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","required":["entity"],"properties":{` + ent + `}}`)},
			{Name: "turn_on", Title: "Turn on", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(`{"type":"object","required":["entity"],"properties":{` + ent + `}}`)},
			{Name: "turn_off", Title: "Turn off", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(`{"type":"object","required":["entity"],"properties":{` + ent + `}}`)},
			{Name: "toggle", Title: "Toggle", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(`{"type":"object","required":["entity"],"properties":{` + ent + `}}`)},
			{Name: "set_light", Title: "Set a light", Description: "Colour and brightness, e.g. for a status light.", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["entity"],"properties":{` + ent + `,
					"color":{"type":"string","description":"A name (red, green, amber, blue, white) or #rrggbb"},
					"brightness":{"type":"integer","minimum":0,"maximum":100,"description":"Percent"},
					"restore":{"type":"object","additionalProperties":true,"description":"A saved state to put back (used by undo)"}}}`)},
			{Name: "scene", Title: "Activate a scene", Risk: sdk.RiskWrite, Input: sdk.Schema(`{"type":"object","required":["scene"],"properties":{"scene":{"type":"string","description":"e.g. scene.movie_night"}}}`)},
			{Name: "call_service", Title: "Call a service", Description: "Any Home Assistant service, e.g. lock.unlock. Agents ask first: a service can do anything.", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["domain","service"],"properties":{"domain":{"type":"string"},"service":{"type":"string"},"data":{"type":"object","additionalProperties":true}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "entity", Title: "Entities", ListAction: "entities", ViewHint: "table"}},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.URL == "" || c.Token == "" {
		return errors.New("set Home Assistant's address and a long-lived access token")
	}
	if err := rest.ValidBase(c.URL); err != nil {
		return err
	}
	tok := c.Token
	api := rest.New(strings.TrimRight(c.URL, "/")+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
	m.set.Put(id, &home{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	h, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var cfg struct {
		Version  string `json:"version"`
		Location string `json:"location_name"`
	}
	if _, err := h.api.Do(ctx, "GET", "/config", nil, nil, &cfg); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s, Home Assistant %s", cfg.Location, cfg.Version)}
}

// State is an entity's state.
type State struct {
	Entity     string         `json:"entity"`
	Name       string         `json:"name"`
	State      string         `json:"state"`
	Unit       string         `json:"unit,omitempty"`
	Changed    string         `json:"changed"`
	Attributes map[string]any `json:"-"`
}

type haState struct {
	EntityID    string         `json:"entity_id"`
	State       string         `json:"state"`
	Attributes  map[string]any `json:"attributes"`
	LastChanged string         `json:"last_changed"`
}

func (s haState) row() State {
	name, _ := s.Attributes["friendly_name"].(string)
	unit, _ := s.Attributes["unit_of_measurement"].(string)
	return State{Entity: s.EntityID, Name: name, State: s.State, Unit: unit, Changed: s.LastChanged, Attributes: s.Attributes}
}

func (h *home) state(ctx context.Context, entity string) (haState, error) {
	var s haState
	if !entityRe.MatchString(entity) {
		return s, fmt.Errorf("%q isn't an entity id like light.desk", entity)
	}
	_, err := h.api.Do(ctx, "GET", "/states/"+entity, nil, nil, &s)
	if rest.IsStatus(err, 404) {
		return s, fmt.Errorf("Home Assistant has no entity %s", entity)
	}
	return s, err
}

func (h *home) service(ctx context.Context, domain, service string, data map[string]any) error {
	_, err := h.api.Do(ctx, "POST", "/services/"+domain+"/"+service, nil, data, nil)
	return err
}

var colors = map[string][3]int{
	"red": {230, 40, 40}, "green": {40, 200, 80}, "amber": {255, 170, 30}, "orange": {255, 120, 0},
	"yellow": {255, 220, 0}, "blue": {40, 110, 255}, "purple": {150, 60, 220}, "white": {255, 255, 255},
}

func parseColor(s string) ([3]int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if c, ok := colors[s]; ok {
		return c, nil
	}
	if len(s) == 7 && s[0] == '#' {
		var c [3]int
		for i := 0; i < 3; i++ {
			v, err := strconv.ParseUint(s[1+2*i:3+2*i], 16, 8)
			if err != nil {
				return c, fmt.Errorf("%q isn't a colour", s)
			}
			c[i] = int(v)
		}
		return c, nil
	}
	return [3]int{}, fmt.Errorf("%q isn't a colour; use a name or #rrggbb", s)
}

// saved is what undo needs to put a light or switch back.
type saved struct {
	On         bool  `json:"on"`
	RGB        []int `json:"rgb,omitempty"`
	Brightness *int  `json:"brightness,omitempty"` // 0..255
}

func snapshot(s haState) saved {
	sv := saved{On: s.State == "on"}
	if rgb, ok := s.Attributes["rgb_color"].([]any); ok && len(rgb) == 3 {
		for _, v := range rgb {
			f, _ := v.(float64)
			sv.RGB = append(sv.RGB, int(f))
		}
	}
	if b, ok := s.Attributes["brightness"].(float64); ok {
		bi := int(b)
		sv.Brightness = &bi
	}
	return sv
}

func domainOf(entity string) string { return strings.SplitN(entity, ".", 2)[0] }

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	h, err := m.set.Get(c.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Domain     string         `json:"domain"`
		Search     string         `json:"search"`
		Entity     string         `json:"entity"`
		Color      string         `json:"color"`
		Brightness *int           `json:"brightness"`
		Restore    *saved         `json:"restore"`
		Scene      string         `json:"scene"`
		Service    string         `json:"service"`
		Data       map[string]any `json:"data"`
	}
	if err := sdk.Decode(c, &p); err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "entities":
		var ss []haState
		if _, err := h.api.Do(ctx, "GET", "/states", nil, nil, &ss); err != nil {
			return sdk.Result{}, err
		}
		out := []State{}
		q := strings.ToLower(p.Search)
		for _, s := range ss {
			r := s.row()
			if p.Domain != "" && domainOf(s.EntityID) != p.Domain {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(r.Entity+" "+r.Name), q) {
				continue
			}
			out = append(out, r)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Entity < out[j].Entity })
		return sdk.JSON(out)

	case "state":
		s, err := h.state(ctx, p.Entity)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"entity": s.EntityID, "state": s.State, "changed": s.LastChanged, "attributes": s.Attributes})

	case "turn_on", "turn_off", "toggle":
		before, err := h.state(ctx, p.Entity)
		if err != nil {
			return sdk.Result{}, err
		}
		if err := h.service(ctx, domainOf(p.Entity), c.Action, map[string]any{"entity_id": p.Entity}); err != nil {
			return sdk.Result{}, err
		}
		back := "turn_" + before.State
		after, _ := h.state(ctx, p.Entity)
		r, _ := sdk.JSON(map[string]string{"entity": p.Entity, "was": before.State, "now": after.State})
		if before.State == "on" || before.State == "off" {
			r.Undo = sdk.UndoWith(back, map[string]string{"entity": p.Entity}, fmt.Sprintf("Turn %s back %s", p.Entity, before.State))
		}
		return r, nil

	case "set_light":
		if domainOf(p.Entity) != "light" {
			return sdk.Result{}, errors.New("set_light works on light.* entities")
		}
		before, err := h.state(ctx, p.Entity)
		if err != nil {
			return sdk.Result{}, err
		}
		prev := snapshot(before)
		if p.Restore != nil {
			if !p.Restore.On {
				err = h.service(ctx, "light", "turn_off", map[string]any{"entity_id": p.Entity})
			} else {
				d := map[string]any{"entity_id": p.Entity}
				if len(p.Restore.RGB) == 3 {
					d["rgb_color"] = p.Restore.RGB
				}
				if p.Restore.Brightness != nil {
					d["brightness"] = *p.Restore.Brightness
				}
				err = h.service(ctx, "light", "turn_on", d)
			}
		} else {
			d := map[string]any{"entity_id": p.Entity}
			if p.Color != "" {
				rgb, err := parseColor(p.Color)
				if err != nil {
					return sdk.Result{}, err
				}
				d["rgb_color"] = rgb[:]
			}
			if p.Brightness != nil {
				d["brightness_pct"] = *p.Brightness
			}
			err = h.service(ctx, "light", "turn_on", d)
		}
		if err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"entity": p.Entity, "set": "ok"})
		r.Undo = sdk.UndoWith("set_light", map[string]any{"entity": p.Entity, "restore": prev}, "Put "+p.Entity+" back as it was")
		return r, nil

	case "scene":
		if !strings.HasPrefix(p.Scene, "scene.") || !entityRe.MatchString(p.Scene) {
			return sdk.Result{}, errors.New("scenes look like scene.movie_night")
		}
		if err := h.service(ctx, "scene", "turn_on", map[string]any{"entity_id": p.Scene}); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"activated": p.Scene})

	case "call_service":
		if !regexp.MustCompile(`^[a-z_]+$`).MatchString(p.Domain) || !regexp.MustCompile(`^[a-z_]+$`).MatchString(p.Service) {
			return sdk.Result{}, errors.New("domain and service are lowercase words, e.g. lock and unlock")
		}
		var changed []haState
		if _, err := h.api.Do(ctx, "POST", "/services/"+p.Domain+"/"+p.Service, nil, p.Data, &changed); err != nil {
			return sdk.Result{}, err
		}
		out := []State{}
		for _, s := range changed {
			out = append(out, s.row())
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}
