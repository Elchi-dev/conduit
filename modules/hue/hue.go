// Package hue works with a Philips Hue bridge through its local CLIP v2 API:
// lights (on/off, brightness, colour and colour temperature), rooms and
// zones, scenes, sensors and batteries. Every change can be previewed, and
// undo puts back the lights it touched as they were.
package hue

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one bridge.
type Config struct {
	URL            string `json:"url"`            // https://192.168.1.20
	ApplicationKey string `json:"applicationKey"` // secret://
	BridgeID       string `json:"bridgeId"`       // 16 hex digits, the certificate's common name
	Fingerprint    string `json:"fingerprint"`    // SHA-256 of the bridge's certificate
}

type conn struct {
	api      *rest.Client
	bridgeID string // lowercase, "" when only the fingerprint is pinned
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
}

// New returns the Hue module.
func New() *Module { return &Module{} }

// pace is the gap between two light commands: the bridge asks for no more
// than about ten a second.
var pace = 100 * time.Millisecond

const maxLights = 100

var (
	uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	bridgeIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
	hexColorRe = regexp.MustCompile(`^#?[0-9a-fA-F]{6}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	ref := func(what string) string {
		return `{"type":"string","maxLength":200,"description":"The ` + what + `'s id or its exact name"}`
	}
	look := `"on":{"type":"boolean"},"brightness":{"type":"number","minimum":0,"maximum":100,"description":"Percent"},` +
		`"transitionMs":{"type":"integer","minimum":0,"maximum":60000}`
	colour := `,"color":{"type":"string","description":"An RGB colour like #ff8800"},` +
		`"xy":{"type":"object","properties":{"x":{"type":"number","minimum":0,"maximum":1},"y":{"type":"number","minimum":0,"maximum":1}}},` +
		`"kelvin":{"type":"integer","minimum":2000,"maximum":6500,"description":"White colour temperature"},` +
		`"mirek":{"type":"integer","minimum":153,"maximum":500}`
	state := `{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"on":{"type":"boolean"},"brightness":{"type":"number"},` +
		`"xy":{"type":"object","properties":{"x":{"type":"number"},"y":{"type":"number"}}},"mirek":{"type":"integer"}}}`
	room := `"room":{"type":"string","maxLength":200,"description":"Only this room or zone (id or name)"}`
	return sdk.Manifest{
		ID: "hue", Name: "Philips Hue", Version: "0.1.0", Category: "Smart home", Icon: "lamp",
		Description: "A Philips Hue bridge: lights, rooms and zones, scenes, sensors and batteries, with previews and undo.",
		Presets:     []string{"homelab", "gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","applicationKey"],"properties":{
			"url":{"type":"string","description":"The bridge, e.g. https://192.168.1.20"},
			"applicationKey":{"type":"string","x-secret":true,"description":"The application key (hue-application-key) made by pressing the bridge's link button; see the docs"},
			"bridgeId":{"type":"string","description":"The bridge id (16 hex digits, like 001788fffe123456): the bridge's certificate must carry it"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the bridge's certificate (stronger than the bridge id alone)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "lights", Title: "Lights", Description: "Every light with its room, on/off, brightness, colour or colour temperature and whether the bridge can reach it.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + room + `}}`)},
			{Name: "rooms", Title: "Rooms and zones", Description: "Rooms and zones with their lights and whether any is on.", Risk: sdk.RiskRead},
			{Name: "scenes", Title: "Scenes", Description: "Scenes with their room or zone and whether one is active.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + room + `}}`)},
			{Name: "sensors", Title: "Sensors", Description: "Motion, temperature, light level, contact and battery of each sensor device.", Risk: sdk.RiskRead},
			{Name: "batteries", Title: "Batteries", Description: "Battery-powered devices by charge, lowest first, with the bridge's low/critical state.", Risk: sdk.RiskRead},
			{Name: "set_light", Title: "Set a light", Description: "Turns one light on or off and/or sets brightness, an RGB colour, xy or a colour temperature (changing the look turns it on unless on is false). Undo puts the light back as it was.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["light"],"properties":{"light":` + ref("light") + `,` + look + colour + `}}`)},
			{Name: "set_group", Title: "Set a room or zone", Description: "Turns all lights of a room or zone on or off and/or sets their brightness. Undo puts each light back as it was.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["group"],"properties":{"group":` + ref("room or zone") + `,` + look + `}}`)},
			{Name: "activate_scene", Title: "Activate a scene", Description: "Recalls a scene. The preview lists each light's change; undo puts every light of the scene back as it was.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["scene"],"properties":{"scene":` + ref("scene") + `,` + room + `}}`)},
			{Name: "restore_lights", Title: "Restore lights", Description: "Sets lights to given states (what undo of the other actions sends). Undo restores what they were before.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["lights"],"properties":{"lights":{"type":"array","minItems":1,"maxItems":100,"items":` + state + `}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("the bridge's address is like https://192.168.1.20 (the v2 API is HTTPS only)")
	}
	if !strings.HasPrefix(c.ApplicationKey, "secret://") {
		return errors.New("store the application key in the vault and enter its secret:// reference")
	}
	bid := strings.ToLower(strings.TrimSpace(c.BridgeID))
	if bid != "" && !bridgeIDRe.MatchString(bid) {
		return errors.New("the bridge id is 16 hex digits, like 001788fffe123456")
	}
	fp := ""
	if strings.TrimSpace(c.Fingerprint) != "" {
		if fp, err = tlspin.Normalize(c.Fingerprint); err != nil {
			return err
		}
	}
	if bid == "" && fp == "" {
		return errors.New("enter the bridge id or the certificate's fingerprint: the bridge's certificate isn't signed by a public authority, so Conduit checks it against one of them")
	}
	tr := sdk.Transport(h)
	tr.TLSClientConfig = pinned(fp, bid)
	ref := c.ApplicationKey
	api := rest.New(u.Scheme+"://"+u.Host+"/clip/v2", func(ctx context.Context, r *http.Request) error {
		key, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("hue-application-key", key)
		return nil
	})
	// The key travels in its own header, which Go forwards on redirects.
	api.HTTP = rest.SameHostOnly(&http.Client{Timeout: 15 * time.Second, Transport: tr})
	m.set.Put(id, &conn{api: api, bridgeID: bid})
	return nil
}

// pinned checks the bridge's certificate: its SHA-256 fingerprint when one
// is set, and its common name against the bridge id when that is set.
func pinned(fp, bid string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // replaced by the checks below
		VerifyPeerCertificate: func(certs [][]byte, _ [][]*x509.Certificate) error {
			if len(certs) == 0 {
				return errors.New("the bridge sent no certificate")
			}
			if fp != "" {
				sum := sha256.Sum256(certs[0])
				if hex.EncodeToString(sum[:]) != fp {
					return errors.New("the bridge's certificate doesn't match the pinned fingerprint")
				}
			}
			if bid != "" {
				cert, err := x509.ParseCertificate(certs[0])
				if err != nil {
					return errors.New("the bridge's certificate can't be read")
				}
				if !strings.EqualFold(cert.Subject.CommonName, bid) {
					return fmt.Errorf("the certificate is for %q, not bridge %s", cert.Subject.CommonName, bid)
				}
			}
			return nil
		},
	}
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

type hueError struct {
	Description string `json:"description"`
}

func apiErr(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the bridge refused the application key (make one with the link button; see the docs)")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("the bridge doesn't know that resource (or this isn't a Hue bridge with the v2 API)")
	case rest.IsStatus(err, http.StatusTooManyRequests), rest.IsStatus(err, http.StatusServiceUnavailable):
		return errors.New("the bridge is busy; try again in a moment")
	}
	return err
}

// get lists one resource type.
func (c *conn) get(ctx context.Context, typ string, out any) error {
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []hueError      `json:"errors"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/resource/"+typ, nil, nil, &env); err != nil {
		return apiErr(err)
	}
	if len(env.Errors) > 0 {
		return fmt.Errorf("the bridge: %s", rest.Redact(env.Errors[0].Description))
	}
	if len(env.Data) == 0 {
		return errors.New("unexpected answer from the bridge")
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return errors.New("unexpected answer from the bridge")
	}
	return nil
}

// put changes one resource; typ is a constant and id a checked UUID.
func (c *conn) put(ctx context.Context, typ, id string, body any) error {
	if !uuidRe.MatchString(id) {
		return fmt.Errorf("%q isn't a Hue resource id", id)
	}
	var env struct {
		Errors []hueError `json:"errors"`
	}
	if _, err := c.api.Do(ctx, http.MethodPut, "/resource/"+typ+"/"+id, nil, body, &env); err != nil {
		if e := (*rest.Error)(nil); errors.As(err, &e) && e.Status == http.StatusBadRequest {
			return fmt.Errorf("the bridge refused the change: %s", e.Message)
		}
		return apiErr(err)
	}
	if len(env.Errors) > 0 {
		return fmt.Errorf("the bridge refused the change: %s", rest.Redact(env.Errors[0].Description))
	}
	return nil
}

type rid struct {
	RID   string `json:"rid"`
	RType string `json:"rtype"`
}

type meta struct {
	Name      string `json:"name"`
	Archetype string `json:"archetype"`
}

type xy struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type light struct {
	ID       string `json:"id"`
	Owner    rid    `json:"owner"`
	Metadata meta   `json:"metadata"`
	On       struct {
		On bool `json:"on"`
	} `json:"on"`
	Dimming *struct {
		Brightness float64 `json:"brightness"`
	} `json:"dimming"`
	ColorTemperature *struct {
		Mirek       *int `json:"mirek"`
		MirekValid  bool `json:"mirek_valid"`
		MirekSchema struct {
			Min int `json:"mirek_minimum"`
			Max int `json:"mirek_maximum"`
		} `json:"mirek_schema"`
	} `json:"color_temperature"`
	Color *struct {
		XY xy `json:"xy"`
	} `json:"color"`
}

type group struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // room, zone
	Metadata meta   `json:"metadata"`
	Children []rid  `json:"children"`
	Services []rid  `json:"services"`
}

type groupedLight struct {
	ID string `json:"id"`
	On struct {
		On bool `json:"on"`
	} `json:"on"`
	Dimming *struct {
		Brightness float64 `json:"brightness"`
	} `json:"dimming"`
}

type scene struct {
	ID       string `json:"id"`
	Metadata meta   `json:"metadata"`
	Group    rid    `json:"group"`
	Actions  []struct {
		Target rid         `json:"target"`
		Action sceneAction `json:"action"`
	} `json:"actions"`
	Status struct {
		Active string `json:"active"`
	} `json:"status"`
}

type sceneAction struct {
	On *struct {
		On bool `json:"on"`
	} `json:"on"`
	Dimming *struct {
		Brightness float64 `json:"brightness"`
	} `json:"dimming"`
	Color *struct {
		XY xy `json:"xy"`
	} `json:"color"`
	ColorTemperature *struct {
		Mirek *int `json:"mirek"`
	} `json:"color_temperature"`
}

type device struct {
	ID          string `json:"id"`
	Metadata    meta   `json:"metadata"`
	ProductData struct {
		ModelID     string `json:"model_id"`
		ProductName string `json:"product_name"`
	} `json:"product_data"`
	Services []rid `json:"services"`
}

// home is what most actions need: lights, devices and groups.
type home struct {
	lights  []light
	devices map[string]device
	groups  []group
	reach   map[string]string // device id → zigbee status
}

func (c *conn) home(ctx context.Context, withGroups bool) (*home, error) {
	h := &home{devices: map[string]device{}, reach: map[string]string{}}
	if err := c.get(ctx, "light", &h.lights); err != nil {
		return nil, err
	}
	var ds []device
	if err := c.get(ctx, "device", &ds); err != nil {
		return nil, err
	}
	for _, d := range ds {
		h.devices[d.ID] = d
	}
	var zc []struct {
		Owner  rid    `json:"owner"`
		Status string `json:"status"`
	}
	if err := c.get(ctx, "zigbee_connectivity", &zc); err == nil {
		for _, z := range zc {
			h.reach[z.Owner.RID] = z.Status
		}
	}
	if withGroups {
		for _, typ := range []string{"room", "zone"} {
			var gs []group
			if err := c.get(ctx, typ, &gs); err != nil {
				return nil, err
			}
			for i := range gs {
				gs[i].Type = typ
			}
			h.groups = append(h.groups, gs...)
		}
	}
	return h, nil
}

// lightsOf returns the ids of a room's or zone's lights.
func (h *home) lightsOf(g group) []string {
	seen := map[string]bool{}
	var ids []string
	add := func(id string) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, ch := range g.Children {
		switch ch.RType {
		case "light":
			add(ch.RID)
		case "device":
			for _, s := range h.devices[ch.RID].Services {
				if s.RType == "light" {
					add(s.RID)
				}
			}
		}
	}
	return ids
}

func (h *home) light(id string) *light {
	for i := range h.lights {
		if h.lights[i].ID == id {
			return &h.lights[i]
		}
	}
	return nil
}

// roomOf names the room a light's device is in.
func (h *home) roomOf(l light) string {
	for _, g := range h.groups {
		if g.Type != "room" {
			continue
		}
		for _, id := range h.lightsOf(g) {
			if id == l.ID {
				return g.Metadata.Name
			}
		}
	}
	return ""
}

// resolve finds one item by id or exact (case-insensitive) name.
func resolve[T any](items []T, ref, what string, id func(T) string, name func(T) string) (T, error) {
	var zero T
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return zero, fmt.Errorf("say which %s (its id or name)", what)
	}
	if len(ref) > 200 {
		return zero, fmt.Errorf("that %s name is too long", what)
	}
	if uuidRe.MatchString(ref) {
		for _, it := range items {
			if id(it) == ref {
				return it, nil
			}
		}
		return zero, fmt.Errorf("there's no %s with id %s", what, ref)
	}
	var hits []T
	for _, it := range items {
		if strings.EqualFold(name(it), ref) {
			hits = append(hits, it)
		}
	}
	switch len(hits) {
	case 0:
		return zero, fmt.Errorf("there's no %s named %q", what, ref)
	case 1:
		return hits[0], nil
	}
	var ids []string
	for _, it := range hits {
		ids = append(ids, id(it))
	}
	return zero, fmt.Errorf("%d %ss are named %q; use the id (%s)", len(hits), what, ref, strings.Join(ids, ", "))
}

func lightID(l light) string   { return l.ID }
func lightName(l light) string { return l.Metadata.Name }
func groupID(g group) string   { return g.ID }
func groupName(g group) string { return g.Metadata.Name }

// state is a light's look, as restore_lights takes it.
type state struct {
	ID         string   `json:"id"`
	On         *bool    `json:"on,omitempty"`
	Brightness *float64 `json:"brightness,omitempty"`
	XY         *xy      `json:"xy,omitempty"`
	Mirek      *int     `json:"mirek,omitempty"`
}

func snapshot(l light) state {
	on := l.On.On
	s := state{ID: l.ID, On: &on}
	if l.Dimming != nil {
		b := l.Dimming.Brightness
		s.Brightness = &b
	}
	switch {
	case l.ColorTemperature != nil && l.ColorTemperature.MirekValid && l.ColorTemperature.Mirek != nil:
		mk := *l.ColorTemperature.Mirek
		s.Mirek = &mk
	case l.Color != nil:
		c := l.Color.XY
		s.XY = &c
	}
	return s
}

// apply returns s changed by n (fields n leaves out stay).
func (s state) apply(n state) state {
	if n.On != nil {
		s.On = n.On
	}
	if n.Brightness != nil {
		s.Brightness = n.Brightness
	}
	if n.XY != nil {
		s.XY, s.Mirek = n.XY, nil
	}
	if n.Mirek != nil {
		s.Mirek, s.XY = n.Mirek, nil
	}
	return s
}

func (s state) view() map[string]any {
	e := map[string]any{}
	if s.On != nil {
		e["on"] = *s.On
	}
	if s.Brightness != nil {
		e["brightness"] = round(*s.Brightness, 1)
	}
	if s.XY != nil {
		e["xy"] = *s.XY
	}
	if s.Mirek != nil && *s.Mirek > 0 {
		e["kelvin"] = 1000000 / *s.Mirek
	}
	return e
}

// body is the light PUT for a state.
func (s state) body(transition *int) map[string]any {
	b := map[string]any{}
	if s.On != nil {
		b["on"] = map[string]bool{"on": *s.On}
	}
	if s.Brightness != nil {
		b["dimming"] = map[string]float64{"brightness": *s.Brightness}
	}
	if s.XY != nil {
		b["color"] = map[string]xy{"xy": *s.XY}
	}
	if s.Mirek != nil {
		b["color_temperature"] = map[string]int{"mirek": *s.Mirek}
	}
	if transition != nil {
		b["dynamics"] = map[string]int{"duration": *transition}
	}
	return b
}

// check validates a state against what the light can do.
func (s state) check(l light) error {
	name := l.Metadata.Name
	if s.Brightness != nil {
		if l.Dimming == nil {
			return fmt.Errorf("%s can't be dimmed", name)
		}
		if *s.Brightness < 0 || *s.Brightness > 100 || math.IsNaN(*s.Brightness) {
			return errors.New("brightness is a percentage between 0 and 100")
		}
	}
	if s.XY != nil {
		if l.Color == nil {
			return fmt.Errorf("%s has no colour (try kelvin)", name)
		}
		if s.XY.X < 0 || s.XY.X > 1 || s.XY.Y < 0 || s.XY.Y > 1 || math.IsNaN(s.XY.X) || math.IsNaN(s.XY.Y) {
			return errors.New("x and y are between 0 and 1")
		}
	}
	if s.Mirek != nil {
		ct := l.ColorTemperature
		if ct == nil {
			return fmt.Errorf("%s has no colour temperature", name)
		}
		lo, hi := ct.MirekSchema.Min, ct.MirekSchema.Max
		if lo == 0 || hi == 0 {
			lo, hi = 153, 500
		}
		if *s.Mirek < lo || *s.Mirek > hi {
			return fmt.Errorf("%s takes colour temperatures from %d K to %d K", name, 1000000/hi, 1000000/lo)
		}
	}
	return nil
}

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

// rgbToXY converts an sRGB colour to CIE xy with the wide-gamut matrix
// Philips documents; the bridge maps it into each lamp's gamut.
func rgbToXY(s string) (xy, error) {
	if !hexColorRe.MatchString(s) {
		return xy{}, errors.New("the colour is like #ff8800")
	}
	b, _ := hex.DecodeString(strings.TrimPrefix(s, "#"))
	lin := func(v byte) float64 {
		f := float64(v) / 255
		if f > 0.04045 {
			return math.Pow((f+0.055)/1.055, 2.4)
		}
		return f / 12.92
	}
	r, g, bl := lin(b[0]), lin(b[1]), lin(b[2])
	X := r*0.664511 + g*0.154324 + bl*0.162028
	Y := r*0.283881 + g*0.668433 + bl*0.047685
	Z := r*0.000088 + g*0.072310 + bl*0.986039
	if X+Y+Z == 0 {
		return xy{}, errors.New("black isn't a colour a light can show; turn it off instead (on: false)")
	}
	return xy{X: round(X/(X+Y+Z), 4), Y: round(Y/(X+Y+Z), 4)}, nil
}

type input struct {
	Light        string   `json:"light"`
	Group        string   `json:"group"`
	Scene        string   `json:"scene"`
	Room         string   `json:"room"`
	On           *bool    `json:"on"`
	Brightness   *float64 `json:"brightness"`
	Color        string   `json:"color"`
	XY           *xy      `json:"xy"`
	Kelvin       *int     `json:"kelvin"`
	Mirek        *int     `json:"mirek"`
	TransitionMs *int     `json:"transitionMs"`
	Lights       []state  `json:"lights"`
}

// wanted turns the input into a change, before it's checked against a light.
func (p input) wanted(colour bool) (state, error) {
	var n state
	n.On, n.Brightness = p.On, p.Brightness
	if p.Brightness != nil && (*p.Brightness < 0 || *p.Brightness > 100 || math.IsNaN(*p.Brightness)) {
		return n, errors.New("brightness is a percentage between 0 and 100")
	}
	if p.TransitionMs != nil && (*p.TransitionMs < 0 || *p.TransitionMs > 60000) {
		return n, errors.New("transitionMs is between 0 and 60000")
	}
	set := 0
	for _, b := range []bool{p.Color != "", p.XY != nil, p.Kelvin != nil, p.Mirek != nil} {
		if b {
			set++
		}
	}
	if set > 0 && !colour {
		return n, errors.New("a room or zone takes on and brightness; set colours per light or with a scene")
	}
	if set > 1 {
		return n, errors.New("give one of color, xy, kelvin or mirek")
	}
	switch {
	case p.Color != "":
		c, err := rgbToXY(p.Color)
		if err != nil {
			return n, err
		}
		n.XY = &c
	case p.XY != nil:
		c := *p.XY
		if c.X < 0 || c.X > 1 || c.Y < 0 || c.Y > 1 || math.IsNaN(c.X) || math.IsNaN(c.Y) {
			return n, errors.New("x and y are between 0 and 1")
		}
		n.XY = &c
	case p.Kelvin != nil:
		if *p.Kelvin < 2000 || *p.Kelvin > 6500 {
			return n, errors.New("kelvin is between 2000 and 6500")
		}
		mk := int(math.Round(1000000 / float64(*p.Kelvin)))
		n.Mirek = &mk
	case p.Mirek != nil:
		if *p.Mirek < 153 || *p.Mirek > 500 {
			return n, errors.New("mirek is between 153 and 500")
		}
		mk := *p.Mirek
		n.Mirek = &mk
	}
	if n.On == nil && n.Brightness == nil && n.XY == nil && n.Mirek == nil {
		return n, errors.New("say what to change: on, brightness or a colour")
	}
	// Changing the look of a light that's off would do nothing visible.
	if n.On == nil {
		t := true
		n.On = &t
	}
	return n, nil
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// restore sets lights to states, pausing between commands.
func (c *conn) restore(ctx context.Context, sts []state) error {
	for i, s := range sts {
		if i > 0 && pace > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pace):
			}
		}
		if err := c.put(ctx, "light", s.ID, s.body(nil)); err != nil {
			return fmt.Errorf("light %s: %w", s.ID, err)
		}
	}
	return nil
}

func undoTo(before []state, what string) *sdk.Undo {
	if len(before) == 0 {
		return nil
	}
	return sdk.UndoWith("restore_lights", map[string]any{"lights": before}, what)
}

func lightOut(h *home, l light) map[string]any {
	e := map[string]any{"id": l.ID, "name": l.Metadata.Name, "on": l.On.On}
	if l.Metadata.Archetype != "" {
		e["type"] = l.Metadata.Archetype
	}
	if r := h.roomOf(l); r != "" {
		e["room"] = r
	}
	s := snapshot(l)
	for k, v := range s.view() {
		if k != "on" {
			e[k] = v
		}
	}
	if st, ok := h.reach[l.Owner.RID]; ok {
		e["reachable"] = st == "connected"
	}
	if d, ok := h.devices[l.Owner.RID]; ok && d.ProductData.ProductName != "" {
		e["product"] = d.ProductData.ProductName
	}
	return e
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "lights":
		h, err := c.home(ctx, true)
		if err != nil {
			return sdk.Result{}, err
		}
		only := map[string]bool(nil)
		if p.Room != "" {
			g, err := resolve(h.groups, p.Room, "room or zone", groupID, groupName)
			if err != nil {
				return sdk.Result{}, err
			}
			only = map[string]bool{}
			for _, id := range h.lightsOf(g) {
				only[id] = true
			}
		}
		out := []map[string]any{}
		for _, l := range h.lights {
			if only == nil || only[l.ID] {
				out = append(out, lightOut(h, l))
			}
		}
		sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]["name"]) < fmt.Sprint(out[j]["name"]) })
		return sdk.JSON(out)

	case "rooms":
		h, err := c.home(ctx, true)
		if err != nil {
			return sdk.Result{}, err
		}
		var gl []groupedLight
		if err := c.get(ctx, "grouped_light", &gl); err != nil {
			return sdk.Result{}, err
		}
		gls := map[string]groupedLight{}
		for _, g := range gl {
			gls[g.ID] = g
		}
		out := []map[string]any{}
		for _, g := range h.groups {
			names := []string{}
			on := 0
			for _, id := range h.lightsOf(g) {
				if l := h.light(id); l != nil {
					names = append(names, l.Metadata.Name)
					if l.On.On {
						on++
					}
				}
			}
			sort.Strings(names)
			e := map[string]any{"id": g.ID, "name": g.Metadata.Name, "kind": g.Type, "lights": names, "lightsOn": on}
			if g.Metadata.Archetype != "" {
				e["archetype"] = g.Metadata.Archetype
			}
			for _, s := range g.Services {
				if x, ok := gls[s.RID]; ok && s.RType == "grouped_light" {
					e["on"] = x.On.On
					if x.Dimming != nil {
						e["brightness"] = round(x.Dimming.Brightness, 1)
					}
				}
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "scenes":
		var ss []scene
		if err := c.get(ctx, "scene", &ss); err != nil {
			return sdk.Result{}, err
		}
		h, err := c.home(ctx, true)
		if err != nil {
			return sdk.Result{}, err
		}
		names := map[string]string{}
		for _, g := range h.groups {
			names[g.ID] = g.Metadata.Name
		}
		only := ""
		if p.Room != "" {
			g, err := resolve(h.groups, p.Room, "room or zone", groupID, groupName)
			if err != nil {
				return sdk.Result{}, err
			}
			only = g.ID
		}
		out := []map[string]any{}
		for _, s := range ss {
			if only != "" && s.Group.RID != only {
				continue
			}
			active := s.Status.Active
			if active == "" {
				active = "inactive"
			}
			out = append(out, map[string]any{"id": s.ID, "name": s.Metadata.Name, "room": names[s.Group.RID], "lights": len(s.Actions), "active": active})
		}
		sort.Slice(out, func(i, j int) bool {
			a, b := fmt.Sprint(out[i]["room"], "\x00", out[i]["name"]), fmt.Sprint(out[j]["room"], "\x00", out[j]["name"])
			return a < b
		})
		return sdk.JSON(out)

	case "sensors", "batteries":
		return c.sensors(ctx, call.Action == "batteries")

	case "set_light":
		h, err := c.home(ctx, false)
		if err != nil {
			return sdk.Result{}, err
		}
		l, err := resolve(h.lights, p.Light, "light", lightID, lightName)
		if err != nil {
			return sdk.Result{}, err
		}
		n, err := p.wanted(true)
		if err != nil {
			return sdk.Result{}, err
		}
		if err := n.check(l); err != nil {
			return sdk.Result{}, err
		}
		before := snapshot(l)
		after := before.apply(n)
		n.ID = l.ID
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: describe(l.Metadata.Name, n), Changes: []sdk.Change{{Target: "light " + l.Metadata.Name, Op: "update",
				Before: mustJSON(before.view()), After: mustJSON(after.view())}}}}, nil
		}
		if err := c.put(ctx, "light", l.ID, n.body(p.TransitionMs)); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"light": l.Metadata.Name, "id": l.ID, "now": after.view()})
		res.Undo = undoTo([]state{before}, "Put "+l.Metadata.Name+" back")
		return res, err

	case "set_group":
		h, err := c.home(ctx, true)
		if err != nil {
			return sdk.Result{}, err
		}
		g, err := resolve(h.groups, p.Group, "room or zone", groupID, groupName)
		if err != nil {
			return sdk.Result{}, err
		}
		n, err := p.wanted(false)
		if err != nil {
			return sdk.Result{}, err
		}
		glID := ""
		for _, s := range g.Services {
			if s.RType == "grouped_light" {
				glID = s.RID
			}
		}
		if glID == "" {
			return sdk.Result{}, fmt.Errorf("%s has no lights to control", g.Metadata.Name)
		}
		var before []state
		var changes []sdk.Change
		for _, id := range h.lightsOf(g) {
			l := h.light(id)
			if l == nil {
				continue
			}
			b := snapshot(*l)
			nb := n
			if l.Dimming == nil {
				nb.Brightness = nil // the bridge leaves on/off-only lights' brightness alone
			}
			before = append(before, b)
			changes = append(changes, sdk.Change{Target: "light " + l.Metadata.Name, Op: "update", Before: mustJSON(b.view()), After: mustJSON(b.apply(nb).view())})
		}
		if len(before) > maxLights {
			return sdk.Result{}, fmt.Errorf("%s has more than %d lights", g.Metadata.Name, maxLights)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: describe(g.Metadata.Name, n), Changes: changes}}, nil
		}
		if err := c.put(ctx, "grouped_light", glID, n.body(p.TransitionMs)); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"group": g.Metadata.Name, "id": g.ID, "lights": len(before), "now": n.view()})
		res.Undo = undoTo(before, fmt.Sprintf("Put the %d lights of %s back", len(before), g.Metadata.Name))
		return res, err

	case "activate_scene":
		var ss []scene
		if err := c.get(ctx, "scene", &ss); err != nil {
			return sdk.Result{}, err
		}
		h, err := c.home(ctx, p.Room != "")
		if err != nil {
			return sdk.Result{}, err
		}
		if p.Room != "" {
			g, err := resolve(h.groups, p.Room, "room or zone", groupID, groupName)
			if err != nil {
				return sdk.Result{}, err
			}
			var in []scene
			for _, s := range ss {
				if s.Group.RID == g.ID {
					in = append(in, s)
				}
			}
			ss = in
		}
		s, err := resolve(ss, p.Scene, "scene", func(s scene) string { return s.ID }, func(s scene) string { return s.Metadata.Name })
		if err != nil {
			return sdk.Result{}, err
		}
		var before []state
		var changes []sdk.Change
		for _, a := range s.Actions {
			l := h.light(a.Target.RID)
			if a.Target.RType != "light" || l == nil {
				continue
			}
			b := snapshot(*l)
			before = append(before, b)
			changes = append(changes, sdk.Change{Target: "light " + l.Metadata.Name, Op: "update", Before: mustJSON(b.view()), After: mustJSON(b.apply(fromScene(a.Action)).view())})
		}
		if len(before) > maxLights {
			return sdk.Result{}, fmt.Errorf("the scene has more than %d lights", maxLights)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Activate the scene %s (%d lights)", s.Metadata.Name, len(before)), Changes: changes}}, nil
		}
		if err := c.put(ctx, "scene", s.ID, map[string]any{"recall": map[string]string{"action": "active"}}); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"scene": s.Metadata.Name, "id": s.ID, "lights": len(before)})
		res.Undo = undoTo(before, "Put the lights back as they were before "+s.Metadata.Name)
		return res, err

	case "restore_lights":
		if len(p.Lights) == 0 || len(p.Lights) > maxLights {
			return sdk.Result{}, fmt.Errorf("give between 1 and %d lights", maxLights)
		}
		h, err := c.home(ctx, false)
		if err != nil {
			return sdk.Result{}, err
		}
		var before []state
		var changes []sdk.Change
		seen := map[string]bool{}
		for _, s := range p.Lights {
			if !uuidRe.MatchString(s.ID) {
				return sdk.Result{}, fmt.Errorf("%q isn't a light id", s.ID)
			}
			if seen[s.ID] {
				return sdk.Result{}, fmt.Errorf("light %s is listed twice", s.ID)
			}
			seen[s.ID] = true
			l := h.light(s.ID)
			if l == nil {
				return sdk.Result{}, fmt.Errorf("there's no light with id %s", s.ID)
			}
			if s.XY != nil && s.Mirek != nil {
				return sdk.Result{}, fmt.Errorf("light %s: give xy or mirek, not both", l.Metadata.Name)
			}
			if err := s.check(*l); err != nil {
				return sdk.Result{}, err
			}
			b := snapshot(*l)
			before = append(before, b)
			changes = append(changes, sdk.Change{Target: "light " + l.Metadata.Name, Op: "update", Before: mustJSON(b.view()), After: mustJSON(b.apply(s).view())})
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Set %d light(s) back", len(p.Lights)), Changes: changes}}, nil
		}
		if err := c.restore(ctx, p.Lights); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"restored": len(p.Lights)})
		res.Undo = undoTo(before, fmt.Sprintf("Put the %d light(s) back again", len(before)))
		return res, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func fromScene(a sceneAction) state {
	var s state
	if a.On != nil {
		on := a.On.On
		s.On = &on
	}
	if a.Dimming != nil {
		b := a.Dimming.Brightness
		s.Brightness = &b
	}
	if a.Color != nil {
		c := a.Color.XY
		s.XY = &c
	}
	if a.ColorTemperature != nil && a.ColorTemperature.Mirek != nil {
		mk := *a.ColorTemperature.Mirek
		s.Mirek = &mk
	}
	return s
}

func describe(name string, n state) string {
	var parts []string
	if n.On != nil && !*n.On {
		return "Turn off " + name
	}
	if n.Brightness != nil {
		parts = append(parts, fmt.Sprintf("brightness %g%%", round(*n.Brightness, 1)))
	}
	if n.XY != nil {
		parts = append(parts, fmt.Sprintf("colour xy %.4g,%.4g", n.XY.X, n.XY.Y))
	}
	if n.Mirek != nil {
		parts = append(parts, fmt.Sprintf("%d K", 1000000 / *n.Mirek))
	}
	if len(parts) == 0 {
		return "Turn on " + name
	}
	return "Turn on " + name + " at " + strings.Join(parts, ", ")
}

// sensors reads motion, temperature, light level, contact and battery
// services and groups them by device.
func (c *conn) sensors(ctx context.Context, batteriesOnly bool) (sdk.Result, error) {
	var ds []device
	if err := c.get(ctx, "device", &ds); err != nil {
		return sdk.Result{}, err
	}
	byID := map[string]map[string]any{}
	order := []string{}
	entry := func(owner string) map[string]any {
		if e, ok := byID[owner]; ok {
			return e
		}
		e := map[string]any{"device": owner}
		for _, d := range ds {
			if d.ID == owner {
				e["name"] = d.Metadata.Name
				if d.ProductData.ProductName != "" {
					e["product"] = d.ProductData.ProductName
				}
			}
		}
		byID[owner] = e
		order = append(order, owner)
		return e
	}
	var power []struct {
		Owner      rid `json:"owner"`
		PowerState struct {
			BatteryState string   `json:"battery_state"`
			BatteryLevel *float64 `json:"battery_level"`
		} `json:"power_state"`
	}
	if err := c.get(ctx, "device_power", &power); err != nil {
		return sdk.Result{}, err
	}
	for _, p := range power {
		if p.PowerState.BatteryLevel == nil {
			continue // mains powered
		}
		e := entry(p.Owner.RID)
		e["battery"] = *p.PowerState.BatteryLevel
		if p.PowerState.BatteryState != "" {
			e["batteryState"] = p.PowerState.BatteryState
		}
	}
	if batteriesOnly {
		out := []map[string]any{}
		for _, id := range order {
			out = append(out, byID[id])
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["battery"].(float64) < out[j]["battery"].(float64) })
		return sdk.JSON(out)
	}
	var motion []struct {
		Owner   rid   `json:"owner"`
		Enabled *bool `json:"enabled"`
		Motion  struct {
			Motion       bool `json:"motion"`
			MotionValid  bool `json:"motion_valid"`
			MotionReport *struct {
				Changed string `json:"changed"`
				Motion  bool   `json:"motion"`
			} `json:"motion_report"`
		} `json:"motion"`
	}
	if err := c.get(ctx, "motion", &motion); err != nil {
		return sdk.Result{}, err
	}
	for _, s := range motion {
		e := entry(s.Owner.RID)
		if s.Enabled != nil && !*s.Enabled {
			e["motionEnabled"] = false
		}
		switch {
		case s.Motion.MotionReport != nil:
			e["motion"], e["motionChanged"] = s.Motion.MotionReport.Motion, s.Motion.MotionReport.Changed
		case s.Motion.MotionValid:
			e["motion"] = s.Motion.Motion
		}
	}
	var temps []struct {
		Owner       rid `json:"owner"`
		Temperature struct {
			Temperature      float64 `json:"temperature"`
			TemperatureValid bool    `json:"temperature_valid"`
			Report           *struct {
				Temperature float64 `json:"temperature"`
			} `json:"temperature_report"`
		} `json:"temperature"`
	}
	if err := c.get(ctx, "temperature", &temps); err != nil {
		return sdk.Result{}, err
	}
	for _, s := range temps {
		e := entry(s.Owner.RID)
		switch {
		case s.Temperature.Report != nil:
			e["temperatureC"] = round(s.Temperature.Report.Temperature, 1)
		case s.Temperature.TemperatureValid:
			e["temperatureC"] = round(s.Temperature.Temperature, 1)
		}
	}
	var levels []struct {
		Owner rid `json:"owner"`
		Light struct {
			LightLevel      int  `json:"light_level"`
			LightLevelValid bool `json:"light_level_valid"`
			Report          *struct {
				LightLevel int `json:"light_level"`
			} `json:"light_level_report"`
		} `json:"light"`
	}
	if err := c.get(ctx, "light_level", &levels); err != nil {
		return sdk.Result{}, err
	}
	for _, s := range levels {
		ll, ok := s.Light.LightLevel, s.Light.LightLevelValid
		if s.Light.Report != nil {
			ll, ok = s.Light.Report.LightLevel, true
		}
		if ok {
			// light_level is 10000·log10(lux)+1.
			entry(s.Owner.RID)["lux"] = round(math.Pow(10, float64(ll-1)/10000), 1)
		}
	}
	var contacts []struct {
		Owner         rid `json:"owner"`
		ContactReport *struct {
			State   string `json:"state"`
			Changed string `json:"changed"`
		} `json:"contact_report"`
	}
	// Contact sensors arrived with later bridge software; an older bridge
	// doesn't know the resource.
	if err := c.get(ctx, "contact", &contacts); err == nil {
		for _, s := range contacts {
			if s.ContactReport != nil {
				e := entry(s.Owner.RID)
				e["contact"], e["contactChanged"] = s.ContactReport.State, s.ContactReport.Changed
			}
		}
	}
	out := []map[string]any{}
	for _, id := range order {
		out = append(out, byID[id])
	}
	sort.SliceStable(out, func(i, j int) bool { return fmt.Sprint(out[i]["name"]) < fmt.Sprint(out[j]["name"]) })
	return sdk.JSON(out)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var br []struct {
		BridgeID string `json:"bridge_id"`
	}
	if err := c.get(ctx, "bridge", &br); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if len(br) == 0 {
		return sdk.Health{Status: "down", Message: "unexpected answer from the bridge"}
	}
	if c.bridgeID != "" && !strings.EqualFold(br[0].BridgeID, c.bridgeID) {
		return sdk.Health{Status: "down", Message: fmt.Sprintf("this is bridge %s, not %s", br[0].BridgeID, c.bridgeID)}
	}
	var ls []light
	if err := c.get(ctx, "light", &ls); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("bridge %s · %d lights", br[0].BridgeID, len(ls))}
}
