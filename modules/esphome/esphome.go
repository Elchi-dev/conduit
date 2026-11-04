// Package esphome works with ESPHome devices through the REST API of their
// web_server component: the entities (found through the /events stream or
// listed in the settings) with their states, switches, lights and buttons.
// Restart, factory-reset, shutdown, safe-mode and firmware buttons and
// switches, and those that open, unlock or sound something (garage, gate,
// door, lock, valve, siren, alarm), are kept apart behind a destructive
// action.
package esphome

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one device.
type Config struct {
	URL      string `json:"url"`      // http://living-room.local
	Username string `json:"username"` // web_server auth, optional
	Password string `json:"password"` // secret://
	// Entities lists the device's entities as domain.object_id; empty
	// means they're found through the /events stream.
	Entities []string `json:"entities"`
	// CriticalEntities are switches and buttons (domain.object_id) that
	// mustn't be used by accident (a server's power, a gate); they're
	// treated like restart buttons.
	CriticalEntities   []string `json:"criticalEntities"`
	Fingerprint        string   `json:"fingerprint"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

type conn struct {
	api      *rest.Client
	plain    bool // a password goes over http
	entities []entityRef
	critical map[entityRef]bool
	// discover bounds the /events read.
	discover, quiet time.Duration
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
}

// New returns the ESPHome module.
func New() *Module { return &Module{} }

var (
	objectRe = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)
	// criticalName matches what restarts, resets, shuts down or reflashes
	// a device, or opens, unlocks, sounds or silences something, anywhere
	// in the object id (restart2, esp_reboot, factoryreset, garage_door):
	// a false match only means the destructive action.
	criticalName = regexp.MustCompile(`restart|reboot|reset|factory|shutdown|safe[_-]?mode|firmware|ota|update|flash|garage|gate|door|lock|valve|siren|alarm|silence|` + germanID)
	// germanID is the same in German, the app's other language, as ESPHome
	// writes it in an object id: lowercase, with an umlaut spelled out or
	// turned into _ (Haustür is haustuer or haust_r, Türöffner t_r_ffner).
	// Tor counts as a word or at the end of a compound (hoftor, tor_2), not
	// inside motor or monitor.
	germanID = `tuer|(^|[_-]|haus|hof|garten|keller|eingangs|terrassen|balkon|wohnungs|neben|hinter|vorder)t_{1,2}r|` +
		`(^|[_-])tor($|[_-]|[0-9]|antrieb)|(garten|hof|einfahrt|einfahrts|zufahrt|zufahrts|haus|eingangs|garagen)tor|` +
		`ffner|schloss|riegel|fenster|heiz|sirene|ventil|kamera|rauchmelder|sicherheit|bew(ae|_{1,2})?sserung`
	domains = map[string]bool{"sensor": true, "binary_sensor": true, "text_sensor": true, "switch": true, "light": true, "fan": true, "cover": true,
		"number": true, "select": true, "button": true, "lock": true, "climate": true, "valve": true, "text": true, "date": true, "time": true, "datetime": true,
		"event": true, "update": true, "alarm_control_panel": true, "media_player": true}
)

const maxEntities = 500

type entityRef struct{ Domain, ID string }

func (e entityRef) String() string { return e.Domain + "." + e.ID }

// parseRef reads domain.object_id (or the stream's domain-object_id).
func parseRef(s string) (entityRef, error) {
	s = strings.TrimSpace(s)
	d, id, ok := strings.Cut(s, ".")
	if !ok {
		d, id, ok = strings.Cut(s, "-")
	}
	if !ok || !domains[d] || !objectRe.MatchString(id) {
		return entityRef{}, fmt.Errorf("%q isn't an entity like switch.relay or sensor.temperature (the object id is lowercase letters, digits, _ and -)", s)
	}
	return entityRef{d, id}, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	ent := func(d string) string {
		return `"id":{"type":"string","maxLength":64,"description":"The ` + d + `'s object id, like relay (or ` + d + `.relay)"}`
	}
	return sdk.Manifest{
		ID: "esphome", Name: "ESPHome", Version: "0.1.0", Category: "Smart home", Icon: "chip",
		Description: "ESPHome devices through their web server: entities and sensor values, switches, lights and buttons; restart and reset buttons kept apart.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The device's web server, e.g. http://living-room.local"},
			"username":{"type":"string","description":"web_server auth username, if set"},
			"password":{"type":"string","x-secret":true,"description":"web_server auth password"},
			"entities":{"type":"array","items":{"type":"string"},"description":"The entities as domain.object_id (sensor.temperature, switch.relay); leave empty to find them through the device's event stream"},
			"criticalEntities":{"type":"array","items":{"type":"string"},"description":"Switches and buttons (domain.object_id) that need press_critical, like a server's power. Those whose object id contains restart, reboot, reset, factory, shutdown, safe_mode, firmware, ota, update, flash, garage, gate, door, lock, valve, siren, alarm or silence are critical without being listed."},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the device's certificate, for https"},
			"insecureSkipVerify":{"type":"boolean","default":false}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "entities", Title: "Entities", Description: "Every entity with its domain, name, state and value; critical switches and buttons are marked.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"domain":{"type":"string","description":"Only this domain, e.g. sensor"}}}`)},
			{Name: "state", Title: "Entity state", Description: "One entity's current state and value.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["entity"],"properties":{"entity":{"type":"string","description":"domain.object_id, e.g. sensor.temperature"}}}`)},
			{Name: "set_switch", Title: "Turn a switch on or off", Description: "Turns a switch on or off. Critical switches (restart, reset, shutdown, safe mode, firmware, garage, gate, door, lock, valve, siren, alarm, or listed in criticalEntities) are refused. Undo puts it back.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["id","on"],"properties":{` + ent("switch") + `,"on":{"type":"boolean"}}}`)},
			{Name: "set_light", Title: "Set a light", Description: "Turns a light on or off, with brightness (percent), an RGB colour and a transition. Undo puts it back.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + ent("light") + `,"on":{"type":"boolean","default":true},"brightness":{"type":"number","minimum":0,"maximum":100},"color":{"type":"string","description":"#rrggbb"},"transition":{"type":"number","minimum":0,"maximum":60,"description":"Seconds"}}}`)},
			{Name: "press_button", Title: "Press a button", Description: "Presses a button entity. Restart, reset, shutdown, safe-mode and firmware buttons, those that open, unlock or sound something (garage, gate, door, lock, valve, siren, alarm, silence), and those in criticalEntities, are refused (use press_critical). There's no undo.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + ent("button") + `}}`)},
			{Name: "press_critical", Title: "Press a critical button", Description: "Presses a critical button, or turns on a critical switch (restart, factory reset, shutdown, safe mode, firmware, garage, gate, door, lock, valve, siren, alarm, or in criticalEntities). The device may restart or lose its configuration, or open, unlock or sound what it drives.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + ent("button") + `,"domain":{"type":"string","enum":["button","switch"],"default":"button"}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("the device's address is like http://living-room.local")
	}
	user := c.Username
	if len(user) > 64 || strings.ContainsAny(user, ":\x00\r\n") {
		return errors.New("the username can't contain a colon or control characters")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	if (c.Password == "") != (user == "") {
		return errors.New("web_server auth takes both a username and a password")
	}
	if u.Scheme == "http" && (c.Fingerprint != "" || c.InsecureSkipVerify) {
		return errors.New("the certificate settings need an https address")
	}
	if len(c.Entities) > maxEntities || len(c.CriticalEntities) > maxEntities {
		return fmt.Errorf("list at most %d entities", maxEntities)
	}
	cn := &conn{critical: map[entityRef]bool{}, discover: 4 * time.Second, quiet: 700 * time.Millisecond}
	for _, s := range c.Entities {
		r, err := parseRef(s)
		if err != nil {
			return fmt.Errorf("entities: %w", err)
		}
		cn.entities = append(cn.entities, r)
	}
	for _, s := range c.CriticalEntities {
		r, err := parseRef(s)
		if err != nil {
			return fmt.Errorf("criticalEntities: %w", err)
		}
		cn.critical[r] = true
	}
	tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
	if err != nil {
		return err
	}
	tr := sdk.Transport(h)
	tr.TLSClientConfig = tc
	ref := c.Password
	cn.api = rest.New(u.Scheme+"://"+u.Host, func(ctx context.Context, r *http.Request) error {
		if ref == "" {
			return nil
		}
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, pw)
		return nil
	})
	// No client timeout: the event stream is bounded by its context; the
	// other requests get one each.
	cn.api.HTTP = rest.SameHostOnly(&http.Client{Transport: tr})
	cn.plain = ref != "" && u.Scheme == "http"
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) isCritical(r entityRef) bool {
	return c.critical[r] || ((r.Domain == "button" || r.Domain == "switch") && criticalName.MatchString(r.ID))
}

func apiErr(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("the device refused the username or password")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("the device has no such entity (or no web_server)")
	}
	return err
}

// entity is a state as the device reports it.
type entity struct {
	ID         string   `json:"id"` // domain-object_id
	Name       string   `json:"name"`
	State      any      `json:"state"`
	Value      any      `json:"value"`
	Brightness *float64 `json:"brightness"`
	Color      *rgb     `json:"color"`
	ColorMode  string   `json:"color_mode"`
}

type rgb struct {
	R int `json:"r"`
	G int `json:"g"`
	B int `json:"b"`
}

func (c *conn) get(ctx context.Context, r entityRef) (entity, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var e entity
	if _, err := c.api.Do(ctx, http.MethodGet, "/"+r.Domain+"/"+r.ID, nil, nil, &e); err != nil {
		return e, apiErr(err)
	}
	return e, nil
}

func (c *conn) post(ctx context.Context, r entityRef, verb string, q url.Values) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := c.api.Send(ctx, http.MethodPost, "/"+r.Domain+"/"+r.ID+"/"+verb, q, nil, nil)
	if err != nil {
		return apiErr(err)
	}
	io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("the device answered %s", res.Status)
	}
	return nil
}

func view(r entityRef, e entity, critical bool) map[string]any {
	out := map[string]any{"entity": r.String(), "domain": r.Domain, "id": r.ID}
	if e.Name != "" {
		out["name"] = e.Name
	}
	if e.State != nil {
		out["state"] = e.State
	}
	if e.Value != nil {
		out["value"] = e.Value
	}
	if e.Brightness != nil {
		out["brightness"] = math.Round(*e.Brightness / 255 * 100)
	}
	if e.Color != nil && e.ColorMode != "" && e.ColorMode != "brightness" && e.ColorMode != "onoff" && e.ColorMode != "color_temperature" {
		out["color"] = fmt.Sprintf("#%02x%02x%02x", e.Color.R, e.Color.G, e.Color.B)
	}
	if critical {
		out["critical"] = true
	}
	return out
}

// stream reads the /events stream for its state events: the device sends
// every entity's state when a client connects. It stops after a quiet gap,
// the time limit or maxEntities.
func (c *conn) stream(ctx context.Context) (title string, found map[entityRef]entity, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.discover)
	defer cancel()
	res, err := c.api.Send(ctx, http.MethodGet, "/events", nil, nil, http.Header{"Accept": {"text/event-stream"}})
	if err != nil {
		return "", nil, apiErr(err)
	}
	defer res.Body.Close()
	type ev struct {
		kind string
		data []byte
	}
	evs := make(chan ev, 64)
	go func() {
		defer close(evs)
		sc := bufio.NewScanner(io.LimitReader(res.Body, 8<<20))
		sc.Buffer(make([]byte, 0, 4096), 64<<10)
		kind := "message"
		var data bytes.Buffer
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if data.Len() > 0 {
					select {
					case evs <- ev{kind, append([]byte(nil), data.Bytes()...)}:
					case <-ctx.Done():
						return
					}
				}
				kind = "message"
				data.Reset()
			case strings.HasPrefix(line, "event:"):
				kind = strings.TrimSpace(line[6:])
			case strings.HasPrefix(line, "data:"):
				if data.Len() > 0 {
					data.WriteByte('\n')
				}
				data.WriteString(strings.TrimPrefix(line[5:], " "))
			}
		}
	}()
	found = map[entityRef]entity{}
	quiet := time.NewTimer(c.discover)
	defer quiet.Stop()
	for {
		select {
		case e, ok := <-evs:
			if !ok {
				return title, found, nil
			}
			switch e.kind {
			case "ping":
				var p struct {
					Title string `json:"title"`
				}
				if json.Unmarshal(e.data, &p) == nil && p.Title != "" {
					title = p.Title
				}
			case "state":
				var st entity
				if json.Unmarshal(e.data, &st) != nil {
					continue
				}
				r, err := parseRef(st.ID)
				if err != nil {
					continue // an entity id this module doesn't take
				}
				if _, ok := found[r]; !ok && len(found) >= maxEntities {
					return title, found, nil
				}
				found[r] = st
				quiet.Reset(c.quiet)
			}
			// "log" events are never read: logs can carry anything.
		case <-quiet.C:
			return title, found, nil
		case <-ctx.Done():
			if len(found) > 0 || title != "" {
				return title, found, nil
			}
			return "", nil, errors.New("the device's event stream sent nothing in time")
		}
	}
}

// all returns every entity with its state.
func (c *conn) all(ctx context.Context) (string, map[entityRef]entity, error) {
	if len(c.entities) == 0 {
		return c.stream(ctx)
	}
	out := map[entityRef]entity{}
	for _, r := range c.entities {
		e, err := c.get(ctx, r)
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", r, err)
		}
		out[r] = e
	}
	return "", out, nil
}

type input struct {
	Domain     string   `json:"domain"`
	Entity     string   `json:"entity"`
	ID         string   `json:"id"`
	On         *bool    `json:"on"`
	Brightness *float64 `json:"brightness"`
	Color      string   `json:"color"`
	Transition *float64 `json:"transition"`
}

// target reads an id for a domain, as relay or domain.relay.
func target(domain, id string) (entityRef, error) {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(id, domain+".") || strings.HasPrefix(id, domain+"-") {
		id = id[len(domain)+1:]
	}
	if !objectRe.MatchString(id) {
		return entityRef{}, fmt.Errorf("%q isn't a %s object id (lowercase letters, digits, _ and -)", id, domain)
	}
	return entityRef{domain, id}, nil
}

func isOn(e entity) (bool, error) {
	switch v := e.Value.(type) {
	case bool:
		return v, nil
	}
	switch s, _ := e.State.(string); strings.ToUpper(s) {
	case "ON":
		return true, nil
	case "OFF":
		return false, nil
	}
	return false, errors.New("the device didn't say whether it's on")
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func onOff(b bool) string { return map[bool]string{true: "on", false: "off"}[b] }

var hexRe = regexp.MustCompile(`^#?[0-9a-fA-F]{6}$`)

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
	case "entities":
		if p.Domain != "" && !domains[p.Domain] {
			return sdk.Result{}, fmt.Errorf("%q isn't an ESPHome domain", p.Domain)
		}
		_, found, err := c.all(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		refs := make([]entityRef, 0, len(found))
		for r := range found {
			if p.Domain == "" || r.Domain == p.Domain {
				refs = append(refs, r)
			}
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
		out := []map[string]any{}
		for _, r := range refs {
			out = append(out, view(r, found[r], c.isCritical(r)))
		}
		return sdk.JSON(out)

	case "state":
		r, err := parseRef(p.Entity)
		if err != nil {
			return sdk.Result{}, err
		}
		e, err := c.get(ctx, r)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(view(r, e, c.isCritical(r)))

	case "set_switch":
		r, err := target("switch", p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		if p.On == nil {
			return sdk.Result{}, errors.New("say on: true or false")
		}
		if c.isCritical(r) {
			return sdk.Result{}, fmt.Errorf("%s is critical (it restarts, resets or shuts down the device, or is in criticalEntities); use press_critical", r)
		}
		e, err := c.get(ctx, r)
		if err != nil {
			return sdk.Result{}, err
		}
		was, err := isOn(e)
		if err != nil {
			return sdk.Result{}, err
		}
		name := r.String()
		if e.Name != "" {
			name = e.Name + " (" + r.String() + ")"
		}
		if call.DryRun {
			sum := "Turn " + onOff(*p.On) + " " + name
			if was == *p.On {
				sum = name + " is already " + onOff(was) + "; nothing would change"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: name, Op: "update", Before: mustJSON(map[string]bool{"on": was}), After: mustJSON(map[string]bool{"on": *p.On})}}}}, nil
		}
		if was == *p.On {
			return sdk.JSON(map[string]any{"entity": r.String(), "on": was, "changed": false})
		}
		if err := c.post(ctx, r, "turn_"+onOff(*p.On), nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"entity": r.String(), "on": *p.On, "changed": true})
		res.Undo = sdk.UndoWith("set_switch", map[string]any{"id": r.ID, "on": was}, "Turn "+name+" back "+onOff(was))
		return res, err

	case "set_light":
		r, err := target("light", p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		if c.isCritical(r) {
			return sdk.Result{}, fmt.Errorf("%s is in criticalEntities; Conduit won't change it", r)
		}
		on := true
		if p.On != nil {
			on = *p.On
		}
		q := url.Values{}
		var rgbv []byte
		if p.Brightness != nil {
			if *p.Brightness < 0 || *p.Brightness > 100 || math.IsNaN(*p.Brightness) {
				return sdk.Result{}, errors.New("brightness is a percentage between 0 and 100")
			}
			if !on {
				return sdk.Result{}, errors.New("brightness goes with on: true")
			}
			q.Set("brightness", strconv.Itoa(int(math.Round(*p.Brightness*2.55))))
		}
		if p.Color != "" {
			if !hexRe.MatchString(p.Color) {
				return sdk.Result{}, errors.New("the colour is like #ff8800")
			}
			if !on {
				return sdk.Result{}, errors.New("color goes with on: true")
			}
			rgbv, _ = hex.DecodeString(strings.TrimPrefix(p.Color, "#"))
			q.Set("r", strconv.Itoa(int(rgbv[0])))
			q.Set("g", strconv.Itoa(int(rgbv[1])))
			q.Set("b", strconv.Itoa(int(rgbv[2])))
		}
		if p.Transition != nil {
			if *p.Transition < 0 || *p.Transition > 60 || math.IsNaN(*p.Transition) {
				return sdk.Result{}, errors.New("transition is between 0 and 60 seconds")
			}
			q.Set("transition", strconv.FormatFloat(*p.Transition, 'f', -1, 64))
		}
		e, err := c.get(ctx, r)
		if err != nil {
			return sdk.Result{}, err
		}
		was, err := isOn(e)
		if err != nil {
			return sdk.Result{}, err
		}
		before := view(r, e, false)
		after := map[string]any{"state": strings.ToUpper(onOff(on))}
		if p.Brightness != nil {
			after["brightness"] = math.Round(*p.Brightness)
		}
		if p.Color != "" {
			after["color"] = strings.ToLower("#" + strings.TrimPrefix(p.Color, "#"))
		}
		name := r.String()
		if e.Name != "" {
			name = e.Name + " (" + r.String() + ")"
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Turn " + onOff(on) + " " + name, Changes: []sdk.Change{{Target: name, Op: "update", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
		}
		if err := c.post(ctx, r, "turn_"+onOff(on), q); err != nil {
			return sdk.Result{}, err
		}
		back := map[string]any{"id": r.ID, "on": was}
		if was {
			if e.Brightness != nil {
				back["brightness"] = math.Round(*e.Brightness/255*1000) / 10
			}
			if col, ok := before["color"]; ok {
				back["color"] = col
			}
		}
		res, err := sdk.JSON(map[string]any{"entity": r.String(), "now": after})
		res.Undo = sdk.UndoWith("set_light", back, "Put "+name+" back")
		return res, err

	case "press_button", "press_critical":
		domain := "button"
		if call.Action == "press_critical" && p.Domain != "" {
			domain = p.Domain
		}
		if domain != "button" && domain != "switch" {
			return sdk.Result{}, errors.New("domain is button or switch")
		}
		r, err := target(domain, p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		crit := c.isCritical(r)
		if call.Action == "press_button" && crit {
			return sdk.Result{}, fmt.Errorf("%s is critical (it restarts, resets, shuts down or reflashes the device, opens, unlocks or sounds something, or is in criticalEntities); use press_critical", r)
		}
		if call.Action == "press_critical" && !crit {
			return sdk.Result{}, fmt.Errorf("%s isn't critical; use press_button or set_switch", r)
		}
		e, err := c.get(ctx, r) // it must exist
		if err != nil {
			return sdk.Result{}, err
		}
		name := r.String()
		if e.Name != "" {
			name = e.Name + " (" + r.String() + ")"
		}
		verb := "press"
		if domain == "switch" {
			verb = "turn_on"
		}
		if call.DryRun {
			sum := "Press " + name
			if domain == "switch" {
				sum = "Turn on " + name
			}
			if crit {
				sum += "; the device may restart, shut down or lose its settings, or open, unlock or sound what it drives"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: name, Op: verb}}}}, nil
		}
		if err := c.post(ctx, r, verb, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"entity": r.String(), "done": verb})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	title, found, err := c.all(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%d entities", len(found))
	if title != "" {
		msg = title + " · " + msg
	}
	if c.plain {
		return sdk.Health{Status: "degraded", Message: msg + " · password sent without encryption (the device is on http)"}
	}
	return sdk.Health{Status: "ok", Message: msg}
}
