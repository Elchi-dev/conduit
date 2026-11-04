package homeassistant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

var (
	// criticalDomains open, unlock, disarm, sound, watch, heat or water
	// something, or (script) can call any service.
	criticalDomains = map[string]string{
		"lock": "a lock", "cover": "a cover (garage door, gate, door, window, shutter or blind)",
		"alarm_control_panel": "an alarm panel", "valve": "a valve", "climate": "heating or cooling",
		"water_heater": "a water heater", "camera": "a camera", "siren": "a siren", "humidifier": "a humidifier",
		"script": "a script, which can call any service",
	}
	// criticalClasses are device classes of what opens or unlocks something,
	// or lets water or gas through, on whatever domain carries them. A
	// switch's outlet or switch class isn't critical.
	criticalClasses = map[string]string{
		"garage": "the garage door", "garage_door": "the garage door", "gate": "the gate", "door": "the door",
		"window": "the window", "lock": "the lock", "shutter": "the shutters", "gas": "the gas", "water": "the water",
	}
	// criticalWord matches entity ids and names of what opens, unlocks,
	// sounds, watches or heats something: a false match only means the
	// destructive action. It's openHAB's and Homebridge's pattern.
	criticalWord = regexp.MustCompile(`(?i)lock|door|gate|window|alarm|siren|secur|camera|valve|heat|hvac|radiator|boiler|thermostat|setpoint|temperature|garage|sprinkler|irrigation|smoke|water ?main|` + germanWord)
	// germanWord is the same in German (Tür, Haustuer, Hoftor, Schloss,
	// Fenster, Heizung …). Tor counts as a word or at the end of a compound
	// (Hoftor), not inside Motor or Monitor.
	germanWord = `tür|tuer|(^|[^a-zäöü])tor([^a-zäöü]|$|antrieb)|(garten|hof|einfahrt|einfahrts|zufahrt|zufahrts|haus|eingangs|garagen)tor|öffner|oeffner|schloss|riegel|fenster|heiz|sirene|ventil|kamera|rauchmelder|sicherheit|bewässerung|bewaesserung`
	// globRe is an entity id or a glob of one (switch.garage_*).
	globRe = regexp.MustCompile(`^[a-z0-9_*?]+\.[a-z0-9_*?]+$`)

	// subjects name what a critical name is about, for the preview; the
	// first match wins (Garagentor is a garage door, not a gate).
	subjects = []struct {
		re   *regexp.Regexp
		what string
	}{
		{regexp.MustCompile(`(?i)garage|garagen`), "the garage door"},
		{regexp.MustCompile(`(?i)gate|(^|[^a-zäöü])tor([^a-zäöü]|$|antrieb)|(garten|hof|einfahrt|einfahrts|zufahrt|zufahrts|haus|eingangs)tor`), "the gate"},
		{regexp.MustCompile(`(?i)door|tür|tuer|öffner|oeffner`), "the door"},
		{regexp.MustCompile(`(?i)window|fenster`), "the window"},
		{regexp.MustCompile(`(?i)lock|schloss|riegel`), "the lock"},
		{regexp.MustCompile(`(?i)valve|ventil|sprinkler|irrigation|bewässerung|bewaesserung|water ?main`), "the water"},
		{regexp.MustCompile(`(?i)alarm|siren|sirene|smoke|rauchmelder|secur|sicherheit`), "the alarm"},
		{regexp.MustCompile(`(?i)camera|kamera`), "the camera"},
		{regexp.MustCompile(`(?i)heat|heiz|hvac|radiator|boiler|thermostat|setpoint|temperature`), "the heating"},
	}
)

var errNoEntity = errors.New("Home Assistant has no entity")

// validCritical checks and lowercases criticalEntities.
func validCritical(list []string) ([]string, error) {
	if len(list) > 200 {
		return nil, errors.New("list at most 200 critical entities")
	}
	out := []string{}
	for _, e := range list {
		e = strings.ToLower(strings.TrimSpace(e))
		if _, err := path.Match(e, ""); err != nil || len(e) > 255 || !globRe.MatchString(e) {
			return nil, fmt.Errorf("a critical entity is an entity id like switch.gate, or a pattern like switch.garage_* (not %q)", e)
		}
		out = append(out, e)
	}
	return out, nil
}

func (h *home) listed(entity string) bool {
	for _, g := range h.critical {
		if ok, _ := path.Match(g, entity); ok {
			return true
		}
	}
	return false
}

func attr(s haState, k string) string {
	v, _ := s.Attributes[k].(string)
	return v
}

// why says why an entity is critical, or "".
func (h *home) why(s haState) string {
	dom := domainOf(s.EntityID)
	obj := strings.TrimPrefix(s.EntityID, dom+".")
	name := attr(s, "friendly_name")
	dc := strings.ToLower(attr(s, "device_class"))
	switch {
	case h.listed(s.EntityID):
		return "listed in criticalEntities"
	case criticalDomains[dom] != "":
		return criticalDomains[dom]
	case s.State == "" || s.State == "unknown" || s.State == "unavailable":
		// What it is now can't be told, so it's treated as critical.
		return "its state is " + orUnknown(s.State) + ", so what it controls can't be checked"
	case dom == "light":
		// A light only lights: a garage or outdoor light is a plain write.
		return ""
	case criticalClasses[dc] != "":
		return "its device class is " + dc
	case criticalWord.MatchString(obj) || criticalWord.MatchString(name):
		return "its name says it opens, unlocks, sounds, watches or heats something"
	}
	return ""
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// position is an entity's state as on or off, or "" when it isn't known.
func position(dom, state string) string {
	switch dom {
	case "cover", "valve":
		switch state {
		case "open":
			return "on"
		case "closed":
			return "off"
		}
		return "" // opening, closing, stopped, unknown
	case "climate", "water_heater":
		switch state {
		case "off":
			return "off"
		case "", "unknown", "unavailable":
			return ""
		}
		return "on" // heat, cool, auto, eco …
	}
	if state == "on" || state == "off" {
		return state
	}
	return ""
}

// exact says whether turning an entity back to its position restores its
// state exactly: a climate turned off from heat may come back in another
// mode, so only off is exact there.
func exact(dom, state string) bool {
	switch dom {
	case "climate", "water_heater":
		return state == "off"
	}
	return position(dom, state) != ""
}

// stateWord is how a domain names on and off.
func stateWord(dom, pos string) string {
	if dom == "cover" || dom == "valve" {
		return map[string]string{"on": "open", "off": "closed"}[pos]
	}
	return pos
}

// serviceFor is the service that turns an entity on or off.
func serviceFor(dom, pos string) string {
	switch dom {
	case "cover", "valve":
		return map[string]string{"on": "open_", "off": "close_"}[pos] + dom
	}
	return "turn_" + pos
}

func subject(s haState) string {
	if w := criticalClasses[strings.ToLower(attr(s, "device_class"))]; w != "" {
		return w
	}
	text := strings.TrimPrefix(s.EntityID, domainOf(s.EntityID)+".") + " " + attr(s, "friendly_name")
	for _, x := range subjects {
		if x.re.MatchString(text) {
			return x.what
		}
	}
	return ""
}

// effect says in words what turning a critical entity on or off does.
func effect(s haState, on bool) string {
	dom := domainOf(s.EntityID)
	pick := func(a, b string) string {
		if on {
			return a
		}
		return b
	}
	subj := subject(s)
	switch dom {
	case "cover", "valve":
		if subj == "" {
			subj = "it"
			if dom == "valve" {
				subj = "the valve"
			}
		}
		return pick("opens ", "closes ") + subj
	case "climate":
		return pick("turns the heating or cooling on", "turns the heating or cooling off")
	case "water_heater":
		return pick("turns the water heater on", "turns the water heater off")
	case "camera":
		return pick("turns the camera on", "turns the camera off (it stops watching)")
	case "siren":
		return pick("sounds the siren", "silences the siren")
	case "humidifier":
		return pick("turns the humidifier on", "turns the humidifier off")
	case "script":
		return pick("runs the script (it can call any service)", "stops the script")
	}
	if subj != "" {
		return pick("turns it on, which may open, unlock or start ", "turns it off, which may close, lock or stop ") + subj
	}
	return pick("turns it on", "turns it off")
}

func title(s haState, entity string) string {
	if n := attr(s, "friendly_name"); n != "" {
		return clip(n, 100) + " (" + entity + ")"
	}
	return entity
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

// noOnOff are critical domains without on and off: their services are
// named for what they do and need call_service.
var noOnOff = map[string]string{
	"lock":                "locks have no on or off: use call_service with lock.lock or lock.unlock",
	"alarm_control_panel": "alarm panels have no on or off: use call_service with alarm_control_panel.alarm_arm_away, alarm_arm_home or alarm_disarm",
}

// plainRefusal is the error turn_on, turn_off and toggle give for a
// critical entity.
func plainRefusal(entity, action, why string) error {
	if msg := noOnOff[domainOf(entity)]; msg != "" {
		return fmt.Errorf("%s is critical (%s); %s", entity, why, msg)
	}
	return fmt.Errorf("%s is critical (%s): use turn_critical with entity %s and action %s", entity, why, entity, strings.TrimPrefix(action, "turn_"))
}

// turnCritical turns a critical entity on or off, or toggles one whose
// state is known.
func (h *home) turnCritical(ctx context.Context, c sdk.Call, entity, act string) (sdk.Result, error) {
	if !entityRe.MatchString(entity) {
		return sdk.Result{}, fmt.Errorf("%q isn't an entity id like switch.garage_door", entity)
	}
	act = strings.ToLower(strings.TrimSpace(act))
	if act != "on" && act != "off" && act != "toggle" {
		return sdk.Result{}, errors.New("action is on, off or toggle")
	}
	dom := domainOf(entity)
	if msg := noOnOff[dom]; msg != "" {
		return sdk.Result{}, errors.New(msg)
	}
	s, rerr := h.state(ctx, entity)
	if errors.Is(rerr, errNoEntity) {
		return sdk.Result{}, rerr
	}
	var why string
	if rerr != nil {
		s = haState{EntityID: entity}
		why = "its state couldn't be read, so what it controls can't be checked"
	} else if why = h.why(s); why == "" {
		alt := "turn_" + act
		if act == "toggle" {
			alt = "toggle"
		}
		return sdk.Result{}, fmt.Errorf("%s isn't critical; use %s", entity, alt)
	}
	cur := ""
	if rerr == nil {
		cur = position(dom, s.State)
	}
	target := act
	if act == "toggle" {
		if cur == "" {
			return sdk.Result{}, fmt.Errorf("%s is %s, not known on or off, so toggling can't say what it would do: use action on or off", entity, orUnknown(s.State))
		}
		target = map[string]string{"on": "off", "off": "on"}[cur]
	}
	if cur == target {
		return sdk.JSON(map[string]string{"entity": entity, "state": s.State, "note": "nothing to change"})
	}
	from := "state unknown"
	if rerr == nil {
		from = orUnknown(s.State)
	}
	verb := map[string]string{"on": "Turn on ", "off": "Turn off "}[target]
	if dom == "cover" || dom == "valve" {
		verb = map[string]string{"on": "Open ", "off": "Close "}[target]
	}
	summary := fmt.Sprintf("%s%s (%s → %s); this %s (%s)", verb, title(s, entity), from, stateWord(dom, target), effect(s, target == "on"), why)
	if c.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{
			Target: entity, Op: serviceFor(dom, target),
			Before: mustJSON(map[string]string{"state": from}), After: mustJSON(map[string]string{"state": stateWord(dom, target)}),
		}}}}, nil
	}
	if err := h.service(ctx, dom, serviceFor(dom, target), map[string]any{"entity_id": entity}); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]string{"entity": entity, "did": strings.TrimSuffix(verb, " ") + ": " + effect(s, target == "on"), "was": from}
	// Read back: a cover or valve may still be on its way (opening).
	if after, err := h.state(ctx, entity); err == nil {
		out["now"] = after.State
	} else {
		out["now"] = "couldn't be read back"
	}
	r, err := sdk.JSON(out)
	if rerr == nil && exact(dom, s.State) {
		r.Undo = sdk.UndoWith("turn_critical", map[string]string{"entity": entity, "action": cur}, fmt.Sprintf("Put %s back %s", entity, s.State))
	}
	return r, err
}

// sceneSafe refuses a scene that would set a critical entity. A scene lists
// the entities it sets in its entity_id attribute; one that doesn't (a scene
// an integration provides), or one whose entities can't be read, can't be
// checked, so it's refused too.
func (h *home) sceneSafe(ctx context.Context, scene string) error {
	s, err := h.state(ctx, scene)
	if err != nil {
		return err
	}
	via := "activate it with call_service (domain scene, service turn_on, data {\"entity_id\":\"" + scene + "\"})"
	var ids []string
	switch v := s.Attributes["entity_id"].(type) {
	case []any:
		for _, e := range v {
			if id, ok := e.(string); ok {
				ids = append(ids, id)
			}
		}
	case string:
		ids = []string{v}
	}
	if len(ids) == 0 {
		return fmt.Errorf("%s doesn't list the entities it sets, so it can't be checked for critical ones: %s", scene, via)
	}
	if len(ids) > 200 {
		return fmt.Errorf("%s sets more than 200 entities, too many to check for critical ones: %s", scene, via)
	}
	for _, id := range ids {
		if !entityRe.MatchString(id) {
			return fmt.Errorf("%s sets %q, which can't be checked: %s", scene, id, via)
		}
		e, err := h.state(ctx, id)
		why := ""
		if err != nil {
			why = "its state couldn't be read, so what it controls can't be checked"
		} else {
			why = h.why(e)
		}
		if why != "" {
			return fmt.Errorf("%s sets %s, which is critical (%s): %s", scene, id, why, via)
		}
	}
	return nil
}
