// Package openhab works with openHAB through its REST API and an API token:
// items with their state, things and their status, rules, sending a command
// to an item and running a rule. Locks, garage doors, gates, doors, windows,
// alarms, cameras, valves and heating (by type, tag, category, group or
// name), and items listed in criticalItems, are kept apart behind a
// destructive action.
package openhab

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one openHAB server.
type Config struct {
	URL   string `json:"url"`   // e.g. http://openhab.local:8080
	Token string `json:"token"` // secret:// API token
	// CriticalItems are item names or labels that need
	// send_critical_command, like a plug feeding a server or a gate opener
	// behind a plain switch.
	CriticalItems      []string `json:"criticalItems"`
	Fingerprint        string   `json:"fingerprint"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

type conn struct {
	api      *rest.Client
	critical map[string]bool // names, and lowercased names and labels
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the openHAB module.
func New() *Module { return &Module{} }

const maxItems = 1000

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// itemRe is openHAB's own item name pattern ([a-zA-Z_0-9]+).
	itemRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,200}$`)
	ruleRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	numRe  = regexp.MustCompile(`^(-?[0-9]+(?:\.[0-9]+)?)(?:\s?([A-Za-z°%/²³µ]+[A-Za-z0-9°%/²³µ]*))?$`)
	// criticalWord matches types, tags, categories, names and labels of
	// what opens, unlocks, sounds, watches or heats something: a false
	// match only means the destructive action.
	criticalWord = regexp.MustCompile(`(?i)lock|door|gate|window|alarm|siren|secur|camera|valve|heat|hvac|radiator|boiler|thermostat|garage|sprinkler|irrigation|smoke|water ?main`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	cmd := `{"type":"object","required":["item","command"],"properties":{
		"item":{"type":"string","maxLength":200,"description":"The item's name (from items), e.g. Kitchen_Light"},
		"command":{"type":"string","maxLength":255,"description":"ON, OFF, a percentage, UP, DOWN, STOP, a number (with its unit), or a text, as the item's type takes"}}}`
	return sdk.Manifest{
		ID: "openhab", Name: "openHAB", Version: "0.1.0", Category: "Smart home", Icon: "home",
		Description: "openHAB items with their state, things and rules; send commands to items, with locks, garage doors, alarms and heating kept apart; run rules.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"openHAB's address, e.g. http://openhab.local:8080"},
			"token":{"type":"string","x-secret":true,"description":"An API token (your profile in the main UI, Create new API token); listing things and rules needs an admin's"},
			"criticalItems":{"type":"array","maxItems":200,"items":{"type":"string","maxLength":200},"description":"Item names or labels that need send_critical_command, like a plug feeding a server or a gate opener behind a plain switch. Locks, doors, gates, windows, alarms, cameras, valves and heating (by tag, category, group or name), groups and temperatures are critical without being listed."},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "items", Title: "Items", Description: "Each item: name, label, type, state, tags, groups, and whether it's critical.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"type":{"type":"string","description":"Only this type, e.g. Switch, Dimmer, Number"},"tag":{"type":"string","description":"Only items with this tag"},"search":{"type":"string","maxLength":100}}}`)},
			{Name: "item", Title: "Item", Description: "One item: state, type, tags, groups, range and options, whether it can be commanded, and why it's critical.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["item"],"properties":{"item":{"type":"string","maxLength":200,"description":"The item's name"}}}`)},
			{Name: "things", Title: "Things", Description: "Each thing (device or service binding): id, label, type, bridge, location and status (ONLINE, OFFLINE and why). Needs an admin's token.", Risk: sdk.RiskRead},
			{Name: "rules", Title: "Rules", Description: "Each rule: id, name, description, tags and status (IDLE, RUNNING, UNINITIALIZED and why).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","maxLength":100}}}`)},
			{Name: "send_command", Title: "Send a command", Description: "Sends a command to an item (ON, OFF, 50, UP, 21.5 °C …), checked against its type, range and options. Critical items (locks, doors, gates, windows, alarms, cameras, valves, heating, groups, or in criticalItems) are refused: use send_critical_command. Undo sends the previous state.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(cmd)},
			{Name: "send_critical_command", Title: "Send a command to a critical item", Description: "Sends a command to a critical item: this can unlock a lock, open a garage door, gate, door or window, disarm an alarm, turn a camera off, open a valve or change the heating. The preview says which. Undo sends the previous state.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(cmd)},
			{Name: "run_rule", Title: "Run a rule", Description: "Runs a rule's actions now, whatever its triggers and conditions: a rule can do anything openHAB can.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["rule"],"properties":{"rule":{"type":"string","maxLength":128,"description":"The rule's id (from rules)"}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "item", Title: "Items", ListAction: "items", ViewHint: "table"}},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like http://openhab.local:8080")
	}
	if c.Token == "" {
		return errors.New("enter an openHAB API token")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	if u.Scheme == "http" && (c.Fingerprint != "" || c.InsecureSkipVerify) {
		return errors.New("the certificate settings need an https address")
	}
	if len(c.CriticalItems) > 200 {
		return errors.New("list at most 200 critical items")
	}
	crit := map[string]bool{}
	for _, a := range c.CriticalItems {
		a = strings.TrimSpace(a)
		if a == "" || len(a) > 200 || strings.ContainsAny(a, "\x00\r\n") {
			return errors.New("a critical item is its name or its label (up to 200 characters)")
		}
		crit[a] = true
		crit[strings.ToLower(a)] = true
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	ref := c.Token
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/rest") + "/rest"
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		// openHAB takes an API token as the basic-auth user name.
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(t)+":")))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, critical: crit})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("openHAB refused the API token (things and rules need an admin's)")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API token's user isn't allowed to do this in openHAB (it needs to be an admin)")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err)
}

// clip redacts server text, then shortens it.
func clip(s string, n int) string {
	s = rest.Redact(strings.TrimSpace(s))
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

type option struct {
	Value   string `json:"value"`
	Command string `json:"command"`
	Label   string `json:"label"`
}

type item struct {
	Name             string   `json:"name"`
	Label            string   `json:"label"`
	Type             string   `json:"type"`
	GroupType        string   `json:"groupType"`
	Category         string   `json:"category"`
	State            string   `json:"state"`
	Tags             []string `json:"tags"`
	GroupNames       []string `json:"groupNames"`
	StateDescription *struct {
		Minimum  *float64 `json:"minimum"`
		Maximum  *float64 `json:"maximum"`
		Step     *float64 `json:"step"`
		ReadOnly bool     `json:"readOnly"`
		Options  []option `json:"options"`
	} `json:"stateDescription"`
	CommandDescription *struct {
		CommandOptions []option `json:"commandOptions"`
	} `json:"commandDescription"`
}

// base is the item's type without its dimension (Number:Temperature is a
// Number).
func (it item) base() string {
	t, _, _ := strings.Cut(it.Type, ":")
	return t
}

func (it item) title() string {
	if it.Label != "" {
		return clip(it.Label, 100) + " (" + it.Name + ")"
	}
	return it.Name
}

// options are the commands the item offers, if it lists them.
func (it item) options() []string {
	var out []string
	if it.CommandDescription != nil {
		for _, o := range it.CommandDescription.CommandOptions {
			out = append(out, o.Command)
		}
	}
	if len(out) == 0 && it.StateDescription != nil {
		for _, o := range it.StateDescription.Options {
			out = append(out, o.Value)
		}
	}
	return out
}

// ownWhy says why an item is critical by itself, or "".
func (c *conn) ownWhy(it item) string {
	switch {
	case c.critical[it.Name] || c.critical[strings.ToLower(it.Name)] || (it.Label != "" && c.critical[strings.ToLower(it.Label)]):
		return "listed in criticalItems"
	case it.base() == "Group":
		return "a group passes the command to every member"
	case strings.EqualFold(it.Type, "Number:Temperature"):
		return "a temperature, such as a heating setpoint"
	}
	for _, t := range it.Tags {
		if criticalWord.MatchString(t) {
			return "tagged " + clip(t, 40)
		}
	}
	switch {
	case criticalWord.MatchString(it.Category):
		return "its category is " + clip(it.Category, 40)
	case criticalWord.MatchString(it.Name) || criticalWord.MatchString(it.Label):
		return "its name says it opens, unlocks, sounds, watches or heats something"
	}
	return ""
}

// why says why an item is critical, counting the groups it's in (the
// equipment of openHAB's semantic model: a Switch inside a Lock or
// GarageDoor group is as critical as the group).
func (c *conn) why(it item, all map[string]item) string {
	if w := c.ownWhy(it); w != "" {
		return w
	}
	seen := map[string]bool{it.Name: true}
	queue := append([]string(nil), it.GroupNames...)
	for len(queue) > 0 && len(seen) < 200 {
		g := queue[0]
		queue = queue[1:]
		if seen[g] {
			continue
		}
		seen[g] = true
		p, ok := all[g]
		if !ok {
			continue
		}
		// The group's own "a group passes the command" doesn't count here.
		gi := p
		gi.Type = p.GroupType
		if w := c.ownWhy(gi); w != "" {
			return "in group " + p.title() + ", " + w
		}
		queue = append(queue, p.GroupNames...)
	}
	return ""
}

func (c *conn) all(ctx context.Context) (map[string]item, []item, error) {
	q := url.Values{"recursive": {"false"}, "fields": {"name,label,type,groupType,category,state,tags,groupNames"}}
	var list []item
	if err := c.get(ctx, "/items", q, &list); err != nil {
		return nil, nil, err
	}
	all := map[string]item{}
	for _, it := range list {
		all[it.Name] = it
	}
	return all, list, nil
}

func (c *conn) item(ctx context.Context, name string) (item, error) {
	name = strings.TrimSpace(name)
	if !itemRe.MatchString(name) {
		return item{}, errors.New("an item is its name, letters, digits and _ (from items)")
	}
	var it item
	if err := c.get(ctx, "/items/"+url.PathEscape(name), url.Values{"metadata": {"none"}}, &it); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return it, fmt.Errorf("there's no item %s", name)
		}
		return it, err
	}
	if it.Name != name {
		// The name goes into the command's path and the undo.
		return it, fmt.Errorf("openHAB answered with another item for %s", name)
	}
	return it, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var list []struct {
		Name string `json:"name"`
	}
	if err := c.get(ctx, "/items", url.Values{"fields": {"name"}}, &list); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no openHAB REST API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("openHAB is up with %d items", len(list))}
}

func (c *conn) row(it item, all map[string]item) map[string]any {
	row := map[string]any{"name": it.Name, "type": clip(it.Type, 60), "state": clip(it.State, 200)}
	if it.Label != "" {
		row["label"] = clip(it.Label, 100)
	}
	if it.GroupType != "" {
		row["groupType"] = clip(it.GroupType, 60)
	}
	if it.Category != "" {
		row["category"] = clip(it.Category, 60)
	}
	if len(it.Tags) > 0 {
		row["tags"] = clipAll(it.Tags)
	}
	if len(it.GroupNames) > 0 {
		row["groups"] = clipAll(it.GroupNames)
	}
	if c.why(it, all) != "" {
		row["critical"] = true
	}
	return row
}

func clipAll(ss []string) []string {
	out := make([]string, 0, len(ss))
	for i, s := range ss {
		if i >= 50 {
			break
		}
		out = append(out, clip(s, 60))
	}
	return out
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Type    string `json:"type"`
		Tag     string `json:"tag"`
		Search  string `json:"search"`
		Item    string `json:"item"`
		Command string `json:"command"`
		Rule    string `json:"rule"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "items":
		all, list, err := c.all(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		q := strings.ToLower(strings.TrimSpace(p.Search))
		t := strings.TrimSpace(p.Type)
		tag := strings.TrimSpace(p.Tag)
		out := []map[string]any{}
		for _, it := range list {
			if len(out) >= maxItems {
				break
			}
			if t != "" && !strings.EqualFold(it.Type, t) && !strings.EqualFold(it.base(), t) {
				continue
			}
			if tag != "" && !hasFold(it.Tags, tag) {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(it.Name+" "+it.Label), q) {
				continue
			}
			out = append(out, c.row(it, all))
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
		return sdk.JSON(out)
	case "item":
		it, err := c.item(ctx, p.Item)
		if err != nil {
			return sdk.Result{}, err
		}
		all, _, err := c.all(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		row := c.row(it, all)
		if why := c.why(it, all); why != "" {
			row["criticalBecause"] = why
		}
		row["commandable"] = commandable(it) == nil
		if sd := it.StateDescription; sd != nil {
			if sd.Minimum != nil {
				row["min"] = *sd.Minimum
			}
			if sd.Maximum != nil {
				row["max"] = *sd.Maximum
			}
			if sd.Step != nil {
				row["step"] = *sd.Step
			}
		}
		if o := it.options(); len(o) > 0 {
			row["options"] = clipAll(o)
		}
		return sdk.JSON(row)
	case "things":
		var list []struct {
			UID          string `json:"UID"`
			Label        string `json:"label"`
			ThingTypeUID string `json:"thingTypeUID"`
			BridgeUID    string `json:"bridgeUID"`
			Location     string `json:"location"`
			StatusInfo   struct {
				Status       string `json:"status"`
				StatusDetail string `json:"statusDetail"`
				Description  string `json:"description"`
			} `json:"statusInfo"`
		}
		// summary leaves out each thing's configuration (addresses,
		// passwords of the devices behind it).
		if err := c.get(ctx, "/things", url.Values{"summary": {"true"}}, &list); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range list {
			if len(out) >= maxItems {
				break
			}
			row := map[string]any{"id": clip(t.UID, 200), "label": clip(t.Label, 100), "type": clip(t.ThingTypeUID, 100), "status": clip(t.StatusInfo.Status, 30)}
			if d := t.StatusInfo.StatusDetail; d != "" && d != "NONE" {
				row["statusDetail"] = clip(d, 60)
			}
			if t.StatusInfo.Description != "" {
				row["statusDescription"] = clip(t.StatusInfo.Description, 200)
			}
			if t.BridgeUID != "" {
				row["bridge"] = clip(t.BridgeUID, 200)
			}
			if t.Location != "" {
				row["location"] = clip(t.Location, 100)
			}
			out = append(out, row)
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
		return sdk.JSON(out)
	case "rules":
		list, err := c.rules(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		q := strings.ToLower(strings.TrimSpace(p.Search))
		out := []map[string]any{}
		for _, r := range list {
			if len(out) >= maxItems {
				break
			}
			if q != "" && !strings.Contains(strings.ToLower(r.UID+" "+r.Name+" "+r.Description), q) {
				continue
			}
			out = append(out, r.row())
		}
		return sdk.JSON(out)
	case "send_command", "send_critical_command":
		name := strings.TrimSpace(p.Item)
		if !itemRe.MatchString(name) {
			return sdk.Result{}, errors.New("an item is its name, letters, digits and _ (from items)")
		}
		cmd := strings.TrimSpace(p.Command)
		if cmd == "" || len(cmd) > 255 || strings.IndexFunc(cmd, unicode.IsControl) >= 0 {
			return sdk.Result{}, errors.New("a command is ON, OFF, a percentage, UP, DOWN, a number or a short text")
		}
		return c.send(ctx, call, name, cmd)
	case "run_rule":
		uid := strings.TrimSpace(p.Rule)
		if !ruleRe.MatchString(uid) {
			return sdk.Result{}, errors.New("a rule is its id (from rules)")
		}
		list, err := c.rules(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var r *rule
		for i := range list {
			if list[i].UID == uid {
				r = &list[i]
			}
		}
		if r == nil {
			return sdk.Result{}, fmt.Errorf("there's no rule %s", uid)
		}
		if call.DryRun {
			b, _ := json.Marshal(r.row())
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Run rule %s (%s) now; it does whatever its actions do, whatever its triggers and conditions", r.name(), uid),
				Changes: []sdk.Change{{Target: "rule " + r.name(), Op: "run", Before: b}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/rules/"+url.PathEscape(uid)+"/runnow", nil, map[string]any{}, nil); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no rule %s", uid)
			}
			return sdk.Result{}, friendly(err)
		}
		out := map[string]any{"rule": uid, "name": r.name(), "ran": true}
		// Read back the rule's status.
		if after, err := c.rules(ctx); err == nil {
			for _, a := range after {
				if a.UID == uid {
					out["status"] = clip(a.Status.Status, 30)
				}
			}
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func hasFold(ss []string, s string) bool {
	for _, x := range ss {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

type rule struct {
	UID         string   `json:"uid"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Status      struct {
		Status       string `json:"status"`
		StatusDetail string `json:"statusDetail"`
	} `json:"status"`
}

func (r rule) name() string {
	if r.Name != "" {
		return clip(r.Name, 100)
	}
	return clip(r.UID, 100)
}

func (r rule) row() map[string]any {
	row := map[string]any{"id": clip(r.UID, 128), "name": r.name(), "status": clip(r.Status.Status, 30)}
	if d := r.Status.StatusDetail; d != "" && d != "NONE" {
		row["statusDetail"] = clip(d, 60)
	}
	if r.Description != "" {
		row["description"] = clip(r.Description, 200)
	}
	if len(r.Tags) > 0 {
		row["tags"] = clipAll(r.Tags)
	}
	return row
}

func (c *conn) rules(ctx context.Context) ([]rule, error) {
	var list []rule
	// summary is what a non-admin may list, and leaves out the scripts.
	err := c.get(ctx, "/rules", url.Values{"summary": {"true"}}, &list)
	return list, err
}

// commandable says why an item can't take commands, or nil.
func commandable(it item) error {
	t := it.base()
	if t == "Group" {
		t = strings.SplitN(it.GroupType, ":", 2)[0]
	}
	if it.StateDescription != nil && it.StateDescription.ReadOnly {
		return fmt.Errorf("%s is read-only", it.title())
	}
	switch t {
	case "Switch", "Dimmer", "Color", "Rollershutter", "Player", "Number", "String":
		return nil
	case "":
		return fmt.Errorf("openHAB doesn't say what type %s is, so it isn't changed", it.title())
	}
	return fmt.Errorf("%s is a %s item, which can't be commanded here", it.title(), clip(t, 40))
}

func pct(s string) (float64, bool) {
	n, err := strconv.ParseFloat(s, 64)
	return n, err == nil && n >= 0 && n <= 100 && !math.IsNaN(n)
}

// check normalizes a command for the item's type, or says why it doesn't
// fit.
func check(it item, cmd string) (string, error) {
	if err := commandable(it); err != nil {
		return "", err
	}
	t := it.base()
	if t == "Group" {
		t = strings.SplitN(it.GroupType, ":", 2)[0]
	}
	up := strings.ToUpper(cmd)
	bad := func(what string) (string, error) { return "", fmt.Errorf("%s takes %s", it.title(), what) }
	switch t {
	case "Switch":
		if up == "ON" || up == "OFF" {
			return up, nil
		}
		return bad("ON or OFF")
	case "Dimmer", "Rollershutter":
		words := map[string]bool{"ON": t == "Dimmer", "OFF": t == "Dimmer", "INCREASE": t == "Dimmer", "DECREASE": t == "Dimmer",
			"UP": t == "Rollershutter", "DOWN": t == "Rollershutter", "STOP": t == "Rollershutter", "MOVE": t == "Rollershutter"}
		if words[up] {
			return up, nil
		}
		if _, ok := pct(cmd); ok {
			return cmd, nil
		}
		if t == "Dimmer" {
			return bad("ON, OFF, INCREASE, DECREASE or a percentage 0–100")
		}
		return bad("UP, DOWN, STOP, MOVE or a percentage 0–100")
	case "Color":
		switch up {
		case "ON", "OFF", "INCREASE", "DECREASE":
			return up, nil
		}
		if _, ok := pct(cmd); ok {
			return cmd, nil
		}
		if hsb(cmd) {
			return strings.ReplaceAll(cmd, " ", ""), nil
		}
		return bad("ON, OFF, INCREASE, DECREASE, a brightness 0–100 or hue,saturation,brightness")
	case "Player":
		switch up {
		case "PLAY", "PAUSE", "NEXT", "PREVIOUS", "REWIND", "FASTFORWARD":
			return up, nil
		}
		return bad("PLAY, PAUSE, NEXT, PREVIOUS, REWIND or FASTFORWARD")
	case "Number":
		mt := numRe.FindStringSubmatch(cmd)
		if mt == nil {
			return bad("a number, optionally with its unit (21.5 °C)")
		}
		n, _ := strconv.ParseFloat(mt[1], 64)
		if sd := it.StateDescription; sd != nil {
			if sd.Minimum != nil && n < *sd.Minimum || sd.Maximum != nil && n > *sd.Maximum {
				lo, hi := math.Inf(-1), math.Inf(1)
				if sd.Minimum != nil {
					lo = *sd.Minimum
				}
				if sd.Maximum != nil {
					hi = *sd.Maximum
				}
				return bad(fmt.Sprintf("a number from %g to %g", lo, hi))
			}
		}
		if o := it.options(); len(o) > 0 && !inList(o, cmd) {
			return bad("one of " + strings.Join(clipAll(o), ", "))
		}
		return cmd, nil
	case "String":
		if o := it.options(); len(o) > 0 && !inList(o, cmd) {
			return bad("one of " + strings.Join(clipAll(o), ", "))
		}
		return cmd, nil
	}
	return "", fmt.Errorf("%s can't be commanded here", it.title())
}

func inList(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func hsb(s string) bool {
	parts := strings.Split(strings.ReplaceAll(s, " ", ""), ",")
	if len(parts) != 3 {
		return false
	}
	h, err := strconv.ParseFloat(parts[0], 64)
	if err != nil || h < 0 || h > 360 {
		return false
	}
	for _, p := range parts[1:] {
		if _, ok := pct(p); !ok {
			return false
		}
	}
	return true
}

// same says whether an item's state already is what the command asks for.
func same(it item, state, cmd string) bool {
	if state == cmd {
		return true
	}
	t := it.base()
	if t == "Group" {
		t = strings.SplitN(it.GroupType, ":", 2)[0]
	}
	switch t {
	case "Dimmer", "Color", "Rollershutter":
		level := state
		if t == "Color" {
			p := strings.Split(state, ",")
			if len(p) != 3 {
				return false
			}
			level = p[2]
		}
		n, ok := pct(level)
		if !ok {
			return false
		}
		switch cmd {
		case "ON":
			return n > 0
		case "OFF":
			return n == 0
		}
		if c, ok := pct(cmd); ok {
			return c == n
		}
	case "Number":
		a, b := numRe.FindStringSubmatch(state), numRe.FindStringSubmatch(cmd)
		if a == nil || b == nil || (b[2] != "" && a[2] != b[2]) {
			return false
		}
		x, _ := strconv.ParseFloat(a[1], 64)
		y, _ := strconv.ParseFloat(b[1], 64)
		return x == y
	}
	return false
}

// effect says in words what a command to a critical item can do.
func effect(cmd string) string {
	switch cmd {
	case "ON":
		return "turns it on (a gate or door opener fires, a valve opens, an alarm sounds, heating starts)"
	case "OFF":
		return "turns it off (a lock may open, a camera or alarm stops, heating stops)"
	case "UP", "DOWN", "MOVE", "STOP":
		return "moves it (a garage door, gate or window opens or closes)"
	}
	return "changes a critical item (a lock, door, gate, window, alarm, camera, valve or heating)"
}

func (c *conn) send(ctx context.Context, call sdk.Call, name, cmd string) (sdk.Result, error) {
	it, err := c.item(ctx, name)
	if err != nil {
		return sdk.Result{}, err
	}
	if it.Type == "" {
		return sdk.Result{}, fmt.Errorf("openHAB doesn't say what type %s is, so it isn't changed", it.title())
	}
	// The groups an item is in decide too; without them the change can't
	// be judged, so it isn't made.
	all, _, err := c.all(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	why := c.why(it, all)
	critical := call.Action == "send_critical_command"
	if why != "" && !critical {
		return sdk.Result{}, fmt.Errorf("%s is critical (%s): use send_critical_command", it.title(), why)
	}
	if why == "" && critical {
		return sdk.Result{}, fmt.Errorf("%s isn't critical; use send_command", it.title())
	}
	v, err := check(it, cmd)
	if err != nil {
		return sdk.Result{}, err
	}
	prev := it.State
	if same(it, prev, v) {
		return sdk.JSON(map[string]any{"item": name, "label": clip(it.Label, 100), "state": clip(prev, 200), "note": "nothing to change"})
	}
	if call.DryRun {
		b, _ := json.Marshal(map[string]string{"state": clip(prev, 200)})
		a, _ := json.Marshal(map[string]string{"command": v})
		sum := fmt.Sprintf("Send %s to %s (a %s item, now %s)", v, it.title(), clip(it.Type, 40), clip(prev, 100))
		if critical {
			sum += "; this " + effect(v) + " (" + why + ")"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "item " + it.title(), Op: "command " + v, Before: b, After: a}}}}, nil
	}
	res, err := c.api.Send(ctx, http.MethodPost, "/items/"+url.PathEscape(name), nil, strings.NewReader(v), http.Header{"Content-Type": {"text/plain"}, "Accept": {"application/json"}})
	if err != nil {
		if rest.IsStatus(err, http.StatusBadRequest) {
			return sdk.Result{}, fmt.Errorf("openHAB couldn't parse %s for %s", v, it.title())
		}
		return sdk.Result{}, friendly(err)
	}
	res.Body.Close()
	if res.StatusCode >= 300 {
		return sdk.Result{}, fmt.Errorf("openHAB answered %d", res.StatusCode)
	}
	out := map[string]any{"item": name, "command": v, "was": clip(prev, 200)}
	if it.Label != "" {
		out["label"] = clip(it.Label, 100)
	}
	// Read back: openHAB applies commands asynchronously, so the state may
	// still be on its way.
	if after, err := c.item(ctx, name); err == nil {
		out["state"] = clip(after.State, 200)
	}
	r, err := sdk.JSON(out)
	// The previous state goes back through the same action when the item
	// takes it as a command (not NULL or UNDEF).
	if back, cerr := check(it, prev); cerr == nil && prev != "NULL" && prev != "UNDEF" {
		r.Undo = sdk.UndoWith(call.Action, map[string]any{"item": name, "command": back}, fmt.Sprintf("Send %s to %s", clip(back, 60), it.title()))
	}
	return r, err
}
