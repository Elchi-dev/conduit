// Package zabbix works with a Zabbix server through its JSON-RPC API and an
// API token: current problems, hosts, maintenance periods, acknowledging
// and closing problems, and creating or deleting maintenance.
//
// Zabbix 6.4 and later take the token in an Authorization header; 5.4 to
// 6.2 take it in the request's "auth" field. The module reads the version
// (apiinfo.version needs no token) and sends the token the right way.
package zabbix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Zabbix server.
type Config struct {
	URL                string `json:"url"`   // the frontend's address, e.g. https://zabbix.example.com
	Token              string `json:"token"` // secret:// API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	endpoint string
	token    string // secret:// reference
	h        sdk.Host
	http     *http.Client

	mu      sync.Mutex
	seq     int
	version []int
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now is the clock (tests).
	Now func() time.Time
}

// New returns the Zabbix module.
func New() *Module { return &Module{Now: time.Now} }

const maxIDs = 100

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	idRe   = regexp.MustCompile(`^[0-9]{1,20}$`)
)

var severityNames = []string{"not classified", "information", "warning", "average", "high", "disaster"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	events := `"events":{"type":"array","minItems":1,"maxItems":100,"items":{"type":"string","pattern":"^[0-9]{1,20}$"},"description":"Problem event ids (from problems)"}`
	message := `"message":{"type":"string","maxLength":2048,"description":"A message added to the problems' history"}`
	return sdk.Manifest{
		ID: "zabbix", Name: "Zabbix", Version: "0.1.0", Category: "Monitoring", Icon: "bell",
		Description: "Zabbix: current problems, hosts and maintenance; acknowledge or close problems, create or delete maintenance.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The Zabbix frontend's address, e.g. https://zabbix.example.com or https://example.com/zabbix"},
			"token":{"type":"string","x-secret":true,"description":"An API token (Users, API tokens; Zabbix 5.4 or later); it acts with its user's role and host permissions"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "problems", Title: "Problems", Description: "Current problems, newest first: event id, name, severity, hosts, since when, and whether they're acknowledged or suppressed.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{
					"minSeverity":{"type":"string","enum":["not classified","information","warning","average","high","disaster"],"default":"not classified"},
					"acknowledged":{"type":"boolean","description":"Only acknowledged (true) or unacknowledged (false) problems"},
					"hosts":{"type":"array","maxItems":100,"items":{"type":"string","pattern":"^[0-9]{1,20}$"},"description":"Only problems on these host ids"},
					"limit":{"type":"integer","default":50,"minimum":1,"maximum":500}}}`)},
			{Name: "hosts", Title: "Hosts", Description: "Hosts with their visible name, whether they're monitored or in maintenance, groups, and interfaces with availability.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string","description":"Part of the name"},"limit":{"type":"integer","default":100,"minimum":1,"maximum":1000}}}`)},
			{Name: "maintenances", Title: "Maintenance", Description: "Maintenance periods: name, window, whether data is collected, and the hosts and groups they cover.", Risk: sdk.RiskRead},
			{Name: "acknowledge", Title: "Acknowledge problems", Description: "Marks problems as acknowledged, optionally with a message. Acknowledged problems stop escalations that wait for an acknowledgement, so this is destructive. Undo unacknowledges the ones that weren't (the message stays).", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["events"],"properties":{` + events + `,` + message + `}}`)},
			{Name: "unacknowledge", Title: "Unacknowledge problems", Description: "Takes the acknowledgement off problems (Zabbix 5.0 or later). Undo acknowledges them again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["events"],"properties":{` + events + `}}`)},
			{Name: "close_problems", Title: "Close problems", Description: "Closes problems by hand (their triggers must allow manual close), which also stops their escalations. It can't be undone.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["events"],"properties":{` + events + `,` + message + `}}`)},
			{Name: "create_maintenance", Title: "Create maintenance", Description: "Puts hosts or host groups into maintenance for a number of minutes from now, which suppresses their problems and notifications. Undo deletes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["name","minutes"],"properties":{
					"name":{"type":"string","maxLength":128},
					"hosts":{"type":"array","maxItems":100,"items":{"type":"string","pattern":"^[0-9]{1,20}$"},"description":"Host ids (from hosts)"},
					"groups":{"type":"array","maxItems":100,"items":{"type":"string","pattern":"^[0-9]{1,20}$"},"description":"Host group ids"},
					"minutes":{"type":"integer","minimum":5,"maximum":43200},
					"collectData":{"type":"boolean","default":true,"description":"Keep collecting data during the maintenance"},
					"description":{"type":"string","maxLength":1000}}}`)},
			{Name: "delete_maintenance", Title: "Delete maintenance", Description: "Deletes a maintenance period, so its hosts alert normally again.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["maintenance"],"properties":{"maintenance":{"type":"string","pattern":"^[0-9]{1,20}$","description":"Maintenance id (from maintenances)"}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://zabbix.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(strings.TrimSuffix(p, "/api_jsonrpc.php"), "/zabbix.php")
	m.set.Put(id, &conn{endpoint: u.Scheme + "://" + u.Host + p + "/api_jsonrpc.php", token: c.Token, h: h, http: rest.SameHostOnly(client)})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errToken = errors.New("Zabbix refused the API token")

// apiError is an error answer from the API.
type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

func (e *apiError) err() error {
	d := strings.ToLower(e.Data + " " + e.Message)
	switch {
	case strings.Contains(d, "not authori"), strings.Contains(d, "session terminated"), strings.Contains(d, "api token"), strings.Contains(d, "not authenticated"):
		return errToken
	case strings.Contains(d, "no permissions"):
		return errors.New("the token's user isn't allowed to do this in Zabbix, or the object doesn't exist")
	}
	msg := strings.TrimSpace(e.Data)
	if msg == "" {
		msg = strings.TrimSpace(e.Message)
	}
	if i := strings.IndexAny(msg, "\r\n"); i >= 0 {
		msg = msg[:i]
	}
	msg = rest.Redact(msg) // before cutting, so a key at the cut isn't half shown
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return errors.New("Zabbix: " + msg)
}

// rpc calls one method; with auth, it sends the token.
func (c *conn) rpc(ctx context.Context, method string, params, out any, auth bool) error {
	var v []int
	if auth {
		var err error
		if v, err = c.apiVersion(ctx); err != nil {
			return err
		}
	}
	c.mu.Lock()
	c.seq++
	n := c.seq
	c.mu.Unlock()
	req := map[string]any{"jsonrpc": "2.0", "method": method, "params": params, "id": n}
	var tok string
	if auth {
		t, err := c.h.Secret(ctx, c.token)
		if err != nil {
			return err
		}
		tok = strings.TrimSpace(t)
		if !atLeast(v, 6, 4) {
			req["auth"] = tok
		}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json-rpc")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("User-Agent", "Conduit")
	if auth && atLeast(v, 6, 4) {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := c.http.Do(r)
	if err != nil {
		return rest.TransportError(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return err
	}
	switch {
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		return errToken
	case res.StatusCode == http.StatusNotFound:
		return errors.New("no Zabbix API at this address (enter the frontend's address)")
	case res.StatusCode >= 300:
		return fmt.Errorf("Zabbix answered %s", res.Status)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *apiError       `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return errors.New("unexpected answer: is this a Zabbix frontend?")
	}
	if env.Error != nil {
		return env.Error.err()
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("unexpected answer from Zabbix: %w", err)
		}
	}
	return nil
}

func (c *conn) apiVersion(ctx context.Context) ([]int, error) {
	c.mu.Lock()
	v := c.version
	c.mu.Unlock()
	if v != nil {
		return v, nil
	}
	var s string
	if err := c.rpc(ctx, "apiinfo.version", []any{}, &s, false); err != nil {
		return nil, err
	}
	for _, p := range strings.Split(strings.TrimSpace(s), ".") {
		n, _ := strconv.Atoi(p)
		v = append(v, n)
	}
	if len(v) == 0 || v[0] == 0 {
		return nil, errors.New("unexpected answer: is this a Zabbix frontend?")
	}
	c.mu.Lock()
	c.version = v
	c.mu.Unlock()
	return v, nil
}

func atLeast(v []int, want ...int) bool {
	for i, w := range want {
		have := 0
		if i < len(v) {
			have = v[i]
		}
		if have != w {
			return have > w
		}
	}
	return true
}

func vstr(v []int) string {
	var s []string
	for _, n := range v {
		s = append(s, strconv.Itoa(n))
	}
	return strings.Join(s, ".")
}

// count runs a get with countOutput.
func (c *conn) count(ctx context.Context, method string, params map[string]any) (int, error) {
	params["countOutput"] = true
	var s any // "12" (a string) in the answers seen, a number in some versions
	if err := c.rpc(ctx, method, params, &s, true); err != nil {
		return 0, err
	}
	n, _ := strconv.Atoi(fmt.Sprint(s))
	return n, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	v, err := c.apiVersion(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if !atLeast(v, 5, 4) {
		return sdk.Health{Status: "down", Message: "Zabbix " + vstr(v) + " has no API tokens; Conduit needs 5.4 or later"}
	}
	hosts, err := c.count(ctx, "host.get", map[string]any{})
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	probs, err := c.count(ctx, "problem.get", map[string]any{})
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("Zabbix %s · %d hosts, %d problems", vstr(v), hosts, probs)}
}

type input struct {
	MinSeverity  string   `json:"minSeverity"`
	Acknowledged *bool    `json:"acknowledged"`
	Hosts        []string `json:"hosts"`
	Groups       []string `json:"groups"`
	Limit        int      `json:"limit"`
	Query        string   `json:"query"`
	Events       []string `json:"events"`
	Message      string   `json:"message"`
	Name         string   `json:"name"`
	Minutes      int      `json:"minutes"`
	CollectData  *bool    `json:"collectData"`
	Description  string   `json:"description"`
	Maintenance  string   `json:"maintenance"`
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
	case "problems":
		return c.problems(ctx, p)
	case "hosts":
		return c.hosts(ctx, p)
	case "maintenances":
		return c.maintenances(ctx)
	case "acknowledge", "unacknowledge", "close_problems":
		return c.ack(ctx, call, p)
	case "create_maintenance":
		now := time.Now
		if m.Now != nil {
			now = m.Now
		}
		return c.createMaintenance(ctx, call.DryRun, p, now())
	case "delete_maintenance":
		return c.deleteMaintenance(ctx, call.DryRun, p.Maintenance)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func checkIDs(in []string, what string, max int) ([]string, error) {
	if len(in) > max {
		return nil, fmt.Errorf("give at most %d %s", max, what)
	}
	seen := map[string]bool{}
	var out []string
	for _, id := range in {
		id = strings.TrimSpace(id)
		if !idRe.MatchString(id) {
			return nil, fmt.Errorf("%s are numeric ids", what)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

func severity(s string) string {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n >= len(severityNames) {
		return s
	}
	return severityNames[n]
}

func clock(s string) string {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return ""
	}
	return time.Unix(n, 0).UTC().Format(time.RFC3339)
}

type problem struct {
	EventID      string `json:"eventid"`
	ObjectID     string `json:"objectid"`
	Name         string `json:"name"`
	Severity     string `json:"severity"`
	Clock        string `json:"clock"`
	Acknowledged string `json:"acknowledged"`
	Suppressed   string `json:"suppressed"`
	REventID     string `json:"r_eventid"`
}

func (c *conn) problems(ctx context.Context, p input) (sdk.Result, error) {
	min := 0
	if p.MinSeverity != "" {
		min = -1
		for i, n := range severityNames {
			if n == p.MinSeverity {
				min = i
			}
		}
		if min < 0 {
			return sdk.Result{}, fmt.Errorf("unknown severity %q", p.MinSeverity)
		}
	}
	hosts, err := checkIDs(p.Hosts, "hosts", maxIDs)
	if err != nil {
		return sdk.Result{}, err
	}
	limit := p.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	params := map[string]any{"output": []string{"eventid", "objectid", "name", "severity", "clock", "acknowledged", "suppressed"},
		"source": 0, "object": 0, "sortfield": []string{"eventid"}, "sortorder": "DESC", "limit": limit}
	if min > 0 {
		var sev []int
		for i := min; i < len(severityNames); i++ {
			sev = append(sev, i)
		}
		params["severities"] = sev
	}
	if p.Acknowledged != nil {
		params["acknowledged"] = *p.Acknowledged
	}
	if len(hosts) > 0 {
		params["hostids"] = hosts
	}
	var list []problem
	if err := c.rpc(ctx, "problem.get", params, &list, true); err != nil {
		return sdk.Result{}, err
	}
	// Host names come from the problems' triggers.
	hostsOf := map[string][]string{}
	var tids []string
	for _, pr := range list {
		if idRe.MatchString(pr.ObjectID) {
			tids = append(tids, pr.ObjectID)
		}
	}
	if len(tids) > 0 {
		var ts []struct {
			TriggerID string `json:"triggerid"`
			Hosts     []struct {
				Name string `json:"name"`
			} `json:"hosts"`
		}
		if c.rpc(ctx, "trigger.get", map[string]any{"output": []string{"triggerid"}, "triggerids": tids, "selectHosts": []string{"name"}}, &ts, true) == nil {
			for _, t := range ts {
				for _, h := range t.Hosts {
					hostsOf[t.TriggerID] = append(hostsOf[t.TriggerID], h.Name)
				}
			}
		}
	}
	out := []map[string]any{}
	for _, pr := range list {
		hs := hostsOf[pr.ObjectID]
		if hs == nil {
			hs = []string{}
		}
		out = append(out, map[string]any{"event": pr.EventID, "name": pr.Name, "severity": severity(pr.Severity), "since": clock(pr.Clock),
			"acknowledged": pr.Acknowledged == "1", "suppressed": pr.Suppressed == "1", "hosts": hs})
	}
	return sdk.JSON(out)
}

func (c *conn) groupsParam(ctx context.Context) (string, error) {
	v, err := c.apiVersion(ctx)
	if err != nil {
		return "", err
	}
	if atLeast(v, 6, 2) {
		return "selectHostGroups", nil
	}
	return "selectGroups", nil
}

type named struct {
	ID   string `json:"groupid"`
	Name string `json:"name"`
}

func groupNames(gs []named) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, g := range gs {
		if !seen[g.Name] {
			seen[g.Name] = true
			out = append(out, g.Name)
		}
	}
	sort.Strings(out)
	return out
}

func (c *conn) hosts(ctx context.Context, p input) (sdk.Result, error) {
	q := strings.TrimSpace(p.Query)
	if len(q) > 200 || strings.ContainsAny(q, "\r\n\x00") {
		return sdk.Result{}, errors.New("the query is one line of at most 200 characters")
	}
	limit := p.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	gp, err := c.groupsParam(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	params := map[string]any{"output": []string{"hostid", "host", "name", "status", "maintenance_status"},
		gp: []string{"name"}, "selectInterfaces": []string{"ip", "dns", "useip", "port", "type", "main", "available"},
		"sortfield": "name", "limit": limit}
	if q != "" {
		params["search"] = map[string]string{"name": q}
	}
	var hs []struct {
		ID          string  `json:"hostid"`
		Host        string  `json:"host"`
		Name        string  `json:"name"`
		Status      string  `json:"status"`
		Maintenance string  `json:"maintenance_status"`
		Groups      []named `json:"groups"`
		HostGroups  []named `json:"hostgroups"`
		Interfaces  []struct {
			IP        string `json:"ip"`
			DNS       string `json:"dns"`
			UseIP     string `json:"useip"`
			Port      string `json:"port"`
			Type      string `json:"type"`
			Main      string `json:"main"`
			Available string `json:"available"`
		} `json:"interfaces"`
	}
	if err := c.rpc(ctx, "host.get", params, &hs, true); err != nil {
		return sdk.Result{}, err
	}
	types := map[string]string{"1": "agent", "2": "SNMP", "3": "IPMI", "4": "JMX"}
	avail := map[string]string{"0": "unknown", "1": "available", "2": "unavailable"}
	out := []map[string]any{}
	for _, h := range hs {
		ifs := []map[string]any{}
		for _, i := range h.Interfaces {
			addr := i.IP
			if i.UseIP == "0" {
				addr = i.DNS
			}
			e := map[string]any{"type": types[i.Type], "address": addr, "port": i.Port, "main": i.Main == "1"}
			if a, ok := avail[i.Available]; ok {
				e["availability"] = a
			}
			ifs = append(ifs, e)
		}
		out = append(out, map[string]any{"id": h.ID, "host": h.Host, "name": h.Name, "monitored": h.Status == "0", "inMaintenance": h.Maintenance == "1",
			"groups": groupNames(append(h.Groups, h.HostGroups...)), "interfaces": ifs})
	}
	return sdk.JSON(out)
}

type maintenance struct {
	ID          string `json:"maintenanceid"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"maintenance_type"`
	Since       string `json:"active_since"`
	Till        string `json:"active_till"`
	Hosts       []struct {
		Name string `json:"name"`
	} `json:"hosts"`
	Groups     []named `json:"groups"`
	HostGroups []named `json:"hostgroups"`
}

func (mt maintenance) summary() map[string]any {
	hosts := []string{}
	for _, h := range mt.Hosts {
		hosts = append(hosts, h.Name)
	}
	sort.Strings(hosts)
	e := map[string]any{"id": mt.ID, "name": mt.Name, "activeSince": clock(mt.Since), "activeTill": clock(mt.Till),
		"collectsData": mt.Type != "1", "hosts": hosts, "groups": groupNames(append(mt.Groups, mt.HostGroups...))}
	if mt.Description != "" {
		e["description"] = mt.Description
	}
	return e
}

func (c *conn) getMaintenances(ctx context.Context, extra map[string]any) ([]maintenance, error) {
	gp, err := c.groupsParam(ctx)
	if err != nil {
		return nil, err
	}
	params := map[string]any{"output": []string{"maintenanceid", "name", "description", "maintenance_type", "active_since", "active_till"},
		"selectHosts": []string{"name"}, gp: []string{"name"}, "sortfield": "name"}
	for k, v := range extra {
		params[k] = v
	}
	var ms []maintenance
	err = c.rpc(ctx, "maintenance.get", params, &ms, true)
	return ms, err
}

func (c *conn) maintenances(ctx context.Context) (sdk.Result, error) {
	ms, err := c.getMaintenances(ctx, nil)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, mt := range ms {
		out = append(out, mt.summary())
	}
	return sdk.JSON(out)
}

func checkText(s, what string, max int, multiline bool) (string, error) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max || strings.ContainsRune(s, 0) || (!multiline && strings.ContainsAny(s, "\r\n")) {
		return "", fmt.Errorf("the %s is at most %d characters", what, max)
	}
	return s, nil
}

func (c *conn) ack(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	ids, err := checkIDs(p.Events, "events", maxIDs)
	if err != nil {
		return sdk.Result{}, err
	}
	if len(ids) == 0 {
		return sdk.Result{}, errors.New("pick the problems (event ids from problems)")
	}
	msg, err := checkText(p.Message, "message", 2048, true)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.Action == "unacknowledge" {
		msg = ""
	}
	var evs []struct {
		EventID      string `json:"eventid"`
		Name         string `json:"name"`
		Acknowledged string `json:"acknowledged"`
		REventID     string `json:"r_eventid"`
	}
	if err := c.rpc(ctx, "event.get", map[string]any{"eventids": ids, "output": []string{"eventid", "name", "acknowledged", "r_eventid"}, "source": 0, "object": 0}, &evs, true); err != nil {
		return sdk.Result{}, err
	}
	byID := map[string]int{}
	for i, e := range evs {
		byID[e.EventID] = i
	}
	var change []string
	var changes []sdk.Change
	for _, id := range ids {
		i, ok := byID[id]
		if !ok {
			return sdk.Result{}, fmt.Errorf("there's no problem event %s", id)
		}
		e := evs[i]
		acked, resolved := e.Acknowledged == "1", e.REventID != "" && e.REventID != "0"
		var skip bool
		switch call.Action {
		case "acknowledge":
			skip = acked && msg == ""
		case "unacknowledge":
			skip = !acked
		case "close_problems":
			skip = resolved
		}
		if skip {
			continue
		}
		change = append(change, id)
		b, _ := json.Marshal(map[string]bool{"acknowledged": acked, "resolved": resolved})
		changes = append(changes, sdk.Change{Target: fmt.Sprintf("%s (event %s)", e.Name, id), Op: strings.TrimSuffix(call.Action, "_problems"), Before: b})
	}
	if len(change) == 0 {
		return sdk.JSON(map[string]any{"changed": []string{}, "note": "nothing to change"})
	}
	v, err := c.apiVersion(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	action := 0
	verb := ""
	switch call.Action {
	case "acknowledge":
		action, verb = 2, "Acknowledge"
	case "unacknowledge":
		if !atLeast(v, 5, 0) {
			return sdk.Result{}, errors.New("unacknowledging needs Zabbix 5.0 or later")
		}
		action, verb = 16, "Unacknowledge"
	case "close_problems":
		action, verb = 1, "Close"
	}
	if msg != "" {
		action |= 4
	}
	if call.DryRun {
		sum := fmt.Sprintf("%s %d problems", verb, len(change))
		if msg != "" {
			sum += " with a message"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: changes}}, nil
	}
	params := map[string]any{"eventids": change, "action": action}
	if msg != "" {
		params["message"] = msg
	}
	if err := c.rpc(ctx, "event.acknowledge", params, nil, true); err != nil {
		if call.Action == "close_problems" && strings.Contains(strings.ToLower(err.Error()), "manual") {
			return sdk.Result{}, errors.New("Zabbix won't close these by hand: their triggers don't allow manual close")
		}
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"changed": change})
	var newlyAcked []string
	for _, id := range change {
		if evs[byID[id]].Acknowledged != "1" {
			newlyAcked = append(newlyAcked, id)
		}
	}
	switch {
	case call.Action == "acknowledge" && len(newlyAcked) > 0 && atLeast(v, 5, 0):
		res.Undo = sdk.UndoWith("unacknowledge", map[string]any{"events": newlyAcked}, fmt.Sprintf("Unacknowledge %d problems", len(newlyAcked)))
	case call.Action == "unacknowledge":
		res.Undo = sdk.UndoWith("acknowledge", map[string]any{"events": change}, fmt.Sprintf("Acknowledge %d problems again", len(change)))
	}
	return res, err
}

func (c *conn) createMaintenance(ctx context.Context, dry bool, p input, now time.Time) (sdk.Result, error) {
	name, err := checkText(p.Name, "name", 128, false)
	if err != nil {
		return sdk.Result{}, err
	}
	if name == "" {
		return sdk.Result{}, errors.New("give the maintenance a name")
	}
	desc, err := checkText(p.Description, "description", 1000, true)
	if err != nil {
		return sdk.Result{}, err
	}
	hosts, err := checkIDs(p.Hosts, "hosts", maxIDs)
	if err != nil {
		return sdk.Result{}, err
	}
	groups, err := checkIDs(p.Groups, "groups", maxIDs)
	if err != nil {
		return sdk.Result{}, err
	}
	if len(hosts)+len(groups) == 0 {
		return sdk.Result{}, errors.New("give the hosts or host groups to put in maintenance")
	}
	if p.Minutes < 5 || p.Minutes > 43200 {
		return sdk.Result{}, errors.New("minutes is 5 to 43200 (30 days)")
	}
	collect := p.CollectData == nil || *p.CollectData
	// Name what's covered, which also checks the ids exist.
	var hostNames, groupNames []string
	if len(hosts) > 0 {
		var hs []struct {
			ID   string `json:"hostid"`
			Name string `json:"name"`
		}
		if err := c.rpc(ctx, "host.get", map[string]any{"output": []string{"hostid", "name"}, "hostids": hosts}, &hs, true); err != nil {
			return sdk.Result{}, err
		}
		got := map[string]string{}
		for _, h := range hs {
			got[h.ID] = h.Name
		}
		for _, id := range hosts {
			if got[id] == "" {
				return sdk.Result{}, fmt.Errorf("there's no host %s", id)
			}
			hostNames = append(hostNames, got[id])
		}
	}
	if len(groups) > 0 {
		var gs []named
		if err := c.rpc(ctx, "hostgroup.get", map[string]any{"output": []string{"groupid", "name"}, "groupids": groups}, &gs, true); err != nil {
			return sdk.Result{}, err
		}
		got := map[string]string{}
		for _, g := range gs {
			got[g.ID] = g.Name
		}
		for _, id := range groups {
			if got[id] == "" {
				return sdk.Result{}, fmt.Errorf("there's no host group %s", id)
			}
			groupNames = append(groupNames, got[id])
		}
	}
	existing, err := c.getMaintenances(ctx, map[string]any{"filter": map[string]string{"name": name}})
	if err != nil {
		return sdk.Result{}, err
	}
	if len(existing) > 0 {
		return sdk.Result{}, fmt.Errorf("a maintenance named %q already exists (id %s)", name, existing[0].ID)
	}
	start := now.Unix() / 60 * 60
	till := start + int64(p.Minutes)*60
	if dry {
		a, _ := json.Marshal(map[string]any{"hosts": hostNames, "groups": groupNames, "from": time.Unix(start, 0).UTC().Format(time.RFC3339),
			"till": time.Unix(till, 0).UTC().Format(time.RFC3339), "collectsData": collect})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Put %s in maintenance for %d minutes", strings.Join(append(hostNames, groupNames...), ", "), p.Minutes),
			Changes: []sdk.Change{{Target: "maintenance " + name, Op: "create", After: a}}}}, nil
	}
	v, err := c.apiVersion(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	typ := 0
	if !collect {
		typ = 1
	}
	params := map[string]any{"name": name, "active_since": start, "active_till": till, "maintenance_type": typ,
		"timeperiods": []map[string]any{{"timeperiod_type": 0, "start_date": start, "period": int64(p.Minutes) * 60}}}
	if desc != "" {
		params["description"] = desc
	}
	if atLeast(v, 6, 0) {
		var hs, gs []map[string]string
		for _, id := range hosts {
			hs = append(hs, map[string]string{"hostid": id})
		}
		for _, id := range groups {
			gs = append(gs, map[string]string{"groupid": id})
		}
		if len(hs) > 0 {
			params["hosts"] = hs
		}
		if len(gs) > 0 {
			params["groups"] = gs
		}
	} else {
		if len(hosts) > 0 {
			params["hostids"] = hosts
		}
		if len(groups) > 0 {
			params["groupids"] = groups
		}
	}
	var got struct {
		IDs []string `json:"maintenanceids"`
	}
	if err := c.rpc(ctx, "maintenance.create", params, &got, true); err != nil {
		return sdk.Result{}, err
	}
	if len(got.IDs) != 1 || !idRe.MatchString(got.IDs[0]) {
		return sdk.Result{}, errors.New("unexpected answer from Zabbix: no maintenance id")
	}
	res, err := sdk.JSON(map[string]any{"maintenance": got.IDs[0], "name": name, "till": time.Unix(till, 0).UTC().Format(time.RFC3339)})
	res.Undo = sdk.UndoWith("delete_maintenance", map[string]string{"maintenance": got.IDs[0]}, "Delete the maintenance "+name)
	return res, err
}

func (c *conn) deleteMaintenance(ctx context.Context, dry bool, id string) (sdk.Result, error) {
	id = strings.TrimSpace(id)
	if !idRe.MatchString(id) {
		return sdk.Result{}, errors.New("a maintenance is its id from maintenances")
	}
	ms, err := c.getMaintenances(ctx, map[string]any{"maintenanceids": []string{id}})
	if err != nil {
		return sdk.Result{}, err
	}
	if len(ms) != 1 || ms[0].ID != id {
		return sdk.Result{}, fmt.Errorf("there's no maintenance %s", id)
	}
	if dry {
		b, _ := json.Marshal(ms[0].summary())
		return sdk.Result{Plan: &sdk.Plan{Summary: "Delete the maintenance " + ms[0].Name, Changes: []sdk.Change{{Target: "maintenance " + ms[0].Name, Op: "delete", Before: b}}}}, nil
	}
	if err := c.rpc(ctx, "maintenance.delete", []string{id}, nil, true); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"deleted": id, "name": ms[0].Name})
}
