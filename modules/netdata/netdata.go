// Package netdata works with a Netdata agent or parent through its v1 and
// v2 APIs: the node's system info, active alarms, charts and their latest
// values, the nodes a parent streams, and silencing alarm notifications
// through the health management API.
package netdata

import (
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
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Netdata agent (or parent).
type Config struct {
	URL                string `json:"url"`           // default http://localhost:19999
	Token              string `json:"token"`         // optional secret:// bearer token, for an agent that requires one
	ManagementKey      string `json:"managementKey"` // optional secret:// health management API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	h      sdk.Host
	mgmKey string // secret:// reference, or ""
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Netdata module.
func New() *Module { return &Module{} }

var (
	pathRe     = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	chartRe    = regexp.MustCompile(`^[A-Za-z0-9_.@:-]{1,200}$`)
	selectorRe = regexp.MustCompile(`^[A-Za-z0-9_.*!:@/ -]{1,200}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	selectors := `"alarm":{"type":"string","description":"Alarm name pattern, e.g. *10min_cpu*"},"chart":{"type":"string","description":"Chart id pattern, e.g. disk_space.*"},"context":{"type":"string","description":"Chart context pattern"},"host":{"type":"string","description":"Host name pattern (on a parent)"}`
	return sdk.Manifest{
		ID: "netdata", Name: "Netdata", Version: "0.1.0", Category: "Monitoring", Icon: "pulse",
		Description: "Netdata: system info, active alarms, charts and their latest values, streamed nodes, and silencing alarm notifications.",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"url":{"type":"string","default":"http://localhost:19999","description":"The agent's (or parent's) address, e.g. http://server.lan:19999"},
			"token":{"type":"string","x-secret":true,"description":"Bearer token, only for an agent that requires one (sent as Authorization: Bearer)"},
			"managementKey":{"type":"string","x-secret":true,"description":"Health management API key (the contents of /var/lib/netdata/netdata.api.key), needed to list or change silencers"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "info", Title: "Node info", Description: "Netdata version, OS, kernel, architecture, CPU cores, memory and disk, virtualization, alarm counts and streamed hosts.", Risk: sdk.RiskRead},
			{Name: "alarms", Title: "Alarms", Description: "Raised alarms (warning and critical), or all of them: name, chart, status, value, since when, what it means, and whether it's silenced.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"all":{"type":"boolean","default":false,"description":"Also list alarms in the clear"},"status":{"type":"string","enum":["CRITICAL","WARNING","CLEAR","UNDEFINED","UNINITIALIZED"]}}}`)},
			{Name: "charts", Title: "Charts", Description: "Charts the node collects: id, title, units, context and family; filter by part of the id, title or context.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","default":100,"minimum":1,"maximum":1000}}}`)},
			{Name: "metric", Title: "Latest values", Description: "One chart's dimensions averaged over the last seconds (default 60), with its title and units.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["chart"],"properties":{"chart":{"type":"string","description":"Chart id (from charts), e.g. system.cpu"},"seconds":{"type":"integer","default":60,"minimum":1,"maximum":86400}}}`)},
			{Name: "nodes", Title: "Nodes", Description: "The nodes this agent knows (itself and any it receives streams from, on a parent): name, id, state and version.", Risk: sdk.RiskRead},
			{Name: "silencers", Title: "Silencers", Description: "Whether alarm notifications are silenced or checks disabled through the management API, and by which selectors. Needs the management key.", Risk: sdk.RiskRead},
			{Name: "silence", Title: "Silence alarms", Description: "Stops notifications for every alarm (all) or for the alarms matching the selectors; the checks keep running. Undo removes the silencing when there was none before.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"all":{"type":"boolean","default":false,"description":"Silence every alarm"},` + selectors + `}}`)},
			{Name: "unsilence", Title: "Unsilence alarms", Description: "Removes every silencer (and any disabling) set through the management API, so all alarms notify again. Undo puts back a single previous silencer.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = "http://localhost:19999"
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like http://server.lan:19999")
	}
	for _, s := range []string{c.Token, c.ManagementKey} {
		if s != "" && !strings.HasPrefix(s, "secret://") {
			return errors.New("store the token and management key in the vault and enter their secret:// references")
		}
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
	base := strings.TrimRight(u.Path, "/")
	for _, s := range []string{"/api/v1", "/api/v2", "/api"} {
		base = strings.TrimSuffix(base, s)
	}
	api := rest.New(u.Scheme+"://"+u.Host+base, func(ctx context.Context, r *http.Request) error {
		if ref == "" {
			return nil
		}
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, h: h, mgmKey: c.ManagementKey})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Netdata refused the request (check the bearer token)")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err)
}

// flex is a number Netdata sends as a number or a string.
type flex string

func (f *flex) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" {
		s = ""
	}
	*f = flex(s)
	return nil
}

func (f flex) int() int64 {
	n, _ := strconv.ParseFloat(string(f), 64)
	return int64(n)
}

type info struct {
	Version     string `json:"version"`
	OSName      string `json:"os_name"`
	OSVersion   string `json:"os_version"`
	Kernel      string `json:"kernel_name"`
	KernelVer   string `json:"kernel_version"`
	Arch        string `json:"architecture"`
	Virt        string `json:"virtualization"`
	Container   string `json:"container"`
	Cores       flex   `json:"cores_total"`
	RAM         flex   `json:"ram_total"`
	Disk        flex   `json:"total_disk_space"`
	Mirrored    []any  `json:"mirrored_hosts"`
	MirroredSts []struct {
		Hostname  string `json:"hostname"`
		Reachable bool   `json:"reachable"`
	} `json:"mirrored_hosts_status"`
	Alarms struct {
		Normal   int `json:"normal"`
		Warning  int `json:"warning"`
		Critical int `json:"critical"`
	} `json:"alarms"`
	Collectors []any `json:"collectors"`
	// The machine GUID, host labels and Cloud claim details aren't decoded.
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var in info
	if err := c.get(ctx, "/api/v1/info", nil, &in); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Netdata API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if in.Version == "" {
		return sdk.Health{Status: "down", Message: "unexpected answer: is this Netdata?"}
	}
	msg := fmt.Sprintf("Netdata %s · %d critical, %d warning alarms", in.Version, in.Alarms.Critical, in.Alarms.Warning)
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	All     bool   `json:"all"`
	Status  string `json:"status"`
	Query   string `json:"query"`
	Limit   int    `json:"limit"`
	Chart   string `json:"chart"`
	Seconds int    `json:"seconds"`
	Alarm   string `json:"alarm"`
	Context string `json:"context"`
	Host    string `json:"host"`
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
	case "info":
		var in info
		if err := c.get(ctx, "/api/v1/info", nil, &in); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"version": in.Version, "os": strings.TrimSpace(in.OSName + " " + in.OSVersion), "kernel": strings.TrimSpace(in.Kernel + " " + in.KernelVer),
			"architecture": in.Arch, "virtualization": in.Virt, "container": in.Container, "cores": in.Cores.int(),
			"memoryGB": float64(in.RAM.int()>>20) / 1024, "alarms": map[string]int{"normal": in.Alarms.Normal, "warning": in.Alarms.Warning, "critical": in.Alarms.Critical},
			"collectors": len(in.Collectors), "hosts": len(in.Mirrored)}
		if d := in.Disk.int(); d > 0 {
			out["diskGB"] = d >> 30
		}
		return sdk.JSON(out)
	case "alarms":
		return c.alarms(ctx, p)
	case "charts":
		return c.charts(ctx, p)
	case "metric":
		return c.metric(ctx, p)
	case "nodes":
		return c.nodes(ctx)
	case "silencers":
		l, err := c.listSilencers(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"all": l.All, "type": l.kind(), "silencers": l.Silencers})
	case "silence":
		return c.silence(ctx, call.DryRun, p)
	case "unsilence":
		return c.unsilence(ctx, call.DryRun)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type alarm struct {
	ID       int64   `json:"id"`
	Name     string  `json:"name"`
	Chart    string  `json:"chart"`
	Family   string  `json:"family"`
	Status   string  `json:"status"`
	Value    *string `json:"value_string"`
	Units    string  `json:"units"`
	Info     string  `json:"info"`
	Summary  string  `json:"summary"`
	Since    int64   `json:"last_status_change"`
	Silenced bool    `json:"silenced"`
	Disabled bool    `json:"disabled"`
	// The recipient (often an address) and the config source aren't read.
}

var severity = map[string]int{"CRITICAL": 0, "WARNING": 1, "CLEAR": 2, "UNDEFINED": 3, "UNINITIALIZED": 4, "REMOVED": 5}

func (c *conn) alarms(ctx context.Context, p input) (sdk.Result, error) {
	if p.Status != "" {
		if _, ok := severity[p.Status]; !ok || p.Status == "REMOVED" {
			return sdk.Result{}, fmt.Errorf("unknown status %q", p.Status)
		}
	}
	q := url.Values{}
	if p.All || (p.Status != "" && p.Status != "CRITICAL" && p.Status != "WARNING") {
		q.Set("all", "true")
	}
	var got struct {
		Hostname string           `json:"hostname"`
		Alarms   map[string]alarm `json:"alarms"`
	}
	if err := c.get(ctx, "/api/v1/alarms", q, &got); err != nil {
		return sdk.Result{}, err
	}
	var list []alarm
	for _, a := range got.Alarms {
		if p.Status == "" || a.Status == p.Status {
			list = append(list, a)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if severity[list[i].Status] != severity[list[j].Status] {
			return severity[list[i].Status] < severity[list[j].Status]
		}
		return list[i].Chart+"."+list[i].Name < list[j].Chart+"."+list[j].Name
	})
	out := []map[string]any{}
	for _, a := range list {
		e := map[string]any{"name": a.Name, "chart": a.Chart, "status": a.Status, "silenced": a.Silenced, "disabled": a.Disabled}
		if a.Value != nil {
			e["value"] = *a.Value
		}
		if a.Since > 0 {
			e["since"] = time.Unix(a.Since, 0).UTC().Format(time.RFC3339)
		}
		if a.Summary != "" {
			e["summary"] = a.Summary
		}
		if a.Info != "" {
			e["info"] = a.Info
		}
		if a.Family != "" {
			e["family"] = a.Family
		}
		out = append(out, e)
	}
	return sdk.JSON(map[string]any{"host": got.Hostname, "count": len(out), "alarms": out})
}

type chart struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Units   string `json:"units"`
	Context string `json:"context"`
	Family  string `json:"family"`
	Type    string `json:"type"`
	Every   int    `json:"update_every"`
}

func (c *conn) charts(ctx context.Context, p input) (sdk.Result, error) {
	needle := strings.ToLower(strings.TrimSpace(p.Query))
	if len(needle) > 200 {
		return sdk.Result{}, errors.New("the query is at most 200 characters")
	}
	limit := p.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var got struct {
		Charts map[string]chart `json:"charts"`
	}
	if err := c.get(ctx, "/api/v1/charts", nil, &got); err != nil {
		return sdk.Result{}, err
	}
	var list []chart
	for id, ch := range got.Charts {
		if ch.ID == "" {
			ch.ID = id
		}
		if needle == "" || strings.Contains(strings.ToLower(ch.ID+"\n"+ch.Title+"\n"+ch.Context), needle) {
			list = append(list, ch)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	out := []map[string]any{}
	for i, ch := range list {
		if i >= limit {
			break
		}
		out = append(out, map[string]any{"id": ch.ID, "title": ch.Title, "units": ch.Units, "context": ch.Context, "family": ch.Family, "everySeconds": ch.Every})
	}
	return sdk.JSON(map[string]any{"total": len(list), "charts": out})
}

func (c *conn) metric(ctx context.Context, p input) (sdk.Result, error) {
	id := strings.TrimSpace(p.Chart)
	if !chartRe.MatchString(id) {
		return sdk.Result{}, errors.New("a chart is its id from charts, e.g. system.cpu")
	}
	secs := p.Seconds
	if secs == 0 {
		secs = 60
	}
	if secs < 1 || secs > 86400 {
		return sdk.Result{}, errors.New("seconds is 1 to 86400")
	}
	var ch chart
	if err := c.get(ctx, "/api/v1/chart", url.Values{"chart": {id}}, &ch); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusBadRequest) {
			return sdk.Result{}, fmt.Errorf("there's no chart %s", id)
		}
		return sdk.Result{}, err
	}
	var data struct {
		Labels []string    `json:"labels"`
		Data   [][]float64 `json:"data"`
	}
	q := url.Values{"chart": {id}, "after": {strconv.Itoa(-secs)}, "points": {"1"}, "group": {"average"}, "format": {"json"}, "options": {"null2zero"}}
	if err := c.get(ctx, "/api/v1/data", q, &data); err != nil {
		return sdk.Result{}, err
	}
	values := map[string]float64{}
	if len(data.Data) > 0 {
		row := data.Data[0]
		for i, l := range data.Labels {
			if i == 0 || i >= len(row) {
				continue // the first column is the time
			}
			values[l] = float64(int64(row[i]*1000)) / 1000
		}
	}
	return sdk.JSON(map[string]any{"chart": id, "title": ch.Title, "units": ch.Units, "seconds": secs, "values": values})
}

func (c *conn) nodes(ctx context.Context) (sdk.Result, error) {
	var got struct {
		Nodes []struct {
			Name    string `json:"nm"`
			ID      string `json:"nd"`
			Index   int    `json:"ni"`
			Version string `json:"v"`
			State   string `json:"state"`
			Hops    *int   `json:"hops"`
		} `json:"nodes"`
	}
	err := c.get(ctx, "/api/v2/nodes", nil, &got)
	if rest.IsStatus(err, http.StatusNotFound) {
		// An agent before v2: the streamed hosts from v1 info.
		var in info
		if err := c.get(ctx, "/api/v1/info", nil, &in); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, h := range in.MirroredSts {
			out = append(out, map[string]any{"name": h.Hostname, "reachable": h.Reachable})
		}
		return sdk.JSON(map[string]any{"api": 1, "nodes": out})
	}
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, n := range got.Nodes {
		e := map[string]any{"name": n.Name, "index": n.Index}
		for k, v := range map[string]string{"id": n.ID, "version": n.Version, "state": n.State} {
			if v != "" {
				e[k] = v
			}
		}
		if n.Hops != nil {
			e["hops"] = *n.Hops
		}
		out = append(out, e)
	}
	return sdk.JSON(map[string]any{"api": 2, "nodes": out})
}

// silencers is the health management API's LIST answer.
type silencers struct {
	All       bool                `json:"all"`
	Type      string              `json:"type"`
	Silencers []map[string]string `json:"silencers"`
}

func (l silencers) kind() string {
	switch strings.ToUpper(l.Type) {
	case "SILENCE":
		return "silence"
	case "DISABLE":
		return "disable"
	}
	return "none"
}

func (l silencers) empty() bool { return !l.All && len(l.Silencers) == 0 }

var errNoKey = errors.New("this needs the health management API key: add managementKey to the instance's settings")

// manage sends one health management command.
func (c *conn) manage(ctx context.Context, q url.Values, out any) error {
	if c.mgmKey == "" {
		return errNoKey
	}
	k, err := c.h.Secret(ctx, c.mgmKey)
	if err != nil {
		return err
	}
	res, err := c.api.Send(ctx, http.MethodGet, "/api/v1/manage/health", q, nil, http.Header{"X-Auth-Token": {strings.TrimSpace(k)}})
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Netdata refused the management key")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("this Netdata has no health management API")
	case err != nil:
		return friendly(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("Netdata answered %s", res.Status)
	}
	if t := strings.ToLower(string(raw)); strings.Contains(t, "auth error") || strings.Contains(t, "not allowed") {
		return errors.New("Netdata refused the management key")
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return errors.New("unexpected answer from Netdata's health management API")
		}
	}
	return nil
}

func (c *conn) listSilencers(ctx context.Context) (silencers, error) {
	var l silencers
	err := c.manage(ctx, url.Values{"cmd": {"LIST"}}, &l)
	return l, err
}

func (p input) selectors() (map[string]string, error) {
	sel := map[string]string{}
	for k, v := range map[string]string{"alarm": p.Alarm, "chart": p.Chart, "context": p.Context, "host": p.Host} {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !selectorRe.MatchString(v) {
			return nil, fmt.Errorf("the %s selector is a Netdata pattern of letters, digits and _ . - * ! : @ / (at most 200 characters)", k)
		}
		sel[k] = v
	}
	return sel, nil
}

func sameSelectors(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func describe(all bool, sel map[string]string) string {
	if all {
		return "all alarms"
	}
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+sel[k])
	}
	return "alarms matching " + strings.Join(parts, ", ")
}

func (c *conn) silence(ctx context.Context, dry bool, p input) (sdk.Result, error) {
	sel, err := p.selectors()
	if err != nil {
		return sdk.Result{}, err
	}
	if p.All == (len(sel) > 0) {
		return sdk.Result{}, errors.New("give all, or at least one of alarm, chart, context and host")
	}
	if c.mgmKey == "" {
		return sdk.Result{}, errNoKey
	}
	before, err := c.listSilencers(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	if before.kind() == "silence" {
		if p.All && before.All {
			return sdk.JSON(map[string]any{"silenced": "all alarms", "note": "nothing to change"})
		}
		for _, s := range before.Silencers {
			if !p.All && sameSelectors(s, sel) {
				return sdk.JSON(map[string]any{"silenced": describe(false, sel), "note": "nothing to change"})
			}
		}
	}
	what := describe(p.All, sel)
	if dry {
		b, _ := json.Marshal(map[string]any{"type": before.kind(), "all": before.All, "silencers": len(before.Silencers)})
		ops := "silence notifications"
		if before.kind() == "disable" {
			ops += " (existing disabled checks become silenced instead)"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: "Silence " + what, Changes: []sdk.Change{{Target: what, Op: ops, Before: b}}}}, nil
	}
	q := url.Values{"cmd": {"SILENCE"}}
	if p.All {
		q.Set("cmd", "SILENCE ALL")
	}
	for k, v := range sel {
		q.Set(k, v)
	}
	if err := c.manage(ctx, q, nil); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"silenced": what}
	res, err := sdk.JSON(out)
	if before.empty() {
		res.Undo = sdk.UndoWith("unsilence", map[string]any{}, "Let all alarms notify again")
	}
	return res, err
}

func (c *conn) unsilence(ctx context.Context, dry bool) (sdk.Result, error) {
	if c.mgmKey == "" {
		return sdk.Result{}, errNoKey
	}
	before, err := c.listSilencers(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	if before.empty() {
		return sdk.JSON(map[string]any{"silencers": 0, "note": "nothing to change"})
	}
	if dry {
		b, _ := json.Marshal(map[string]any{"type": before.kind(), "all": before.All, "silencers": before.Silencers})
		a, _ := json.Marshal(map[string]any{"type": "none"})
		return sdk.Result{Plan: &sdk.Plan{Summary: "Remove every Netdata silencer", Changes: []sdk.Change{{Target: "health management silencers", Op: "reset", Before: b, After: a}}}}, nil
	}
	if err := c.manage(ctx, url.Values{"cmd": {"RESET"}}, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"removed": len(before.Silencers), "wasAll": before.All})
	// Undo puts back what can be put back exactly: silence all, or one
	// silencer.
	if before.kind() == "silence" {
		switch {
		case before.All && len(before.Silencers) == 0:
			res.Undo = sdk.UndoWith("silence", map[string]any{"all": true}, "Silence all alarms again")
		case !before.All && len(before.Silencers) == 1:
			in := map[string]any{}
			ok := true
			for k, v := range before.Silencers[0] {
				if (k != "alarm" && k != "chart" && k != "context" && k != "host") || !selectorRe.MatchString(v) {
					ok = false
				}
				in[k] = v
			}
			if ok && len(in) > 0 {
				res.Undo = sdk.UndoWith("silence", in, "Silence those alarms again")
			}
		}
	}
	return res, err
}
