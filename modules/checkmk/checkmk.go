// Package checkmk works with a Checkmk site through its REST API and an
// automation user: hosts and services with their states, current problems,
// downtimes, acknowledging problems, and scheduling or ending downtimes.
package checkmk

import (
	"context"
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
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Checkmk site.
type Config struct {
	URL                string `json:"url"`      // the site's address, e.g. https://monitor.example.com/mysite
	Username           string `json:"username"` // automation user
	Secret             string `json:"secret"`   // secret:// automation secret
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	now  func() time.Time
}

// New returns the Checkmk module.
func New() *Module { return &Module{now: time.Now} }

var (
	pathRe = regexp.MustCompile(`^/[A-Za-z0-9/._~-]+$`)
	userRe = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
	hostRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,252}$`)
	siteRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,16}$`)
	dtRe   = regexp.MustCompile(`^[0-9]{1,12}$`)
)

// Limits.
const (
	maxRows     = 1000
	maxDowntime = 30 * 24 * 60 // minutes
	maxComment  = 1000
	maxOutput   = 500 // characters of a check's output
)

var (
	hostStates    = []string{"UP", "DOWN", "UNREACHABLE"}
	serviceStates = []string{"OK", "WARN", "CRIT", "UNKNOWN"}
)

func stateName(names []string, n int) string {
	if n >= 0 && n < len(names) {
		return names[n]
	}
	return strconv.Itoa(n)
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	target := `"host":{"type":"string","description":"Host name"},"service":{"type":"string","description":"Service description, e.g. CPU load (leave out for the host itself)"}`
	return sdk.Manifest{
		ID: "checkmk", Name: "Checkmk", Version: "0.1.0", Category: "Monitoring", Icon: "check",
		Description: "Checkmk: hosts and services with their states, current problems and downtimes; acknowledge problems, schedule or end downtimes.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","secret"],"properties":{
			"url":{"type":"string","description":"The site's address, e.g. https://monitor.example.com/mysite"},
			"username":{"type":"string","description":"An automation user (Setup, Users), e.g. automation"},
			"secret":{"type":"string","x-secret":true,"description":"That user's automation secret"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "hosts", Title: "Hosts", Description: "Monitored hosts, at most 1000: name, address, state (UP, DOWN, UNREACHABLE), output, acknowledged, in downtime, and how many services are WARN, CRIT or UNKNOWN. Only problem hosts when asked.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"problemsOnly":{"type":"boolean","default":false}}}`)},
			{Name: "services", Title: "Services", Description: "One host's services: description, state (OK, WARN, CRIT, UNKNOWN), output, since when, acknowledged and in downtime.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["host"],"properties":{"host":{"type":"string"}}}`)},
			{Name: "problems", Title: "Problems", Description: "Hosts that are down or unreachable and services that aren't OK, worst first, at most 1000 each. Acknowledged ones and those in downtime too, unless left out.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"unhandledOnly":{"type":"boolean","default":false,"description":"Leave out acknowledged problems and those in downtime"}}}`)},
			{Name: "downtimes", Title: "Downtimes", Description: "Scheduled downtimes: id, site, host, service, start, end, author and comment. Filter by host.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"host":{"type":"string"}}}`)},
			{Name: "acknowledge", Title: "Acknowledge a problem", Description: "Acknowledges a host or service problem with a comment, which stops its further notifications until the state changes (or, when sticky, until it's OK). Hiding a problem can hide an outage, so this is destructive. There's no undo: remove the acknowledgement in Checkmk.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["host","comment"],"properties":{` + target + `,"comment":{"type":"string"},"sticky":{"type":"boolean","default":true,"description":"Keep it until the host or service is OK, not just until the next state change"},"notify":{"type":"boolean","default":false,"description":"Notify the contacts about the acknowledgement"}}}`)},
			{Name: "schedule_downtime", Title: "Schedule a downtime", Description: "Puts a host (with its services) or one service into downtime from now for 1 minute to 30 days, which suppresses its notifications. Destructive, since it can hide an outage. Undo ends the downtime.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["host","comment"],"properties":{` + target + `,"durationMinutes":{"type":"integer","minimum":1,"maximum":43200,"default":60},"comment":{"type":"string"}}}`)},
			{Name: "end_downtime", Title: "End a downtime", Description: "Ends a downtime now, so its host or service notifies again. Undo schedules it again for the time it had left (when it had started).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id","site"],"properties":{"id":{"type":"string","description":"Downtime id (from downtimes)"},"site":{"type":"string","description":"Its site id (from downtimes)"}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is the site's, like https://monitor.example.com/mysite")
	}
	path := strings.TrimRight(u.Path, "/")
	path = strings.TrimSuffix(path, "/check_mk/api/1.0")
	path = strings.TrimSuffix(path, "/check_mk")
	if !pathRe.MatchString(path) {
		return errors.New("the address ends in the site's name, like https://monitor.example.com/mysite")
	}
	c.Username = strings.TrimSpace(c.Username)
	if !userRe.MatchString(c.Username) {
		return errors.New("enter the automation user's name")
	}
	if !strings.HasPrefix(c.Secret, "secret://") {
		return errors.New("store the automation secret in the vault and enter its secret:// reference")
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
	user, ref := c.Username, c.Secret
	api := rest.New(u.Scheme+"://"+u.Host+path+"/check_mk/api/1.0", func(ctx context.Context, r *http.Request) error {
		s, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+user+" "+strings.TrimSpace(s))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Checkmk refused the automation user or secret")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the automation user isn't allowed to do this in Checkmk")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Site     string `json:"site"`
		Edition  string `json:"edition"`
		Versions struct {
			Checkmk string `json:"checkmk"`
		} `json:"versions"`
	}
	if err := c.do(ctx, http.MethodGet, "/version", nil, nil, &v); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Checkmk REST API at this address (it ends in the site's name)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "site " + v.Site + " · Checkmk " + v.Versions.Checkmk
	if v.Edition != "" {
		msg += " (" + v.Edition + ")"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Livestatus filters, sent as JSON in the query parameter (never as text).
type expr map[string]any

func eq(col string, v any) expr { return expr{"op": "=", "left": col, "right": v} }
func ne(col string, v any) expr { return expr{"op": "!=", "left": col, "right": v} }
func and(es ...expr) expr {
	if len(es) == 1 {
		return es[0]
	}
	return expr{"op": "and", "expr": es}
}

type hostRow struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	State      int    `json:"state"`
	Output     string `json:"plugin_output"`
	Acked      int    `json:"acknowledged"`
	Downtime   int    `json:"scheduled_downtime_depth"`
	Since      int64  `json:"last_state_change"`
	Warn       int    `json:"num_services_warn"`
	Crit       int    `json:"num_services_crit"`
	Unknown    int    `json:"num_services_unknown"`
	HasChecked int    `json:"has_been_checked"`
}

type serviceRow struct {
	Host     string `json:"host_name"`
	Desc     string `json:"description"`
	State    int    `json:"state"`
	Output   string `json:"plugin_output"`
	Acked    int    `json:"acknowledged"`
	Downtime int    `json:"scheduled_downtime_depth"`
	HostDown int    `json:"host_scheduled_downtime_depth"`
	Since    int64  `json:"last_state_change"`
}

var (
	hostColumns    = []string{"name", "address", "state", "plugin_output", "acknowledged", "scheduled_downtime_depth", "last_state_change", "num_services_warn", "num_services_crit", "num_services_unknown", "has_been_checked"}
	serviceColumns = []string{"host_name", "description", "state", "plugin_output", "acknowledged", "scheduled_downtime_depth", "host_scheduled_downtime_depth", "last_state_change"}
)

func (c *conn) hosts(ctx context.Context, filter expr) ([]hostRow, error) {
	q := url.Values{"columns": hostColumns}
	if filter != nil {
		b, _ := json.Marshal(filter)
		q.Set("query", string(b))
	}
	var r struct {
		Value []struct {
			Extensions hostRow `json:"extensions"`
		} `json:"value"`
	}
	if err := c.do(ctx, http.MethodGet, "/domain-types/host/collections/all", q, nil, &r); err != nil {
		return nil, err
	}
	out := make([]hostRow, 0, len(r.Value))
	for _, v := range r.Value {
		out = append(out, v.Extensions)
	}
	return out, nil
}

func (c *conn) services(ctx context.Context, filter expr) ([]serviceRow, error) {
	q := url.Values{"columns": serviceColumns}
	if filter != nil {
		b, _ := json.Marshal(filter)
		q.Set("query", string(b))
	}
	var r struct {
		Value []struct {
			Extensions serviceRow `json:"extensions"`
		} `json:"value"`
	}
	if err := c.do(ctx, http.MethodGet, "/domain-types/service/collections/all", q, nil, &r); err != nil {
		return nil, err
	}
	out := make([]serviceRow, 0, len(r.Value))
	for _, v := range r.Value {
		out = append(out, v.Extensions)
	}
	return out, nil
}

func when(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

// output passes a check's text on cut short and with anything that looks
// like a credential redacted: plugins print what they see.
func output(s string) string { return clip(rest.Redact(s), maxOutput) }

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func (h hostRow) row() map[string]any {
	row := map[string]any{"name": h.Name, "address": h.Address, "state": stateName(hostStates, h.State), "output": output(h.Output), "since": when(h.Since),
		"acknowledged": h.Acked > 0, "inDowntime": h.Downtime > 0, "servicesWarn": h.Warn, "servicesCrit": h.Crit, "servicesUnknown": h.Unknown}
	if h.HasChecked == 0 {
		row["state"] = "PENDING"
	}
	return row
}

func (s serviceRow) row() map[string]any {
	return map[string]any{"host": s.Host, "service": s.Desc, "state": stateName(serviceStates, s.State), "output": output(s.Output), "since": when(s.Since),
		"acknowledged": s.Acked > 0, "inDowntime": s.Downtime > 0 || s.HostDown > 0}
}

// severity orders problems worst first: CRIT, UNKNOWN, WARN.
func severity(state int) int {
	switch state {
	case 2:
		return 0
	case 3:
		return 1
	}
	return 2
}

type downtime struct {
	ID         string `json:"id"`
	Extensions struct {
		SiteID    string `json:"site_id"`
		HostName  string `json:"host_name"`
		Service   string `json:"service_description"`
		IsService string `json:"is_service"`
		Author    string `json:"author"`
		Comment   string `json:"comment"`
		Start     string `json:"start_time"`
		End       string `json:"end_time"`
		Recurring string `json:"recurring"`
	} `json:"extensions"`
}

func (d downtime) service() string {
	if d.Extensions.IsService == "yes" {
		return d.Extensions.Service
	}
	return ""
}

func (d downtime) row() map[string]any {
	row := map[string]any{"id": d.ID, "site": d.Extensions.SiteID, "host": d.Extensions.HostName, "start": d.Extensions.Start, "end": d.Extensions.End,
		"author": d.Extensions.Author, "comment": d.Extensions.Comment}
	if s := d.service(); s != "" {
		row["service"] = s
	}
	if d.Extensions.Recurring != "" && d.Extensions.Recurring != "no" {
		row["recurring"] = d.Extensions.Recurring
	}
	return row
}

func (c *conn) downtimes(ctx context.Context, host string) ([]downtime, error) {
	q := url.Values{}
	if host != "" {
		q.Set("host_name", host)
	}
	var r struct {
		Value []downtime `json:"value"`
	}
	err := c.do(ctx, http.MethodGet, "/domain-types/downtime/collections/all", q, nil, &r)
	return r.Value, err
}

type input struct {
	Host            string `json:"host"`
	Service         string `json:"service"`
	ProblemsOnly    bool   `json:"problemsOnly"`
	UnhandledOnly   bool   `json:"unhandledOnly"`
	Comment         string `json:"comment"`
	Sticky          *bool  `json:"sticky"`
	Notify          bool   `json:"notify"`
	DurationMinutes int    `json:"durationMinutes"`
	ID              string `json:"id"`
	Site            string `json:"site"`
}

// checkTarget validates a host name and an optional service description
// before any request.
func (p *input) checkTarget(required bool) error {
	p.Host, p.Service = strings.TrimSpace(p.Host), strings.TrimSpace(p.Service)
	if p.Host == "" && !required {
		return nil
	}
	if !hostRe.MatchString(p.Host) {
		return errors.New("a host is its name in Checkmk (letters, digits, . _ -)")
	}
	if len(p.Service) > 255 || !utf8.ValidString(p.Service) || strings.IndexFunc(p.Service, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("a service is its description, as Checkmk shows it")
	}
	return nil
}

func (p *input) checkComment() error {
	p.Comment = strings.TrimSpace(p.Comment)
	if p.Comment == "" {
		return errors.New("say why in the comment")
	}
	if len(p.Comment) > maxComment || strings.IndexFunc(p.Comment, func(r rune) bool { return r < 0x20 && r != '\n' }) >= 0 {
		return errors.New("the comment is at most 1000 characters of text")
	}
	return nil
}

func (p input) label() string {
	if p.Service != "" {
		return fmt.Sprintf("service %q on %s", p.Service, p.Host)
	}
	return "host " + p.Host
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
	case "hosts":
		var f expr
		if p.ProblemsOnly {
			f = ne("state", 0)
		}
		hs, err := c.hosts(ctx, f)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.Slice(hs, func(i, j int) bool { return hs[i].Name < hs[j].Name })
		out := []map[string]any{}
		for i, h := range hs {
			if i >= maxRows {
				break
			}
			out = append(out, h.row())
		}
		return sdk.JSON(map[string]any{"hosts": out, "truncated": len(hs) > maxRows})
	case "services":
		if err := p.checkTarget(true); err != nil {
			return sdk.Result{}, err
		}
		ss, err := c.services(ctx, eq("host_name", p.Host))
		if err != nil {
			return sdk.Result{}, err
		}
		sort.Slice(ss, func(i, j int) bool { return ss[i].Desc < ss[j].Desc })
		out := []map[string]any{}
		for i, s := range ss {
			if i >= maxRows {
				break
			}
			out = append(out, s.row())
		}
		return sdk.JSON(map[string]any{"host": p.Host, "services": out, "truncated": len(ss) > maxRows})
	case "problems":
		return c.problems(ctx, p.UnhandledOnly)
	case "downtimes":
		if err := p.checkTarget(false); err != nil {
			return sdk.Result{}, err
		}
		ds, err := c.downtimes(ctx, p.Host)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for i, d := range ds {
			if i >= maxRows {
				break
			}
			out = append(out, d.row())
		}
		return sdk.JSON(map[string]any{"downtimes": out, "truncated": len(ds) > maxRows})
	case "acknowledge":
		if err := p.checkTarget(true); err != nil {
			return sdk.Result{}, err
		}
		if err := p.checkComment(); err != nil {
			return sdk.Result{}, err
		}
		return c.acknowledge(ctx, call, p)
	case "schedule_downtime":
		if err := p.checkTarget(true); err != nil {
			return sdk.Result{}, err
		}
		if err := p.checkComment(); err != nil {
			return sdk.Result{}, err
		}
		if p.DurationMinutes == 0 {
			p.DurationMinutes = 60
		}
		if p.DurationMinutes < 1 || p.DurationMinutes > maxDowntime {
			return sdk.Result{}, errors.New("the duration is 1 minute to 30 days (43200 minutes)")
		}
		return m.scheduleDowntime(ctx, c, call, p)
	case "end_downtime":
		p.ID, p.Site = strings.TrimSpace(p.ID), strings.TrimSpace(p.Site)
		if !dtRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("a downtime is its id (digits, from downtimes)")
		}
		if !siteRe.MatchString(p.Site) {
			return sdk.Result{}, errors.New("enter the downtime's site id (from downtimes)")
		}
		return m.endDowntime(ctx, c, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) problems(ctx context.Context, unhandled bool) (sdk.Result, error) {
	hf := []expr{ne("state", 0), eq("has_been_checked", 1)}
	sf := []expr{ne("state", 0), eq("has_been_checked", 1)}
	if unhandled {
		hf = append(hf, eq("acknowledged", 0), eq("scheduled_downtime_depth", 0))
		sf = append(sf, eq("acknowledged", 0), eq("scheduled_downtime_depth", 0), eq("host_scheduled_downtime_depth", 0))
	}
	hs, err := c.hosts(ctx, and(hf...))
	if err != nil {
		return sdk.Result{}, err
	}
	ss, err := c.services(ctx, and(sf...))
	if err != nil {
		return sdk.Result{}, err
	}
	sort.SliceStable(hs, func(i, j int) bool {
		if hs[i].State != hs[j].State {
			return hs[i].State < hs[j].State // DOWN before UNREACHABLE
		}
		return hs[i].Name < hs[j].Name
	})
	sort.SliceStable(ss, func(i, j int) bool {
		if a, b := severity(ss[i].State), severity(ss[j].State); a != b {
			return a < b
		}
		return ss[i].Since > ss[j].Since
	})
	ho, so := []map[string]any{}, []map[string]any{}
	for _, h := range hs {
		if h.State != 0 && len(ho) < maxRows {
			ho = append(ho, h.row())
		}
	}
	for _, s := range ss {
		if s.State != 0 && len(so) < maxRows {
			so = append(so, s.row())
		}
	}
	return sdk.JSON(map[string]any{"hosts": ho, "services": so, "truncated": len(hs) > maxRows || len(ss) > maxRows})
}

// state looks the target up: its state, whether it's acknowledged, and
// whether it's in downtime.
func (c *conn) state(ctx context.Context, p input) (state int, acked, down bool, err error) {
	if p.Service == "" {
		hs, err := c.hosts(ctx, eq("name", p.Host))
		if err != nil {
			return 0, false, false, err
		}
		for _, h := range hs {
			if h.Name == p.Host {
				return h.State, h.Acked > 0, h.Downtime > 0, nil
			}
		}
		return 0, false, false, fmt.Errorf("Checkmk doesn't monitor a host %s", p.Host)
	}
	ss, err := c.services(ctx, and(eq("host_name", p.Host), eq("description", p.Service)))
	if err != nil {
		return 0, false, false, err
	}
	for _, s := range ss {
		if s.Host == p.Host && s.Desc == p.Service {
			return s.State, s.Acked > 0, s.Downtime > 0, nil
		}
	}
	return 0, false, false, fmt.Errorf("there's no service %q on %s", p.Service, p.Host)
}

func (c *conn) acknowledge(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	state, acked, _, err := c.state(ctx, p)
	if err != nil {
		return sdk.Result{}, err
	}
	if state == 0 {
		ok := "UP"
		if p.Service != "" {
			ok = "OK"
		}
		return sdk.Result{}, fmt.Errorf("the %s is %s, so there's no problem to acknowledge", p.label(), ok)
	}
	if acked {
		return sdk.JSON(map[string]any{"host": p.Host, "service": p.Service, "note": "nothing to change: it's already acknowledged"})
	}
	sticky := p.Sticky == nil || *p.Sticky
	body := map[string]any{"host_name": p.Host, "sticky": sticky, "persistent": false, "notify": p.Notify, "comment": p.Comment}
	path := "/domain-types/acknowledge/collections/host"
	body["acknowledge_type"] = "host"
	if p.Service != "" {
		path = "/domain-types/acknowledge/collections/service"
		body["acknowledge_type"] = "service"
		body["service_description"] = p.Service
	}
	if call.DryRun {
		after, _ := json.Marshal(body)
		return sdk.Result{Plan: &sdk.Plan{Summary: "Acknowledge the problem on " + p.label() + " (its notifications stop)",
			Changes: []sdk.Change{{Target: p.label(), Op: "acknowledge", After: after}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, path, nil, body, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"host": p.Host, "service": p.Service, "acknowledged": true, "sticky": sticky})
}

func (d downtime) covers(p input) bool {
	return d.Extensions.HostName == p.Host && d.service() == p.Service
}

func (m *Module) scheduleDowntime(ctx context.Context, c *conn, call sdk.Call, p input) (sdk.Result, error) {
	if _, _, _, err := c.state(ctx, p); err != nil {
		return sdk.Result{}, err
	}
	start := m.clock().UTC().Truncate(time.Second)
	end := start.Add(time.Duration(p.DurationMinutes) * time.Minute)
	ds, err := c.downtimes(ctx, p.Host)
	if err != nil {
		return sdk.Result{}, err
	}
	for _, d := range ds {
		if !d.covers(p) {
			continue
		}
		s, e1 := time.Parse(time.RFC3339, d.Extensions.Start)
		e, e2 := time.Parse(time.RFC3339, d.Extensions.End)
		if e1 == nil && e2 == nil && !s.After(start) && !e.Before(end) {
			return sdk.JSON(map[string]any{"id": d.ID, "site": d.Extensions.SiteID, "end": d.Extensions.End, "note": "nothing to change: a downtime already covers this time"})
		}
	}
	body := map[string]any{"host_name": p.Host, "start_time": start.Format(time.RFC3339), "end_time": end.Format(time.RFC3339), "comment": p.Comment, "duration": 0}
	path := "/domain-types/downtime/collections/host"
	body["downtime_type"] = "host"
	if p.Service != "" {
		path = "/domain-types/downtime/collections/service"
		body["downtime_type"] = "service"
		body["service_descriptions"] = []string{p.Service}
	}
	if call.DryRun {
		after, _ := json.Marshal(body)
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Put %s into downtime for %s (its notifications stop)", p.label(), time.Duration(p.DurationMinutes)*time.Minute),
			Changes: []sdk.Change{{Target: p.label(), Op: "create", After: after}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, path, nil, body, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"host": p.Host, "service": p.Service, "start": body["start_time"], "end": body["end_time"]})
	// Checkmk answers 204 without the new downtime's id: find it by its
	// target, comment and end, to offer the undo.
	// Only a downtime that wasn't there before, with the same start too, and
	// only when exactly one fits: ending someone else's downtime on undo
	// would bring back notifications they silenced.
	existed := map[string]bool{}
	for _, d := range ds {
		existed[d.Extensions.SiteID+"/"+d.ID] = true
	}
	if after, lerr := c.downtimes(ctx, p.Host); lerr == nil {
		var found *downtime
		n := 0
		for i, d := range after {
			s, serr := time.Parse(time.RFC3339, d.Extensions.Start)
			e, perr := time.Parse(time.RFC3339, d.Extensions.End)
			if existed[d.Extensions.SiteID+"/"+d.ID] || !d.covers(p) || d.Extensions.Comment != p.Comment || perr != nil || serr != nil ||
				math.Abs(e.Sub(end).Seconds()) > 60 || math.Abs(s.Sub(start).Seconds()) > 60 || !dtRe.MatchString(d.ID) || !siteRe.MatchString(d.Extensions.SiteID) {
				continue
			}
			found, n = &after[i], n+1
		}
		if n == 1 {
			res, err = sdk.JSON(map[string]any{"id": found.ID, "site": found.Extensions.SiteID, "host": p.Host, "service": p.Service, "start": body["start_time"], "end": body["end_time"]})
			res.Undo = sdk.UndoWith("end_downtime", map[string]string{"id": found.ID, "site": found.Extensions.SiteID}, "End the downtime on "+p.label())
		}
	}
	return res, err
}

func (m *Module) endDowntime(ctx context.Context, c *conn, call sdk.Call, p input) (sdk.Result, error) {
	ds, err := c.downtimes(ctx, "")
	if err != nil {
		return sdk.Result{}, err
	}
	var d *downtime
	for i := range ds {
		if ds[i].ID == p.ID && ds[i].Extensions.SiteID == p.Site {
			d = &ds[i]
			break
		}
	}
	if d == nil {
		return sdk.JSON(map[string]any{"id": p.ID, "site": p.Site, "note": "nothing to change: there's no such downtime (it may have ended)"})
	}
	target := input{Host: d.Extensions.HostName, Service: d.service()}
	if call.DryRun {
		before, _ := json.Marshal(d.row())
		return sdk.Result{Plan: &sdk.Plan{Summary: "End the downtime on " + target.label() + " (" + d.Extensions.Comment + ")",
			Changes: []sdk.Change{{Target: "downtime " + p.ID + " on " + target.label(), Op: "delete", Before: before}}}}, nil
	}
	body := map[string]any{"site_id": p.Site, "delete_type": "by_id", "downtime_id": p.ID}
	if err := c.do(ctx, http.MethodPost, "/domain-types/downtime/actions/delete/invoke", nil, body, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"ended": p.ID, "site": p.Site, "host": target.Host, "service": target.Service})
	// A downtime that hadn't started yet (or recurs) isn't offered back: the
	// undo would start one now, hiding problems the original never covered.
	start, serr := time.Parse(time.RFC3339, d.Extensions.Start)
	started := serr == nil && !start.After(m.clock()) && (d.Extensions.Recurring == "" || d.Extensions.Recurring == "no")
	if end, perr := time.Parse(time.RFC3339, d.Extensions.End); perr == nil && started && hostRe.MatchString(target.Host) {
		if left := end.Sub(m.clock()); left > time.Minute {
			mins := int(math.Ceil(left.Minutes()))
			if mins > maxDowntime {
				mins = maxDowntime
			}
			comment := strings.TrimSpace(d.Extensions.Comment)
			if comment == "" {
				comment = "restored by Conduit"
			}
			undo := map[string]any{"host": target.Host, "comment": clip(comment, maxComment-4), "durationMinutes": mins}
			if target.Service != "" {
				undo["service"] = target.Service
			}
			res.Undo = sdk.UndoWith("schedule_downtime", undo, "Put "+target.label()+" into downtime again")
		}
	}
	return res, err
}

func (m *Module) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}
