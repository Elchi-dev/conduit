// Package crowdsec works with a CrowdSec Local API: active decisions (with
// a bouncer key or a machine login), alerts and their events (machine
// login), and adding or deleting ban decisions, with guards against banning
// Conduit's own host, private ranges and huge ranges.
package crowdsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one CrowdSec Local API.
type Config struct {
	URL                string   `json:"url"`        // default http://127.0.0.1:8080
	Machine            string   `json:"machine"`    // machine id, for alerts and changes
	Password           string   `json:"password"`   // secret:// machine password
	BouncerKey         string   `json:"bouncerKey"` // secret:// bouncer API key, for reading decisions
	Protect            []string `json:"protect"`    // addresses and ranges never banned
	AllowPrivate       bool     `json:"allowPrivate"`
	Fingerprint        string   `json:"fingerprint"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

type conn struct {
	bouncer *rest.Client // nil without a bouncer key
	machine *rest.Client // nil without a machine login
	login   *rest.Client
	id      string
	pass    string
	host    sdk.Host

	protect      []netip.Prefix
	allowPrivate bool
	local        func() []netip.Addr

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Local replaces the lookup of this machine's own addresses (tests).
	Local func() []netip.Addr
}

// New returns the CrowdSec module.
func New() *Module { return &Module{} }

var (
	pathRe     = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	machineRe  = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,128}$`)
	scenarioRe = regexp.MustCompile(`^[A-Za-z0-9/._:-]{1,200}$`)
)

const (
	maxRows   = 1000
	minBan    = time.Minute
	maxBan    = 365 * 24 * time.Hour
	defaultTo = "4h"
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "crowdsec", Name: "CrowdSec", Version: "0.1.0", Category: "Security", Icon: "shield",
		Description: "CrowdSec Local API: active decisions, alerts with their events, and adding or deleting ban decisions with guards against locking yourself out.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"url":{"type":"string","default":"http://127.0.0.1:8080","description":"The Local API's address"},
			"machine":{"type":"string","description":"A machine id (cscli machines add conduit --auto): needed for alerts and for adding or deleting decisions"},
			"password":{"type":"string","x-secret":true,"description":"The machine's password"},
			"bouncerKey":{"type":"string","x-secret":true,"description":"A bouncer API key (cscli bouncers add conduit): enough to read decisions"},
			"protect":{"type":"array","items":{"type":"string"},"description":"Addresses and ranges never to ban, such as your public address or office network (this machine's own addresses are always protected)"},
			"allowPrivate":{"type":"boolean","default":false,"description":"Allow banning private, loopback, link-local and shared ranges"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the Local API's certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "decisions", Title: "Decisions", Description: "Active decisions (bans, captchas): id, type, scope, value, time left, origin and scenario. Community blocklist decisions only when asked.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"ip":{"type":"string","description":"Only decisions covering this address"},"includeCommunity":{"type":"boolean","default":false,"description":"Include the community blocklist (CAPI) and subscribed lists"},"limit":{"type":"integer","minimum":1,"maximum":1000,"default":200}}}`)},
			{Name: "alerts", Title: "Alerts", Description: "Recent alerts: scenario, source address, country and network, event count, when, which machine and the decisions taken. Event details are left out (see alert). Needs a machine login.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"ip":{"type":"string","description":"Only alerts about this address"},"scenario":{"type":"string","description":"Only this scenario, e.g. crowdsecurity/ssh-bf"},"since":{"type":"string","default":"24h","description":"How far back, e.g. 1h, 24h, 168h"},"limit":{"type":"integer","minimum":1,"maximum":1000,"default":100}}}`)},
			{Name: "alert", Title: "Alert details", Description: "One alert with its events (request paths, user agents, target hosts), cut short and with credentials masked. They can hold attacker payloads and internal host names, so this is sensitive. Needs a machine login.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"integer","description":"Alert id (from alerts)"}}}`)},
			{Name: "ban", Title: "Ban an address or range", Description: "Adds a ban decision that every bouncer applies. Refused for this machine's own addresses and the protected ones, private and loopback ranges (unless allowed in the settings) and ranges wider than /16 (IPv4) or /48 (IPv6). Undo deletes the decision. Needs a machine login.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["ip"],"properties":{"ip":{"type":"string","description":"An address, or a range in CIDR form"},"duration":{"type":"string","default":"4h","description":"How long, e.g. 30m, 4h, 168h (1 minute to 1 year)"},"reason":{"type":"string","description":"Why, kept as the decision's scenario"}}}`)},
			{Name: "delete_decision", Title: "Delete a decision", Description: "Removes one decision, which unblocks that address or range. Undo bans it again for the time it had left. Needs a machine login.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["decision"],"properties":{"decision":{"type":"integer","description":"Decision id (from decisions)"}}}`)},
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
		c.URL = "http://127.0.0.1:8080"
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) || strings.Contains(u.Path, "..") {
		return errors.New("the address is like http://127.0.0.1:8080")
	}
	machine := strings.TrimSpace(c.Machine)
	if machine != "" && !machineRe.MatchString(machine) {
		return errors.New("the machine id is its name from cscli machines list")
	}
	if (machine != "") != (c.Password != "") {
		return errors.New("a machine login needs both the machine id and its password")
	}
	if c.Password != "" && !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the machine password in the vault and enter its secret:// reference")
	}
	if c.BouncerKey != "" && !strings.HasPrefix(c.BouncerKey, "secret://") {
		return errors.New("store the bouncer key in the vault and enter its secret:// reference")
	}
	if machine == "" && c.BouncerKey == "" {
		return errors.New("enter a machine login, a bouncer key, or both")
	}
	var protect []netip.Prefix
	for _, s := range c.Protect {
		p, err := parseTarget(s)
		if err != nil {
			return fmt.Errorf("protect: %w", err)
		}
		protect = append(protect, p)
	}
	if a, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil {
		// The Local API's own host: banning it would cut Conduit off it.
		a = a.Unmap()
		protect = append(protect, netip.PrefixFrom(a, a.BitLen()))
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
	client = rest.SameHostOnly(client)
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/v1")
	cn := &conn{id: machine, pass: c.Password, host: h, protect: protect, allowPrivate: c.AllowPrivate, local: m.Local}
	if cn.local == nil {
		cn.local = localAddrs
	}
	if c.BouncerKey != "" {
		ref := c.BouncerKey
		cn.bouncer = rest.New(base, func(ctx context.Context, r *http.Request) error {
			k, err := h.Secret(ctx, ref)
			if err != nil {
				return err
			}
			r.Header.Set("X-Api-Key", strings.TrimSpace(k))
			return nil
		})
		cn.bouncer.HTTP = client
	}
	if machine != "" {
		cn.login = rest.New(base, nil)
		cn.login.HTTP = client
		cn.machine = rest.New(base, func(ctx context.Context, r *http.Request) error {
			t, err := cn.jwt(ctx)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+t)
			return nil
		})
		cn.machine.HTTP = client
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func localAddrs() []netip.Addr {
	var out []netip.Addr
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

var errLogin = errors.New("CrowdSec refused the machine login (check the machine id and password, and that the machine is validated: cscli machines validate)")

// jwt returns a session token for the machine, signing in when there's none
// or it's about to expire.
func (c *conn) jwt(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	pw, err := c.host.Secret(ctx, c.pass)
	if err != nil {
		return "", err
	}
	var r struct {
		Token  string `json:"token"`
		Expire string `json:"expire"`
	}
	_, err = c.login.Do(ctx, http.MethodPost, "/v1/watchers/login", nil, map[string]any{"machine_id": c.id, "password": strings.TrimSpace(pw), "scenarios": []string{}}, &r)
	if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
		return "", errLogin
	}
	if err != nil {
		return "", err
	}
	if r.Token == "" {
		return "", errors.New("CrowdSec signed in the machine but sent no token")
	}
	exp, err := time.Parse(time.RFC3339, r.Expire)
	if err != nil || time.Until(exp) > 24*time.Hour {
		exp = time.Now().Add(time.Hour)
	}
	c.token, c.expires = r.Token, exp.Add(-time.Minute)
	return c.token, nil
}

var errNoMachine = errors.New("this needs a machine login (machine id and password in the settings)")

// mdo calls the API as the machine, signing in again once if the session
// was refused.
func (c *conn) mdo(ctx context.Context, method, path string, q url.Values, body, out any) error {
	if c.machine == nil {
		return errNoMachine
	}
	_, err := c.machine.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		_, err = c.machine.Do(ctx, method, path, q, body, out)
	}
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errLogin
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("CrowdSec doesn't let this machine do that")
	}
	return err
}

func (c *conn) bdo(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.bouncer.Do(ctx, http.MethodGet, path, q, nil, out)
	if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
		return errors.New("CrowdSec refused the bouncer key")
	}
	return err
}

// clean makes text from the API safe to show: credentials masked first,
// then control characters dropped and the result cut to n characters.
func clean(s string, n int) string {
	return clip(rest.Redact(s), n)
}

// clip drops control characters and cuts to n characters.
func clip(s string, n int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s))
	if utf8.RuneCountInString(s) > n {
		r := []rune(s)
		s = string(r[:n]) + "…"
	}
	return s
}

// parseTarget reads an address or a CIDR range in canonical form.
func parseTarget(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 || strings.ContainsAny(s, "%") {
		return netip.Prefix{}, fmt.Errorf("%q isn't an IP address or CIDR range", s)
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q isn't an IP address or CIDR range", s)
		}
		if p.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("%q: write IPv4 ranges in IPv4 form", s)
		}
		if p.Masked() != p {
			return netip.Prefix{}, fmt.Errorf("%q isn't the start of its range; did you mean %s?", s, p.Masked())
		}
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q isn't an IP address or CIDR range", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// special lists the ranges refused unless private ranges are allowed.
var special = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
		"::1/128", "fc00::/7", "fe80::/10",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// value is how a target is written in a decision.
func value(p netip.Prefix) (scope, val string) {
	if p.Bits() == p.Addr().BitLen() {
		return "Ip", p.Addr().String()
	}
	return "Range", p.String()
}

// guard refuses targets whose ban would lock out this machine or the
// protected addresses, a private network, or a huge range.
func (c *conn) guard(p netip.Prefix) error {
	a := p.Addr()
	if a.Is4() && p.Bits() < 16 {
		return fmt.Errorf("refusing: %s is wider than a /16", p)
	}
	if a.Is6() && p.Bits() < 48 {
		return fmt.Errorf("refusing: %s is wider than a /48", p)
	}
	if a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return fmt.Errorf("refusing: %s isn't a host or network to ban", p)
	}
	for _, own := range c.local() {
		if p.Contains(own) {
			return fmt.Errorf("refusing: %s covers this machine's own address %s, so the ban would cut Conduit off", p, own)
		}
	}
	for _, pr := range c.protect {
		if p.Overlaps(pr) {
			return fmt.Errorf("refusing: %s overlaps the protected %s", p, pr)
		}
	}
	if !c.allowPrivate {
		for _, sp := range special {
			if p.Overlaps(sp) {
				return fmt.Errorf("refusing: %s is in the private or local range %s (allow private ranges in the settings to ban there)", p, sp)
			}
		}
	}
	return nil
}

type decision struct {
	ID        int64  `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

func (d decision) row() map[string]any {
	r := map[string]any{"id": d.ID, "origin": clip(d.Origin, 40), "type": clip(d.Type, 40), "scope": clip(d.Scope, 40), "value": clip(d.Value, 64),
		"timeLeft": left(d.Duration), "scenario": clip(d.Scenario, 200)}
	if d.Simulated {
		r["simulated"] = true
	}
	return r
}

// left is a decision's remaining time rounded to the second.
func left(s string) string {
	d, err := time.ParseDuration(s)
	if err != nil {
		return clip(s, 40)
	}
	if d < 0 {
		return "expired"
	}
	return d.Round(time.Second).String()
}

type alert struct {
	ID        int64  `json:"id"`
	Scenario  string `json:"scenario"`
	MachineID string `json:"machine_id"`
	Events    int    `json:"events_count"`
	StartAt   string `json:"start_at"`
	StopAt    string `json:"stop_at"`
	CreatedAt string `json:"created_at"`
	Simulated bool   `json:"simulated"`
	Source    struct {
		Scope  string `json:"scope"`
		Value  string `json:"value"`
		IP     string `json:"ip"`
		Range  string `json:"range"`
		CN     string `json:"cn"`
		ASName string `json:"as_name"`
		ASN    string `json:"as_number"`
	} `json:"source"`
	Decisions []decision `json:"decisions"`
	Meta      []kv       `json:"meta"`
	EventList []struct {
		Timestamp string `json:"timestamp"`
		Meta      []kv   `json:"meta"`
	} `json:"events"`
}

type kv struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (a alert) row() map[string]any {
	ds := []map[string]any{}
	for _, d := range a.Decisions {
		ds = append(ds, map[string]any{"id": d.ID, "type": clip(d.Type, 40), "value": clip(d.Value, 64), "timeLeft": left(d.Duration)})
	}
	src := map[string]any{"scope": clip(a.Source.Scope, 40), "value": clip(a.Source.Value, 64)}
	if a.Source.CN != "" {
		src["country"] = clip(a.Source.CN, 8)
	}
	if a.Source.ASName != "" {
		src["network"] = clip(a.Source.ASName, 100)
	}
	if a.Source.ASN != "" {
		src["asn"] = clip(a.Source.ASN, 20)
	}
	r := map[string]any{"id": a.ID, "scenario": clip(a.Scenario, 200), "source": src, "events": a.Events, "startAt": a.StartAt, "stopAt": a.StopAt,
		"createdAt": a.CreatedAt, "machine": clip(a.MachineID, 128), "decisions": ds}
	if a.Simulated {
		r["simulated"] = true
	}
	return r
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var parts []string
	if c.machine != nil {
		var as []alert
		if err := c.mdo(ctx, http.MethodGet, "/v1/alerts", url.Values{"limit": {"1"}, "include_capi": {"false"}}, nil, &as); err != nil {
			return sdk.Health{Status: "down", Message: health(err)}
		}
		parts = append(parts, "machine "+c.id+" signed in")
	}
	if c.bouncer != nil {
		var ds []decision
		if err := c.bdo(ctx, "/v1/decisions", url.Values{"ip": {"192.0.2.1"}}, &ds); err != nil {
			return sdk.Health{Status: "down", Message: health(err)}
		}
		parts = append(parts, "bouncer key accepted")
	}
	return sdk.Health{Status: "ok", Message: strings.Join(parts, ", ")}
}

func health(err error) string {
	if rest.IsStatus(err, http.StatusNotFound) {
		return "no CrowdSec Local API at this address"
	}
	return err.Error()
}

func positive(n int64, what string) error {
	if n < 1 || n > 1<<53 {
		return fmt.Errorf("the %s is its number from CrowdSec", what)
	}
	return nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		IP               string `json:"ip"`
		Scenario         string `json:"scenario"`
		Since            string `json:"since"`
		Limit            int    `json:"limit"`
		IncludeCommunity bool   `json:"includeCommunity"`
		ID               int64  `json:"id"`
		Decision         int64  `json:"decision"`
		Duration         string `json:"duration"`
		Reason           string `json:"reason"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	limit := func(def int) (int, error) {
		if p.Limit == 0 {
			return def, nil
		}
		if p.Limit < 1 || p.Limit > maxRows {
			return 0, fmt.Errorf("limit is between 1 and %d", maxRows)
		}
		return p.Limit, nil
	}
	var ip string
	if strings.TrimSpace(p.IP) != "" && call.Action != "ban" {
		a, err := netip.ParseAddr(strings.TrimSpace(p.IP))
		if err != nil || a.Zone() != "" {
			return sdk.Result{}, errors.New("ip is one address, like 203.0.113.7")
		}
		ip = a.Unmap().String()
	}
	switch call.Action {
	case "decisions":
		n, err := limit(200)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.decisions(ctx, ip, p.IncludeCommunity, n)
	case "alerts":
		n, err := limit(100)
		if err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{"limit": {strconv.Itoa(n)}, "include_capi": {"false"}}
		since := strings.TrimSpace(p.Since)
		if since == "" {
			since = "24h"
		}
		if d, err := time.ParseDuration(since); err != nil || d <= 0 || d > 24*366*time.Hour {
			return sdk.Result{}, errors.New("since is a duration like 1h, 24h or 168h")
		}
		q.Set("since", since)
		if ip != "" {
			q.Set("ip", ip)
		}
		if s := strings.TrimSpace(p.Scenario); s != "" {
			if !scenarioRe.MatchString(s) {
				return sdk.Result{}, errors.New("the scenario is its name, like crowdsecurity/ssh-bf")
			}
			q.Set("scenario", s)
		}
		var as []alert
		if err := c.mdo(ctx, http.MethodGet, "/v1/alerts", q, nil, &as); err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for i, a := range as {
			if i == n {
				break
			}
			rows = append(rows, a.row())
		}
		return sdk.JSON(map[string]any{"alerts": rows, "since": since})
	case "alert":
		if err := positive(p.ID, "alert"); err != nil {
			return sdk.Result{}, err
		}
		return c.alert(ctx, p.ID)
	case "ban":
		return c.ban(ctx, call, p.IP, p.Duration, p.Reason)
	case "delete_decision":
		if err := positive(p.Decision, "decision"); err != nil {
			return sdk.Result{}, err
		}
		return c.deleteDecision(ctx, call, p.Decision)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// active lists active decisions. A bouncer key reads them directly; a
// machine reads them from the alerts that carry them.
func (c *conn) active(ctx context.Context, ip string, community bool) ([]decision, error) {
	if c.bouncer != nil {
		q := url.Values{}
		if ip != "" {
			q.Set("ip", ip)
		}
		if !community {
			q.Set("origins", "crowdsec,cscli,cscli-import,appsec,console")
		}
		var ds []decision
		if err := c.bdo(ctx, "/v1/decisions", q, &ds); err != nil {
			return nil, err
		}
		return ds, nil
	}
	q := url.Values{"has_active_decision": {"true"}, "include_capi": {strconv.FormatBool(community)}}
	if ip != "" {
		q.Set("ip", ip)
	}
	var as []alert
	if err := c.mdo(ctx, http.MethodGet, "/v1/alerts", q, nil, &as); err != nil {
		return nil, err
	}
	var ds []decision
	for _, a := range as {
		for _, d := range a.Decisions {
			if d.Scenario == "" {
				d.Scenario = a.Scenario
			}
			if !strings.HasPrefix(d.Duration, "-") {
				ds = append(ds, d)
			}
		}
	}
	return ds, nil
}

func (c *conn) decisions(ctx context.Context, ip string, community bool, n int) (sdk.Result, error) {
	ds, err := c.active(ctx, ip, community)
	if err != nil {
		return sdk.Result{}, err
	}
	sort.SliceStable(ds, func(i, j int) bool { return ds[i].ID > ds[j].ID })
	byType := map[string]int{}
	rows := []map[string]any{}
	for _, d := range ds {
		byType[clip(d.Type, 40)]++
		if len(rows) < n {
			rows = append(rows, d.row())
		}
	}
	return sdk.JSON(map[string]any{"total": len(ds), "byType": byType, "decisions": rows, "truncated": len(ds) > n})
}

func (c *conn) alert(ctx context.Context, id int64) (sdk.Result, error) {
	var a alert
	if err := c.mdo(ctx, http.MethodGet, "/v1/alerts/"+strconv.FormatInt(id, 10), nil, nil, &a); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no alert %d", id)
		}
		return sdk.Result{}, err
	}
	if a.ID != id {
		return sdk.Result{}, fmt.Errorf("there's no alert %d", id)
	}
	pairs := func(ms []kv) map[string]string {
		out := map[string]string{}
		for i, m := range ms {
			if i == 50 {
				break
			}
			out[clip(m.Key, 60)] = clean(m.Value, 500)
		}
		return out
	}
	row := a.row()
	row["context"] = pairs(a.Meta)
	evs := []map[string]any{}
	for i, e := range a.EventList {
		if i == 50 {
			break
		}
		evs = append(evs, map[string]any{"time": clip(e.Timestamp, 40), "meta": pairs(e.Meta)})
	}
	row["eventDetails"] = evs
	if len(a.EventList) > 50 {
		row["eventDetailsTruncated"] = true
	}
	return sdk.JSON(row)
}

func (c *conn) ban(ctx context.Context, call sdk.Call, target, duration, reason string) (sdk.Result, error) {
	p, err := parseTarget(target)
	if err != nil {
		return sdk.Result{}, err
	}
	duration = strings.TrimSpace(duration)
	if duration == "" {
		duration = defaultTo
	}
	d, err := time.ParseDuration(duration)
	if err != nil || d < minBan || d > maxBan {
		return sdk.Result{}, errors.New("the duration is between 1m and 8760h, like 30m, 4h or 168h")
	}
	duration = d.String()
	reason = clip(reason, 200)
	if reason == "" {
		reason = "manual ban from Conduit"
	}
	if err := c.guard(p); err != nil {
		return sdk.Result{}, err
	}
	if c.machine == nil {
		return sdk.Result{}, errNoMachine
	}
	scope, val := value(p)
	ds, err := c.active(ctx, "", false)
	if err != nil {
		return sdk.Result{}, err
	}
	for _, x := range ds {
		if strings.EqualFold(x.Type, "ban") && x.Value == val && !x.Simulated {
			return sdk.JSON(map[string]any{"decision": x.ID, "value": val, "banned": true, "timeLeft": left(x.Duration), "note": "nothing to change"})
		}
	}
	if call.DryRun {
		after, _ := json.Marshal(map[string]string{"type": "ban", "scope": scope, "value": val, "duration": duration, "reason": reason})
		return sdk.Result{Plan: &sdk.Plan{Summary: "Ban " + val + " for " + duration, Changes: []sdk.Change{{Target: scope + " " + val, Op: "ban", After: after}}}}, nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	body := []map[string]any{{
		"scenario": reason, "scenario_hash": "", "scenario_version": "", "message": "manual 'ban' from '" + c.id + "'",
		"events_count": 1, "start_at": now, "stop_at": now, "capacity": 0, "leakspeed": "0", "simulated": false, "events": []any{},
		"source": map[string]any{"scope": scope, "value": val, "ip": ipOf(p), "range": rangeOf(p)},
		// "cscli" is the origin of manual decisions: bouncers and the
		// console treat it as one.
		"decisions": []map[string]any{{"duration": duration, "origin": "cscli", "scenario": reason, "scope": scope, "value": val, "type": "ban"}},
	}}
	var ids []string
	if err := c.mdo(ctx, http.MethodPost, "/v1/alerts", nil, body, &ids); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"value": val, "scope": scope, "banned": true, "duration": duration}
	var alertID int64
	if len(ids) == 1 {
		alertID, _ = strconv.ParseInt(ids[0], 10, 64)
	}
	if alertID < 1 {
		return sdk.JSON(out)
	}
	out["alert"] = alertID
	var a alert
	if err := c.mdo(ctx, http.MethodGet, "/v1/alerts/"+strconv.FormatInt(alertID, 10), nil, nil, &a); err != nil {
		out["note"] = "banned; couldn't read the decision back, so there's no undo"
		return sdk.JSON(out)
	}
	for _, x := range a.Decisions {
		if x.Value == val && x.ID > 0 {
			out["decision"] = x.ID
			res, err := sdk.JSON(out)
			res.Undo = sdk.UndoWith("delete_decision", map[string]int64{"decision": x.ID}, "Unban "+val)
			return res, err
		}
	}
	return sdk.JSON(out)
}

func ipOf(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return ""
}

func rangeOf(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return ""
	}
	return p.String()
}

func (c *conn) deleteDecision(ctx context.Context, call sdk.Call, id int64) (sdk.Result, error) {
	if c.machine == nil {
		return sdk.Result{}, errNoMachine
	}
	ds, err := c.active(ctx, "", false)
	if err != nil {
		return sdk.Result{}, err
	}
	var found *decision
	for i := range ds {
		if ds[i].ID == id {
			found = &ds[i]
		}
	}
	target := fmt.Sprintf("decision %d", id)
	if found != nil {
		target = fmt.Sprintf("decision %d (%s %s %s, %s left, %s)", id, clip(found.Type, 40), clip(found.Scope, 40), clip(found.Value, 64), left(found.Duration), clip(found.Scenario, 120))
	}
	if call.DryRun {
		var before json.RawMessage
		if found != nil {
			before, _ = json.Marshal(found.row())
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: "Delete " + target, Changes: []sdk.Change{{Target: target, Op: "delete", Before: before}}}}, nil
	}
	var r struct {
		Deleted string `json:"nbDeleted"`
	}
	if err := c.mdo(ctx, http.MethodDelete, "/v1/decisions/"+strconv.FormatInt(id, 10), nil, nil, &r); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.JSON(map[string]any{"decision": id, "deleted": false, "note": "nothing to change"})
		}
		return sdk.Result{}, err
	}
	if r.Deleted == "0" {
		return sdk.JSON(map[string]any{"decision": id, "deleted": false, "note": "nothing to change"})
	}
	out := map[string]any{"decision": id, "deleted": true}
	res, err := sdk.JSON(out)
	if found != nil && strings.EqualFold(found.Type, "ban") && (strings.EqualFold(found.Scope, "ip") || strings.EqualFold(found.Scope, "range")) {
		if d, perr := time.ParseDuration(found.Duration); perr == nil && d >= minBan {
			if d > maxBan {
				d = maxBan
			}
			d = d.Round(time.Minute)
			res.Undo = sdk.UndoWith("ban", map[string]string{"ip": found.Value, "duration": d.String(), "reason": clip(found.Scenario, 200)}, "Ban "+clip(found.Value, 64)+" again")
		}
	}
	return res, err
}
