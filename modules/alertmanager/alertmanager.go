// Package alertmanager works with a Prometheus Alertmanager through its v2
// API: cluster status, firing alerts, receivers and silences, and creating
// or expiring silences.
package alertmanager

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Alertmanager.
type Config struct {
	URL                string `json:"url"`
	Token              string `json:"token"`    // optional secret:// bearer token
	Username           string `json:"username"` // optional basic-auth user
	Password           string `json:"password"` // secret://, with username
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

// New returns the Alertmanager module.
func New() *Module { return &Module{now: time.Now} }

var (
	pathRe    = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	silenceRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	labelRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// Limits.
const (
	maxSilence  = 30 * 24 * 60 // minutes
	maxMatchers = 20
	maxAlerts   = 500
	maxValue    = 1024
	maxComment  = 1000
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	matchers := `"matchers":{"type":"array","minItems":1,"maxItems":20,"description":"Label matchers; an alert is silenced when all match","items":{"type":"object","required":["name","value"],"properties":{"name":{"type":"string"},"value":{"type":"string"},"isRegex":{"type":"boolean","default":false},"isEqual":{"type":"boolean","default":true}}}}`
	return sdk.Manifest{
		ID: "alertmanager", Name: "Alertmanager", Version: "0.1.0", Category: "Monitoring", Icon: "bell",
		Description: "Prometheus Alertmanager: cluster status, firing alerts, receivers and silences; create or expire silences.",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"The Alertmanager's address, e.g. http://alertmanager:9093"},
			"token":{"type":"string","x-secret":true,"description":"Bearer token, if a proxy in front asks for one"},
			"username":{"type":"string","description":"Basic-auth user, if the web config asks for one"},
			"password":{"type":"string","x-secret":true,"description":"Basic-auth password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Status", Description: "Version, uptime, and the cluster's state and peers. The configuration (which holds receiver credentials) is never read.", Risk: sdk.RiskRead},
			{Name: "alerts", Title: "Alerts", Description: "Firing alerts, newest first, at most 500: name, state, since when, labels, summary and receivers. Silenced and inhibited ones only when asked; filter by label.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"includeSilenced":{"type":"boolean","default":false},"includeInhibited":{"type":"boolean","default":false},"labels":{"type":"object","additionalProperties":{"type":"string"},"description":"Only alerts with these label values, e.g. {\"severity\":\"critical\"}"}}}`)},
			{Name: "receivers", Title: "Receivers", Description: "The receivers' names (where notifications go). Their settings are never read.", Risk: sdk.RiskRead},
			{Name: "silences", Title: "Silences", Description: "Active and pending silences (expired ones too when asked): matchers, start, end, author and comment.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"includeExpired":{"type":"boolean","default":false}}}`)},
			{Name: "create_silence", Title: "Silence alerts", Description: "Mutes the alerts matching every matcher for 1 minute to 30 days, so nobody is notified about them. Hiding alerts can hide an outage, so this is destructive. Undo expires the silence.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["matchers","comment"],"properties":{` + matchers + `,"durationMinutes":{"type":"integer","minimum":1,"maximum":43200,"default":120},"comment":{"type":"string","description":"Why"}}}`)},
			{Name: "expire_silence", Title: "Expire a silence", Description: "Ends a silence now, so its alerts notify again. Undo silences them again for the time it had left.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Silence id (from silences)"}}}`)},
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
		return errors.New("the address is like http://alertmanager:9093")
	}
	auth, err := authFunc(h, c.Token, c.Username, c.Password)
	if err != nil {
		return err
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
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v2")
	api := rest.New(u.Scheme+"://"+u.Host+base, auth)
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// authFunc checks the optional credentials (references only) and returns
// what sets them on a request: a bearer token, or a basic-auth user and
// password, or nothing.
func authFunc(h sdk.Host, token, user, pass string) (func(context.Context, *http.Request) error, error) {
	token, user, pass = strings.TrimSpace(token), strings.TrimSpace(user), strings.TrimSpace(pass)
	for _, s := range []string{token, pass} {
		if s != "" && !strings.HasPrefix(s, "secret://") {
			return nil, errors.New("store the token or password in the vault and enter its secret:// reference")
		}
	}
	switch {
	case token != "" && (user != "" || pass != ""):
		return nil, errors.New("use a token or a user and password, not both")
	case (user == "") != (pass == ""):
		return nil, errors.New("basic auth needs both the user and the password")
	case token != "":
		return func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, token)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
			return nil
		}, nil
	case user != "":
		return func(ctx context.Context, r *http.Request) error {
			p, err := h.Secret(ctx, pass)
			if err != nil {
				return err
			}
			r.SetBasicAuth(user, p)
			return nil
		}, nil
	}
	return nil, nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Alertmanager refused the credentials")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("these credentials aren't allowed to do this")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

// status is decoded field by field: config.original holds receiver
// credentials (SMTP passwords, webhook URLs, API keys).
type status struct {
	Cluster struct {
		Status string `json:"status"`
		Name   string `json:"name"`
		Peers  []struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		} `json:"peers"`
	} `json:"cluster"`
	VersionInfo struct {
		Version string `json:"version"`
	} `json:"versionInfo"`
	Uptime string `json:"uptime"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s status
	if err := c.do(ctx, http.MethodGet, "/api/v2/status", nil, nil, &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Alertmanager v2 API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "Alertmanager " + s.VersionInfo.Version
	if s.Cluster.Status != "" && s.Cluster.Status != "disabled" {
		msg += fmt.Sprintf(" · cluster %s, %d peers", s.Cluster.Status, len(s.Cluster.Peers))
		if s.Cluster.Status != "ready" {
			return sdk.Health{Status: "degraded", Message: msg}
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Matcher is one silence matcher.
type Matcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"isRegex"`
	IsEqual *bool  `json:"isEqual,omitempty"`
}

func (x Matcher) equal() bool { return x.IsEqual == nil || *x.IsEqual }

type silence struct {
	ID        string                 `json:"id"`
	Status    struct{ State string } `json:"status"`
	Matchers  []Matcher              `json:"matchers"`
	StartsAt  string                 `json:"startsAt"`
	EndsAt    string                 `json:"endsAt"`
	CreatedBy string                 `json:"createdBy"`
	Comment   string                 `json:"comment"`
}

func (s silence) summary() map[string]any {
	return map[string]any{"id": s.ID, "state": s.Status.State, "matchers": describe(s.Matchers), "startsAt": s.StartsAt, "endsAt": s.EndsAt, "createdBy": s.CreatedBy, "comment": s.Comment}
}

func describe(ms []Matcher) string {
	parts := make([]string, 0, len(ms))
	for _, x := range ms {
		op := "="
		switch {
		case x.IsRegex && x.equal():
			op = "=~"
		case x.IsRegex:
			op = "!~"
		case !x.equal():
			op = "!="
		}
		parts = append(parts, x.Name+op+strconv.Quote(x.Value))
	}
	return strings.Join(parts, ", ")
}

// sameMatchers compares two matcher sets, in any order.
func sameMatchers(a, b []Matcher) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(ms []Matcher) []string {
		out := make([]string, 0, len(ms))
		for _, x := range ms {
			out = append(out, fmt.Sprintf("%q|%q|%t|%t", x.Name, x.Value, x.IsRegex, x.equal()))
		}
		sort.Strings(out)
		return out
	}
	ka, kb := key(a), key(b)
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

// checkMatchers validates matchers before any request: label names as
// Prometheus spells them, values of bounded length, regexes that compile
// the way Alertmanager reads them (anchored), and at least one matcher
// that isn't negative, which Alertmanager requires.
func checkMatchers(ms []Matcher) error {
	if len(ms) == 0 || len(ms) > maxMatchers {
		return fmt.Errorf("add 1 to %d matchers", maxMatchers)
	}
	positive := false
	for i, x := range ms {
		if !labelRe.MatchString(x.Name) {
			return fmt.Errorf("matcher %d: a label name is letters, digits and _ (not starting with a digit)", i+1)
		}
		if len(x.Value) > maxValue {
			return fmt.Errorf("matcher %s: the value is too long", x.Name)
		}
		if x.IsRegex {
			if _, err := regexp.Compile("^(?:" + x.Value + ")$"); err != nil {
				return fmt.Errorf("matcher %s: %v", x.Name, err)
			}
		}
		if x.equal() {
			positive = true
		}
		if x.IsEqual == nil {
			t := true
			ms[i].IsEqual = &t
		}
	}
	if !positive {
		return errors.New("at least one matcher must be = or =~ (Alertmanager refuses only negative ones)")
	}
	return nil
}

type input struct {
	IncludeSilenced  bool              `json:"includeSilenced"`
	IncludeInhibited bool              `json:"includeInhibited"`
	IncludeExpired   bool              `json:"includeExpired"`
	Labels           map[string]string `json:"labels"`
	Matchers         []Matcher         `json:"matchers"`
	DurationMinutes  int               `json:"durationMinutes"`
	Comment          string            `json:"comment"`
	ID               string            `json:"id"`
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
	case "status":
		var s status
		if err := c.do(ctx, http.MethodGet, "/api/v2/status", nil, nil, &s); err != nil {
			return sdk.Result{}, err
		}
		peers := []string{}
		for _, x := range s.Cluster.Peers {
			peers = append(peers, x.Name+" "+x.Address)
		}
		return sdk.JSON(map[string]any{"version": s.VersionInfo.Version, "uptime": s.Uptime, "cluster": s.Cluster.Status, "clusterName": s.Cluster.Name, "peers": peers})
	case "alerts":
		return c.alerts(ctx, p)
	case "receivers":
		var rs []struct {
			Name string `json:"name"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/v2/receivers", nil, nil, &rs); err != nil {
			return sdk.Result{}, err
		}
		out := []string{}
		for _, r := range rs {
			out = append(out, r.Name)
		}
		sort.Strings(out)
		return sdk.JSON(out)
	case "silences":
		list, err := c.silences(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range list {
			if s.Status.State == "expired" && !p.IncludeExpired {
				continue
			}
			out = append(out, s.summary())
		}
		return sdk.JSON(out)
	case "create_silence":
		return m.createSilence(ctx, c, call, p)
	case "expire_silence":
		return m.expireSilence(ctx, c, call, strings.TrimSpace(p.ID))
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) alerts(ctx context.Context, p input) (sdk.Result, error) {
	q := url.Values{"active": {"true"}, "silenced": {strconv.FormatBool(p.IncludeSilenced)}, "inhibited": {strconv.FormatBool(p.IncludeInhibited)}, "unprocessed": {"false"}}
	if len(p.Labels) > maxMatchers {
		return sdk.Result{}, fmt.Errorf("filter by at most %d labels", maxMatchers)
	}
	names := make([]string, 0, len(p.Labels))
	for k := range p.Labels {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := p.Labels[k]
		if !labelRe.MatchString(k) {
			return sdk.Result{}, fmt.Errorf("%q isn't a label name", k)
		}
		if len(v) > maxValue {
			return sdk.Result{}, fmt.Errorf("the value for %s is too long", k)
		}
		// strconv.Quote escapes " and \ the way Alertmanager's matcher
		// parser reads them.
		q.Add("filter", k+"="+strconv.Quote(v))
	}
	var list []struct {
		Labels       map[string]string `json:"labels"`
		Annotations  map[string]string `json:"annotations"`
		StartsAt     string            `json:"startsAt"`
		GeneratorURL string            `json:"generatorURL"`
		Fingerprint  string            `json:"fingerprint"`
		Receivers    []struct {
			Name string `json:"name"`
		} `json:"receivers"`
		Status struct {
			State       string   `json:"state"`
			SilencedBy  []string `json:"silencedBy"`
			InhibitedBy []string `json:"inhibitedBy"`
		} `json:"status"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v2/alerts", q, nil, &list); err != nil {
		return sdk.Result{}, err
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].StartsAt > list[j].StartsAt })
	out := []map[string]any{}
	for _, a := range list {
		if len(out) >= maxAlerts {
			break
		}
		recv := []string{}
		for _, r := range a.Receivers {
			recv = append(recv, r.Name)
		}
		row := map[string]any{"name": a.Labels["alertname"], "state": a.Status.State, "since": a.StartsAt, "labels": a.Labels, "fingerprint": a.Fingerprint, "receivers": recv}
		if a.GeneratorURL != "" {
			row["link"] = rest.StripUserinfo(a.GeneratorURL)
		}
		for _, k := range []string{"summary", "description"} {
			if s := a.Annotations[k]; s != "" {
				row[k] = clip(s, 500)
			}
		}
		if len(a.Status.SilencedBy) > 0 {
			row["silencedBy"] = a.Status.SilencedBy
		}
		if len(a.Status.InhibitedBy) > 0 {
			row["inhibitedBy"] = a.Status.InhibitedBy
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"alerts": out, "total": len(list), "truncated": len(list) > len(out)})
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}

func (c *conn) silences(ctx context.Context) ([]silence, error) {
	var list []silence
	err := c.do(ctx, http.MethodGet, "/api/v2/silences", nil, nil, &list)
	return list, err
}

func (m *Module) createSilence(ctx context.Context, c *conn, call sdk.Call, p input) (sdk.Result, error) {
	if err := checkMatchers(p.Matchers); err != nil {
		return sdk.Result{}, err
	}
	p.Comment = strings.TrimSpace(p.Comment)
	if p.Comment == "" {
		return sdk.Result{}, errors.New("say why in the comment")
	}
	if len(p.Comment) > maxComment {
		return sdk.Result{}, errors.New("the comment is too long")
	}
	mins := p.DurationMinutes
	if mins == 0 {
		mins = 120
	}
	if mins < 1 || mins > maxSilence {
		return sdk.Result{}, errors.New("the duration is 1 minute to 30 days (43200 minutes)")
	}
	start := m.clock().UTC()
	end := start.Add(time.Duration(mins) * time.Minute)
	// Nothing to change when an active silence with the same matchers
	// already lasts at least as long.
	list, err := c.silences(ctx)
	if err != nil {
		return sdk.Result{}, err
	}
	for _, s := range list {
		if s.Status.State != "active" || !sameMatchers(s.Matchers, p.Matchers) {
			continue
		}
		if e, err := time.Parse(time.RFC3339, s.EndsAt); err == nil && !e.Before(end) {
			return sdk.JSON(map[string]any{"id": s.ID, "endsAt": s.EndsAt, "note": "nothing to change: a silence with these matchers already lasts this long"})
		}
	}
	body := map[string]any{"matchers": p.Matchers, "startsAt": start.Format(time.RFC3339), "endsAt": end.Format(time.RFC3339), "createdBy": "Conduit", "comment": p.Comment}
	if call.DryRun {
		after, _ := json.Marshal(body)
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Silence alerts matching %s for %s", describe(p.Matchers), time.Duration(mins)*time.Minute),
			Changes: []sdk.Change{{Target: "silence " + describe(p.Matchers), Op: "create", After: after}}}}, nil
	}
	var r struct {
		SilenceID string `json:"silenceID"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v2/silences", nil, body, &r); err != nil {
		return sdk.Result{}, err
	}
	if !silenceRe.MatchString(r.SilenceID) {
		return sdk.Result{}, errors.New("Alertmanager didn't answer with the new silence's id")
	}
	res, err := sdk.JSON(map[string]any{"id": r.SilenceID, "endsAt": body["endsAt"]})
	res.Undo = sdk.UndoWith("expire_silence", map[string]any{"id": r.SilenceID}, "Expire the silence")
	return res, err
}

func (m *Module) expireSilence(ctx context.Context, c *conn, call sdk.Call, sid string) (sdk.Result, error) {
	if !silenceRe.MatchString(sid) {
		return sdk.Result{}, errors.New("enter the silence id (from silences)")
	}
	var s silence
	if err := c.do(ctx, http.MethodGet, "/api/v2/silence/"+url.PathEscape(sid), nil, nil, &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no silence %s", sid)
		}
		return sdk.Result{}, err
	}
	if s.ID != sid {
		return sdk.Result{}, fmt.Errorf("Alertmanager answered with another silence for %s", sid)
	}
	if s.Status.State == "expired" {
		return sdk.JSON(map[string]any{"id": sid, "note": "nothing to change: the silence has already expired"})
	}
	if call.DryRun {
		before, _ := json.Marshal(s.summary())
		return sdk.Result{Plan: &sdk.Plan{Summary: "Expire the silence on " + describe(s.Matchers),
			Changes: []sdk.Change{{Target: "silence " + sid, Op: "expire", Before: before}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, "/api/v2/silence/"+url.PathEscape(sid), nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"expired": sid})
	if end, perr := time.Parse(time.RFC3339, s.EndsAt); perr == nil {
		if left := end.Sub(m.clock()); left > time.Minute {
			mins := int(math.Ceil(left.Minutes()))
			if mins > maxSilence {
				mins = maxSilence
			}
			comment := s.Comment
			if strings.TrimSpace(comment) == "" {
				comment = "restored by Conduit"
			}
			res.Undo = sdk.UndoWith("create_silence", map[string]any{"matchers": s.Matchers, "comment": clip(comment, maxComment-4), "durationMinutes": mins},
				"Silence "+describe(s.Matchers)+" again")
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
