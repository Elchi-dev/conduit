// Package wazuh works with a Wazuh server through its API (a user and
// password exchanged for a session token): agents and their status,
// restarting an agent, and, through the Wazuh indexer, an alerts summary,
// recent alerts and a vulnerability summary.
package wazuh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

// Config is one Wazuh server, and optionally its indexer.
type Config struct {
	URL                string `json:"url"`      // e.g. https://wazuh.example.com:55000
	User               string `json:"user"`     // API user
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	IndexerURL         string `json:"indexerUrl"`      // e.g. https://wazuh.example.com:9200
	IndexerUser        string `json:"indexerUser"`     // read-only indexer user
	IndexerPassword    string `json:"indexerPassword"` // secret://
	IndexerFingerprint string `json:"indexerFingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api   *rest.Client
	login *rest.Client
	idx   *rest.Client // nil without an indexer
	user  string
	pass  string
	host  sdk.Host

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the clients made from the host (tests).
	HTTP *http.Client
}

// New returns the Wazuh module.
func New() *Module { return &Module{} }

var (
	pathRe  = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	userRe  = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
	agentRe = regexp.MustCompile(`^[0-9]{1,6}$`)
)

const maxPages = 20

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	agent := `"agent":{"type":"string","description":"Agent id, like 001 (from agents)"}`
	return sdk.Manifest{
		ID: "wazuh", Name: "Wazuh", Version: "0.1.0", Category: "Security", Icon: "shield",
		Description: "Wazuh: agents and their status, restarting an agent, and (with the indexer) an alerts summary, recent alerts and vulnerabilities by severity.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","user","password"],"properties":{
			"url":{"type":"string","description":"The Wazuh server API, e.g. https://wazuh.example.com:55000"},
			"user":{"type":"string","description":"An API user (Server management, Security); restarting agents needs agent:restart"},
			"password":{"type":"string","x-secret":true,"description":"The API user's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server API's certificate (Wazuh makes a self-signed one)"},
			"indexerUrl":{"type":"string","description":"The Wazuh indexer, e.g. https://wazuh.example.com:9200, for alerts and vulnerabilities"},
			"indexerUser":{"type":"string","description":"An indexer user that can read wazuh-alerts-* and wazuh-states-vulnerabilities-*"},
			"indexerPassword":{"type":"string","x-secret":true,"description":"The indexer user's password"},
			"indexerFingerprint":{"type":"string","description":"SHA-256 fingerprint of the indexer's certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks for both (not recommended; use the fingerprints)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "agents", Title: "Agents", Description: "Agents with id, name, address, status, OS, agent version, groups, node and last keep-alive, and counts by status.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["active","disconnected","never_connected","pending"]}}}`)},
			{Name: "alerts", Title: "Alerts summary", Description: "Alerts over a period counted by rule level, with the most frequent rules and the agents with the most alerts. Needs the indexer.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"hours":{"type":"integer","minimum":1,"maximum":720,"default":24},"minLevel":{"type":"integer","minimum":0,"maximum":16,"default":0},` + agent + `}}`)},
			{Name: "recent_alerts", Title: "Recent alerts", Description: "The latest alerts at or above a level, with rule, agent, source address and the log line (cut short, credentials masked). Log lines can hold attacker payloads and internal host names, so this is sensitive. Needs the indexer.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"hours":{"type":"integer","minimum":1,"maximum":720,"default":24},"minLevel":{"type":"integer","minimum":0,"maximum":16,"default":7},"limit":{"type":"integer","minimum":1,"maximum":50,"default":20},` + agent + `}}`)},
			{Name: "vulnerabilities", Title: "Vulnerability summary", Description: "Detected vulnerabilities by severity, with the most common CVEs and the most affected agents (from the indexer on Wazuh 4.8 and later; for one agent, from the server API on earlier versions).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + agent + `}}`)},
			{Name: "restart_agent", Title: "Restart an agent", Description: "Restarts the Wazuh agent on one host; it stops reporting until it's back. Not the manager (000).", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["agent"],"properties":{` + agent + `}}`)},
		},
	}
}

func parseBase(s, example string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) || strings.Contains(u.Path, "..") {
		return nil, fmt.Errorf("the address is like %s", example)
	}
	return u, nil
}

func (m *Module) client(h sdk.Host, fingerprint string, insecure bool) (*http.Client, error) {
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if fingerprint != "" || insecure {
			tc, err := tlspin.Config(fingerprint, insecure)
			if err != nil {
				return nil, err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	return rest.SameHostOnly(client), nil
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := parseBase(c.URL, "https://wazuh.example.com:55000")
	if err != nil {
		return err
	}
	user := strings.TrimSpace(c.User)
	if !userRe.MatchString(user) {
		return errors.New("the user is an API user name, like wazuh-wui")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the API password in the vault and enter its secret:// reference")
	}
	client, err := m.client(h, c.Fingerprint, c.InsecureSkipVerify)
	if err != nil {
		return err
	}
	base := u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
	cn := &conn{user: user, pass: c.Password, host: h}
	cn.login = rest.New(base, nil)
	cn.login.HTTP = client
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := cn.jwt(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = client
	if strings.TrimSpace(c.IndexerURL) != "" {
		iu, err := parseBase(c.IndexerURL, "https://wazuh.example.com:9200")
		if err != nil {
			return fmt.Errorf("indexer: %w", err)
		}
		iuser := strings.TrimSpace(c.IndexerUser)
		if !userRe.MatchString(iuser) {
			return errors.New("the indexer user is a user name, like admin")
		}
		if !strings.HasPrefix(c.IndexerPassword, "secret://") {
			return errors.New("store the indexer password in the vault and enter its secret:// reference")
		}
		ic, err := m.client(h, c.IndexerFingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		ref := c.IndexerPassword
		cn.idx = rest.New(iu.Scheme+"://"+iu.Host+strings.TrimRight(iu.Path, "/"), func(ctx context.Context, r *http.Request) error {
			p, err := h.Secret(ctx, ref)
			if err != nil {
				return err
			}
			r.SetBasicAuth(iuser, strings.TrimSpace(p))
			return nil
		})
		cn.idx.HTTP = ic
	} else if c.IndexerUser != "" || c.IndexerPassword != "" {
		return errors.New("the indexer user and password need the indexer's address")
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errLogin = errors.New("Wazuh refused the API user and password")

// jwt returns a session token, signing in when there's none or it's about
// to expire (Wazuh's default lifetime is 15 minutes).
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
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	user, pass := c.user, strings.TrimSpace(pw)
	c.login.Auth = func(_ context.Context, req *http.Request) error { req.SetBasicAuth(user, pass); return nil }
	_, err = c.login.Do(ctx, http.MethodPost, "/security/user/authenticate", nil, nil, &r)
	c.login.Auth = nil
	if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
		return "", errLogin
	}
	if err != nil {
		return "", err
	}
	if r.Data.Token == "" {
		return "", errors.New("Wazuh signed in but sent no token")
	}
	c.token, c.expires = r.Data.Token, time.Now().Add(10*time.Minute)
	return c.token, nil
}

// envelope is the Wazuh API's answer.
type envelope[T any] struct {
	Data    T      `json:"data"`
	Message string `json:"message"`
	Error   int    `json:"error"`
}

type items[T any] struct {
	Items  []T `json:"affected_items"`
	Total  int `json:"total_affected_items"`
	Failed []struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		ID []string `json:"id"`
	} `json:"failed_items"`
}

// do calls the server API, signing in again once if the session was refused.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, method, path, q, nil, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		_, err = c.api.Do(ctx, method, path, q, nil, out)
	}
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errLogin
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API user isn't allowed to do this in Wazuh (check its roles)")
	}
	return err
}

var errNoIndexer = errors.New("alerts and vulnerabilities are kept in the Wazuh indexer: set its address, user and password in the settings")

func (c *conn) search(ctx context.Context, index string, body, out any) error {
	if c.idx == nil {
		return errNoIndexer
	}
	_, err := c.idx.Do(ctx, http.MethodPost, "/"+index+"/_search", nil, body, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("the Wazuh indexer refused its user and password")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("the indexer user can't read %s", index)
	}
	return err
}

// clean makes text from Wazuh safe to show: credentials masked first, then
// control characters dropped and the result cut to n characters.
func clean(s string, n int) string { return clip(rest.Redact(s), n) }

func clip(s string, n int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s))
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n]) + "…"
	}
	return s
}

func agentID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !agentRe.MatchString(s) {
		return "", errors.New("the agent is its id, like 001 (from agents)")
	}
	n, _ := strconv.Atoi(s)
	return fmt.Sprintf("%03d", n), nil
}

type agent struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	IP            string   `json:"ip"`
	Status        string   `json:"status"`
	Version       string   `json:"version"`
	Group         []string `json:"group"`
	NodeName      string   `json:"node_name"`
	LastKeepAlive string   `json:"lastKeepAlive"`
	OS            struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"os"`
}

const agentFields = "id,name,ip,status,version,group,node_name,lastKeepAlive,os.name,os.version"

type summary struct {
	Active         int `json:"active"`
	Disconnected   int `json:"disconnected"`
	NeverConnected int `json:"never_connected"`
	Pending        int `json:"pending"`
	Total          int `json:"total"`
}

func (c *conn) summary(ctx context.Context) (summary, error) {
	var r envelope[struct {
		Connection *summary `json:"connection"`
		summary
		OldTotal int `json:"Total"`
	}]
	if err := c.do(ctx, http.MethodGet, "/agents/summary/status", nil, &r); err != nil {
		return summary{}, err
	}
	if r.Data.Connection != nil {
		return *r.Data.Connection, nil
	}
	s := r.Data.summary
	if s.Total == 0 {
		s.Total = r.Data.OldTotal
	}
	return s, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var info envelope[struct {
		Version string `json:"api_version"`
	}]
	if err := c.do(ctx, http.MethodGet, "/", nil, &info); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Wazuh server API at this address (it listens on port 55000)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	s, err := c.summary(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%d agents, %d active", s.Total, s.Active)
	if s.Disconnected > 0 {
		msg += fmt.Sprintf(", %d disconnected", s.Disconnected)
	}
	if v := clip(info.Data.Version, 20); v != "" {
		msg = "Wazuh " + v + ", " + msg
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Status   string `json:"status"`
		Agent    string `json:"agent"`
		Hours    int    `json:"hours"`
		MinLevel *int   `json:"minLevel"`
		Limit    int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	var ag string
	if strings.TrimSpace(p.Agent) != "" || call.Action == "restart_agent" {
		if ag, err = agentID(p.Agent); err != nil {
			return sdk.Result{}, err
		}
	}
	hours := p.Hours
	if hours == 0 {
		hours = 24
	}
	if hours < 1 || hours > 720 {
		return sdk.Result{}, errors.New("hours is between 1 and 720")
	}
	level := 0
	if call.Action == "recent_alerts" {
		level = 7
	}
	if p.MinLevel != nil {
		level = *p.MinLevel
	}
	if level < 0 || level > 16 {
		return sdk.Result{}, errors.New("minLevel is between 0 and 16")
	}
	switch call.Action {
	case "agents":
		switch p.Status {
		case "", "active", "disconnected", "never_connected", "pending":
		default:
			return sdk.Result{}, errors.New("status is active, disconnected, never_connected or pending")
		}
		return c.agents(ctx, p.Status)
	case "alerts":
		return c.alerts(ctx, hours, level, ag)
	case "recent_alerts":
		limit := p.Limit
		if limit == 0 {
			limit = 20
		}
		if limit < 1 || limit > 50 {
			return sdk.Result{}, errors.New("limit is between 1 and 50")
		}
		return c.recent(ctx, hours, level, ag, limit)
	case "vulnerabilities":
		return c.vulnerabilities(ctx, ag)
	case "restart_agent":
		return c.restart(ctx, call, ag)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (a agent) row() map[string]any {
	groups := []string{}
	for _, g := range a.Group {
		groups = append(groups, clip(g, 100))
	}
	return map[string]any{"id": a.ID, "name": clip(a.Name, 128), "ip": clip(a.IP, 64), "status": a.Status, "os": strings.TrimSpace(clip(a.OS.Name, 60) + " " + clip(a.OS.Version, 40)),
		"version": clip(a.Version, 40), "groups": groups, "node": clip(a.NodeName, 64), "lastKeepAlive": clip(a.LastKeepAlive, 40)}
}

func (c *conn) agents(ctx context.Context, status string) (sdk.Result, error) {
	rows := []map[string]any{}
	byStatus := map[string]int{}
	more := false
	for page := 0; ; page++ {
		if page == maxPages {
			more = true
			break
		}
		q := url.Values{"limit": {"500"}, "offset": {strconv.Itoa(page * 500)}, "select": {agentFields}, "sort": {"+id"}}
		if status != "" {
			q.Set("status", status)
		}
		var r envelope[items[agent]]
		if err := c.do(ctx, http.MethodGet, "/agents", q, &r); err != nil {
			return sdk.Result{}, err
		}
		for _, a := range r.Data.Items {
			byStatus[a.Status]++
			rows = append(rows, a.row())
		}
		if len(r.Data.Items) < 500 || len(rows) >= r.Data.Total {
			break
		}
	}
	return sdk.JSON(map[string]any{"agents": rows, "byStatus": byStatus, "truncated": more})
}

type bucket struct {
	Key      json.RawMessage `json:"key"`
	DocCount int             `json:"doc_count"`
	Top      *struct {
		Hits struct {
			Hits []struct {
				Source json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	} `json:"top"`
}

func key(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.Trim(string(raw), `"`)
}

type searchResult struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source json.RawMessage `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
	Aggs map[string]struct {
		Buckets []bucket `json:"buckets"`
	} `json:"aggregations"`
}

func filters(hours, level int, ag string) []any {
	f := []any{map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": fmt.Sprintf("now-%dh", hours)}}}}
	if level > 0 {
		f = append(f, map[string]any{"range": map[string]any{"rule.level": map[string]any{"gte": level}}})
	}
	if ag != "" {
		f = append(f, map[string]any{"term": map[string]any{"agent.id": ag}})
	}
	return f
}

func (c *conn) alerts(ctx context.Context, hours, level int, ag string) (sdk.Result, error) {
	body := map[string]any{
		"size": 0, "track_total_hits": true,
		"query": map[string]any{"bool": map[string]any{"filter": filters(hours, level, ag)}},
		"aggs": map[string]any{
			"levels": map[string]any{"terms": map[string]any{"field": "rule.level", "size": 20}},
			"rules": map[string]any{"terms": map[string]any{"field": "rule.id", "size": 10},
				"aggs": map[string]any{"top": map[string]any{"top_hits": map[string]any{"size": 1, "_source": []string{"rule.description", "rule.level"}}}}},
			"agents": map[string]any{"terms": map[string]any{"field": "agent.name", "size": 10}},
		},
	}
	var r searchResult
	if err := c.search(ctx, "wazuh-alerts-*", body, &r); err != nil {
		return sdk.Result{}, err
	}
	byLevel := map[string]int{}
	for _, b := range r.Aggs["levels"].Buckets {
		byLevel[clip(key(b.Key), 4)] = b.DocCount
	}
	rules := []map[string]any{}
	for _, b := range r.Aggs["rules"].Buckets {
		row := map[string]any{"rule": clip(key(b.Key), 12), "count": b.DocCount}
		if b.Top != nil && len(b.Top.Hits.Hits) > 0 {
			var s struct {
				Rule struct {
					Description string `json:"description"`
					Level       int    `json:"level"`
				} `json:"rule"`
			}
			if json.Unmarshal(b.Top.Hits.Hits[0].Source, &s) == nil {
				row["description"] = clean(s.Rule.Description, 200)
				row["level"] = s.Rule.Level
			}
		}
		rules = append(rules, row)
	}
	agents := []map[string]any{}
	for _, b := range r.Aggs["agents"].Buckets {
		agents = append(agents, map[string]any{"agent": clip(key(b.Key), 128), "count": b.DocCount})
	}
	out := map[string]any{"hours": hours, "total": r.Hits.Total.Value, "byLevel": byLevel, "topRules": rules, "topAgents": agents}
	if level > 0 {
		out["minLevel"] = level
	}
	if ag != "" {
		out["agent"] = ag
	}
	return sdk.JSON(out)
}

func (c *conn) recent(ctx context.Context, hours, level int, ag string, limit int) (sdk.Result, error) {
	body := map[string]any{
		"size":    limit,
		"sort":    []any{map[string]any{"timestamp": map[string]any{"order": "desc"}}},
		"_source": []string{"timestamp", "rule.id", "rule.level", "rule.description", "rule.groups", "agent.id", "agent.name", "data.srcip", "location", "full_log"},
		"query":   map[string]any{"bool": map[string]any{"filter": filters(hours, level, ag)}},
	}
	var r searchResult
	if err := c.search(ctx, "wazuh-alerts-*", body, &r); err != nil {
		return sdk.Result{}, err
	}
	rows := []map[string]any{}
	for i, h := range r.Hits.Hits {
		if i == limit {
			break
		}
		var s struct {
			Timestamp string `json:"timestamp"`
			Rule      struct {
				ID          string   `json:"id"`
				Level       int      `json:"level"`
				Description string   `json:"description"`
				Groups      []string `json:"groups"`
			} `json:"rule"`
			Agent struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"agent"`
			Data struct {
				SrcIP string `json:"srcip"`
			} `json:"data"`
			Location string `json:"location"`
			FullLog  string `json:"full_log"`
		}
		if json.Unmarshal(h.Source, &s) != nil {
			continue
		}
		groups := []string{}
		for j, g := range s.Rule.Groups {
			if j == 10 {
				break
			}
			groups = append(groups, clip(g, 60))
		}
		row := map[string]any{"time": clip(s.Timestamp, 40), "rule": clip(s.Rule.ID, 12), "level": s.Rule.Level, "description": clean(s.Rule.Description, 200),
			"groups": groups, "agent": clip(s.Agent.Name, 128), "agentId": clip(s.Agent.ID, 8), "location": clean(s.Location, 200), "log": clean(s.FullLog, 500)}
		if s.Data.SrcIP != "" {
			row["srcip"] = clip(s.Data.SrcIP, 64)
		}
		rows = append(rows, row)
	}
	return sdk.JSON(map[string]any{"hours": hours, "minLevel": level, "total": r.Hits.Total.Value, "alerts": rows})
}

var severities = []string{"Critical", "High", "Medium", "Low"}

func (c *conn) vulnerabilities(ctx context.Context, ag string) (sdk.Result, error) {
	if c.idx == nil {
		if ag == "" {
			return sdk.Result{}, errNoIndexer
		}
		// Wazuh before 4.8 kept vulnerabilities in the server API.
		var r envelope[map[string]map[string]int]
		if err := c.do(ctx, http.MethodGet, "/vulnerability/"+url.PathEscape(ag)+"/summary/severity", nil, &r); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, errors.New("this Wazuh server keeps vulnerabilities in the indexer (4.8 and later): set its address, user and password in the settings")
			}
			return sdk.Result{}, err
		}
		by := map[string]int{}
		for k, v := range r.Data["severity"] {
			by[clip(k, 20)] = v
		}
		return sdk.JSON(map[string]any{"agent": ag, "bySeverity": by, "source": "server API"})
	}
	q := map[string]any{"match_all": map[string]any{}}
	if ag != "" {
		q = map[string]any{"bool": map[string]any{"filter": []any{map[string]any{"term": map[string]any{"agent.id": ag}}}}}
	}
	body := map[string]any{
		"size": 0, "track_total_hits": true, "query": q,
		"aggs": map[string]any{
			"severity": map[string]any{"terms": map[string]any{"field": "vulnerability.severity", "size": 10}},
			"cves":     map[string]any{"terms": map[string]any{"field": "vulnerability.id", "size": 10}},
			"agents":   map[string]any{"terms": map[string]any{"field": "agent.name", "size": 10}},
		},
	}
	var r searchResult
	if err := c.search(ctx, "wazuh-states-vulnerabilities-*", body, &r); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, errors.New("the indexer has no vulnerability index (it needs Wazuh 4.8 or later with vulnerability detection on)")
		}
		return sdk.Result{}, err
	}
	by := map[string]int{}
	for _, s := range severities {
		by[s] = 0
	}
	for _, b := range r.Aggs["severity"].Buckets {
		by[clip(key(b.Key), 20)] = b.DocCount
	}
	top := func(name string, n int) []map[string]any {
		out := []map[string]any{}
		for _, b := range r.Aggs[name].Buckets {
			out = append(out, map[string]any{"name": clip(key(b.Key), n), "count": b.DocCount})
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["count"].(int) > out[j]["count"].(int) })
		return out
	}
	out := map[string]any{"total": r.Hits.Total.Value, "bySeverity": by, "topCves": top("cves", 40), "topAgents": top("agents", 128), "source": "indexer"}
	if ag != "" {
		out["agent"] = ag
	}
	return sdk.JSON(out)
}

func (c *conn) restart(ctx context.Context, call sdk.Call, id string) (sdk.Result, error) {
	if id == "000" {
		return sdk.Result{}, errors.New("agent 000 is the Wazuh manager itself; restart it on the server")
	}
	var r envelope[items[agent]]
	if err := c.do(ctx, http.MethodGet, "/agents", url.Values{"agents_list": {id}, "select": {agentFields}}, &r); err != nil {
		return sdk.Result{}, err
	}
	var a *agent
	for i := range r.Data.Items {
		if r.Data.Items[i].ID == id {
			a = &r.Data.Items[i]
		}
	}
	if a == nil {
		return sdk.Result{}, fmt.Errorf("there's no agent %s", id)
	}
	name := clip(a.Name, 128)
	if a.Status != "active" {
		return sdk.Result{}, fmt.Errorf("agent %s (%s) is %s; only a connected agent can be restarted", id, name, clip(a.Status, 30))
	}
	target := fmt.Sprintf("agent %s (%s, %s, %s)", id, name, clip(a.IP, 64), strings.TrimSpace(clip(a.OS.Name, 60)+" "+clip(a.OS.Version, 40)))
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Restart the Wazuh agent on " + name, Changes: []sdk.Change{{Target: target, Op: "restart"}}}}, nil
	}
	var res envelope[items[string]]
	if err := c.do(ctx, http.MethodPut, "/agents/"+url.PathEscape(id)+"/restart", nil, &res); err != nil {
		return sdk.Result{}, err
	}
	for _, f := range res.Data.Failed {
		return sdk.Result{}, fmt.Errorf("Wazuh couldn't restart agent %s: %s", id, clean(f.Error.Message, 200))
	}
	ok := false
	for _, x := range res.Data.Items {
		ok = ok || x == id
	}
	if !ok {
		return sdk.Result{}, fmt.Errorf("Wazuh didn't confirm restarting agent %s", id)
	}
	return sdk.JSON(map[string]any{"agent": id, "name": name, "restarted": true})
}
