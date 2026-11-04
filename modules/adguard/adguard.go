// Package adguard reads and controls AdGuard Home.
package adguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one AdGuard Home.
type Config struct {
	URL      string `json:"url"`      // e.g. http://adguard.local:3000
	Username string `json:"username"` // web interface user
	Password string `json:"password"` // secret://
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the AdGuard Home module.
func New() *Module { return &Module{} }

const ruleIn = `{"type":"object","required":["rule"],"properties":{"rule":{"type":"string","maxLength":1024,"description":"A filtering rule, e.g. ||ads.example.com^ to block or @@||example.com^ to allow"}}}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "adguard", Name: "AdGuard Home", Version: "0.1.0", Category: "Network", Icon: "shield",
		Description: "What AdGuard Home blocks, pause protection, and keep your own filtering rules.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"The web interface's address, e.g. http://adguard.local:3000"},
			"username":{"type":"string"},
			"password":{"type":"string","x-secret":true}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Status", Description: "Whether protection is on, and today's numbers.", Risk: sdk.RiskRead},
			{Name: "query_log", Title: "Recent queries", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":50,"maximum":500},"blockedOnly":{"type":"boolean"}}}`)},
			{Name: "protection_off", Title: "Pause protection", Description: "For some minutes, or until switched back on (0). Nothing is filtered meanwhile, for every client, so this is destructive.", Risk: sdk.RiskDestructive, Reversible: true,
				Input: sdk.Schema(`{"type":"object","properties":{"minutes":{"type":"integer","default":10,"minimum":0,"maximum":1440}}}`)},
			{Name: "protection_on", Title: "Turn protection back on", Risk: sdk.RiskWrite, Reversible: true},
			{Name: "rule_add", Title: "Add a filtering rule", Description: "A blocking rule stops a domain resolving for every client, an allow rule lets it through every filter, so this is destructive. Undo removes it.", Risk: sdk.RiskDestructive, Reversible: true, Input: sdk.Schema(ruleIn)},
			{Name: "rule_remove", Title: "Remove a filtering rule", Risk: sdk.RiskDestructive, Reversible: true, Input: sdk.Schema(ruleIn)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("the address is like http://adguard.local:3000")
	}
	if strings.TrimSpace(c.Username) == "" || !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("add the username, and the password as a vault reference")
	}
	user, pwRef := c.Username, c.Password
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/")+"/control", func(ctx context.Context, r *http.Request) error {
		pw, err := h.Secret(ctx, pwRef)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, pw)
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

type status struct {
	Protection bool   `json:"protection_enabled"`
	Running    bool   `json:"running"`
	Version    string `json:"version"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s status
	if _, err := c.api.Do(ctx, "GET", "/status", nil, nil, &s); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if !s.Running {
		return sdk.Health{Status: "down", Message: "DNS isn't running"}
	}
	if !s.Protection {
		return sdk.Health{Status: "degraded", Message: "protection is paused"}
	}
	return sdk.Health{Status: "ok", Message: "AdGuard Home " + s.Version}
}

func validRule(r string) (string, error) {
	r = strings.TrimSpace(r)
	if r == "" || len(r) > 1024 || strings.ContainsAny(r, "\r\n\x00") {
		return "", errors.New("a rule is one line of up to 1024 characters")
	}
	return r, nil
}

func (c *conn) rules(ctx context.Context) ([]string, error) {
	var f struct {
		UserRules []string `json:"user_rules"`
	}
	if _, err := c.api.Do(ctx, "GET", "/filtering/status", nil, nil, &f); err != nil {
		return nil, err
	}
	if f.UserRules == nil {
		f.UserRules = []string{}
	}
	return f.UserRules, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Limit       int    `json:"limit"`
		BlockedOnly bool   `json:"blockedOnly"`
		Minutes     *int   `json:"minutes"`
		Rule        string `json:"rule"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "status":
		var s status
		if _, err := c.api.Do(ctx, "GET", "/status", nil, nil, &s); err != nil {
			return sdk.Result{}, err
		}
		var st struct {
			Queries int                `json:"num_dns_queries"`
			Blocked int                `json:"num_blocked_filtering"`
			AvgMS   float64            `json:"avg_processing_time"`
			Top     []map[string]int64 `json:"top_blocked_domains"`
		}
		if _, err := c.api.Do(ctx, "GET", "/stats", nil, nil, &st); err != nil {
			return sdk.Result{}, err
		}
		type top struct {
			Domain string `json:"domain"`
			Count  int64  `json:"count"`
		}
		tops := []top{}
		for _, m := range st.Top {
			for d, n := range m {
				tops = append(tops, top{d, n})
			}
		}
		if len(tops) > 10 {
			tops = tops[:10]
		}
		pct := 0.0
		if st.Queries > 0 {
			pct = float64(st.Blocked) * 100 / float64(st.Queries)
		}
		return sdk.JSON(map[string]any{"protection": s.Protection, "running": s.Running, "version": s.Version,
			"queries": st.Queries, "blocked": st.Blocked, "percentBlocked": pct, "avgResponseMs": st.AvgMS * 1000, "topBlocked": tops})

	case "query_log":
		n := p.Limit
		if n <= 0 || n > 500 {
			n = 50
		}
		q := url.Values{"limit": {strconv.Itoa(n)}}
		if p.BlockedOnly {
			q.Set("response_status", "blocked")
		}
		var lg struct {
			Data []struct {
				Time     string `json:"time"`
				Client   string `json:"client"`
				Reason   string `json:"reason"`
				Question struct {
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"question"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, "GET", "/querylog", q, nil, &lg); err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Time   string `json:"time"`
			Client string `json:"client"`
			Domain string `json:"domain"`
			Type   string `json:"type"`
			Result string `json:"result"`
		}
		out := []row{}
		for _, d := range lg.Data {
			out = append(out, row{Time: d.Time, Client: d.Client, Domain: d.Question.Name, Type: d.Question.Type, Result: d.Reason})
		}
		return sdk.JSON(out)

	case "protection_off":
		mins := 10
		if p.Minutes != nil {
			mins = *p.Minutes
		}
		if mins < 0 || mins > 1440 {
			return sdk.Result{}, errors.New("pause for 0 (until switched back on) to 1440 minutes")
		}
		body := map[string]any{"enabled": false}
		if mins > 0 {
			body["duration"] = mins * 60 * 1000
		}
		if _, err := c.api.Do(ctx, "POST", "/protection", nil, body, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"protection": false, "minutes": mins})
		r.Undo = sdk.UndoWith("protection_on", map[string]string{}, "Turn protection back on")
		return r, nil

	case "protection_on":
		if _, err := c.api.Do(ctx, "POST", "/protection", nil, map[string]any{"enabled": true}, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]bool{"protection": true})
		r.Undo = sdk.UndoWith("protection_off", map[string]int{"minutes": 0}, "Pause protection again")
		return r, nil

	case "rule_add", "rule_remove":
		rule, err := validRule(p.Rule)
		if err != nil {
			return sdk.Result{}, err
		}
		rules, err := c.rules(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		next := []string{}
		found := false
		for _, r := range rules {
			if r == rule {
				found = true
				if call.Action == "rule_remove" {
					continue
				}
			}
			next = append(next, r)
		}
		if call.Action == "rule_add" && !found {
			next = append(next, rule)
		}
		if call.Action == "rule_remove" && !found {
			return sdk.Result{}, errors.New("there's no such rule")
		}
		if _, err := c.api.Do(ctx, "POST", "/filtering/set_rules", nil, map[string]any{"rules": next}, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"rule": rule, "rules": len(next)})
		if call.Action == "rule_add" && !found {
			r.Undo = sdk.UndoWith("rule_remove", map[string]string{"rule": rule}, "Remove the rule again")
		} else if call.Action == "rule_remove" {
			r.Undo = sdk.UndoWith("rule_add", map[string]string{"rule": rule}, "Put the rule back")
		}
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
