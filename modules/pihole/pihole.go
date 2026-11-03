// Package pihole reads and controls a Pi-hole (v6) DNS blocker.
package pihole

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Pi-hole.
type Config struct {
	URL      string `json:"url"`      // e.g. http://pi.hole
	Password string `json:"password"` // secret://, the web or an app password
}

type conn struct {
	cfg  Config
	host sdk.Host
	base string
	http *http.Client

	mu      sync.Mutex
	sid     string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Pi-hole module.
func New() *Module { return &Module{} }

var domainRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$`)

const domainIn = `{"type":"object","required":["domain"],"properties":{"domain":{"type":"string"},"list":{"type":"string","enum":["deny","allow"],"default":"deny"}}}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "pihole", Name: "Pi-hole", Version: "0.1.0", Category: "Network", Icon: "shield",
		Description: "How much your Pi-hole blocks, pause blocking for a while, and block or allow domains.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","password"],"properties":{
			"url":{"type":"string","description":"The Pi-hole's address, e.g. http://pi.hole"},
			"password":{"type":"string","x-secret":true,"description":"An app password (Settings, Web interface / API) or the web password"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "summary", Title: "Summary", Description: "Queries today, how many were blocked, and whether blocking is on.", Risk: sdk.RiskRead},
			{Name: "top_blocked", Title: "Most blocked domains", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"count":{"type":"integer","default":10,"maximum":100}}}`)},
			{Name: "disable", Title: "Pause blocking", Description: "For some seconds, or until switched back on (0).", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","properties":{"seconds":{"type":"integer","default":300,"minimum":0,"maximum":86400}}}`)},
			{Name: "enable", Title: "Turn blocking back on", Risk: sdk.RiskWrite, Reversible: true},
			{Name: "domain_add", Title: "Block or allow a domain", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(domainIn)},
			{Name: "domain_remove", Title: "Remove a domain from a list", Risk: sdk.RiskWrite, Reversible: true, Input: sdk.Schema(domainIn)},
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
		return errors.New("the address is like http://pi.hole")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	cn := &conn{cfg: c, host: h, base: u.Scheme + "://" + u.Host + "/api", http: m.HTTP}
	if cn.http == nil {
		cn.http = &http.Client{Timeout: 20 * time.Second}
	}
	// The session id travels in X-FTL-SID, which Go would forward to another host.
	cn.http = rest.SameHostOnly(cn.http)
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// session logs in (once per validity period) and returns the session id.
func (c *conn) session(ctx context.Context, fresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !fresh && c.sid != "" && time.Now().Before(c.expires) {
		return c.sid, nil
	}
	pw, err := c.host.Secret(ctx, c.cfg.Password)
	if err != nil {
		return "", err
	}
	r := rest.New(c.base, nil)
	r.HTTP = c.http
	var out struct {
		Session struct {
			Valid    bool   `json:"valid"`
			SID      string `json:"sid"`
			Validity int    `json:"validity"`
			Message  string `json:"message"`
		} `json:"session"`
	}
	if _, err := r.Do(ctx, "POST", "/auth", nil, map[string]string{"password": pw}, &out); err != nil {
		return "", fmt.Errorf("Pi-hole sign-in: %w", err)
	}
	if !out.Session.Valid {
		return "", errors.New("Pi-hole refused the password")
	}
	v := out.Session.Validity
	if v <= 0 {
		v = 300
	}
	c.sid, c.expires = out.Session.SID, time.Now().Add(time.Duration(v)*time.Second-30*time.Second)
	return c.sid, nil
}

// do calls the API, signing in again once if the session expired.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	for attempt := 0; attempt < 2; attempt++ {
		sid, err := c.session(ctx, attempt > 0)
		if err != nil {
			return err
		}
		r := rest.New(c.base, func(_ context.Context, req *http.Request) error {
			if sid != "" {
				req.Header.Set("X-FTL-SID", sid)
			}
			return nil
		})
		r.HTTP = c.http
		_, err = r.Do(ctx, method, path, q, body, out)
		if rest.IsStatus(err, http.StatusUnauthorized) && attempt == 0 {
			continue
		}
		return err
	}
	return nil
}

type blocking struct {
	Blocking string   `json:"blocking"` // enabled, disabled, failed, unknown
	Timer    *float64 `json:"timer"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var b blocking
	if err := c.do(ctx, "GET", "/dns/blocking", nil, nil, &b); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if b.Blocking != "enabled" {
		return sdk.Health{Status: "degraded", Message: "blocking is " + b.Blocking}
	}
	return sdk.Health{Status: "ok", Message: "blocking"}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	p := struct {
		Count   int    `json:"count"`
		Seconds *int   `json:"seconds"`
		Domain  string `json:"domain"`
		List    string `json:"list"`
	}{}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "summary":
		var s struct {
			Queries struct {
				Total   int     `json:"total"`
				Blocked int     `json:"blocked"`
				Percent float64 `json:"percent_blocked"`
			} `json:"queries"`
			Clients struct {
				Active int `json:"active"`
			} `json:"clients"`
			Gravity struct {
				Domains int `json:"domains_being_blocked"`
			} `json:"gravity"`
		}
		if err := c.do(ctx, "GET", "/stats/summary", nil, nil, &s); err != nil {
			return sdk.Result{}, err
		}
		var b blocking
		if err := c.do(ctx, "GET", "/dns/blocking", nil, nil, &b); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"queries": s.Queries.Total, "blocked": s.Queries.Blocked, "percentBlocked": s.Queries.Percent,
			"activeClients": s.Clients.Active, "domainsOnBlocklists": s.Gravity.Domains, "blocking": b.Blocking}
		if b.Timer != nil {
			out["blockingResumesInSeconds"] = int(*b.Timer)
		}
		return sdk.JSON(out)

	case "top_blocked":
		n := p.Count
		if n <= 0 || n > 100 {
			n = 10
		}
		var t struct {
			Domains []struct {
				Domain string `json:"domain"`
				Count  int    `json:"count"`
			} `json:"domains"`
		}
		if err := c.do(ctx, "GET", "/stats/top_domains", url.Values{"blocked": {"true"}, "count": {strconv.Itoa(n)}}, nil, &t); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(t.Domains)

	case "disable":
		secs := 300
		if p.Seconds != nil {
			secs = *p.Seconds
		}
		if secs < 0 || secs > 86400 {
			return sdk.Result{}, errors.New("pause for 0 (until switched back on) to 86400 seconds")
		}
		body := map[string]any{"blocking": false, "timer": nil}
		if secs > 0 {
			body["timer"] = secs
		}
		var b blocking
		if err := c.do(ctx, "POST", "/dns/blocking", nil, body, &b); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(b)
		r.Undo = sdk.UndoWith("enable", map[string]string{}, "Turn blocking back on")
		return r, nil

	case "enable":
		var b blocking
		if err := c.do(ctx, "POST", "/dns/blocking", nil, map[string]any{"blocking": true, "timer": nil}, &b); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(b)
		r.Undo = sdk.UndoWith("disable", map[string]int{"seconds": 0}, "Pause blocking again")
		return r, nil

	case "domain_add", "domain_remove":
		d := strings.ToLower(strings.TrimSpace(p.Domain))
		if !domainRe.MatchString(d) || len(d) > 253 {
			return sdk.Result{}, errors.New("give a domain such as ads.example.com")
		}
		list := p.List
		if list == "" {
			list = "deny"
		}
		if list != "deny" && list != "allow" {
			return sdk.Result{}, errors.New("the list is deny or allow")
		}
		in := map[string]string{"domain": d, "list": list}
		if call.Action == "domain_add" {
			if err := c.do(ctx, "POST", "/domains/"+list+"/exact", nil, map[string]any{"domain": d, "comment": "added by Conduit", "enabled": true}, nil); err != nil {
				return sdk.Result{}, err
			}
			r, _ := sdk.JSON(in)
			r.Undo = sdk.UndoWith("domain_remove", in, "Take "+d+" off the "+list+" list")
			return r, nil
		}
		if err := c.do(ctx, "DELETE", "/domains/"+list+"/exact/"+url.PathEscape(d), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(in)
		r.Undo = sdk.UndoWith("domain_add", in, "Put "+d+" back on the "+list+" list")
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
