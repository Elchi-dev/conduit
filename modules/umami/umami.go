// Package umami reads website analytics from Umami: a self-hosted server
// (signing in with a user name and password for a session token) or Umami
// Cloud (an API key). Websites, totals over a period, visitors right now and
// the top pages, referrers and countries. It never changes anything.
package umami

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
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Umami server or Umami Cloud account.
type Config struct {
	Address            string `json:"address"`  // self-hosted, e.g. https://umami.example.com
	Username           string `json:"username"` // self-hosted
	Password           string `json:"password"` // secret://, self-hosted
	APIKey             string `json:"apiKey"`   // secret://, Umami Cloud
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api   *rest.Client
	login *rest.Client // self-hosted: signs in, without credentials on the client
	host  sdk.Host
	user  string
	pass  string // secret:// reference
	cloud bool
	now   func() time.Time

	mu    sync.Mutex
	token string // self-hosted session token
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.umami.is/v1 for Umami Cloud (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Umami module.
func New() *Module { return &Module{} }

const cloudBase = "https://api.umami.is/v1"

var (
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	dateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	prefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
	userRe   = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,255}$`)
)

// Periods are the ranges ending now that the period input takes.
var Periods = map[string]time.Duration{
	"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
	"90d": 90 * 24 * time.Hour, "12mo": 365 * 24 * time.Hour,
}

// metricTypes maps the "by" input to Umami's metric type; page is "url"
// before Umami 3 and "path" from it.
var metricTypes = map[string]string{
	"page": "url", "referrer": "referrer", "country": "country",
	"browser": "browser", "os": "os", "device": "device", "event": "event",
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	website := `"website":{"type":"string","description":"Website ID (a UUID, see websites)"}`
	period := `"period":{"type":"string","enum":["24h","7d","30d","90d","12mo"],"default":"7d","description":"The range ending now"},"from":{"type":"string","format":"date","description":"Start date (YYYY-MM-DD, UTC), with to, instead of a period"},"to":{"type":"string","format":"date","description":"End date (YYYY-MM-DD, UTC), inclusive"}`
	return sdk.Manifest{
		ID: "umami", Name: "Umami", Version: "0.1.0", Category: "Monitoring", Icon: "chart",
		Description: "Umami analytics (self-hosted or Umami Cloud): websites, pageviews, visitors, visits and bounce rate over a period, visitors now, top pages, referrers and countries. Read only.",
		Presets:     []string{"developer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"address":{"type":"string","description":"Your Umami server, e.g. https://umami.example.com (leave empty for Umami Cloud)"},
			"username":{"type":"string","description":"Self-hosted: the user to sign in as (a view-only user is enough)"},
			"password":{"type":"string","x-secret":true,"description":"Self-hosted: that user's password"},
			"apiKey":{"type":"string","x-secret":true,"description":"Umami Cloud: an API key (Settings, API keys), instead of address, user name and password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "websites", Title: "Websites", Description: "Websites with their ID, name and domain (including teams' websites).", Risk: sdk.RiskRead},
			{Name: "stats", Title: "Totals over a period", Description: "Pageviews, visitors, visits, bounce rate (%) and average visit time (seconds) of a website over a period.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["website"],"properties":{` + website + `,` + period + `}}`)},
			{Name: "active", Title: "Visitors now", Description: "Visitors on a website in the last 5 minutes.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["website"],"properties":{` + website + `}}`)},
			{Name: "top", Title: "Top pages, referrers, countries", Description: "The top pages, referrers, countries, browsers, operating systems, devices or events of a website over a period, by count.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["website","by"],"properties":{` + website + `,"by":{"type":"string","enum":["page","referrer","country","browser","os","device","event"]},` + period + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":10}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	client = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	addr := strings.TrimSpace(c.Address)
	cn := &conn{host: h, now: now}

	if c.APIKey != "" {
		if c.Username != "" || c.Password != "" {
			return errors.New("give an API key (Umami Cloud) or a user name and password (self-hosted), not both")
		}
		if addr != "" && strings.TrimRight(addr, "/") != cloudBase && strings.TrimRight(addr, "/") != "https://cloud.umami.is" {
			return errors.New("an API key is for Umami Cloud; leave the address empty, or sign in to your own server with a user name and password")
		}
		if !strings.HasPrefix(c.APIKey, "secret://") {
			return errors.New("store the API key in the vault and enter its secret:// reference")
		}
		base := cloudBase
		if m.Base != "" {
			base = m.Base
		}
		ref := c.APIKey
		cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
			k, err := h.Secret(ctx, ref)
			if err != nil {
				return err
			}
			r.Header.Set("x-umami-api-key", strings.TrimSpace(k))
			return nil
		})
		cn.api.HTTP = client
		cn.cloud = true
		m.set.Put(id, cn)
		return nil
	}

	u, err := url.Parse(addr)
	prefix := ""
	if err == nil {
		prefix = strings.TrimRight(u.Path, "/")
	}
	if addr == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return errors.New("the address is your Umami server, like https://umami.example.com (or give an Umami Cloud API key)")
	}
	user := strings.TrimSpace(c.Username)
	if !userRe.MatchString(user) {
		return errors.New("enter the user name to sign in as")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	base := u.Scheme + "://" + u.Host + prefix + "/api"
	cn.user, cn.pass = user, c.Password
	cn.login = rest.New(base, nil)
	cn.login.HTTP = client
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := cn.session(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errLogin = errors.New("Umami refused the user name or password")

// session returns the session token, signing in when there's none.
func (c *conn) session(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		return c.token, nil
	}
	pw, err := c.host.Secret(ctx, c.pass)
	if err != nil {
		return "", err
	}
	var a struct {
		Token string `json:"token"`
	}
	if _, err := c.login.Do(ctx, http.MethodPost, "/auth/login", nil, map[string]string{"username": c.user, "password": pw}, &a); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusBadRequest) {
			return "", errLogin
		}
		return "", fmt.Errorf("signing in to Umami: %w", err)
	}
	if a.Token == "" || len(a.Token) > 8192 || strings.ContainsAny(a.Token, "\r\n ") {
		return "", errors.New("unexpected answer from Umami when signing in")
	}
	c.token = a.Token
	return c.token, nil
}

// get calls the API; a self-hosted session that expired is renewed once.
func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	if err != nil && !c.cloud && rest.IsStatus(err, http.StatusUnauthorized) {
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		_, err = c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	}
	return err
}

func (c *conn) friendly(err error, what string) error {
	switch {
	case errors.Is(err, errLogin):
		return err
	case rest.IsStatus(err, http.StatusUnauthorized):
		if c.cloud {
			return errors.New("Umami Cloud refused the API key")
		}
		return errLogin
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Umami refused: this user can't see %s", what)
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Umami's rate limit was hit; try again in a minute")
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var ws websitesAnswer
	if err := c.get(ctx, "/websites", url.Values{"pageSize": {"1"}}, &ws); err != nil {
		return sdk.Health{Status: "down", Message: c.friendly(err, "websites").Error()}
	}
	if c.cloud {
		return sdk.Health{Status: "ok", Message: "Umami Cloud"}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + clip(c.user, 60)}
}

type website struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Domain    string `json:"domain"`
	CreatedAt string `json:"createdAt"`
}

// websitesAnswer is the paged answer of Umami 2 and later, or the plain
// list of older versions.
type websitesAnswer struct {
	Data  []website
	Count int
}

func (w *websitesAnswer) UnmarshalJSON(b []byte) error {
	var list []website
	if json.Unmarshal(b, &list) == nil {
		w.Data, w.Count = list, len(list)
		return nil
	}
	var pg struct {
		Data  []website `json:"data"`
		Count int       `json:"count"`
	}
	if err := json.Unmarshal(b, &pg); err != nil {
		return err
	}
	w.Data, w.Count = pg.Data, pg.Count
	return nil
}

// value reads a stat that's a number (Umami 3) or {"value":n,"prev":n} (Umami 2).
type value float64

func (v *value) UnmarshalJSON(b []byte) error {
	var n float64
	if json.Unmarshal(b, &n) == nil {
		*v = value(n)
		return nil
	}
	var o struct {
		Value float64 `json:"value"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	*v = value(o.Value)
	return nil
}

type input struct {
	Website string `json:"website"`
	Period  string `json:"period"`
	From    string `json:"from"`
	To      string `json:"to"`
	By      string `json:"by"`
	Limit   int    `json:"limit"`
}

func websiteID(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !uuidRe.MatchString(s) {
		return "", errors.New("the website is its ID, a UUID (see websites)")
	}
	return s, nil
}

// window turns the period or from/to into startAt and endAt in milliseconds.
func (c *conn) window(p input) (url.Values, string, error) {
	now := c.now().UTC()
	var start, end time.Time
	label := ""
	from, to := strings.TrimSpace(p.From), strings.TrimSpace(p.To)
	if from != "" || to != "" {
		if p.Period != "" {
			return nil, "", errors.New("give a period or from and to, not both")
		}
		f, err1 := time.Parse("2006-01-02", from)
		t, err2 := time.Parse("2006-01-02", to)
		if !dateRe.MatchString(from) || !dateRe.MatchString(to) || err1 != nil || err2 != nil {
			return nil, "", errors.New("from and to are both dates, like 2026-10-01")
		}
		if t.Before(f) {
			return nil, "", errors.New("to is on or after from")
		}
		if t.Sub(f) > 5*366*24*time.Hour {
			return nil, "", errors.New("a custom range spans at most five years")
		}
		if f.After(now) {
			return nil, "", errors.New("from is in the future")
		}
		start, end = f, t.Add(24*time.Hour-time.Millisecond)
		if end.After(now) {
			end = now
		}
		label = from + " to " + to
	} else {
		period := p.Period
		if period == "" {
			period = "7d"
		}
		d, ok := Periods[period]
		if !ok {
			return nil, "", errors.New("the period is one of 24h, 7d, 30d, 90d, 12mo")
		}
		start, end, label = now.Add(-d), now, period
	}
	return url.Values{"startAt": {strconv.FormatInt(start.UnixMilli(), 10)}, "endAt": {strconv.FormatInt(end.UnixMilli(), 10)}}, label, nil
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
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
	case "websites":
		out := []map[string]any{}
		for pg := 1; pg <= 10; pg++ {
			var ws websitesAnswer
			q := url.Values{"page": {strconv.Itoa(pg)}, "pageSize": {"100"}, "includeTeams": {"true"}}
			if err := c.get(ctx, "/websites", q, &ws); err != nil {
				return sdk.Result{}, c.friendly(err, "websites")
			}
			for _, w := range ws.Data {
				out = append(out, map[string]any{"id": clip(w.ID, 36), "name": clip(w.Name, 200), "domain": clip(w.Domain, 253), "created": clip(w.CreatedAt, 40)})
			}
			if len(ws.Data) < 100 || len(out) >= ws.Count {
				break
			}
		}
		return sdk.JSON(map[string]any{"websites": out})

	case "stats":
		id, err := websiteID(p.Website)
		if err != nil {
			return sdk.Result{}, err
		}
		q, label, err := c.window(p)
		if err != nil {
			return sdk.Result{}, err
		}
		var st struct {
			Pageviews value `json:"pageviews"`
			Visitors  value `json:"visitors"`
			Visits    value `json:"visits"`
			Bounces   value `json:"bounces"`
			Totaltime value `json:"totaltime"`
		}
		if err := c.get(ctx, "/websites/"+id+"/stats", q, &st); err != nil {
			return sdk.Result{}, c.friendly(err, "website "+id)
		}
		out := map[string]any{"website": id, "period": label, "pageviews": int64(st.Pageviews), "visitors": int64(st.Visitors), "visits": int64(st.Visits), "bounceRate": 0.0, "avgVisitSeconds": 0.0}
		if st.Visits > 0 {
			out["bounceRate"] = float64(int(float64(st.Bounces)/float64(st.Visits)*1000+0.5)) / 10
			out["avgVisitSeconds"] = float64(int(float64(st.Totaltime)/float64(st.Visits)*10+0.5)) / 10
		}
		return sdk.JSON(out)

	case "active":
		id, err := websiteID(p.Website)
		if err != nil {
			return sdk.Result{}, err
		}
		var raw json.RawMessage
		if err := c.get(ctx, "/websites/"+id+"/active", nil, &raw); err != nil {
			return sdk.Result{}, c.friendly(err, "website "+id)
		}
		n, err := activeCount(raw)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"website": id, "visitors": n, "window": "last 5 minutes"})

	case "top":
		id, err := websiteID(p.Website)
		if err != nil {
			return sdk.Result{}, err
		}
		typ, ok := metricTypes[p.By]
		if !ok {
			return sdk.Result{}, errors.New("by is one of page, referrer, country, browser, os, device, event")
		}
		limit := p.Limit
		if limit == 0 {
			limit = 10
		}
		if limit < 1 || limit > 100 {
			return sdk.Result{}, errors.New("the limit is between 1 and 100")
		}
		q, label, err := c.window(p)
		if err != nil {
			return sdk.Result{}, err
		}
		q.Set("type", typ)
		q.Set("limit", strconv.Itoa(limit))
		var rows []struct {
			X *string `json:"x"`
			Y float64 `json:"y"`
		}
		err = c.get(ctx, "/websites/"+id+"/metrics", q, &rows)
		if err != nil && typ == "url" && rest.IsStatus(err, http.StatusBadRequest) {
			// Umami 3 calls it path.
			q.Set("type", "path")
			err = c.get(ctx, "/websites/"+id+"/metrics", q, &rows)
		}
		if err != nil {
			return sdk.Result{}, c.friendly(err, "website "+id)
		}
		list := []map[string]any{}
		for i, r := range rows {
			if i == limit {
				break
			}
			name := "(none)"
			if r.X != nil && *r.X != "" {
				name = clip(*r.X, 300)
			}
			list = append(list, map[string]any{p.By: name, "count": int64(r.Y)})
		}
		return sdk.JSON(map[string]any{"website": id, "period": label, "by": p.By, "top": list})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// activeCount reads the active visitors from the shapes Umami versions use:
// {"visitors":n}, {"x":n} or [{"x":n}].
func activeCount(raw json.RawMessage) (int64, error) {
	var o map[string]float64
	if json.Unmarshal(raw, &o) == nil {
		for _, k := range []string{"visitors", "x"} {
			if v, ok := o[k]; ok {
				return int64(v), nil
			}
		}
	}
	var l []map[string]float64
	if json.Unmarshal(raw, &l) == nil {
		if len(l) == 0 {
			return 0, nil
		}
		return int64(l[0]["x"]), nil
	}
	return 0, errors.New("unexpected answer from Umami's active visitors")
}
