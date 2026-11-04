// Package plausible reads website analytics from Plausible (plausible.io or a
// self-hosted Plausible Community Edition) through the Stats API v2 with an
// API key: sites, visitors right now, totals over a period (visitors,
// visits, pageviews, bounce rate, visit duration) and top pages, sources and
// countries. It never changes anything.
package plausible

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
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Plausible account.
type Config struct {
	Address            string   `json:"address"` // https://plausible.io or a self-hosted server
	APIKey             string   `json:"apiKey"`  // secret://
	Sites              []string `json:"sites"`   // domains this instance may read; empty for any the key can see
	Fingerprint        string   `json:"fingerprint"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

type conn struct {
	api   *rest.Client
	sites []string // allowed sites; empty for any
	host  string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Plausible module.
func New() *Module { return &Module{} }

const defaultAddress = "https://plausible.io"

var (
	// A site is its domain as entered in Plausible (example.com, blog.example.com).
	siteRe   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))*$`)
	dateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	prefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
)

// Periods are the date ranges the Stats API names.
var Periods = []string{"day", "7d", "30d", "month", "6mo", "12mo", "year", "all"}

// breakdowns maps the "by" input to a Stats API dimension.
var breakdowns = map[string]string{
	"page":       "event:page",
	"entry_page": "visit:entry_page",
	"exit_page":  "visit:exit_page",
	"source":     "visit:source",
	"referrer":   "visit:referrer",
	"country":    "visit:country_name",
	"device":     "visit:device",
	"browser":    "visit:browser",
	"os":         "visit:os",
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	site := `"site":{"type":"string","description":"Site domain as in Plausible, e.g. example.com"}`
	period := `"period":{"type":"string","enum":["day","7d","30d","month","6mo","12mo","year","all"],"default":"30d","description":"day is today; month and year are the current calendar ones"},"from":{"type":"string","format":"date","description":"Start date (YYYY-MM-DD), with to, instead of a period"},"to":{"type":"string","format":"date","description":"End date (YYYY-MM-DD), inclusive"}`
	return sdk.Manifest{
		ID: "plausible", Name: "Plausible Analytics", Version: "0.1.0", Category: "Monitoring", Icon: "chart",
		Description: "Plausible Analytics (plausible.io or self-hosted): sites, visitors now, visitors, pageviews, bounce rate and visit duration over a period, top pages, sources and countries. Read only.",
		Presets:     []string{"developer", "team", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"address":{"type":"string","default":"https://plausible.io","description":"https://plausible.io, or your server, e.g. https://plausible.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"A Stats API key (Account settings, API keys)"},
			"sites":{"type":"array","items":{"type":"string"},"description":"Site domains this instance may read (and lists when the key can't list sites); empty for every site the key can see"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-hosted server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "sites", Title: "Sites", Description: "Sites with their time zone (needs a key that may use the Sites API; otherwise the sites listed in the settings).", Risk: sdk.RiskRead},
			{Name: "realtime", Title: "Visitors now", Description: "Unique visitors on a site in the last 5 minutes.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `}}`)},
			{Name: "aggregate", Title: "Totals over a period", Description: "Visitors, visits, pageviews, views per visit, bounce rate (%) and average visit duration (seconds) over a period.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `,` + period + `}}`)},
			{Name: "breakdown", Title: "Top pages, sources, countries", Description: "The top pages, entry or exit pages, sources, referrers, countries, devices, browsers or operating systems by visitors, with pageviews.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["site","by"],"properties":{` + site + `,"by":{"type":"string","enum":["page","entry_page","exit_page","source","referrer","country","device","browser","os"]},` + period + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":10}}}`)},
		},
	}
}

func parseAddress(s string) (*url.URL, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = defaultAddress
	}
	u, err := url.Parse(s)
	prefix := ""
	if err == nil {
		prefix = strings.TrimRight(u.Path, "/")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return nil, "", errors.New("the address is https://plausible.io or your server, like https://plausible.example.com")
	}
	return u, prefix, nil
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, prefix, err := parseAddress(c.Address)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	var sites []string
	for _, s := range c.Sites {
		s = strings.ToLower(strings.TrimSpace(s))
		if len(s) > 253 || !siteRe.MatchString(s) {
			return fmt.Errorf("the site %q is a domain, like example.com", s)
		}
		sites = append(sites, s)
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
	ref := c.APIKey
	api := rest.New(u.Scheme+"://"+u.Host+prefix, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, sites: sites, host: u.Host})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, site string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		if site != "" {
			return fmt.Errorf("Plausible refused the API key for %s (is the key right, and does its account have the site?)", site)
		}
		return errors.New("Plausible refused the API key")
	case rest.IsStatus(err, http.StatusPaymentRequired):
		return errors.New("Plausible refused: the plan doesn't include API access")
	case rest.IsStatus(err, http.StatusNotFound):
		if site != "" {
			return fmt.Errorf("there's no site %s (or the key can't see it)", site)
		}
		return errors.New("this server has no Stats API (is it Plausible 2.1 or later?)")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Plausible's rate limit was hit; try again in a minute")
	}
	return err
}

// site checks a site and that this instance may read it.
func (c *conn) site(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if len(s) > 253 || !siteRe.MatchString(s) {
		return "", errors.New("the site is its domain as in Plausible, like example.com")
	}
	if len(c.sites) > 0 {
		for _, a := range c.sites {
			if a == s {
				return s, nil
			}
		}
		return "", fmt.Errorf("%s isn't one of the sites this instance may read (%s)", s, strings.Join(c.sites, ", "))
	}
	return s, nil
}

func (c *conn) realtime(ctx context.Context, site string) (int64, error) {
	res, err := c.api.Send(ctx, http.MethodGet, "/api/v1/stats/realtime/visitors", url.Values{"site_id": {site}}, nil, http.Header{"Accept": {"application/json"}})
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4096))
	if err != nil {
		return 0, err
	}
	if res.StatusCode >= 300 {
		return 0, fmt.Errorf("unexpected answer from Plausible: %s", res.Status)
	}
	n, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
	if err != nil {
		return 0, errors.New("unexpected answer from Plausible's realtime endpoint")
	}
	return n, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if len(c.sites) > 0 {
		n, err := c.realtime(ctx, c.sites[0])
		if err != nil {
			return sdk.Health{Status: "down", Message: friendly(err, c.sites[0]).Error()}
		}
		return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s · %d visitors now", c.sites[0], n)}
	}
	var ss sitesAnswer
	if _, err := c.api.Do(ctx, http.MethodGet, "/api/v1/sites", url.Values{"limit": {"1"}}, nil, &ss); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusPaymentRequired) {
			return sdk.Health{Status: "down", Message: "Plausible refused the key for listing sites; list the sites to read in the settings, or use a key with Sites API access"}
		}
		return sdk.Health{Status: "down", Message: friendly(err, "").Error()}
	}
	return sdk.Health{Status: "ok", Message: "connected to " + c.host}
}

type sitesAnswer struct {
	Sites []struct {
		Domain   string `json:"domain"`
		Timezone string `json:"timezone"`
	} `json:"sites"`
	Meta struct {
		After *string `json:"after"`
	} `json:"meta"`
}

type input struct {
	Site   string `json:"site"`
	Period string `json:"period"`
	From   string `json:"from"`
	To     string `json:"to"`
	By     string `json:"by"`
	Limit  int    `json:"limit"`
}

// dateRange turns the period or from/to into a Stats API date_range.
func dateRange(p input) (any, string, error) {
	from, to := strings.TrimSpace(p.From), strings.TrimSpace(p.To)
	if from != "" || to != "" {
		if p.Period != "" {
			return nil, "", errors.New("give a period or from and to, not both")
		}
		if !dateRe.MatchString(from) || !dateRe.MatchString(to) {
			return nil, "", errors.New("from and to are both dates, like 2026-10-01")
		}
		f, err1 := time.Parse("2006-01-02", from)
		t, err2 := time.Parse("2006-01-02", to)
		if err1 != nil || err2 != nil {
			return nil, "", errors.New("from and to are both dates, like 2026-10-01")
		}
		if t.Before(f) {
			return nil, "", errors.New("to is on or after from")
		}
		if t.Sub(f) > 5*366*24*time.Hour {
			return nil, "", errors.New("a custom range spans at most five years")
		}
		return []string{from, to}, from + " to " + to, nil
	}
	period := p.Period
	if period == "" {
		period = "30d"
	}
	for _, v := range Periods {
		if v == period {
			return period, period, nil
		}
	}
	return nil, "", fmt.Errorf("the period is one of %s", strings.Join(Periods, ", "))
}

type queryAnswer struct {
	Results []struct {
		Metrics    []*float64 `json:"metrics"`
		Dimensions []any      `json:"dimensions"`
	} `json:"results"`
}

func (c *conn) query(ctx context.Context, body map[string]any, site string) (queryAnswer, error) {
	var a queryAnswer
	_, err := c.api.Do(ctx, http.MethodPost, "/api/v2/query", nil, body, &a)
	return a, friendly(err, site)
}

func num(v []*float64, i int) float64 {
	if i < len(v) && v[i] != nil {
		return *v[i]
	}
	return 0
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
	case "sites":
		out := []map[string]any{}
		var after string
		for pg := 0; pg < 10; pg++ {
			q := url.Values{"limit": {"100"}}
			if after != "" {
				q.Set("after", after)
			}
			var ss sitesAnswer
			if _, err := c.api.Do(ctx, http.MethodGet, "/api/v1/sites", q, nil, &ss); err != nil {
				if len(c.sites) > 0 && (rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusPaymentRequired) || rest.IsStatus(err, http.StatusNotFound)) {
					list := []map[string]any{}
					for _, s := range c.sites {
						list = append(list, map[string]any{"domain": s})
					}
					return sdk.JSON(map[string]any{"sites": list, "note": "the key can't list sites, so these are the sites from the settings"})
				}
				if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusPaymentRequired) {
					return sdk.Result{}, errors.New("Plausible refused the key for listing sites (that needs Sites API access); list the sites in the settings instead")
				}
				return sdk.Result{}, friendly(err, "")
			}
			for _, s := range ss.Sites {
				d := strings.ToLower(s.Domain)
				if len(c.sites) > 0 {
					if _, err := c.site(d); err != nil {
						continue
					}
				}
				out = append(out, map[string]any{"domain": clip(d, 253), "timezone": clip(s.Timezone, 64)})
			}
			if ss.Meta.After == nil || *ss.Meta.After == "" || len(ss.Sites) == 0 {
				break
			}
			after = *ss.Meta.After
		}
		return sdk.JSON(map[string]any{"sites": out})

	case "realtime":
		site, err := c.site(p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		n, err := c.realtime(ctx, site)
		if err != nil {
			return sdk.Result{}, friendly(err, site)
		}
		return sdk.JSON(map[string]any{"site": site, "visitors": n, "window": "last 5 minutes"})

	case "aggregate":
		site, err := c.site(p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		dr, label, err := dateRange(p)
		if err != nil {
			return sdk.Result{}, err
		}
		a, err := c.query(ctx, map[string]any{"site_id": site, "date_range": dr,
			"metrics": []string{"visitors", "visits", "pageviews", "views_per_visit", "bounce_rate", "visit_duration"}}, site)
		if err != nil {
			return sdk.Result{}, err
		}
		if len(a.Results) == 0 {
			return sdk.JSON(map[string]any{"site": site, "period": label, "visitors": 0, "visits": 0, "pageviews": 0})
		}
		v := a.Results[0].Metrics
		return sdk.JSON(map[string]any{"site": site, "period": label,
			"visitors": int64(num(v, 0)), "visits": int64(num(v, 1)), "pageviews": int64(num(v, 2)),
			"viewsPerVisit": num(v, 3), "bounceRate": num(v, 4), "visitDurationSeconds": num(v, 5)})

	case "breakdown":
		site, err := c.site(p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		dim, ok := breakdowns[p.By]
		if !ok {
			return sdk.Result{}, errors.New("by is one of page, entry_page, exit_page, source, referrer, country, device, browser, os")
		}
		dr, label, err := dateRange(p)
		if err != nil {
			return sdk.Result{}, err
		}
		limit := p.Limit
		if limit == 0 {
			limit = 10
		}
		if limit < 1 || limit > 100 {
			return sdk.Result{}, errors.New("the limit is between 1 and 100")
		}
		a, err := c.query(ctx, map[string]any{"site_id": site, "date_range": dr,
			"metrics": []string{"visitors", "pageviews"}, "dimensions": []string{dim},
			"order_by": [][]string{{"visitors", "desc"}}, "pagination": map[string]int{"limit": limit, "offset": 0}}, site)
		if err != nil {
			return sdk.Result{}, err
		}
		rows := []map[string]any{}
		for i, r := range a.Results {
			if i == limit {
				break
			}
			name := ""
			if len(r.Dimensions) > 0 {
				name = fmt.Sprint(r.Dimensions[0])
			}
			rows = append(rows, map[string]any{p.By: clip(name, 300), "visitors": int64(num(r.Metrics, 0)), "pageviews": int64(num(r.Metrics, 1))})
		}
		return sdk.JSON(map[string]any{"site": site, "period": label, "by": p.By, "top": rows})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
