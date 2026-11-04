// Package searchconsole reads Google Search Console through its API,
// signing in with a service account's JSON key: the sites it can see,
// search performance (clicks, impressions, CTR and position by query, page,
// country, device or date) and submitted sitemaps. It never changes
// anything.
package searchconsole

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/oauth"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Scope is the one OAuth scope the module asks for.
const Scope = "https://www.googleapis.com/auth/webmasters.readonly"

// Config is one service account.
type Config struct {
	ServiceAccount string `json:"serviceAccount"` // secret:// JSON key
}

type conn struct {
	sa       string
	host     sdk.Host
	http     *http.Client
	api      *rest.Client
	tokenURL string
	tok      oauth.Cache
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://searchconsole.googleapis.com, TokenURL the
	// token endpoint and HTTP the client (tests). They aren't settings, so
	// an instance can't send its credentials anywhere else; a key's own
	// token_uri is never used.
	Base     string
	TokenURL string
	HTTP     *http.Client
}

// New returns the Search Console module.
func New() *Module { return &Module{} }

const (
	defaultToken = "https://oauth2.googleapis.com/token"
	maxRows      = 1000
	maxOutput    = 256 << 10
)

var (
	dateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	domainRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))+$`)
	pathRe   = regexp.MustCompile(`^/(?:[A-Za-z0-9._~%!$&'()*+,;=:@-]+/)*$`)
)

// Dimensions are the ways search performance can be grouped.
var Dimensions = []string{"query", "page", "country", "device", "date", "searchAppearance"}

// Types are the search types Search Console reports on.
var Types = []string{"web", "image", "video", "news", "discover", "googleNews"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	site := `"site":{"type":"string","description":"The property as in sites: sc-domain:example.com or https://www.example.com/"}`
	return sdk.Manifest{
		ID: "searchconsole", Name: "Google Search Console", Version: "0.1.0", Category: "Monitoring", Icon: "chart",
		Description: "Google Search Console: sites, search clicks, impressions, CTR and position by query, page, country, device or date, and sitemaps. Read only.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["serviceAccount"],"properties":{
			"serviceAccount":{"type":"string","x-secret":true,"description":"A service account's JSON key; add the account's email as a user (Restricted is enough) on each property it may read"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "sites", Title: "Sites", Description: "The Search Console properties the service account can see, with its permission level.", Risk: sdk.RiskRead},
			{Name: "search_analytics", Title: "Search performance", Description: "Clicks, impressions, CTR and average position over a date range, in total or grouped by query, page, country, device, date or search appearance, sorted by clicks.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `,
					"dimensions":{"type":"array","items":{"type":"string","enum":["query","page","country","device","date","searchAppearance"]},"maxItems":3},
					"type":{"type":"string","enum":["web","image","video","news","discover","googleNews"],"default":"web"},
					"days":{"type":"integer","minimum":1,"maximum":480,"default":28,"description":"The last days, today included (the newest data lags by a day or two)"},
					"from":{"type":"string","format":"date","description":"Start date (YYYY-MM-DD), with to, instead of days"},
					"to":{"type":"string","format":"date","description":"End date (YYYY-MM-DD), inclusive; at most 16 months after from"},
					"limit":{"type":"integer","minimum":1,"maximum":1000,"default":100}}}`)},
			{Name: "sitemaps", Title: "Sitemaps", Description: "Submitted sitemaps: path, type, when submitted and downloaded, pending, errors, warnings and submitted URL counts.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.ServiceAccount, "secret://") {
		return errors.New("store the service-account JSON key in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	client = rest.SameHostOnly(client)
	tokenURL := defaultToken
	if m.TokenURL != "" {
		tokenURL = m.TokenURL
	}
	cn := &conn{sa: c.ServiceAccount, host: h, http: client, tokenURL: tokenURL}
	base := "https://searchconsole.googleapis.com"
	if m.Base != "" {
		base = m.Base
	}
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := cn.token(ctx)
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

func (c *conn) token(ctx context.Context) (string, error) {
	return c.tok.Get(ctx, func(ctx context.Context) (oauth.Grant, error) {
		raw, err := c.host.Secret(ctx, c.sa)
		if err != nil {
			return oauth.Grant{}, err
		}
		sa, key, err := oauth.ParseServiceAccount(raw)
		if err != nil {
			return oauth.Grant{}, err
		}
		now := time.Now()
		jwt, err := oauth.SignRS256(key, sa.PrivateKeyID, map[string]any{"iss": sa.ClientEmail, "scope": Scope,
			"aud": c.tokenURL, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
		if err != nil {
			return oauth.Grant{}, errors.New("couldn't sign with the service-account key")
		}
		g, err := oauth.Exchange(ctx, c.http, c.tokenURL, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {jwt}}, "", "")
		return g, explainToken(err)
	})
}

func explainToken(err error) error {
	var e *oauth.Error
	if !errors.As(err, &e) {
		return err
	}
	switch e.Code {
	case "invalid_grant":
		return errors.New("Google refused the service account's sign-in (a deleted or disabled key, or this machine's clock is off)")
	case "invalid_client", "unauthorized_client":
		return errors.New("Google refused the service account (is it deleted or disabled?)")
	}
	return fmt.Errorf("Google didn't issue a token for the service account: %v", e)
}

func friendly(err error, site string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Google refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		if site != "" {
			return fmt.Errorf("Google refused access to %s: add the service account's email as a user on that property, and turn on the Search Console API in its Cloud project", site)
		}
		return errors.New("Google refused this: turn on the Search Console API in the service account's Cloud project")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("Search Console has no property %s (or the service account can't see it)", site)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Search Console's quota is used up for now; try again later")
	case rest.IsStatus(err, http.StatusBadRequest):
		return fmt.Errorf("Google refused the query: %s", clip(err.Error(), 300))
	}
	return err
}

// do calls the API; a 401 drops the cached token and tries once more.
func (c *conn) do(ctx context.Context, method, path string, body, out any) error {
	_, err := c.api.Do(ctx, method, path, nil, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.tok.Drop()
		_, err = c.api.Do(ctx, method, path, nil, body, out)
	}
	return err
}

type siteList struct {
	Sites []struct {
		URL        string `json:"siteUrl"`
		Permission string `json:"permissionLevel"`
	} `json:"siteEntry"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s siteList
	if err := c.do(ctx, http.MethodGet, "/webmasters/v3/sites", nil, &s); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "").Error()}
	}
	if len(s.Sites) == 0 {
		return sdk.Health{Status: "ok", Message: "signed in; no property is shared with the service account yet"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d sites", len(s.Sites))}
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// siteURL checks a property: a domain property (sc-domain:example.com) or
// a URL-prefix one (https://www.example.com/ with an optional path).
func siteURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	bad := errors.New("the site is the property as in sites: sc-domain:example.com or https://www.example.com/")
	if len(s) > 500 {
		return "", bad
	}
	if d, ok := strings.CutPrefix(s, "sc-domain:"); ok {
		d = strings.ToLower(d)
		if len(d) > 253 || !domainRe.MatchString(d) {
			return "", bad
		}
		return "sc-domain:" + d, nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", bad
	}
	host := strings.ToLower(u.Hostname())
	if h := strings.ToLower(u.Host); !domainRe.MatchString(host) || (h != host && (u.Port() == "" || h != host+":"+u.Port())) {
		return "", bad
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if !pathRe.MatchString(path) || strings.Contains(path, "/../") || strings.Contains(path, "/./") {
		return "", bad
	}
	return u.Scheme + "://" + strings.ToLower(u.Host) + path, nil
}

func sitePath(site string) string { return "/webmasters/v3/sites/" + url.PathEscape(site) }

type input struct {
	Site       string   `json:"site"`
	Dimensions []string `json:"dimensions"`
	Type       string   `json:"type"`
	Days       int      `json:"days"`
	From       string   `json:"from"`
	To         string   `json:"to"`
	Limit      int      `json:"limit"`
}

func oneOf(v string, list []string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// dateRange turns days or from/to into dates; Search Console keeps 16
// months of data.
func dateRange(p input, now time.Time) (string, string, error) {
	from, to := strings.TrimSpace(p.From), strings.TrimSpace(p.To)
	if from != "" || to != "" {
		if p.Days != 0 {
			return "", "", errors.New("give days or from and to, not both")
		}
		f, err1 := time.Parse("2006-01-02", from)
		t, err2 := time.Parse("2006-01-02", to)
		if !dateRe.MatchString(from) || !dateRe.MatchString(to) || err1 != nil || err2 != nil {
			return "", "", errors.New("from and to are both dates, like 2026-10-01")
		}
		if t.Before(f) {
			return "", "", errors.New("to is on or after from")
		}
		if t.After(f.AddDate(0, 16, 0)) {
			return "", "", errors.New("a query spans at most 16 months")
		}
		return from, to, nil
	}
	days := p.Days
	if days == 0 {
		days = 28
	}
	if days < 1 || days > 480 {
		return "", "", errors.New("days is between 1 and 480 (16 months)")
	}
	today := now.UTC()
	return today.AddDate(0, 0, 1-days).Format("2006-01-02"), today.Format("2006-01-02"), nil
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
		var s siteList
		if err := c.do(ctx, http.MethodGet, "/webmasters/v3/sites", nil, &s); err != nil {
			return sdk.Result{}, friendly(err, "")
		}
		out := []map[string]any{}
		for _, x := range s.Sites {
			if len(out) == 1000 {
				break
			}
			out = append(out, map[string]any{"site": clip(x.URL, 500), "permission": clip(x.Permission, 40)})
		}
		return sdk.JSON(out)
	case "search_analytics":
		site, err := siteURL(p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		if len(p.Dimensions) > 3 {
			return sdk.Result{}, errors.New("group by at most 3 dimensions")
		}
		seen := map[string]bool{}
		for _, d := range p.Dimensions {
			if !oneOf(d, Dimensions) || seen[d] {
				return sdk.Result{}, fmt.Errorf("dimensions are distinct values of %s", strings.Join(Dimensions, ", "))
			}
			seen[d] = true
		}
		typ := p.Type
		if typ == "" {
			typ = "web"
		}
		if !oneOf(typ, Types) {
			return sdk.Result{}, fmt.Errorf("the type is one of %s", strings.Join(Types, ", "))
		}
		start, end, err := dateRange(p, time.Now())
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.Limit
		if n == 0 {
			n = 100
		}
		if n < 1 || n > maxRows {
			return sdk.Result{}, fmt.Errorf("the limit is between 1 and %d", maxRows)
		}
		body := map[string]any{"startDate": start, "endDate": end, "type": typ, "rowLimit": n}
		if len(p.Dimensions) > 0 {
			body["dimensions"] = p.Dimensions
		}
		var a struct {
			Rows []struct {
				Keys        []string `json:"keys"`
				Clicks      float64  `json:"clicks"`
				Impressions float64  `json:"impressions"`
				CTR         float64  `json:"ctr"`
				Position    float64  `json:"position"`
			} `json:"rows"`
			Aggregation string `json:"responseAggregationType"`
		}
		if err := c.do(ctx, http.MethodPost, sitePath(site)+"/searchAnalytics/query", body, &a); err != nil {
			return sdk.Result{}, friendly(err, site)
		}
		rows := []map[string]any{}
		size, cut := 0, false
		for _, r := range a.Rows {
			if len(rows) == n {
				cut = true
				break
			}
			row := map[string]any{"clicks": int64(r.Clicks), "impressions": int64(r.Impressions), "ctr": r.CTR, "position": r.Position}
			for i, d := range p.Dimensions {
				if i < len(r.Keys) {
					row[d] = clip(r.Keys[i], 300)
				}
			}
			b, _ := json.Marshal(row)
			if size += len(b); size > maxOutput {
				cut = true
				break
			}
			rows = append(rows, row)
		}
		out := map[string]any{"site": site, "from": start, "to": end, "type": typ, "dimensions": append([]string{}, p.Dimensions...), "rows": rows}
		if cut {
			out["truncated"] = true
		}
		return sdk.JSON(out)
	case "sitemaps":
		site, err := siteURL(p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		var s struct {
			Sitemaps []struct {
				Path           string `json:"path"`
				Type           string `json:"type"`
				LastSubmitted  string `json:"lastSubmitted"`
				LastDownloaded string `json:"lastDownloaded"`
				Pending        bool   `json:"isPending"`
				Index          bool   `json:"isSitemapsIndex"`
				Warnings       string `json:"warnings"`
				Errors         string `json:"errors"`
				Contents       []struct {
					Type      string `json:"type"`
					Submitted string `json:"submitted"`
				} `json:"contents"`
			} `json:"sitemap"`
		}
		if err := c.do(ctx, http.MethodGet, sitePath(site)+"/sitemaps", nil, &s); err != nil {
			return sdk.Result{}, friendly(err, site)
		}
		out := []map[string]any{}
		for _, x := range s.Sitemaps {
			if len(out) == 500 {
				break
			}
			contents := []map[string]string{}
			for _, ct := range x.Contents {
				if len(contents) == 10 {
					break
				}
				contents = append(contents, map[string]string{"type": clip(ct.Type, 40), "submitted": clip(ct.Submitted, 20)})
			}
			out = append(out, map[string]any{"path": clip(x.Path, 500), "type": clip(x.Type, 40), "lastSubmitted": clip(x.LastSubmitted, 40),
				"lastDownloaded": clip(x.LastDownloaded, 40), "pending": x.Pending, "index": x.Index, "errors": clip(x.Errors, 20), "warnings": clip(x.Warnings, 20), "contents": contents})
		}
		return sdk.JSON(map[string]any{"site": site, "sitemaps": out})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
