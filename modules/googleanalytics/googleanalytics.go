// Package googleanalytics reads Google Analytics 4 reports through the
// Google Analytics Data API, signing in with a service account's JSON key:
// the properties it can see (Admin API), reports with chosen dimensions,
// metrics and a date range, and the realtime report. It never changes
// anything.
package googleanalytics

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
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/oauth"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Scope is the one OAuth scope the module asks for: read-only Analytics,
// which covers the Admin API's property list and the Data API's reports.
const Scope = "https://www.googleapis.com/auth/analytics.readonly"

// Config is one service account.
type Config struct {
	ServiceAccount string `json:"serviceAccount"` // secret:// JSON key
}

type conn struct {
	sa       string
	host     sdk.Host
	http     *http.Client
	admin    *rest.Client
	data     *rest.Client
	tokenURL string
	tok      oauth.Cache
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://analyticsadmin.googleapis.com and
	// https://analyticsdata.googleapis.com, TokenURL the token endpoint and
	// HTTP the client (tests). They aren't settings, so an instance can't
	// send its credentials anywhere else; a key's own token_uri is never
	// used.
	Base     string
	TokenURL string
	HTTP     *http.Client
}

// New returns the Google Analytics module.
func New() *Module { return &Module{} }

const (
	defaultToken = "https://oauth2.googleapis.com/token"
	maxRows      = 1000
	maxOutput    = 256 << 10
)

var (
	propertyRe = regexp.MustCompile(`^(?:properties/)?([0-9]{1,20})$`)
	dateRe     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	// A GA4 API name: a built-in like pagePath or sessionDefaultChannelGroup,
	// or a prefixed one like customEvent:plan or keyEvents:purchase.
	fieldRe = regexp.MustCompile(`^[a-z][A-Za-z0-9]{1,63}(?::[A-Za-z0-9_]{1,64})?$`)
)

// identifying are the words of names that would identify a visitor (or a
// purchase, which leads to one) rather than describe traffic, compared
// without case, underscores or dashes: userId, user_id or a custom
// customEvent:user_id, clientId, a session id, an email. User-scoped custom
// dimensions (customUser:…) are refused whatever their name.
var identifying = []string{"userid", "clientid", "sessionid", "pseudoid", "transactionid", "email", "phone", "ipaddress"}

// identifies says whether a dimension or metric name could single out a
// visitor.
func identifies(n string) bool {
	l := strings.ToLower(n)
	if strings.HasPrefix(l, "customuser:") {
		return true
	}
	l = strings.NewReplacer("_", "", "-", "").Replace(l)
	if l == "signedinwithuserid" { // yes or no, not the id
		return false
	}
	for _, w := range identifying {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	prop := `"property":{"type":"string","description":"Property id (from properties), e.g. 123456789"}`
	fields := `"dimensions":{"type":"array","items":{"type":"string"},"maxItems":9,"description":"GA4 dimension API names, e.g. pagePath, country, sessionDefaultChannelGroup"},"metrics":{"type":"array","items":{"type":"string"},"maxItems":10,"description":"GA4 metric API names, e.g. activeUsers, sessions, screenPageViews"},"limit":{"type":"integer","minimum":1,"maximum":1000,"default":100}`
	return sdk.Manifest{
		ID: "googleanalytics", Name: "Google Analytics", Version: "0.1.0", Category: "Monitoring", Icon: "chart",
		Description: "Google Analytics 4: properties, reports with your choice of dimensions, metrics and dates, and active users right now. Read only.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["serviceAccount"],"properties":{
			"serviceAccount":{"type":"string","x-secret":true,"description":"A service account's JSON key; add the account's email as a Viewer on each property it may read"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "properties", Title: "Properties", Description: "The GA4 properties the service account can see, with their account.", Risk: sdk.RiskRead},
			{Name: "report", Title: "Report", Description: "A report over a date range: rows of the chosen dimensions with the chosen metrics (default activeUsers, sessions, screenPageViews), sorted by the first metric.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["property"],"properties":{` + prop + `,` + fields + `,"days":{"type":"integer","minimum":1,"maximum":366,"default":28,"description":"The last days, today included"},"from":{"type":"string","format":"date","description":"Start date (YYYY-MM-DD), with to, instead of days"},"to":{"type":"string","format":"date","description":"End date (YYYY-MM-DD), inclusive; at most a year after from"}}}`)},
			{Name: "realtime", Title: "Active now", Description: "Active users in the last 30 minutes, optionally by dimensions like country, deviceCategory or unifiedScreenName.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["property"],"properties":{` + prop + `,` + fields + `}}`)},
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
	auth := func(ctx context.Context, r *http.Request) error {
		t, err := cn.token(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	}
	adminBase, dataBase := "https://analyticsadmin.googleapis.com", "https://analyticsdata.googleapis.com"
	if m.Base != "" {
		adminBase, dataBase = m.Base, m.Base
	}
	cn.admin, cn.data = rest.New(adminBase, auth), rest.New(dataBase, auth)
	cn.admin.HTTP, cn.data.HTTP = client, client
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

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Google refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Google refused this: add the service account's email as a Viewer on the property, and turn on the Google Analytics Data and Admin APIs in its Cloud project")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("Google has no such property (or the service account can't see it)")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("the property's Analytics quota is used up for now; try again later")
	case rest.IsStatus(err, http.StatusBadRequest):
		return fmt.Errorf("Google refused the report: %s", clip(err.Error(), 300))
	}
	return err
}

// do calls an API; a 401 drops the cached token and tries once more.
func (c *conn) do(ctx context.Context, api *rest.Client, method, path string, q url.Values, body, out any) error {
	_, err := api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.tok.Drop()
		_, err = api.Do(ctx, method, path, q, body, out)
	}
	return err
}

type summaries struct {
	AccountSummaries []struct {
		Account     string `json:"account"`
		DisplayName string `json:"displayName"`
		Properties  []struct {
			Property     string `json:"property"`
			DisplayName  string `json:"displayName"`
			PropertyType string `json:"propertyType"`
		} `json:"propertySummaries"`
	} `json:"accountSummaries"`
	NextPageToken string `json:"nextPageToken"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s summaries
	if err := c.do(ctx, c.admin, http.MethodGet, "/v1beta/accountSummaries", url.Values{"pageSize": {"200"}}, nil, &s); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err).Error()}
	}
	n := 0
	for _, a := range s.AccountSummaries {
		n += len(a.Properties)
	}
	if n == 0 {
		return sdk.Health{Status: "ok", Message: "signed in; no property is shared with the service account yet"}
	}
	more := ""
	if s.NextPageToken != "" {
		more = "+"
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d%s properties", n, more)}
}

type input struct {
	Property   string   `json:"property"`
	Dimensions []string `json:"dimensions"`
	Metrics    []string `json:"metrics"`
	Limit      int      `json:"limit"`
	Days       int      `json:"days"`
	From       string   `json:"from"`
	To         string   `json:"to"`
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func property(raw string) (string, error) {
	m := propertyRe.FindStringSubmatch(strings.TrimSpace(raw))
	if m == nil {
		return "", errors.New("the property is its numeric id from properties, like 123456789")
	}
	return m[1], nil
}

func names(in []string, kind string, max int, def []string) ([]string, error) {
	if len(in) == 0 {
		return def, nil
	}
	if len(in) > max {
		return nil, fmt.Errorf("at most %d %s", max, kind)
	}
	seen := map[string]bool{}
	out := []string{}
	for _, n := range in {
		n = strings.TrimSpace(n)
		if !fieldRe.MatchString(n) || identifies(n) {
			return nil, fmt.Errorf("%q isn't a %s name this module reads (GA4 API names like pagePath or activeUsers)", clip(n, 80), strings.TrimSuffix(kind, "s"))
		}
		if seen[n] {
			return nil, fmt.Errorf("%s is listed twice", n)
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}

// dateRange turns days or from/to into a Data API date range.
func dateRange(p input) (start, end string, err error) {
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
		if t.After(f.AddDate(1, 0, 0)) {
			return "", "", errors.New("a report spans at most one year")
		}
		return from, to, nil
	}
	days := p.Days
	if days == 0 {
		days = 28
	}
	if days < 1 || days > 366 {
		return "", "", errors.New("days is between 1 and 366")
	}
	return strconv.Itoa(days-1) + "daysAgo", "today", nil
}

func limit(n int) (int, error) {
	if n == 0 {
		return 100, nil
	}
	if n < 1 || n > maxRows {
		return 0, fmt.Errorf("the limit is between 1 and %d", maxRows)
	}
	return n, nil
}

type report struct {
	DimensionHeaders []struct {
		Name string `json:"name"`
	} `json:"dimensionHeaders"`
	MetricHeaders []struct {
		Name string `json:"name"`
	} `json:"metricHeaders"`
	Rows []struct {
		Dims []struct {
			Value string `json:"value"`
		} `json:"dimensionValues"`
		Mets []struct {
			Value string `json:"value"`
		} `json:"metricValues"`
	} `json:"rows"`
	RowCount int `json:"rowCount"`
}

// table turns a report into rows keyed by the requested names, up to n rows
// and maxOutput bytes.
func table(r report, dims, mets []string, n int) ([]map[string]any, bool) {
	rows := []map[string]any{}
	size := 0
	for _, x := range r.Rows {
		if len(rows) == n {
			return rows, true
		}
		row := map[string]any{}
		for i, d := range dims {
			if i < len(x.Dims) {
				row[d] = clip(x.Dims[i].Value, 300)
			}
		}
		for i, mt := range mets {
			if i < len(x.Mets) {
				if v, err := strconv.ParseFloat(x.Mets[i].Value, 64); err == nil {
					row[mt] = v
				} else {
					row[mt] = clip(x.Mets[i].Value, 40)
				}
			}
		}
		b, _ := json.Marshal(row)
		if size += len(b); size > maxOutput {
			return rows, true
		}
		rows = append(rows, row)
	}
	return rows, false
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
	case "properties":
		return c.properties(ctx)
	case "report", "realtime":
		prop, err := property(p.Property)
		if err != nil {
			return sdk.Result{}, err
		}
		defMetrics := []string{"activeUsers", "sessions", "screenPageViews"}
		if call.Action == "realtime" {
			defMetrics = []string{"activeUsers"}
		}
		dims, err := names(p.Dimensions, "dimensions", 9, []string{})
		if err != nil {
			return sdk.Result{}, err
		}
		mets, err := names(p.Metrics, "metrics", 10, defMetrics)
		if err != nil {
			return sdk.Result{}, err
		}
		n, err := limit(p.Limit)
		if err != nil {
			return sdk.Result{}, err
		}
		body := map[string]any{"metrics": named(mets), "limit": n,
			"orderBys": []any{map[string]any{"metric": map[string]string{"metricName": mets[0]}, "desc": true}}}
		if len(dims) > 0 {
			body["dimensions"] = named(dims)
		}
		out := map[string]any{"property": prop}
		path := "/v1beta/properties/" + url.PathEscape(prop)
		if call.Action == "report" {
			start, end, err := dateRange(p)
			if err != nil {
				return sdk.Result{}, err
			}
			body["dateRanges"] = []map[string]string{{"startDate": start, "endDate": end}}
			out["from"], out["to"] = start, end
			path += ":runReport"
		} else {
			if p.Days != 0 || p.From != "" || p.To != "" {
				return sdk.Result{}, errors.New("the realtime report always covers the last 30 minutes")
			}
			out["window"] = "last 30 minutes"
			path += ":runRealtimeReport"
		}
		var r report
		if err := c.do(ctx, c.data, http.MethodPost, path, nil, body, &r); err != nil {
			return sdk.Result{}, friendly(err)
		}
		rows, cut := table(r, dims, mets, n)
		out["dimensions"], out["metrics"], out["rows"], out["rowCount"] = dims, mets, rows, r.RowCount
		if cut {
			out["truncated"] = true
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func named(ns []string) []map[string]string {
	out := []map[string]string{}
	for _, n := range ns {
		out = append(out, map[string]string{"name": n})
	}
	return out
}

func (c *conn) properties(ctx context.Context) (sdk.Result, error) {
	out := []map[string]any{}
	token := ""
	for pg := 0; pg < 10; pg++ {
		q := url.Values{"pageSize": {"200"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var s summaries
		if err := c.do(ctx, c.admin, http.MethodGet, "/v1beta/accountSummaries", q, nil, &s); err != nil {
			return sdk.Result{}, friendly(err)
		}
		for _, a := range s.AccountSummaries {
			for _, p := range a.Properties {
				id, err := property(p.Property)
				if err != nil {
					continue
				}
				out = append(out, map[string]any{"property": id, "name": clip(p.DisplayName, 200), "type": strings.TrimPrefix(p.PropertyType, "PROPERTY_TYPE_"),
					"account": strings.TrimPrefix(a.Account, "accounts/"), "accountName": clip(a.DisplayName, 200)})
			}
		}
		if s.NextPageToken == "" || len(out) >= 2000 {
			break
		}
		token = s.NextPageToken
	}
	return sdk.JSON(out)
}
