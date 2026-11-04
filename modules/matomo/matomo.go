// Package matomo reads website analytics from a self-hosted Matomo (or
// Matomo Cloud) through its Reporting API with a token_auth: sites, a visits
// summary over a period, the top pages and referrers, and the visitors of
// the last minutes as counts. It reads aggregates only, never single
// visits, and never changes anything.
package matomo

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

// Config is one Matomo server.
type Config struct {
	Address            string `json:"address"` // https://matomo.example.com
	Token              string `json:"token"`   // secret:// token_auth
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api  *rest.Client
	host sdk.Host
	ref  string
	name string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Matomo module.
func New() *Module { return &Module{} }

const (
	maxRows   = 1000
	maxOutput = 256 << 10
)

var (
	prefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*$`)
	dateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// Periods are the Matomo periods a date names.
var Periods = []string{"day", "week", "month", "year"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	site := `"site":{"type":"integer","minimum":1,"description":"Site id (idSite, from sites)"}`
	period := `"period":{"type":"string","enum":["day","week","month","year"],"default":"month","description":"The day, week, month or year that contains date"},"date":{"type":"string","default":"today","description":"today, yesterday or YYYY-MM-DD"},"from":{"type":"string","format":"date","description":"Start date (YYYY-MM-DD), with to, instead of period and date"},"to":{"type":"string","format":"date","description":"End date (YYYY-MM-DD), inclusive; at most a year after from"}`
	limit := `"limit":{"type":"integer","minimum":1,"maximum":1000,"default":10}`
	return sdk.Manifest{
		ID: "matomo", Name: "Matomo", Version: "0.1.0", Category: "Monitoring", Icon: "chart",
		Description: "Matomo analytics: sites, visits, visitors, actions, bounce rate and time on site over a period, top pages and referrers, and visitors in the last minutes. Aggregates only; read only.",
		Presets:     []string{"developer", "team", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["address","token"],"properties":{
			"address":{"type":"string","description":"Your Matomo, e.g. https://matomo.example.com (with its path if it's served under one)"},
			"token":{"type":"string","x-secret":true,"description":"An auth token (Administration, Personal, Security, Auth tokens) of a user with view access to the sites"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "sites", Title: "Sites", Description: "Sites the token can view: id, name, main URL, time zone, currency and whether it's an ecommerce site.", Risk: sdk.RiskRead},
			{Name: "visits_summary", Title: "Visits summary", Description: "Visits, unique visitors, users, actions, actions per visit, bounce rate, average time on site and converted visits over a period.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `,` + period + `}}`)},
			{Name: "top_pages", Title: "Top pages", Description: "The most visited page URLs over a period, with visits, pageviews, average time on page, bounce and exit rates.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `,` + period + `,` + limit + `}}`)},
			{Name: "top_referrers", Title: "Top referrers", Description: "Where visits came from over a period (search engines, websites, campaigns, social networks), by visits.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `,` + period + `,` + limit + `}}`)},
			{Name: "live", Title: "Visitors now", Description: "Counts of visits, visitors and actions in the last minutes (30 by default). Never the visits themselves.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `,"minutes":{"type":"integer","minimum":1,"maximum":1440,"default":30}}}`)},
		},
	}
}

func parseAddress(s string) (*url.URL, string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	prefix := ""
	if err == nil {
		prefix = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/index.php")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return nil, "", errors.New("the address is your Matomo, like https://matomo.example.com")
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
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the auth token in the vault and enter its secret:// reference")
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
	// No Auth hook: the token goes in each POST body, never in a URL, so it
	// can't end up in a log line or an error that quotes the address.
	api := rest.New(u.Scheme+"://"+u.Host+prefix, nil)
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, host: h, ref: c.Token, name: u.Host})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// clean makes server text safe to pass on: the token is removed and
// anything else credential-like redacted before it's shortened.
func clean(s, tok string) string {
	if tok != "" {
		s = strings.ReplaceAll(s, tok, "[redacted]")
	}
	return clip(rest.Redact(s), 300)
}

var errToken = errors.New("Matomo refused the auth token (is it right, and not expired?)")

// call runs one Reporting API method and decodes its JSON answer.
func (c *conn) call(ctx context.Context, method string, params url.Values, out any) error {
	tok, err := c.host.Secret(ctx, c.ref)
	if err != nil {
		return err
	}
	tok = strings.TrimSpace(tok)
	form := url.Values{}
	for k, v := range params {
		form[k] = v
	}
	form.Set("module", "API")
	form.Set("method", method)
	form.Set("format", "JSON")
	form.Set("token_auth", tok)
	res, err := c.api.Send(ctx, http.MethodPost, "/index.php", nil, strings.NewReader(form.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}})
	if err != nil {
		var e *rest.Error
		if errors.As(err, &e) {
			if e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden {
				return errToken
			}
			return &rest.Error{Status: e.Status, Message: clean(e.Message, tok)}
		}
		// A transport error names only the URL, which never holds the token.
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("unexpected answer from Matomo: %s", res.Status)
	}
	raw = bytes.TrimSpace(raw)
	if bytes.HasPrefix(raw, []byte("{")) {
		var e struct {
			Result  string `json:"result"`
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Result == "error" {
			msg := strings.ToLower(e.Message)
			switch {
			case strings.Contains(msg, "authenticate") || strings.Contains(msg, "token_auth") || strings.Contains(msg, "token is"):
				return errToken
			case strings.Contains(msg, "access"):
				return errors.New("the token's user has no view access to this (give it view access to the site in Matomo)")
			}
			return fmt.Errorf("Matomo refused: %s", clean(e.Message, tok))
		}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errors.New("unexpected answer from Matomo (is the address its Matomo, with the API enabled?)")
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Value string `json:"value"`
	}
	if err := c.call(ctx, "API.getMatomoVersion", nil, &v); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "Matomo " + clip(v.Value, 20) + " at " + c.name}
}

type input struct {
	Site    int    `json:"site"`
	Period  string `json:"period"`
	Date    string `json:"date"`
	From    string `json:"from"`
	To      string `json:"to"`
	Limit   int    `json:"limit"`
	Minutes int    `json:"minutes"`
}

// when turns the input into Matomo's period and date.
func when(p input) (period, date string, err error) {
	from, to := strings.TrimSpace(p.From), strings.TrimSpace(p.To)
	if from != "" || to != "" {
		if p.Period != "" || p.Date != "" {
			return "", "", errors.New("give period and date, or from and to, not both")
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
			return "", "", errors.New("a range spans at most one year")
		}
		return "range", from + "," + to, nil
	}
	period, date = p.Period, strings.TrimSpace(p.Date)
	if period == "" {
		period = "month"
	}
	ok := false
	for _, v := range Periods {
		ok = ok || v == period
	}
	if !ok {
		return "", "", fmt.Errorf("the period is one of %s", strings.Join(Periods, ", "))
	}
	if date == "" {
		date = "today"
	}
	if date != "today" && date != "yesterday" {
		if _, err := time.Parse("2006-01-02", date); err != nil || !dateRe.MatchString(date) {
			return "", "", errors.New("the date is today, yesterday or a date like 2026-10-01")
		}
	}
	return period, date, nil
}

// num reads a Matomo number, which may come as a number or a string like
// "12", "45%" or "3.2".
func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(x), "%"), "s"), 64)
		return f
	}
	return 0
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

func pick(rows []map[string]any, n int, row func(map[string]any) map[string]any) ([]map[string]any, bool) {
	out := []map[string]any{}
	size := 0
	for _, r := range rows {
		if len(out) == n {
			return out, true
		}
		x := row(r)
		b, _ := json.Marshal(x)
		if size += len(b); size > maxOutput {
			return out, true
		}
		out = append(out, x)
	}
	return out, false
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
	if call.Action == "sites" {
		var ss []map[string]any
		if err := c.call(ctx, "SitesManager.getSitesWithAtLeastViewAccess", nil, &ss); err != nil {
			return sdk.Result{}, err
		}
		out, _ := pick(ss, maxRows, func(s map[string]any) map[string]any {
			return map[string]any{"site": int64(num(s["idsite"])), "name": clip(str(s["name"]), 200), "url": clip(str(s["main_url"]), 300),
				"timezone": clip(str(s["timezone"]), 64), "currency": clip(str(s["currency"]), 8), "ecommerce": num(s["ecommerce"]) == 1}
		})
		return sdk.JSON(out)
	}
	switch call.Action {
	case "visits_summary", "top_pages", "top_referrers", "live":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	if p.Site < 1 || p.Site > 1<<31-1 {
		return sdk.Result{}, errors.New("the site is its id (idSite) from sites, like 1")
	}
	idSite := strconv.Itoa(p.Site)
	if call.Action == "live" {
		if p.Period != "" || p.Date != "" || p.From != "" || p.To != "" {
			return sdk.Result{}, errors.New("live counts the last minutes; give minutes instead of a period")
		}
		mins := p.Minutes
		if mins == 0 {
			mins = 30
		}
		if mins < 1 || mins > 1440 {
			return sdk.Result{}, errors.New("minutes is between 1 and 1440")
		}
		var rs []map[string]any
		if err := c.call(ctx, "Live.getCounters", url.Values{"idSite": {idSite}, "lastMinutes": {strconv.Itoa(mins)}}, &rs); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"site": p.Site, "minutes": mins, "visits": 0, "visitors": 0, "actions": 0, "convertedVisits": 0}
		if len(rs) > 0 {
			r := rs[0]
			out["visits"], out["visitors"], out["actions"], out["convertedVisits"] = int64(num(r["visits"])), int64(num(r["visitors"])), int64(num(r["actions"])), int64(num(r["visitsConverted"]))
		}
		return sdk.JSON(out)
	}
	period, date, err := when(p)
	if err != nil {
		return sdk.Result{}, err
	}
	q := url.Values{"idSite": {idSite}, "period": {period}, "date": {date}}
	head := map[string]any{"site": p.Site, "period": period, "date": date}
	if call.Action == "visits_summary" {
		if p.Limit != 0 {
			return sdk.Result{}, errors.New("the visits summary has no limit")
		}
		var raw json.RawMessage
		if err := c.call(ctx, "VisitsSummary.get", q, &raw); err != nil {
			return sdk.Result{}, err
		}
		var v map[string]any
		json.Unmarshal(raw, &v) // [] when there's no data
		for k, f := range map[string]string{"visits": "nb_visits", "visitors": "nb_uniq_visitors", "users": "nb_users", "actions": "nb_actions",
			"actionsPerVisit": "nb_actions_per_visit", "bounceRate": "bounce_rate", "avgTimeOnSiteSeconds": "avg_time_on_site", "convertedVisits": "nb_visits_converted"} {
			head[k] = num(v[f])
		}
		return sdk.JSON(head)
	}
	n := p.Limit
	if n == 0 {
		n = 10
	}
	if n < 1 || n > maxRows {
		return sdk.Result{}, fmt.Errorf("the limit is between 1 and %d", maxRows)
	}
	q.Set("filter_limit", strconv.Itoa(n))
	q.Set("filter_sort_column", "nb_visits")
	q.Set("filter_sort_order", "desc")
	var rs []map[string]any
	var row func(map[string]any) map[string]any
	if call.Action == "top_pages" {
		q.Set("flat", "1")
		if err := c.call(ctx, "Actions.getPageUrls", q, &rs); err != nil {
			return sdk.Result{}, err
		}
		row = func(r map[string]any) map[string]any {
			return map[string]any{"page": clip(pageLabel(str(r["label"])), 300), "visits": int64(num(r["nb_visits"])), "pageviews": int64(num(r["nb_hits"])),
				"avgTimeOnPageSeconds": num(r["avg_time_on_page"]), "bounceRate": num(r["bounce_rate"]), "exitRate": num(r["exit_rate"])}
		}
	} else {
		if err := c.call(ctx, "Referrers.getAll", q, &rs); err != nil {
			return sdk.Result{}, err
		}
		row = func(r map[string]any) map[string]any {
			typ := str(r["referer_type"])
			if typ == "" {
				typ = str(r["referrer_type"])
			}
			return map[string]any{"referrer": clip(str(r["label"]), 300), "type": refType(typ), "visits": int64(num(r["nb_visits"]))}
		}
	}
	out, cut := pick(rs, n, row)
	head["top"] = out
	if cut {
		head["truncated"] = true
	}
	return sdk.JSON(head)
}

// pageLabel drops a page URL's query and fragment: Matomo keeps the query
// of each URL it tracks unless it's excluded in the site's settings, and a
// query often holds one visitor's details (an email in a sign-up link, a
// reset token, a search). It's shown as "?…".
func pageLabel(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		return s[:i] + "?…"
	}
	return s
}

// refType names Matomo's referrer type codes.
func refType(s string) string {
	switch s {
	case "1":
		return "direct"
	case "2":
		return "search"
	case "3":
		return "website"
	case "6":
		return "campaign"
	case "7":
		return "social"
	}
	return clip(s, 20)
}
