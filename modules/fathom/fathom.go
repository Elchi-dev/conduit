// Package fathom reads website analytics from Fathom Analytics through its
// API with an API key: sites, aggregations (visits, unique visitors,
// pageviews, average duration and bounce rate, grouped by page, referrer,
// country, device and more, or by date) and the visitors on a site right
// now. It never changes anything.
package fathom

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
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Fathom account.
type Config struct {
	APIKey string `json:"apiKey"` // secret://
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://api.usefathom.com and HTTP the client (tests).
	// Neither is a setting, so an instance can't send its key anywhere else.
	Base string
	HTTP *http.Client
}

// New returns the Fathom module.
func New() *Module { return &Module{} }

const (
	maxRows   = 1000
	maxOutput = 256 << 10
)

var (
	siteRe = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)
	dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// Aggregates are the numbers an aggregation can return.
var Aggregates = []string{"visits", "uniques", "pageviews", "avg_duration", "bounce_rate"}

// Groupings are the fields an aggregation can be grouped by.
var Groupings = []string{"pathname", "hostname", "referrer_hostname", "referrer_pathname", "browser", "country_code", "device_type", "operating_system",
	"utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term"}

// DateGroupings are the time buckets an aggregation can be split into.
var DateGroupings = []string{"hour", "day", "month", "year"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	site := `"site":{"type":"string","description":"Site id (from sites), e.g. CDBUGS"}`
	return sdk.Manifest{
		ID: "fathom", Name: "Fathom Analytics", Version: "0.1.0", Category: "Monitoring", Icon: "chart",
		Description: "Fathom Analytics: sites, visits, unique visitors, pageviews, duration and bounce rate by page, referrer, country, device or date, and visitors right now. Read only.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"An API key (Settings, API) with read access to the sites"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "sites", Title: "Sites", Description: "Sites the key can read: id, name and sharing setting.", Risk: sdk.RiskRead},
			{Name: "aggregation", Title: "Totals and top lists", Description: "Visits, unique visitors, pageviews, average duration (seconds) and bounce rate over a date range, in total or grouped by fields like pathname or referrer_hostname, or by hour, day, month or year.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["site"],"properties":{` + site + `,
					"aggregates":{"type":"array","items":{"type":"string","enum":["visits","uniques","pageviews","avg_duration","bounce_rate"]},"description":"Default: all five"},
					"groupBy":{"type":"array","items":{"type":"string","enum":["pathname","hostname","referrer_hostname","referrer_pathname","browser","country_code","device_type","operating_system","utm_source","utm_medium","utm_campaign","utm_content","utm_term"]},"maxItems":3},
					"dateGrouping":{"type":"string","enum":["hour","day","month","year"]},
					"days":{"type":"integer","minimum":1,"maximum":366,"default":30,"description":"The last days, today included (UTC)"},
					"from":{"type":"string","format":"date","description":"Start date (YYYY-MM-DD, UTC), with to, instead of days"},
					"to":{"type":"string","format":"date","description":"End date (YYYY-MM-DD), inclusive; at most a year after from"},
					"limit":{"type":"integer","minimum":1,"maximum":1000,"default":100}}}`)},
			{Name: "current_visitors", Title: "Visitors now", Description: "Visitors on a site right now, with the pages they're on and where they came from, as counts.", Risk: sdk.RiskRead,
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
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	base := "https://api.usefathom.com"
	if m.Base != "" {
		base = m.Base
	}
	ref := c.APIKey
	api := rest.New(base+"/v1", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, site string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Fathom refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		if site != "" {
			return fmt.Errorf("the API key may not read site %s", site)
		}
		return errors.New("the API key may not do this in Fathom")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("Fathom has no site %s (or the key can't see it)", site)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Fathom's rate limit was hit; try again in a minute")
	case rest.IsStatus(err, http.StatusBadRequest), rest.IsStatus(err, http.StatusUnprocessableEntity):
		return fmt.Errorf("Fathom refused the query: %s", clip(err.Error(), 300))
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s siteList
	if _, err := c.api.Do(ctx, http.MethodGet, "/sites", url.Values{"limit": {"100"}}, nil, &s); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "").Error()}
	}
	more := ""
	if s.HasMore {
		more = "+"
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d%s sites", len(s.Data), more)}
}

type siteList struct {
	Data []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Sharing string `json:"sharing"`
	} `json:"data"`
	HasMore bool `json:"has_more"`
}

type input struct {
	Site         string   `json:"site"`
	Aggregates   []string `json:"aggregates"`
	GroupBy      []string `json:"groupBy"`
	DateGrouping string   `json:"dateGrouping"`
	Days         int      `json:"days"`
	From         string   `json:"from"`
	To           string   `json:"to"`
	Limit        int      `json:"limit"`
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func oneOf(v string, list []string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func distinct(vs []string, list []string, kind string, max int) error {
	if len(vs) > max {
		return fmt.Errorf("at most %d %s", max, kind)
	}
	seen := map[string]bool{}
	for _, v := range vs {
		if !oneOf(v, list) || seen[v] {
			return fmt.Errorf("%s are distinct values of %s", kind, strings.Join(list, ", "))
		}
		seen[v] = true
	}
	return nil
}

func site(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if !siteRe.MatchString(s) {
		return "", errors.New("the site is its id from sites, like CDBUGS")
	}
	return s, nil
}

// dateRange turns days or from/to into Fathom's timestamps (UTC).
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
		if t.After(f.AddDate(1, 0, 0)) {
			return "", "", errors.New("a range spans at most one year")
		}
		return from + " 00:00:00", to + " 23:59:59", nil
	}
	days := p.Days
	if days == 0 {
		days = 30
	}
	if days < 1 || days > 366 {
		return "", "", errors.New("days is between 1 and 366")
	}
	today := now.UTC()
	return today.AddDate(0, 0, 1-days).Format("2006-01-02") + " 00:00:00", today.Format("2006-01-02") + " 23:59:59", nil
}

// num reads a Fathom number, which may come as a string.
func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
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
		after := ""
		for pg := 0; pg < 10; pg++ {
			q := url.Values{"limit": {"100"}}
			if after != "" {
				q.Set("starting_after", after)
			}
			var s siteList
			if _, err := c.api.Do(ctx, http.MethodGet, "/sites", q, nil, &s); err != nil {
				return sdk.Result{}, friendly(err, "")
			}
			for _, x := range s.Data {
				out = append(out, map[string]any{"site": clip(x.ID, 32), "name": clip(x.Name, 200), "sharing": clip(x.Sharing, 20)})
			}
			if !s.HasMore || len(s.Data) == 0 || !siteRe.MatchString(s.Data[len(s.Data)-1].ID) {
				break
			}
			after = s.Data[len(s.Data)-1].ID
		}
		return sdk.JSON(out)

	case "aggregation":
		id, err := site(p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		aggs := p.Aggregates
		if len(aggs) == 0 {
			aggs = Aggregates
		}
		if err := distinct(aggs, Aggregates, "aggregates", len(Aggregates)); err != nil {
			return sdk.Result{}, err
		}
		if err := distinct(p.GroupBy, Groupings, "groupBy fields", 3); err != nil {
			return sdk.Result{}, err
		}
		if p.DateGrouping != "" && !oneOf(p.DateGrouping, DateGroupings) {
			return sdk.Result{}, fmt.Errorf("dateGrouping is one of %s", strings.Join(DateGroupings, ", "))
		}
		from, to, err := dateRange(p, time.Now())
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
		q := url.Values{"entity": {"pageview"}, "entity_id": {id}, "aggregates": {strings.Join(aggs, ",")},
			"date_from": {from}, "date_to": {to}, "limit": {strconv.Itoa(n)}, "sort_by": {aggs[0] + ":desc"}}
		if len(p.GroupBy) > 0 {
			q.Set("field_grouping", strings.Join(p.GroupBy, ","))
		}
		if p.DateGrouping != "" {
			q.Set("date_grouping", p.DateGrouping)
			q.Set("sort_by", "timestamp:asc")
		}
		var rs []map[string]any
		if _, err := c.api.Do(ctx, http.MethodGet, "/aggregations", q, nil, &rs); err != nil {
			return sdk.Result{}, friendly(err, id)
		}
		rows := []map[string]any{}
		size, cut := 0, false
		for _, r := range rs {
			if len(rows) == n {
				cut = true
				break
			}
			row := map[string]any{}
			for _, a := range aggs {
				row[a] = num(r[a])
			}
			for _, g := range p.GroupBy {
				row[g] = clip(str(r[g]), 300)
			}
			if p.DateGrouping != "" {
				row["date"] = clip(str(r["date"]), 40)
			}
			b, _ := json.Marshal(row)
			if size += len(b); size > maxOutput {
				cut = true
				break
			}
			rows = append(rows, row)
		}
		out := map[string]any{"site": id, "from": from, "to": to, "rows": rows}
		if cut {
			out["truncated"] = true
		}
		return sdk.JSON(out)

	case "current_visitors":
		id, err := site(p.Site)
		if err != nil {
			return sdk.Result{}, err
		}
		var a struct {
			Total     any              `json:"total"`
			Content   []map[string]any `json:"content"`
			Referrers []map[string]any `json:"referrers"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/current_visitors", url.Values{"site_id": {id}, "detailed": {"true"}}, nil, &a); err != nil {
			return sdk.Result{}, friendly(err, id)
		}
		pages, refs := []map[string]any{}, []map[string]any{}
		for _, x := range a.Content {
			if len(pages) == 50 {
				break
			}
			pages = append(pages, map[string]any{"hostname": clip(str(x["hostname"]), 253), "pathname": clip(str(x["pathname"]), 300), "visitors": int64(num(x["total"]))})
		}
		for _, x := range a.Referrers {
			if len(refs) == 50 {
				break
			}
			refs = append(refs, map[string]any{"hostname": clip(str(x["referrer_hostname"]), 253), "pathname": clip(str(x["referrer_pathname"]), 300), "visitors": int64(num(x["total"]))})
		}
		return sdk.JSON(map[string]any{"site": id, "visitors": int64(num(a.Total)), "pages": pages, "referrers": refs})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
