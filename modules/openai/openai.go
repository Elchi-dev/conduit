// Package openai reads an OpenAI API organization's usage and spend
// through the Usage and Costs endpoints with an Admin key: completions
// tokens and requests by day and by model, project, batch or service tier,
// costs by line item or project, and the model list. Nothing it does
// creates keys, changes members or sends prompts.
package openai

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
	"time"

	"github.com/elchi-dev/conduit/modules/internal/aispend"
	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one OpenAI organization.
type Config struct {
	AdminKey string `json:"adminKey"` // secret:// Admin key (sk-admin-...)
	APIKey   string `json:"apiKey"`   // optional secret:// API key, for models
}

type conn struct {
	admin *rest.Client
	api   *rest.Client // nil without an API key
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.openai.com/v1 (tests).
	Base string
	now  func() time.Time
}

// New returns the OpenAI module.
func New() *Module { return &Module{} }

const (
	maxPages  = 5 // usage pages hold 31 daily buckets, cost pages 180
	maxGroups = 200
	maxModels = 200
)

var searchRe = regexp.MustCompile(`^[A-Za-z0-9 ._:/@+-]{1,100}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	rng := `"from":{"type":"string","description":"First day, YYYY-MM-DD (UTC); default six days before to"},"to":{"type":"string","description":"Last day, YYYY-MM-DD (UTC), included; default today. At most 93 days in all"}`
	return sdk.Manifest{
		ID: "openai", Name: "OpenAI", Version: "0.1.0", Category: "Development", Icon: "chart",
		Description: "OpenAI API: completions tokens and requests by day, model or project, spend by line item or project, and available models. Read-only.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["adminKey"],"properties":{
			"adminKey":{"type":"string","x-secret":true,"description":"Admin key (platform.openai.com, Organization settings, Admin keys); an organization owner creates it"},
			"apiKey":{"type":"string","x-secret":true,"description":"Optional regular API key, only to list models"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "usage", Title: "Completions usage", Description: "Input, cached input and output tokens and requests for completions, per day and per model, project, batch or service tier, for up to 93 days.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + rng + `,"groupBy":{"type":"array","maxItems":4,"items":{"type":"string","enum":["model","project","batch","service_tier"]},"default":["model"]}}}`)},
			{Name: "costs", Title: "Spend", Description: "Spend per day and per line item (model and token type) or project, with the total, for up to 93 days.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + rng + `,"groupBy":{"type":"array","maxItems":2,"items":{"type":"string","enum":["line_item","project"]},"default":["line_item"]}}}`)},
			{Name: "models", Title: "Models", Description: "Models the API key can use, with owner and creation date. Needs the optional API key.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","maxLength":100,"description":"Only ids containing this, e.g. gpt"},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}}}`)},
		},
	}
}

func bearer(h sdk.Host, ref string) func(context.Context, *http.Request) error {
	return func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
		return nil
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.AdminKey, "secret://") {
		return errors.New("store the Admin key in the vault and enter its secret:// reference")
	}
	if c.APIKey != "" && !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	base := "https://api.openai.com/v1"
	if m.Base != "" {
		base = m.Base
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	client = rest.SameHostOnly(client)
	cn := &conn{admin: rest.New(base, bearer(h, c.AdminKey))}
	cn.admin.HTTP = client
	if c.APIKey != "" {
		cn.api = rest.New(base, bearer(h, c.APIKey))
		cn.api.HTTP = client
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, admin bool) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized) && admin:
		return errors.New("OpenAI refused the Admin key")
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("OpenAI refused the API key")
	case rest.IsStatus(err, http.StatusForbidden) && admin:
		return errors.New("OpenAI refused: usage and costs need an Admin key (Organization settings, Admin keys), not a project or user key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("OpenAI refused: the API key isn't allowed to list models")
	}
	return err
}

func (m *Module) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	start := m.clock().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	q := url.Values{"start_time": {strconv.FormatInt(start.Unix(), 10)}, "limit": {"1"}}
	if _, err := c.admin.Do(ctx, http.MethodGet, "/organization/costs", q, nil, nil); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, true).Error()}
	}
	return sdk.Health{Status: "ok", Message: "Admin key accepted"}
}

type bucket[T any] struct {
	StartTime int64 `json:"start_time"`
	Results   []T   `json:"results"`
}

type page[T any] struct {
	Data     []bucket[T] `json:"data"`
	HasMore  bool        `json:"has_more"`
	NextPage *string     `json:"next_page"`
}

func pages[T any](ctx context.Context, c *rest.Client, path string, q url.Values) ([]bucket[T], bool, error) {
	var all []bucket[T]
	for i := 0; i < maxPages; i++ {
		var p page[T]
		if _, err := c.Do(ctx, http.MethodGet, path, q, nil, &p); err != nil {
			return nil, false, friendly(err, true)
		}
		all = append(all, p.Data...)
		if !p.HasMore || p.NextPage == nil || *p.NextPage == "" {
			return all, false, nil
		}
		if len(*p.NextPage) > 512 {
			return all, true, nil
		}
		q.Set("page", *p.NextPage)
	}
	return all, true, nil
}

func day(unix int64) string { return time.Unix(unix, 0).UTC().Format("2006-01-02") }

// str is a name OpenAI reports, made fit to show (aispend.Label), or def.
func str(p *string, def string) string {
	if p == nil {
		return def
	}
	if s := aispend.Label(*p); s != "" {
		return s
	}
	return def
}

type usageResult struct {
	Input       int64   `json:"input_tokens"`
	Cached      int64   `json:"input_cached_tokens"`
	Output      int64   `json:"output_tokens"`
	Requests    int64   `json:"num_model_requests"`
	Model       *string `json:"model"`
	ProjectID   *string `json:"project_id"`
	Batch       *bool   `json:"batch"`
	ServiceTier *string `json:"service_tier"`
	// user_id and api_key_id aren't decoded.
}

type tokens struct {
	InputTokens       int64 `json:"inputTokens"`
	CachedInputTokens int64 `json:"cachedInputTokens"`
	OutputTokens      int64 `json:"outputTokens"`
	Requests          int64 `json:"requests"`
}

func (t *tokens) add(r usageResult) {
	t.InputTokens += r.Input
	t.CachedInputTokens += r.Cached
	t.OutputTokens += r.Output
	t.Requests += r.Requests
}

type costResult struct {
	Amount struct {
		Value    json.Number `json:"value"`
		Currency string      `json:"currency"`
	} `json:"amount"`
	LineItem  *string `json:"line_item"`
	ProjectID *string `json:"project_id"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		From    string   `json:"from"`
		To      string   `json:"to"`
		GroupBy []string `json:"groupBy"`
		Search  string   `json:"search"`
		Limit   int      `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "usage":
		groups, err := aispend.Groups(p.GroupBy, map[string]string{"model": "model", "project": "project_id", "batch": "batch", "service_tier": "service_tier"}, []string{"model"})
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := aispend.ParseRange(p.From, p.To, m.clock())
		if err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{"start_time": {strconv.FormatInt(r.From.Unix(), 10)}, "end_time": {strconv.FormatInt(r.End.Unix(), 10)}, "bucket_width": {"1d"}, "limit": {"31"}}
		for _, g := range groups {
			q.Add("group_by", g)
		}
		buckets, more, err := pages[usageResult](ctx, c.admin, "/organization/usage/completions", q)
		if err != nil {
			return sdk.Result{}, err
		}
		type group struct {
			Model       string `json:"model,omitempty"`
			Project     string `json:"project,omitempty"`
			Batch       *bool  `json:"batch,omitempty"`
			ServiceTier string `json:"serviceTier,omitempty"`
			tokens
		}
		type dayRow struct {
			Date string `json:"date"`
			tokens
		}
		var total tokens
		byKey := map[[4]string]*group{}
		days := []dayRow{}
		for _, b := range buckets {
			d := dayRow{Date: day(b.StartTime)}
			for _, x := range b.Results {
				d.add(x)
				total.add(x)
				g := group{}
				if aispend.Has(groups, "model") {
					g.Model = str(x.Model, "unknown")
				}
				if aispend.Has(groups, "project_id") {
					g.Project = str(x.ProjectID, "default")
				}
				if aispend.Has(groups, "batch") {
					v := x.Batch != nil && *x.Batch
					g.Batch = &v
				}
				if aispend.Has(groups, "service_tier") {
					g.ServiceTier = str(x.ServiceTier, "unknown")
				}
				k := [4]string{g.Model, g.Project, fmt.Sprint(g.Batch != nil && *g.Batch), g.ServiceTier}
				if byKey[k] == nil {
					byKey[k] = &g
				}
				byKey[k].add(x)
			}
			days = append(days, d)
		}
		list := []group{}
		for _, g := range byKey {
			list = append(list, *g)
		}
		sum := func(g group) int64 { return g.InputTokens + g.OutputTokens }
		sort.Slice(list, func(i, j int) bool {
			if sum(list[i]) != sum(list[j]) {
				return sum(list[i]) > sum(list[j])
			}
			return fmt.Sprint(list[i].Model, list[i].Project, list[i].ServiceTier, list[i].Batch != nil && *list[i].Batch) <
				fmt.Sprint(list[j].Model, list[j].Project, list[j].ServiceTier, list[j].Batch != nil && *list[j].Batch)
		})
		sort.SliceStable(days, func(i, j int) bool { return days[i].Date < days[j].Date })
		out := map[string]any{"from": r.From.Format("2006-01-02"), "to": r.End.AddDate(0, 0, -1).Format("2006-01-02"),
			"total": total, "groups": capped(list, maxGroups), "groupCount": len(list), "days": days}
		if more {
			out["truncated"] = true
		}
		return sdk.JSON(out)
	case "costs":
		groups, err := aispend.Groups(p.GroupBy, map[string]string{"line_item": "line_item", "project": "project_id"}, []string{"line_item"})
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := aispend.ParseRange(p.From, p.To, m.clock())
		if err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{"start_time": {strconv.FormatInt(r.From.Unix(), 10)}, "end_time": {strconv.FormatInt(r.End.Unix(), 10)}, "bucket_width": {"1d"}, "limit": {"180"}}
		for _, g := range groups {
			q.Add("group_by", g)
		}
		buckets, more, err := pages[costResult](ctx, c.admin, "/organization/costs", q)
		if err != nil {
			return sdk.Result{}, err
		}
		type group struct {
			Project  string `json:"project,omitempty"`
			LineItem string `json:"lineItem,omitempty"`
			Currency string `json:"currency"`
			Amount   string `json:"amount"`
		}
		type dayRow struct {
			Date   string            `json:"date"`
			Totals map[string]string `json:"totals"`
		}
		var totals, byGroup aispend.Sums
		meta := map[string]group{}
		days := []dayRow{}
		for _, b := range buckets {
			var d aispend.Sums
			for _, x := range b.Results {
				val := x.Amount.Value.String()
				if val == "" {
					val = "0" // amount is optional
				}
				v, err := aispend.Amount(val)
				if err != nil {
					return sdk.Result{}, fmt.Errorf("unexpected amount from OpenAI for %s", day(b.StartTime))
				}
				cur, err := aispend.Currency(x.Amount.Currency)
				if err != nil {
					return sdk.Result{}, fmt.Errorf("unexpected currency from OpenAI for %s", day(b.StartTime))
				}
				d.Add(cur, v)
				totals.Add(cur, v)
				g := group{Currency: cur}
				if aispend.Has(groups, "project_id") {
					g.Project = str(x.ProjectID, "default")
				}
				if aispend.Has(groups, "line_item") {
					g.LineItem = str(x.LineItem, "other")
				}
				k := g.Project + "\x00" + g.LineItem + "\x00" + g.Currency
				meta[k] = g
				byGroup.Add(k, v)
			}
			days = append(days, dayRow{Date: day(b.StartTime), Totals: d.Strings()})
		}
		keys := byGroup.Keys()
		sort.SliceStable(keys, func(i, j int) bool { return byGroup.Get(keys[i]).Cmp(byGroup.Get(keys[j])) > 0 })
		list := []group{}
		for _, k := range keys {
			g := meta[k]
			g.Amount = aispend.Format(byGroup.Get(k))
			list = append(list, g)
		}
		sort.SliceStable(days, func(i, j int) bool { return days[i].Date < days[j].Date })
		out := map[string]any{"from": r.From.Format("2006-01-02"), "to": r.End.AddDate(0, 0, -1).Format("2006-01-02"),
			"totals": totals.Strings(), "groups": capped(list, maxGroups), "groupCount": len(list), "days": days}
		if more {
			out["truncated"] = true
		}
		return sdk.JSON(out)
	case "models":
		if p.Search != "" && !searchRe.MatchString(p.Search) {
			return sdk.Result{}, errors.New("search with letters, digits and . _ : / @ + - only")
		}
		if p.Limit <= 0 || p.Limit > maxModels {
			p.Limit = 50
		}
		if c.api == nil {
			return sdk.Result{}, errors.New("listing models needs an API key: add one (apiKey) to this instance's settings")
		}
		var out struct {
			Data []struct {
				ID      string `json:"id"`
				Created int64  `json:"created"`
				OwnedBy string `json:"owned_by"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/models", nil, nil, &out); err != nil {
			return sdk.Result{}, friendly(err, false)
		}
		type model struct {
			ID      string `json:"id"`
			OwnedBy string `json:"ownedBy,omitempty"`
			Created string `json:"created,omitempty"`
		}
		s := strings.ToLower(p.Search)
		list := []model{}
		for _, x := range out.Data {
			if s != "" && !strings.Contains(strings.ToLower(x.ID), s) {
				continue
			}
			mo := model{ID: x.ID, OwnedBy: aispend.Owner(x.OwnedBy)}
			if x.Created > 0 {
				mo.Created = day(x.Created)
			}
			list = append(list, mo)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		return sdk.JSON(map[string]any{"models": capped(list, p.Limit), "matching": len(list)})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func capped[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}
