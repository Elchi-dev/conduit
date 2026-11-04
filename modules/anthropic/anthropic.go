// Package anthropic reads a Claude Console (Anthropic API) organization's
// usage and spend through the Admin API: tokens by day and by model,
// workspace or service tier, costs in US dollars, and the model list.
// Nothing it does creates keys, changes members or sends prompts.
package anthropic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/aispend"
	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Anthropic organization.
type Config struct {
	AdminKey string `json:"adminKey"` // secret:// Admin API key (sk-ant-admin...)
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
	// Base replaces https://api.anthropic.com (tests).
	Base string
	now  func() time.Time
}

// New returns the Anthropic module.
func New() *Module { return &Module{} }

const (
	version    = "2023-06-01"
	maxPages   = 5   // of up to 31 daily buckets: more than the 93-day range needs
	maxGroups  = 200 // rows in an answer
	maxModels  = 200
	modelPages = 3
)

var searchRe = regexp.MustCompile(`^[A-Za-z0-9 ._:/@+-]{1,100}$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	rng := `"from":{"type":"string","description":"First day, YYYY-MM-DD (UTC); default six days before to"},"to":{"type":"string","description":"Last day, YYYY-MM-DD (UTC), included; default today. At most 93 days in all"}`
	return sdk.Manifest{
		ID: "anthropic", Name: "Anthropic", Version: "0.1.0", Category: "Development", Icon: "chart",
		Description: "Anthropic (Claude API): token usage by day, model, workspace or service tier, spend in US dollars, and available models. Read-only.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["adminKey"],"properties":{
			"adminKey":{"type":"string","x-secret":true,"description":"Admin API key (Claude Console, Settings, Admin keys; starts sk-ant-admin). Organizations only"},
			"apiKey":{"type":"string","x-secret":true,"description":"Optional regular API key, only to list models"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "usage", Title: "Token usage", Description: "Tokens (uncached input, cache writes, cache reads, output) and web searches per day and per model, workspace or service tier, for up to 93 days.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + rng + `,"groupBy":{"type":"array","maxItems":3,"items":{"type":"string","enum":["model","workspace","service_tier"]},"default":["model"]}}}`)},
			{Name: "costs", Title: "Spend", Description: "Spend in US dollars per day and per cost line (model and token type) or workspace, with the total, for up to 93 days.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + rng + `,"groupBy":{"type":"array","maxItems":2,"items":{"type":"string","enum":["description","workspace"]},"default":["description"]}}}`)},
			{Name: "models", Title: "Models", Description: "Models the API key can use, newest first, with display name and release date. Needs the optional API key.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","maxLength":100,"description":"Only ids or names containing this, e.g. sonnet"},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}}}`)},
		},
	}
}

func keyed(h sdk.Host, ref string) func(context.Context, *http.Request) error {
	return func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("x-api-key", strings.TrimSpace(k))
		r.Header.Set("anthropic-version", version)
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
		return errors.New("store the Admin API key in the vault and enter its secret:// reference")
	}
	if c.APIKey != "" && !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	base := "https://api.anthropic.com"
	if m.Base != "" {
		base = m.Base
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	client = rest.SameHostOnly(client)
	cn := &conn{admin: rest.New(base, keyed(h, c.AdminKey))}
	cn.admin.HTTP = client
	if c.APIKey != "" {
		cn.api = rest.New(base, keyed(h, c.APIKey))
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
		return errors.New("Anthropic refused the Admin API key")
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Anthropic refused the API key")
	case rest.IsStatus(err, http.StatusForbidden) && admin:
		return errors.New("Anthropic refused: this needs an Admin API key (Claude Console, Settings, Admin keys) of an organization")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Anthropic refused: the API key can't list models")
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
	var org struct {
		Name string `json:"name"`
	}
	if _, err := c.admin.Do(ctx, http.MethodGet, "/v1/organizations/me", nil, nil, &org); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, true).Error()}
	}
	msg := "Admin API key accepted"
	if n := strings.TrimSpace(org.Name); n != "" && len(n) <= 100 {
		msg += " for " + n
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type bucket[T any] struct {
	StartingAt string `json:"starting_at"`
	Results    []T    `json:"results"`
}

type page[T any] struct {
	Data     []bucket[T] `json:"data"`
	HasMore  bool        `json:"has_more"`
	NextPage *string     `json:"next_page"`
}

// pages reads every page of a report, up to maxPages; it reports whether
// more were left.
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

func date(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func str(p *string, def string) string {
	if p == nil || *p == "" {
		return def
	}
	return *p
}

type usageResult struct {
	Uncached      int64 `json:"uncached_input_tokens"`
	CacheCreation struct {
		OneHour  int64 `json:"ephemeral_1h_input_tokens"`
		FiveMins int64 `json:"ephemeral_5m_input_tokens"`
	} `json:"cache_creation"`
	CacheRead     int64 `json:"cache_read_input_tokens"`
	Output        int64 `json:"output_tokens"`
	ServerToolUse struct {
		WebSearch int64 `json:"web_search_requests"`
	} `json:"server_tool_use"`
	Model       *string `json:"model"`
	WorkspaceID *string `json:"workspace_id"`
	ServiceTier *string `json:"service_tier"`
	// api_key_id and account ids aren't decoded.
}

type tokens struct {
	InputTokens      int64 `json:"inputTokens"`
	CacheWriteTokens int64 `json:"cacheWriteTokens"`
	CacheReadTokens  int64 `json:"cacheReadTokens"`
	OutputTokens     int64 `json:"outputTokens"`
	WebSearches      int64 `json:"webSearches,omitempty"`
}

func (t *tokens) add(r usageResult) {
	t.InputTokens += r.Uncached
	t.CacheWriteTokens += r.CacheCreation.OneHour + r.CacheCreation.FiveMins
	t.CacheReadTokens += r.CacheRead
	t.OutputTokens += r.Output
	t.WebSearches += r.ServerToolUse.WebSearch
}

func (t tokens) sum() int64 {
	return t.InputTokens + t.CacheWriteTokens + t.CacheReadTokens + t.OutputTokens
}

type costResult struct {
	Amount      string  `json:"amount"`
	Currency    string  `json:"currency"`
	CostType    *string `json:"cost_type"`
	Description *string `json:"description"`
	Model       *string `json:"model"`
	TokenType   *string `json:"token_type"`
	WorkspaceID *string `json:"workspace_id"`
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
		groups, err := aispend.Groups(p.GroupBy, map[string]string{"model": "model", "workspace": "workspace_id", "service_tier": "service_tier"}, []string{"model"})
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := aispend.ParseRange(p.From, p.To, m.clock())
		if err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{"starting_at": {r.From.Format(time.RFC3339)}, "ending_at": {r.End.Format(time.RFC3339)}, "bucket_width": {"1d"}, "limit": {"31"}}
		for _, g := range groups {
			q.Add("group_by[]", g)
		}
		buckets, more, err := pages[usageResult](ctx, c.admin, "/v1/organizations/usage_report/messages", q)
		if err != nil {
			return sdk.Result{}, err
		}
		type group struct {
			Model       string `json:"model,omitempty"`
			Workspace   string `json:"workspace,omitempty"`
			ServiceTier string `json:"serviceTier,omitempty"`
			tokens
		}
		type dayRow struct {
			Date string `json:"date"`
			tokens
		}
		var total tokens
		byKey := map[[3]string]*group{}
		days := []dayRow{}
		for _, b := range buckets {
			d := dayRow{Date: date(b.StartingAt)}
			for _, x := range b.Results {
				d.add(x)
				total.add(x)
				k := [3]string{}
				if aispend.Has(groups, "model") {
					k[0] = str(x.Model, "unknown")
				}
				if aispend.Has(groups, "workspace_id") {
					k[1] = str(x.WorkspaceID, "default")
				}
				if aispend.Has(groups, "service_tier") {
					k[2] = str(x.ServiceTier, "unknown")
				}
				g := byKey[k]
				if g == nil {
					g = &group{Model: k[0], Workspace: k[1], ServiceTier: k[2]}
					byKey[k] = g
				}
				g.add(x)
			}
			days = append(days, d)
		}
		list := []group{}
		for _, g := range byKey {
			list = append(list, *g)
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].sum() != list[j].sum() {
				return list[i].sum() > list[j].sum()
			}
			return fmt.Sprint(list[i].Model, list[i].Workspace, list[i].ServiceTier) < fmt.Sprint(list[j].Model, list[j].Workspace, list[j].ServiceTier)
		})
		sort.SliceStable(days, func(i, j int) bool { return days[i].Date < days[j].Date })
		out := map[string]any{"from": r.From.Format("2006-01-02"), "to": r.End.AddDate(0, 0, -1).Format("2006-01-02"),
			"total": total, "groups": capped(list, maxGroups), "groupCount": len(list), "days": days}
		if more {
			out["truncated"] = true
		}
		return sdk.JSON(out)
	case "costs":
		groups, err := aispend.Groups(p.GroupBy, map[string]string{"description": "description", "workspace": "workspace_id"}, []string{"description"})
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := aispend.ParseRange(p.From, p.To, m.clock())
		if err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{"starting_at": {r.From.Format(time.RFC3339)}, "ending_at": {r.End.Format(time.RFC3339)}, "bucket_width": {"1d"}, "limit": {"31"}}
		for _, g := range groups {
			q.Add("group_by[]", g)
		}
		buckets, more, err := pages[costResult](ctx, c.admin, "/v1/organizations/cost_report", q)
		if err != nil {
			return sdk.Result{}, err
		}
		hundred := big.NewRat(100, 1)
		type group struct {
			Workspace   string `json:"workspace,omitempty"`
			Description string `json:"description,omitempty"`
			Model       string `json:"model,omitempty"`
			CostType    string `json:"costType,omitempty"`
			TokenType   string `json:"tokenType,omitempty"`
			Currency    string `json:"currency"`
			Amount      string `json:"amount"`
			amt         *big.Rat
		}
		type dayRow struct {
			Date   string            `json:"date"`
			Totals map[string]string `json:"totals"`
		}
		var totals aispend.Sums
		byKey := map[string]*group{}
		var order []string
		days := []dayRow{}
		for _, b := range buckets {
			var day aispend.Sums
			for _, x := range b.Results {
				cents, err := aispend.Amount(x.Amount)
				if err != nil {
					return sdk.Result{}, fmt.Errorf("unexpected amount from Anthropic for %s", date(b.StartingAt))
				}
				usd := new(big.Rat).Quo(cents, hundred) // amounts are in cents
				cur := strings.ToUpper(strings.TrimSpace(x.Currency))
				if cur == "" {
					cur = "USD"
				}
				day.Add(cur, usd)
				totals.Add(cur, usd)
				g := group{Currency: cur}
				if aispend.Has(groups, "workspace_id") {
					g.Workspace = str(x.WorkspaceID, "default")
				}
				if aispend.Has(groups, "description") {
					g.Description, g.Model, g.CostType, g.TokenType = str(x.Description, ""), str(x.Model, ""), str(x.CostType, ""), str(x.TokenType, "")
				}
				k := strings.Join([]string{g.Workspace, g.Description, g.Model, g.CostType, g.TokenType, g.Currency}, "\x00")
				if byKey[k] == nil {
					g.amt = new(big.Rat)
					byKey[k] = &g
					order = append(order, k)
				}
				byKey[k].amt.Add(byKey[k].amt, usd)
			}
			days = append(days, dayRow{Date: date(b.StartingAt), Totals: day.Strings()})
		}
		list := []group{}
		for _, k := range order {
			g := byKey[k]
			g.Amount = aispend.Format(g.amt)
			list = append(list, *g)
		}
		sort.SliceStable(list, func(i, j int) bool { return list[i].amt.Cmp(list[j].amt) > 0 })
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
		type model struct {
			ID             string `json:"id"`
			DisplayName    string `json:"displayName,omitempty"`
			CreatedAt      string `json:"createdAt,omitempty"`
			MaxInputTokens *int64 `json:"maxInputTokens,omitempty"`
		}
		var all []model
		q := url.Values{"limit": {"1000"}}
		for i := 0; i < modelPages; i++ {
			var out struct {
				Data []struct {
					ID             string `json:"id"`
					DisplayName    string `json:"display_name"`
					CreatedAt      string `json:"created_at"`
					MaxInputTokens *int64 `json:"max_input_tokens"`
				} `json:"data"`
				HasMore bool   `json:"has_more"`
				LastID  string `json:"last_id"`
			}
			if _, err := c.api.Do(ctx, http.MethodGet, "/v1/models", q, nil, &out); err != nil {
				return sdk.Result{}, friendly(err, false)
			}
			for _, x := range out.Data {
				all = append(all, model{x.ID, x.DisplayName, date(x.CreatedAt), x.MaxInputTokens})
			}
			if !out.HasMore || out.LastID == "" || len(out.LastID) > 200 {
				break
			}
			q.Set("after_id", out.LastID)
		}
		s := strings.ToLower(p.Search)
		list := []model{}
		for _, x := range all {
			if s != "" && !strings.Contains(strings.ToLower(x.ID), s) && !strings.Contains(strings.ToLower(x.DisplayName), s) {
				continue
			}
			list = append(list, x)
		}
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
