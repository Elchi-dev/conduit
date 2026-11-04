// Package openrouter reads an OpenRouter account through its API: credits
// bought and used, the key's limit and usage, the model catalogue with
// prices, and recent activity by model. Nothing it does spends credits.
package openrouter

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one OpenRouter account.
type Config struct {
	APIKey string `json:"apiKey"` // secret://
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://openrouter.ai/api/v1 (tests).
	Base string
}

// New returns the OpenRouter module.
func New() *Module { return &Module{} }

var (
	dateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	searchRe = regexp.MustCompile(`^[A-Za-z0-9 ._:/@+-]{1,100}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "openrouter", Name: "OpenRouter", Version: "0.1.0", Category: "Development", Icon: "network",
		Description: "OpenRouter: credits left, the key's limit and usage, models with prices, and spend by model and day. Read-only.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"API key (openrouter.ai, Keys). Activity needs a provisioning key"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "credits", Title: "Credits", Description: "Credits bought, used and left on the account, in US dollars.", Risk: sdk.RiskRead},
			{Name: "key_info", Title: "This key", Description: "The key's label (masked), credit limit, what's left of it, usage today, this week and this month, and whether it's a free-tier key. Never the key itself.", Risk: sdk.RiskRead},
			{Name: "models", Title: "Models and prices", Description: "Models with context length and price per million input and output tokens, cheapest first or by name.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","maxLength":100,"description":"Only ids or names containing this, e.g. claude or llama"},"sort":{"type":"string","enum":["name","price"],"default":"name"},"free":{"type":"boolean","description":"Only free models"},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}}}`)},
			{Name: "activity", Title: "Activity", Description: "Spend, requests and tokens by model for each of the last 30 days (or one date), with totals. Needs a provisioning key.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"date":{"type":"string","description":"One day, YYYY-MM-DD, within the last 30 days"}}}`)},
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
	base := "https://openrouter.ai/api/v1"
	if m.Base != "" {
		base = m.Base
	}
	ref := c.APIKey
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("OpenRouter refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("OpenRouter refused: this needs a provisioning key (openrouter.ai, Provisioning keys)")
	}
	return err
}

type keyData struct {
	Label          string   `json:"label"`
	Limit          *float64 `json:"limit"`
	LimitRemaining *float64 `json:"limit_remaining"`
	LimitReset     *string  `json:"limit_reset"`
	Usage          float64  `json:"usage"`
	UsageDaily     *float64 `json:"usage_daily"`
	UsageWeekly    *float64 `json:"usage_weekly"`
	UsageMonthly   *float64 `json:"usage_monthly"`
	IsFreeTier     bool     `json:"is_free_tier"`
	Provisioning   bool     `json:"is_provisioning_key"`
}

func (c *conn) key(ctx context.Context) (keyData, error) {
	var out struct {
		Data keyData `json:"data"`
	}
	_, err := c.api.Do(ctx, http.MethodGet, "/key", nil, nil, &out)
	return out.Data, friendly(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	k, err := c.key(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if k.LimitRemaining != nil && *k.LimitRemaining <= 0 {
		return sdk.Health{Status: "degraded", Message: "the key's credit limit is used up"}
	}
	return sdk.Health{Status: "ok", Message: "key " + mask(k.Label) + " accepted"}
}

// mask keeps a key label only when it's already masked (sk-or-v1-abc...def);
// a label someone typed is kept, anything that looks like a whole key isn't.
func mask(label string) string {
	label = strings.TrimSpace(label)
	if strings.Contains(label, "...") || strings.Contains(label, "…") {
		return label
	}
	return rest.Redact(label)
}

func perMillion(s string) *float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f < 0 {
		return nil
	}
	v := f * 1e6
	return &v
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Search string `json:"search"`
		Sort   string `json:"sort"`
		Free   bool   `json:"free"`
		Limit  int    `json:"limit"`
		Date   string `json:"date"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "credits":
		var out struct {
			Data struct {
				Total float64 `json:"total_credits"`
				Used  float64 `json:"total_usage"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/credits", nil, nil, &out); err != nil {
			return sdk.Result{}, friendly(err)
		}
		return sdk.JSON(map[string]any{"currency": "USD", "bought": out.Data.Total, "used": out.Data.Used, "left": out.Data.Total - out.Data.Used})
	case "key_info":
		k, err := c.key(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"label": mask(k.Label), "currency": "USD", "usage": k.Usage, "limit": k.Limit, "limitRemaining": k.LimitRemaining,
			"freeTier": k.IsFreeTier, "provisioningKey": k.Provisioning}
		if k.LimitReset != nil {
			out["limitReset"] = *k.LimitReset
		}
		for name, v := range map[string]*float64{"usageToday": k.UsageDaily, "usageThisWeek": k.UsageWeekly, "usageThisMonth": k.UsageMonthly} {
			if v != nil {
				out[name] = *v
			}
		}
		return sdk.JSON(out)
	case "models":
		if p.Search != "" && !searchRe.MatchString(p.Search) {
			return sdk.Result{}, errors.New("search with letters, digits and . _ : / @ + - only")
		}
		if p.Sort != "" && p.Sort != "name" && p.Sort != "price" {
			return sdk.Result{}, errors.New("sort is name or price")
		}
		if p.Limit <= 0 || p.Limit > 200 {
			p.Limit = 50
		}
		var out struct {
			Data []struct {
				ID            string `json:"id"`
				Name          string `json:"name"`
				ContextLength int    `json:"context_length"`
				Created       int64  `json:"created"`
				Pricing       struct {
					Prompt     string `json:"prompt"`
					Completion string `json:"completion"`
					Request    string `json:"request"`
					Image      string `json:"image"`
				} `json:"pricing"`
				Architecture struct {
					InputModalities  []string `json:"input_modalities"`
					OutputModalities []string `json:"output_modalities"`
				} `json:"architecture"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/models", nil, nil, &out); err != nil {
			return sdk.Result{}, friendly(err)
		}
		type model struct {
			ID            string   `json:"id"`
			Name          string   `json:"name"`
			ContextLength int      `json:"contextLength,omitempty"`
			InputPerM     *float64 `json:"inputPerMillion"`
			OutputPerM    *float64 `json:"outputPerMillion"`
			Free          bool     `json:"free"`
			Input         []string `json:"input,omitempty"`
			Output        []string `json:"output,omitempty"`
		}
		q := strings.ToLower(p.Search)
		list := []model{}
		for _, x := range out.Data {
			if q != "" && !strings.Contains(strings.ToLower(x.ID), q) && !strings.Contains(strings.ToLower(x.Name), q) {
				continue
			}
			in, o := perMillion(x.Pricing.Prompt), perMillion(x.Pricing.Completion)
			free := in != nil && o != nil && *in == 0 && *o == 0
			if p.Free && !free {
				continue
			}
			list = append(list, model{x.ID, x.Name, x.ContextLength, in, o, free, x.Architecture.InputModalities, x.Architecture.OutputModalities})
		}
		price := func(x model) float64 {
			if x.InputPerM == nil || x.OutputPerM == nil {
				return 1e18
			}
			return *x.InputPerM + *x.OutputPerM
		}
		sort.SliceStable(list, func(i, j int) bool {
			if p.Sort == "price" && price(list[i]) != price(list[j]) {
				return price(list[i]) < price(list[j])
			}
			return list[i].ID < list[j].ID
		})
		total := len(list)
		if len(list) > p.Limit {
			list = list[:p.Limit]
		}
		return sdk.JSON(map[string]any{"models": list, "matching": total, "currency": "USD"})
	case "activity":
		q := url.Values{}
		if p.Date != "" {
			if !dateRe.MatchString(p.Date) {
				return sdk.Result{}, errors.New("the date is YYYY-MM-DD")
			}
			if _, err := time.Parse("2006-01-02", p.Date); err != nil {
				return sdk.Result{}, errors.New("the date is YYYY-MM-DD")
			}
			q.Set("date", p.Date)
		}
		var out struct {
			Data []struct {
				Date             string  `json:"date"`
				Model            string  `json:"model"`
				Provider         string  `json:"provider_name"`
				Usage            float64 `json:"usage"`
				BYOK             float64 `json:"byok_usage_inference"`
				Requests         int64   `json:"requests"`
				PromptTokens     int64   `json:"prompt_tokens"`
				CompletionTokens int64   `json:"completion_tokens"`
				ReasoningTokens  int64   `json:"reasoning_tokens"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/activity", q, nil, &out); err != nil {
			return sdk.Result{}, friendly(err)
		}
		type row struct {
			Date             string  `json:"date"`
			Model            string  `json:"model"`
			Provider         string  `json:"provider,omitempty"`
			Spend            float64 `json:"spend"`
			BYOKSpend        float64 `json:"byokSpend,omitempty"`
			Requests         int64   `json:"requests"`
			PromptTokens     int64   `json:"promptTokens"`
			CompletionTokens int64   `json:"completionTokens"`
			ReasoningTokens  int64   `json:"reasoningTokens,omitempty"`
		}
		rows := []row{}
		byModel := map[string]float64{}
		var spend float64
		var reqs int64
		for _, x := range out.Data {
			rows = append(rows, row{x.Date, x.Model, x.Provider, x.Usage, x.BYOK, x.Requests, x.PromptTokens, x.CompletionTokens, x.ReasoningTokens})
			byModel[x.Model] += x.Usage
			spend += x.Usage
			reqs += x.Requests
		}
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Date != rows[j].Date {
				return rows[i].Date > rows[j].Date
			}
			return rows[i].Spend > rows[j].Spend
		})
		type tot struct {
			Model string  `json:"model"`
			Spend float64 `json:"spend"`
		}
		totals := []tot{}
		for k, v := range byModel {
			totals = append(totals, tot{k, v})
		}
		sort.Slice(totals, func(i, j int) bool {
			if totals[i].Spend != totals[j].Spend {
				return totals[i].Spend > totals[j].Spend
			}
			return totals[i].Model < totals[j].Model
		})
		return sdk.JSON(map[string]any{"currency": "USD", "spend": spend, "requests": reqs, "byModel": totals, "days": rows})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
