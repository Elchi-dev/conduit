// Package litellm administers a LiteLLM proxy with its master key: the
// models it routes to, spend by model, key, team and provider, virtual keys
// (never their values), budgets, a live health check of one model's
// deployments (rate limited: each check is a billed call), and blocking or
// unblocking a key.
package litellm

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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one LiteLLM proxy.
type Config struct {
	URL       string `json:"url"`       // e.g. http://127.0.0.1:4000
	MasterKey string `json:"masterKey"` // secret://
}

type conn struct {
	api    *rest.Client
	health *rest.Client // the live deployment check takes longer
	host   string
	now    func() time.Time

	mu     sync.Mutex
	checks []time.Time // deployment_health calls in the last minute
}

// healthPerMinute caps deployment_health per instance: every check is a
// real, billed request to a provider.
const healthPerMinute = 10

// allowCheck records a deployment check, or says when the next one is
// allowed.
func (c *conn) allowCheck() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	kept := c.checks[:0]
	for _, t := range c.checks {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	c.checks = kept
	if len(c.checks) >= healthPerMinute {
		wait := time.Minute - now.Sub(c.checks[0])
		return fmt.Errorf("at most %d deployment checks a minute (each is a billed call); try again in %d seconds", healthPerMinute, int(wait.Seconds())+1)
	}
	c.checks = append(c.checks, now)
	return nil
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the LiteLLM module.
func New() *Module { return &Module{} }

var (
	// LiteLLM stores virtual keys as their SHA-256, which admin endpoints
	// accept in place of the key; it can't be used to call models.
	hashRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	aliasRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.:@/-]{0,99}$`)
	idRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,99}$`)
	dateRe  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

const keyIn = `{"type":"object","properties":{"key":{"type":"string","description":"The key's id from keys (a 64-character hash), never the key itself"},"alias":{"type":"string","description":"Or the key's alias"}}}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "litellm", Name: "LiteLLM", Version: "0.1.0", Category: "Development", Icon: "layers",
		Description: "A LiteLLM proxy: models it routes to, spend by model, key, team and provider, virtual keys (masked), budgets, deployment health, block and unblock a key.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","masterKey"],"properties":{
			"url":{"type":"string","default":"http://127.0.0.1:4000","description":"The proxy's address"},
			"masterKey":{"type":"string","x-secret":true,"description":"The proxy's master key (LITELLM_MASTER_KEY), or an admin key"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "models", Title: "Models", Description: "The model names the proxy offers, each with the provider model behind it, mode, context size and price per million tokens. Never provider keys.", Risk: sdk.RiskRead},
			{Name: "spend", Title: "Spend", Description: "Spend, requests and tokens today, this month or between two dates, broken down by model, key, team or provider. Needs the proxy's database.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"period":{"type":"string","enum":["today","month","custom"],"default":"today"},"start":{"type":"string","description":"YYYY-MM-DD, with period custom"},"end":{"type":"string","description":"YYYY-MM-DD, with period custom"},"by":{"type":"string","enum":["model","key","team","provider"],"default":"model"}}}`)},
			{Name: "keys", Title: "Virtual keys", Description: "Virtual keys with id, masked key, alias, team, spend, budget, expiry and whether they're blocked. Never the key values.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"team":{"type":"string","description":"Only keys of this team id"},"search":{"type":"string","description":"Only aliases containing this"}}}`)},
			{Name: "budgets", Title: "Budgets", Description: "Budgets defined on the proxy, and every team's spend against its budget, with how much is used.", Risk: sdk.RiskRead},
			{Name: "deployment_health", Title: "Check a model's deployments", Description: "Runs LiteLLM's health check for one model (a name from models), which sends a tiny request to its deployment, and says whether it's healthy and why not. Write: each check is a real call that a paid provider bills (a few tokens) and counts against rate limits, so it's one model per call and at most 10 checks a minute.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["model"],"properties":{"model":{"type":"string","maxLength":200,"description":"A model name from models, e.g. gpt-4o"}}}`)},
			{Name: "block_key", Title: "Block a key", Description: "Blocks a virtual key: every request with it is refused until it's unblocked. Destructive: it cuts off whoever uses the key. Undo unblocks it.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(keyIn)},
			{Name: "unblock_key", Title: "Unblock a key", Description: "Unblocks a blocked virtual key so it can spend again. Destructive: it restores access (and spending) that someone cut off. Undo blocks it again.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(keyIn)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.URL == "" {
		c.URL = "http://127.0.0.1:4000"
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.URL), "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is like http://127.0.0.1:4000")
	}
	if !strings.HasPrefix(c.MasterKey, "secret://") {
		return errors.New("store the master key in the vault and enter its secret:// reference")
	}
	ref := c.MasterKey
	auth := func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(k))
		return nil
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api := rest.New(u.String(), auth)
	api.HTTP = rest.SameHostOnly(client)
	api.HTTP.Timeout = 30 * time.Second
	hc := rest.New(u.String(), auth)
	hc.HTTP = rest.SameHostOnly(client)
	hc.HTTP.Timeout = 2 * time.Minute
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, health: hc, host: u.Host, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("LiteLLM refused the master key (or it isn't an admin key)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var ready struct {
		Status  string `json:"status"`
		DB      string `json:"db"`
		Version string `json:"litellm_version"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/health/readiness", nil, nil, &ready); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/key/list", url.Values{"page": {"1"}, "size": {"1"}}, nil, nil); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "key list").Error()}
	}
	msg := "LiteLLM"
	if ready.Version != "" {
		msg += " " + ready.Version
	}
	if ready.DB != "" && ready.DB != "connected" {
		return sdk.Health{Status: "degraded", Message: msg + ", database " + ready.DB + " (keys and spend need it)"}
	}
	return sdk.Health{Status: "ok", Message: msg + " at " + c.host}
}

type key struct {
	Token          string   `json:"token"`
	KeyName        string   `json:"key_name"`
	KeyAlias       *string  `json:"key_alias"`
	Spend          float64  `json:"spend"`
	MaxBudget      *float64 `json:"max_budget"`
	BudgetDuration *string  `json:"budget_duration"`
	BudgetResetAt  *string  `json:"budget_reset_at"`
	Expires        *string  `json:"expires"`
	Blocked        *bool    `json:"blocked"`
	TeamID         *string  `json:"team_id"`
	UserID         *string  `json:"user_id"`
	Models         []string `json:"models"`
	CreatedAt      *string  `json:"created_at"`
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// masked shows LiteLLM's masked form (sk-...abcd) and nothing longer.
func masked(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.Index(name, "..."); i >= 0 && len(name)-i-3 <= 6 && i <= 8 {
		return name
	}
	return ""
}

func (k key) summary() map[string]any {
	out := map[string]any{"id": k.Token, "masked": masked(k.KeyName), "alias": str(k.KeyAlias), "spend": k.Spend,
		"blocked": k.Blocked != nil && *k.Blocked, "models": k.Models}
	if k.Models == nil {
		out["models"] = []string{}
	}
	for name, v := range map[string]*string{"team": k.TeamID, "user": k.UserID, "expires": k.Expires, "budgetDuration": k.BudgetDuration, "budgetResetAt": k.BudgetResetAt, "created": k.CreatedAt} {
		if v != nil && *v != "" {
			out[name] = *v
		}
	}
	if k.MaxBudget != nil {
		out["maxBudget"] = *k.MaxBudget
		if *k.MaxBudget > 0 {
			out["percentUsed"] = int(k.Spend * 100 / *k.MaxBudget)
		}
	}
	return out
}

func (c *conn) keys(ctx context.Context, team string) ([]key, error) {
	var all []key
	for page := 1; page <= 20; page++ {
		q := url.Values{"page": {strconv.Itoa(page)}, "size": {"100"}, "return_full_object": {"true"}}
		if team != "" {
			q.Set("team_id", team)
		}
		var out struct {
			Keys       []key `json:"keys"`
			TotalPages int   `json:"total_pages"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/key/list", q, nil, &out); err != nil {
			return nil, friendly(err, "key list")
		}
		all = append(all, out.Keys...)
		if page >= out.TotalPages || len(out.Keys) == 0 {
			break
		}
	}
	return all, nil
}

// resolve finds the key named by id or alias. Full key values are refused
// so they never land in an approval or the audit log.
func (c *conn) resolve(ctx context.Context, id, alias string) (key, error) {
	id, alias = strings.TrimSpace(id), strings.TrimSpace(alias)
	switch {
	case strings.HasPrefix(id, "sk-") || strings.HasPrefix(alias, "sk-"):
		return key{}, errors.New("give the key's id or alias from keys, never the key itself")
	case id != "" && !hashRe.MatchString(id):
		return key{}, errors.New("the key id is the 64-character hash from keys")
	case id == "" && !aliasRe.MatchString(alias):
		return key{}, errors.New("give a key id or alias from keys")
	}
	if id != "" {
		var out struct {
			Key  string `json:"key"`
			Info key    `json:"info"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/key/info", url.Values{"key": {id}}, nil, &out); err != nil {
			return key{}, friendly(err, "key with that id")
		}
		out.Info.Token = id
		return out.Info, nil
	}
	keys, err := c.keys(ctx, "")
	if err != nil {
		return key{}, err
	}
	var found []key
	for _, k := range keys {
		if str(k.KeyAlias) == alias {
			found = append(found, k)
		}
	}
	switch len(found) {
	case 0:
		return key{}, errors.New("there's no key with that alias")
	case 1:
		if !hashRe.MatchString(found[0].Token) {
			return key{}, errors.New("LiteLLM didn't give that key's id")
		}
		return found[0], nil
	}
	return key{}, fmt.Errorf("%d keys have that alias; give the id instead", len(found))
}

type metrics struct {
	Spend            float64 `json:"spend"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	Requests         int64   `json:"api_requests"`
	Successful       int64   `json:"successful_requests"`
	Failed           int64   `json:"failed_requests"`
}

type entry struct {
	Metrics  metrics        `json:"metrics"`
	Metadata map[string]any `json:"metadata"`
}

type row struct {
	Name     string  `json:"name"`
	Alias    string  `json:"alias,omitempty"`
	Spend    float64 `json:"spend"`
	Requests int64   `json:"requests"`
	Failed   int64   `json:"failed,omitempty"`
	Tokens   int64   `json:"tokens"`
}

func (c *conn) spend(ctx context.Context, start, end, by string) (map[string]any, error) {
	path := "/user/daily/activity"
	group := map[string]string{"model": "models", "key": "api_keys", "provider": "providers", "team": "entities"}[by]
	if by == "team" {
		path = "/team/daily/activity"
	}
	rows := map[string]*row{}
	var total row
	for page := 1; page <= 20; page++ {
		q := url.Values{"start_date": {start}, "end_date": {end}, "page": {strconv.Itoa(page)}, "page_size": {"100"}}
		var out struct {
			Results []struct {
				Date      string                      `json:"date"`
				Metrics   metrics                     `json:"metrics"`
				Breakdown map[string]map[string]entry `json:"breakdown"`
			} `json:"results"`
			Metadata struct {
				HasMore bool `json:"has_more"`
			} `json:"metadata"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &out); err != nil {
			return nil, friendly(err, "spend report (this needs the proxy's database)")
		}
		for _, d := range out.Results {
			total.Spend += d.Metrics.Spend
			total.Requests += d.Metrics.Requests
			total.Failed += d.Metrics.Failed
			total.Tokens += d.Metrics.TotalTokens
			for name, e := range d.Breakdown[group] {
				r := rows[name]
				if r == nil {
					r = &row{Name: name}
					rows[name] = r
				}
				for _, f := range []string{"key_alias", "team_alias"} {
					if s, ok := e.Metadata[f].(string); ok && s != "" {
						r.Alias = s
					}
				}
				r.Spend += e.Metrics.Spend
				r.Requests += e.Metrics.Requests
				r.Failed += e.Metrics.Failed
				r.Tokens += e.Metrics.TotalTokens
			}
		}
		if !out.Metadata.HasMore {
			break
		}
	}
	list := []row{}
	for _, r := range rows {
		list = append(list, *r)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Spend != list[j].Spend {
			return list[i].Spend > list[j].Spend
		}
		return list[i].Name < list[j].Name
	})
	return map[string]any{"start": start, "end": end, "by": by, "currency": "USD", "spend": total.Spend, "requests": total.Requests,
		"failed": total.Failed, "tokens": total.Tokens, "breakdown": list}, nil
}

func validDate(s string) bool {
	if !dateRe.MatchString(s) {
		return false
	}
	_, err := time.Parse("2006-01-02", s)
	return err == nil
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
	var p struct {
		Period string `json:"period"`
		Start  string `json:"start"`
		End    string `json:"end"`
		By     string `json:"by"`
		Team   string `json:"team"`
		Search string `json:"search"`
		Key    string `json:"key"`
		Alias  string `json:"alias"`
		Model  string `json:"model"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "models":
		var out struct {
			Data []struct {
				ModelName     string `json:"model_name"`
				LiteLLMParams struct {
					Model   string `json:"model"`
					APIBase string `json:"api_base"`
				} `json:"litellm_params"`
				ModelInfo struct {
					ID               string   `json:"id"`
					Provider         string   `json:"litellm_provider"`
					Mode             string   `json:"mode"`
					MaxInputTokens   *int64   `json:"max_input_tokens"`
					MaxOutputTokens  *int64   `json:"max_output_tokens"`
					InputCostPerTok  *float64 `json:"input_cost_per_token"`
					OutputCostPerTok *float64 `json:"output_cost_per_token"`
				} `json:"model_info"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/model/info", nil, nil, &out); err != nil {
			return sdk.Result{}, friendly(err, "model list")
		}
		list := []map[string]any{}
		for _, x := range out.Data {
			r := map[string]any{"name": x.ModelName, "deploymentId": x.ModelInfo.ID, "model": x.LiteLLMParams.Model, "provider": x.ModelInfo.Provider, "mode": x.ModelInfo.Mode}
			if x.LiteLLMParams.APIBase != "" {
				r["apiBase"] = rest.ShortURL(x.LiteLLMParams.APIBase)
			}
			if x.ModelInfo.MaxInputTokens != nil {
				r["maxInputTokens"] = *x.ModelInfo.MaxInputTokens
			}
			if x.ModelInfo.MaxOutputTokens != nil {
				r["maxOutputTokens"] = *x.ModelInfo.MaxOutputTokens
			}
			if x.ModelInfo.InputCostPerTok != nil {
				r["inputPerMillion"] = *x.ModelInfo.InputCostPerTok * 1e6
			}
			if x.ModelInfo.OutputCostPerTok != nil {
				r["outputPerMillion"] = *x.ModelInfo.OutputCostPerTok * 1e6
			}
			list = append(list, r)
		}
		return sdk.JSON(list)
	case "spend":
		today := c.now().UTC()
		var start, end string
		switch p.Period {
		case "", "today":
			start, end = today.Format("2006-01-02"), today.Format("2006-01-02")
		case "month":
			start, end = time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02"), today.Format("2006-01-02")
		case "custom":
			if !validDate(p.Start) || !validDate(p.End) || p.Start > p.End {
				return sdk.Result{}, errors.New("a custom period needs start and end as YYYY-MM-DD, start first")
			}
			start, end = p.Start, p.End
		default:
			return sdk.Result{}, errors.New("the period is today, month or custom")
		}
		if p.By == "" {
			p.By = "model"
		}
		if p.By != "model" && p.By != "key" && p.By != "team" && p.By != "provider" {
			return sdk.Result{}, errors.New("break spend down by model, key, team or provider")
		}
		out, err := c.spend(ctx, start, end, p.By)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(out)
	case "keys":
		if p.Team != "" && !idRe.MatchString(p.Team) {
			return sdk.Result{}, errors.New("the team is a team id from budgets")
		}
		if len(p.Search) > 100 {
			return sdk.Result{}, errors.New("search is at most 100 characters")
		}
		keys, err := c.keys(ctx, p.Team)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		q := strings.ToLower(p.Search)
		for _, k := range keys {
			if q != "" && !strings.Contains(strings.ToLower(str(k.KeyAlias)), q) {
				continue
			}
			list = append(list, k.summary())
		}
		return sdk.JSON(list)
	case "budgets":
		var budgets []struct {
			ID             string   `json:"budget_id"`
			MaxBudget      *float64 `json:"max_budget"`
			SoftBudget     *float64 `json:"soft_budget"`
			TPM            *int64   `json:"tpm_limit"`
			RPM            *int64   `json:"rpm_limit"`
			BudgetDuration *string  `json:"budget_duration"`
			BudgetResetAt  *string  `json:"budget_reset_at"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/budget/list", nil, nil, &budgets); err != nil {
			return sdk.Result{}, friendly(err, "budget list")
		}
		var teams []struct {
			ID             string   `json:"team_id"`
			Alias          *string  `json:"team_alias"`
			Spend          float64  `json:"spend"`
			MaxBudget      *float64 `json:"max_budget"`
			BudgetDuration *string  `json:"budget_duration"`
			BudgetResetAt  *string  `json:"budget_reset_at"`
			Blocked        bool     `json:"blocked"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/team/list", nil, nil, &teams); err != nil {
			return sdk.Result{}, friendly(err, "team list")
		}
		bl := []map[string]any{}
		for _, b := range budgets {
			r := map[string]any{"id": b.ID, "maxBudget": b.MaxBudget, "softBudget": b.SoftBudget, "tpmLimit": b.TPM, "rpmLimit": b.RPM,
				"duration": str(b.BudgetDuration), "resetsAt": str(b.BudgetResetAt)}
			bl = append(bl, r)
		}
		tl := []map[string]any{}
		for _, t := range teams {
			r := map[string]any{"id": t.ID, "alias": str(t.Alias), "spend": t.Spend, "maxBudget": t.MaxBudget, "duration": str(t.BudgetDuration),
				"resetsAt": str(t.BudgetResetAt), "blocked": t.Blocked}
			if t.MaxBudget != nil && *t.MaxBudget > 0 {
				r["percentUsed"] = int(t.Spend * 100 / *t.MaxBudget)
			}
			tl = append(tl, r)
		}
		return sdk.JSON(map[string]any{"currency": "USD", "budgets": bl, "teams": tl})
	case "deployment_health":
		model := strings.TrimSpace(p.Model)
		if model == "" || len(model) > 200 || strings.ContainsAny(model, "\x00\r\n\t") {
			return sdk.Result{}, errors.New("give one model, a name from models (checking every deployment at once isn't offered: each check is billed)")
		}
		var known struct {
			Data []struct {
				ModelName string `json:"model_name"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/model/info", nil, nil, &known); err != nil {
			return sdk.Result{}, friendly(err, "model list")
		}
		deployments := 0
		for _, x := range known.Data {
			if x.ModelName == model {
				deployments++
			}
		}
		if deployments == 0 {
			return sdk.Result{}, fmt.Errorf("the proxy has no model %q; see models for the names", clip(model, 80))
		}
		if err := c.allowCheck(); err != nil {
			return sdk.Result{}, err
		}
		var out struct {
			Healthy   []map[string]any `json:"healthy_endpoints"`
			Unhealthy []map[string]any `json:"unhealthy_endpoints"`
		}
		if _, err := c.health.Do(ctx, http.MethodGet, "/health", url.Values{"model": {model}}, nil, &out); err != nil {
			return sdk.Result{}, friendly(err, "health check")
		}
		// Only the fields below are passed on: LiteLLM echoes each
		// deployment's parameters, which can include provider keys.
		pick := func(e map[string]any, withErr bool) map[string]any {
			r := map[string]any{}
			if s, ok := e["model"].(string); ok {
				r["model"] = s
			}
			if s, ok := e["api_base"].(string); ok && s != "" {
				r["apiBase"] = rest.ShortURL(s)
			}
			if withErr {
				if s, ok := e["error"].(string); ok {
					// The first line says what failed; the rest is a stack trace.
					s, _, _ = strings.Cut(s, "\n")
					r["error"] = rest.Redact(clip(s, 300))
				}
			}
			return r
		}
		h, u := []map[string]any{}, []map[string]any{}
		for _, e := range out.Healthy {
			h = append(h, pick(e, false))
		}
		for _, e := range out.Unhealthy {
			u = append(u, pick(e, true))
		}
		return sdk.JSON(map[string]any{"model": model, "healthy": h, "unhealthy": u, "healthyCount": len(h), "unhealthyCount": len(u)})
	case "block_key", "unblock_key":
		block := call.Action == "block_key"
		k, err := c.resolve(ctx, p.Key, p.Alias)
		if err != nil {
			return sdk.Result{}, err
		}
		verb, undo := "Block", "unblock_key"
		if !block {
			verb, undo = "Unblock", "block_key"
		}
		name := str(k.KeyAlias)
		if name == "" {
			name = masked(k.KeyName)
		}
		if name == "" {
			name = k.Token[:8] + "…"
		}
		was := k.Blocked != nil && *k.Blocked
		if call.DryRun {
			before, _ := json.Marshal(map[string]any{"blocked": was, "spend": k.Spend, "team": str(k.TeamID)})
			after, _ := json.Marshal(map[string]any{"blocked": block})
			summary := verb + " the key " + name
			if was == block {
				summary = "Nothing to do: the key " + name + " is already " + map[bool]string{true: "blocked", false: "unblocked"}[block]
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "key " + name, Op: strings.ToLower(verb), Before: before, After: after}}}}, nil
		}
		if was == block {
			// No undo: undoing would change a state this call didn't set.
			return sdk.JSON(map[string]any{"key": k.Token, "name": name, "blocked": block, "unchanged": true})
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/key/"+strings.ToLower(verb), nil, map[string]string{"key": k.Token}, nil); err != nil {
			return sdk.Result{}, friendly(err, "key with that id")
		}
		res, err := sdk.JSON(map[string]any{"key": k.Token, "name": name, "blocked": block})
		if err != nil {
			return res, err
		}
		in, _ := json.Marshal(map[string]string{"key": k.Token})
		desc := "Unblock the key " + name
		if !block {
			desc = "Block the key " + name + " again"
		}
		res.Undo = &sdk.Undo{Action: undo, Input: in, Description: desc}
		return res, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
