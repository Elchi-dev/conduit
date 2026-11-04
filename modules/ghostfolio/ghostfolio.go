// Package ghostfolio reads a Ghostfolio wealth tracker (Ghostfolio Premium
// in the cloud, or a self-hosted server) through its API: accounts and
// balances, the portfolio summary, performance over a range, and holdings.
//
// Ghostfolio signs in with the user's security token, which it exchanges
// for a short-lived session token (a JWT). Everything here is read-only and
// financial, so every action is sensitive.
package ghostfolio

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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Ghostfolio user.
type Config struct {
	URL                string `json:"url"`   // default https://ghostfol.io; self-hosted: the server's address
	Token              string `json:"token"` // secret:// security token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

const defaultBase = "https://ghostfol.io"

type conn struct {
	h    sdk.Host
	ref  string
	api  *rest.Client
	auth *rest.Client

	mu  sync.Mutex
	jwt string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://ghostfol.io when no address is set (tests).
	Base string
}

// New returns the Ghostfolio module.
func New() *Module { return &Module{} }

var (
	pathRe  = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	yearRe  = regexp.MustCompile(`^(19|20)\d{2}$`)
	ranges  = map[string]bool{"1d": true, "wtd": true, "mtd": true, "ytd": true, "1y": true, "5y": true, "max": true}
	maxText = 100
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	rng := `"range":{"type":"string","default":"max","description":"1d, wtd, mtd, ytd, 1y, 5y, max, or a year like 2025"}`
	return sdk.Manifest{
		ID: "ghostfolio", Name: "Ghostfolio", Version: "0.1.0", Category: "Productivity", Icon: "chart",
		Description: "Your Ghostfolio portfolio: accounts and balances, the summary, performance over a range, and holdings. Read-only; financial data is kept out of logs.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"url":{"type":"string","default":"https://ghostfol.io","description":"Ghostfolio in the cloud, or your server's address, e.g. https://ghostfolio.example.com"},
			"token":{"type":"string","x-secret":true,"description":"Your security token (shown when the account was created; a new one under My Ghostfolio, Access). It signs in as you"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "accounts", Title: "Accounts", Description: "Accounts with their platform, currency, cash balance and value, and the totals in your base currency. Financial data, kept out of logs.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "summary", Title: "Portfolio summary", Description: "Current value, investment, net performance, dividends, fees, cash and net worth. Financial data, kept out of logs.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "performance", Title: "Performance", Description: "Net performance (amount and percent, with and without currency effects), investment and value over a range. Financial data, kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + rng + `}}`)},
			{Name: "holdings", Title: "Holdings", Description: "Holdings by value: symbol, name, asset class, quantity, price, value, allocation and performance. Financial data, kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string","description":"Only holdings whose symbol or name contains this"},"limit":{"type":"integer","minimum":1,"maximum":500,"default":50}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = defaultBase
		if m.Base != "" {
			c.URL = m.Base
		}
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://ghostfolio.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the security token in the vault and enter its secret:// reference")
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
	client = rest.SameHostOnly(client)
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	cn := &conn{h: h, ref: c.Token}
	cn.auth = rest.New(base+"/api", nil)
	cn.auth.HTTP = client
	cn.api = rest.New(base+"/api", func(ctx context.Context, r *http.Request) error {
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

var errRefused = errors.New("Ghostfolio refused the security token")

// session returns the session token, exchanging the security token for a
// new one when there's none.
func (c *conn) session(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jwt != "" {
		return c.jwt, nil
	}
	tok, err := c.h.Secret(ctx, c.ref)
	if err != nil {
		return "", err
	}
	var out struct {
		AuthToken string `json:"authToken"`
	}
	if _, err := c.auth.Do(ctx, http.MethodPost, "/v1/auth/anonymous", nil, map[string]string{"accessToken": strings.TrimSpace(tok)}, &out); err != nil {
		switch {
		case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
			return "", errRefused
		case rest.IsStatus(err, http.StatusNotFound):
			return "", errors.New("no Ghostfolio API at this address")
		}
		return "", err
	}
	if out.AuthToken == "" {
		return "", errors.New("Ghostfolio answered without a session token")
	}
	c.jwt = out.AuthToken
	return c.jwt, nil
}

func (c *conn) forget() {
	c.mu.Lock()
	c.jwt = ""
	c.mu.Unlock()
}

// get reads a path, signing in again once if the session expired.
func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	for try := 0; ; try++ {
		_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
		if err == nil {
			return nil
		}
		if errors.Is(err, errRefused) {
			return err
		}
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			c.forget()
			if try == 0 {
				continue
			}
			return errors.New("Ghostfolio refused the session; check the security token")
		}
		return err
	}
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u struct {
		Settings struct {
			BaseCurrency string `json:"baseCurrency"`
		} `json:"settings"`
	}
	if err := c.get(ctx, "/v1/user", nil, &u); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Ghostfolio API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in"
	if u.Settings.BaseCurrency != "" {
		msg += " · base currency " + u.Settings.BaseCurrency
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// num keeps a number as the server wrote it: money is never a float here.
type num = json.Number

func rat(n num) *big.Rat {
	r, ok := new(big.Rat).SetString(string(n))
	if !ok {
		return new(big.Rat)
	}
	return r
}

// keep copies the listed fields of a JSON object that are numbers or
// strings, so nothing else the server adds ends up in the output.
func keep(raw map[string]json.RawMessage, fields ...string) map[string]any {
	out := map[string]any{}
	for _, f := range fields {
		v, ok := raw[f]
		if !ok {
			continue
		}
		var n json.Number
		var s string
		var b bool
		switch {
		case json.Unmarshal(v, &n) == nil:
			out[f] = n
		case json.Unmarshal(v, &s) == nil:
			out[f] = s
		case json.Unmarshal(v, &b) == nil:
			out[f] = b
		}
	}
	return out
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Range string `json:"range"`
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "accounts":
		return c.accounts(ctx)
	case "summary":
		var d struct {
			Summary map[string]json.RawMessage `json:"summary"`
			HasErr  bool                       `json:"hasError"`
		}
		if err := c.get(ctx, "/v1/portfolio/details", nil, &d); err != nil {
			return sdk.Result{}, err
		}
		out := keep(d.Summary, "currentValueInBaseCurrency", "totalValueInBaseCurrency", "totalInvestment", "netPerformance", "netPerformancePercentage",
			"netPerformanceWithCurrencyEffect", "netPerformancePercentageWithCurrencyEffect", "annualizedPerformancePercent", "dividendInBaseCurrency",
			"interest", "fees", "cash", "liabilities", "netWorth", "totalBuy", "totalSell", "activityCount", "dateOfFirstActivity")
		if d.HasErr {
			out["note"] = "Ghostfolio couldn't price every holding; some figures may be incomplete"
		}
		return sdk.JSON(out)
	case "performance":
		r := strings.TrimSpace(p.Range)
		if r == "" {
			r = "max"
		}
		if !ranges[r] && !yearRe.MatchString(r) {
			return sdk.Result{}, errors.New("range is 1d, wtd, mtd, ytd, 1y, 5y, max or a year like 2025")
		}
		var d struct {
			Performance    map[string]json.RawMessage `json:"performance"`
			FirstOrderDate string                     `json:"firstOrderDate"`
			HasErrors      bool                       `json:"hasErrors"`
		}
		if err := c.get(ctx, "/v2/portfolio/performance", url.Values{"range": {r}}, &d); err != nil {
			return sdk.Result{}, err
		}
		out := keep(d.Performance, "currentValueInBaseCurrency", "currentNetWorth", "totalInvestment", "netPerformance", "netPerformancePercentage",
			"netPerformanceWithCurrencyEffect", "netPerformancePercentageWithCurrencyEffect")
		out["range"] = r
		if d.FirstOrderDate != "" {
			out["firstActivity"] = d.FirstOrderDate
		}
		if d.HasErrors {
			out["note"] = "Ghostfolio couldn't price every holding; some figures may be incomplete"
		}
		return sdk.JSON(out)
	case "holdings":
		q := strings.TrimSpace(p.Query)
		if len([]rune(q)) > maxText {
			return sdk.Result{}, fmt.Errorf("the query is at most %d characters", maxText)
		}
		n := p.Limit
		if n < 0 || n > 500 {
			return sdk.Result{}, errors.New("limit is 1 to 500")
		}
		if n == 0 {
			n = 50
		}
		return c.holdings(ctx, strings.ToLower(q), n)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) accounts(ctx context.Context) (sdk.Result, error) {
	var d struct {
		Accounts []struct {
			ID                    string `json:"id"`
			Name                  string `json:"name"`
			Currency              string `json:"currency"`
			Balance               num    `json:"balance"`
			BalanceInBaseCurrency num    `json:"balanceInBaseCurrency"`
			Value                 num    `json:"value"`
			ValueInBaseCurrency   num    `json:"valueInBaseCurrency"`
			IsExcluded            bool   `json:"isExcluded"`
			TransactionCount      int    `json:"transactionCount"`
			Platform              *struct {
				Name string `json:"name"`
			} `json:"platform"`
			// Comments aren't decoded: they're free text the user wrote.
		} `json:"accounts"`
		TotalBalance num `json:"totalBalanceInBaseCurrency"`
		TotalValue   num `json:"totalValueInBaseCurrency"`
	}
	if err := c.get(ctx, "/v1/account", nil, &d); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, a := range d.Accounts {
		row := map[string]any{"id": a.ID, "name": a.Name, "currency": a.Currency, "activities": a.TransactionCount}
		for k, v := range map[string]num{"balance": a.Balance, "balanceInBaseCurrency": a.BalanceInBaseCurrency, "value": a.Value, "valueInBaseCurrency": a.ValueInBaseCurrency} {
			if v != "" {
				row[k] = v
			}
		}
		if a.Platform != nil && a.Platform.Name != "" {
			row["platform"] = a.Platform.Name
		}
		if a.IsExcluded {
			row["excluded"] = true
		}
		out = append(out, row)
	}
	res := map[string]any{"accounts": out}
	if d.TotalBalance != "" {
		res["totalBalanceInBaseCurrency"] = d.TotalBalance
	}
	if d.TotalValue != "" {
		res["totalValueInBaseCurrency"] = d.TotalValue
	}
	return sdk.JSON(res)
}

type holding struct {
	Symbol                 string `json:"symbol"`
	Name                   string `json:"name"`
	Currency               string `json:"currency"`
	AssetClass             string `json:"assetClass"`
	AssetSubClass          string `json:"assetSubClass"`
	DataSource             string `json:"dataSource"`
	Quantity               num    `json:"quantity"`
	MarketPrice            num    `json:"marketPrice"`
	Investment             num    `json:"investment"`
	ValueInBaseCurrency    num    `json:"valueInBaseCurrency"`
	Allocation             num    `json:"allocationInPercentage"`
	NetPerformance         num    `json:"netPerformance"`
	NetPerformancePercent  num    `json:"netPerformancePercent"`
	NetPerformancePercentC num    `json:"netPerformancePercentWithCurrencyEffect"`
	DividendInBaseCurrency num    `json:"dividend"`
}

// holdings reads /portfolio/holdings, or the holdings of /portfolio/details
// on servers older than that endpoint (where they're a map by symbol).
func (c *conn) holdings(ctx context.Context, q string, n int) (sdk.Result, error) {
	var hs []holding
	var d struct {
		Holdings []holding `json:"holdings"`
	}
	err := c.get(ctx, "/v1/portfolio/holdings", nil, &d)
	switch {
	case err == nil:
		hs = d.Holdings
	case rest.IsStatus(err, http.StatusNotFound):
		var old struct {
			Holdings json.RawMessage `json:"holdings"`
		}
		if err := c.get(ctx, "/v1/portfolio/details", nil, &old); err != nil {
			return sdk.Result{}, err
		}
		var byKey map[string]holding
		if json.Unmarshal(old.Holdings, &hs) != nil {
			if err := json.Unmarshal(old.Holdings, &byKey); err != nil {
				return sdk.Result{}, errors.New("unexpected holdings from Ghostfolio")
			}
			for _, h := range byKey {
				hs = append(hs, h)
			}
		}
	default:
		return sdk.Result{}, err
	}
	sort.SliceStable(hs, func(i, j int) bool {
		if x := rat(hs[i].ValueInBaseCurrency).Cmp(rat(hs[j].ValueInBaseCurrency)); x != 0 {
			return x > 0
		}
		return hs[i].Symbol < hs[j].Symbol
	})
	out := []map[string]any{}
	total := 0
	for _, h := range hs {
		if q != "" && !strings.Contains(strings.ToLower(h.Symbol), q) && !strings.Contains(strings.ToLower(h.Name), q) {
			continue
		}
		total++
		if len(out) >= n {
			continue
		}
		row := map[string]any{"symbol": h.Symbol, "name": h.Name, "currency": h.Currency}
		for k, v := range map[string]string{"assetClass": h.AssetClass, "assetSubClass": h.AssetSubClass, "dataSource": h.DataSource} {
			if v != "" {
				row[k] = v
			}
		}
		for k, v := range map[string]num{"quantity": h.Quantity, "marketPrice": h.MarketPrice, "investment": h.Investment, "valueInBaseCurrency": h.ValueInBaseCurrency,
			"allocation": h.Allocation, "netPerformance": h.NetPerformance, "netPerformancePercent": h.NetPerformancePercent,
			"netPerformancePercentWithCurrencyEffect": h.NetPerformancePercentC, "dividend": h.DividendInBaseCurrency} {
			if v != "" {
				row[k] = v
			}
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"total": total, "holdings": out})
}
