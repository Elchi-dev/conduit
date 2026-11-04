// Package firefly works with a Firefly III personal finance manager through
// its REST API and a personal access token: accounts and balances, recent
// transactions, this month's budgets and spending, bills due, and recording
// or deleting a transaction in the books.
//
// Firefly III is bookkeeping: nothing here moves real money. Recording a
// transaction changes your books only, so it's a write with an undo; reads
// of balances and transactions are sensitive.
package firefly

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
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Firefly III server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://money.example.com
	Token              string `json:"token"` // secret:// personal access token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string
	now    func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces the clock (tests).
	Now func() time.Time
}

// New returns the Firefly III module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	dateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	monthRe  = regexp.MustCompile(`^\d{4}-\d{2}$`)
	amountRe = regexp.MustCompile(`^\d{1,15}(\.\d{1,12})?$`)
	idRe     = regexp.MustCompile(`^[1-9]\d{0,18}$`)
	currRe   = regexp.MustCompile(`^[A-Z]{3}$`)
)

var accountTypes = map[string]bool{"asset": true, "expense": true, "revenue": true, "liability": true, "liabilities": true, "all": true}

const (
	maxText = 1000
	maxTags = 20
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}`
	return sdk.Manifest{
		ID: "firefly", Name: "Firefly III", Version: "0.1.0", Category: "Productivity", Icon: "credit-card",
		Description: "Your Firefly III books: balances, recent transactions, budgets and spending this month, bills due, and recording transactions. Never moves real money.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Firefly III's address, e.g. https://money.example.com"},
			"token":{"type":"string","x-secret":true,"description":"A personal access token (Options → Profile → OAuth → Personal access tokens). It has full access to your books"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "accounts", Title: "Accounts and balances", Description: "Accounts with their current balance (asset accounts by default). Financial data, kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"type":{"type":"string","enum":["asset","expense","revenue","liability","all"],"default":"asset"},"includeInactive":{"type":"boolean","default":false}}}`)},
			{Name: "transactions", Title: "Recent transactions", Description: "The newest transactions, optionally of one account or between dates. Financial data, kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"account":{"type":"integer","minimum":1,"description":"Account id (see accounts)"},"type":{"type":"string","enum":["withdrawal","deposit","transfer","all"],"default":"all"},"start":{"type":"string","format":"date"},"end":{"type":"string","format":"date"},` + limit + `}}`)},
			{Name: "budgets", Title: "Budgets and spending", Description: "This month's (or another month's) spending, income and what's left, and each budget's limit, spent and left. Financial data, kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"month":{"type":"string","description":"YYYY-MM, this month by default"}}}`)},
			{Name: "bills", Title: "Bills due", Description: "Active bills with the dates they're expected this month (or another), and whether they're paid. Financial data, kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"month":{"type":"string","description":"YYYY-MM, this month by default"}}}`)},
			{Name: "create_transaction", Title: "Record a transaction", Description: "Records a withdrawal, deposit or transfer in your books (it moves no real money). Firefly's rules run on it. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["type","amount","description","source","destination"],"properties":{
					"type":{"type":"string","enum":["withdrawal","deposit","transfer"]},
					"amount":{"type":"string","description":"Positive decimal, e.g. 12.50"},
					"description":{"type":"string"},
					"date":{"type":"string","description":"YYYY-MM-DD, today by default"},
					"source":{"type":"string","description":"Account id, or a name (a withdrawal's source is your asset account; a deposit's is a revenue account, created if new)"},
					"destination":{"type":"string","description":"Account id, or a name (a withdrawal's destination is an expense account, created if new)"},
					"currency":{"type":"string","description":"ISO code, the account's currency by default"},
					"category":{"type":"string"},"budget":{"type":"integer","minimum":1,"description":"Budget id"},
					"tags":{"type":"array","maxItems":20,"items":{"type":"string"}},"notes":{"type":"string"}}}`)},
			{Name: "delete_transaction", Title: "Delete a transaction", Description: "Deletes a transaction (all its splits) from your books. Firefly III can't bring it back. Its preview shows the transaction, so it's kept out of logs.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1,"description":"Transaction id (see transactions)"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://money.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the personal access token in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	ref := c.Token
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1"), "/api")
	api := rest.New(origin+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, origin: origin, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Firefly III refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Firefly III refused the request: %v", err)
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	// about/user needs the token; about alone doesn't on every version.
	if err := c.do(ctx, http.MethodGet, "/about/user", nil, nil, nil); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Firefly III API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var about struct {
		Data struct {
			Version    string `json:"version"`
			APIVersion string `json:"api_version"`
		} `json:"data"`
	}
	msg := "signed in"
	if c.do(ctx, http.MethodGet, "/about", nil, nil, &about) == nil && about.Data.Version != "" {
		msg += " · Firefly III " + about.Data.Version
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type resource[T any] struct {
	ID         string `json:"id"`
	Attributes T      `json:"attributes"`
}

type list[T any] struct {
	Data []resource[T] `json:"data"`
	Meta struct {
		Pagination struct {
			Total       int `json:"total"`
			TotalPages  int `json:"total_pages"`
			CurrentPage int `json:"current_page"`
		} `json:"pagination"`
	} `json:"meta"`
}

type account struct {
	Name           string  `json:"name"`
	Type           string  `json:"type"`
	Role           *string `json:"account_role"`
	Active         bool    `json:"active"`
	CurrentBalance string  `json:"current_balance"`
	BalanceDate    string  `json:"current_balance_date"`
	CurrencyCode   string  `json:"currency_code"`
	IncludeNetWrth bool    `json:"include_net_worth"`
}

type split struct {
	JournalID    string   `json:"transaction_journal_id"`
	Type         string   `json:"type"`
	Date         string   `json:"date"`
	Amount       string   `json:"amount"`
	CurrencyCode string   `json:"currency_code"`
	Description  string   `json:"description"`
	SourceID     string   `json:"source_id"`
	SourceName   string   `json:"source_name"`
	DestID       string   `json:"destination_id"`
	DestName     string   `json:"destination_name"`
	CategoryName *string  `json:"category_name"`
	BudgetName   *string  `json:"budget_name"`
	Tags         []string `json:"tags"`
}

type group struct {
	GroupTitle   *string `json:"group_title"`
	Transactions []split `json:"transactions"`
}

// all reads pages of a list (up to max items).
func all[T any](ctx context.Context, c *conn, path string, q url.Values, max int) ([]resource[T], error) {
	var out []resource[T]
	if q == nil {
		q = url.Values{}
	}
	for pg := 1; pg <= 20; pg++ {
		q.Set("page", strconv.Itoa(pg))
		q.Set("limit", "100")
		var l list[T]
		if err := c.do(ctx, http.MethodGet, path, q, nil, &l); err != nil {
			return nil, err
		}
		out = append(out, l.Data...)
		if len(out) >= max || len(l.Data) == 0 || pg >= l.Meta.Pagination.TotalPages {
			break
		}
	}
	if len(out) > max {
		out = out[:max]
	}
	return out, nil
}

func (c *conn) month(s string) (time.Time, time.Time, error) {
	now := c.now()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	if s != "" {
		if !monthRe.MatchString(s) {
			return time.Time{}, time.Time{}, errors.New("month is YYYY-MM")
		}
		t, err := time.Parse("2006-01", s)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("%q isn't a month", s)
		}
		start = t
	}
	return start, start.AddDate(0, 1, -1), nil
}

func day(t time.Time) string { return t.Format("2006-01-02") }

func checkDate(s string) error {
	if s == "" {
		return nil
	}
	if !dateRe.MatchString(s) {
		return fmt.Errorf("%q isn't a date like 2026-11-04", s)
	}
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return fmt.Errorf("%q isn't a date", s)
	}
	return nil
}

func (c *conn) link(kind, id string) string { return c.origin + "/" + kind + "/show/" + id }

func ptr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (c *conn) txSummary(r resource[group]) map[string]any {
	out := map[string]any{"id": r.ID, "url": c.link("transactions", r.ID)}
	if len(r.Attributes.Transactions) == 0 {
		return out
	}
	s := r.Attributes.Transactions[0]
	out["type"], out["date"], out["currency"] = s.Type, s.Date, s.CurrencyCode
	out["description"], out["source"], out["destination"] = s.Description, s.SourceName, s.DestName
	if t := ptr(r.Attributes.GroupTitle); t != "" {
		out["description"] = t
	}
	if n := ptr(s.CategoryName); n != "" {
		out["category"] = n
	}
	if n := ptr(s.BudgetName); n != "" {
		out["budget"] = n
	}
	if len(s.Tags) > 0 {
		out["tags"] = s.Tags
	}
	total := new(big.Rat)
	for _, x := range r.Attributes.Transactions {
		if v, ok := new(big.Rat).SetString(x.Amount); ok {
			total.Add(total, v)
		}
	}
	out["amount"] = total.FloatString(2)
	if len(r.Attributes.Transactions) > 1 {
		out["splits"] = len(r.Attributes.Transactions)
	}
	return out
}

func sum(vals ...string) *big.Rat {
	t := new(big.Rat)
	for _, v := range vals {
		if r, ok := new(big.Rat).SetString(v); ok {
			t.Add(t, r)
		}
	}
	return t
}

type input struct {
	Type            string   `json:"type"`
	IncludeInactive bool     `json:"includeInactive"`
	Account         int      `json:"account"`
	Start           string   `json:"start"`
	End             string   `json:"end"`
	Limit           int      `json:"limit"`
	Month           string   `json:"month"`
	ID              int      `json:"id"`
	Amount          string   `json:"amount"`
	Description     string   `json:"description"`
	Date            string   `json:"date"`
	Source          string   `json:"source"`
	Destination     string   `json:"destination"`
	Currency        string   `json:"currency"`
	Category        string   `json:"category"`
	Budget          int      `json:"budget"`
	Tags            []string `json:"tags"`
	Notes           string   `json:"notes"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
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
	case "accounts":
		t := p.Type
		if t == "" {
			t = "asset"
		}
		if !accountTypes[t] {
			return sdk.Result{}, errors.New("type is asset, expense, revenue, liability or all")
		}
		if t == "liability" {
			t = "liabilities"
		}
		accts, err := all[account](ctx, c, "/accounts", url.Values{"type": {t}, "date": {day(c.now())}}, 500)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		totals := map[string]*big.Rat{}
		for _, a := range accts {
			if !a.Attributes.Active && !p.IncludeInactive {
				continue
			}
			r := map[string]any{"id": a.ID, "name": a.Attributes.Name, "type": a.Attributes.Type, "balance": a.Attributes.CurrentBalance, "currency": a.Attributes.CurrencyCode, "url": c.link("accounts", a.ID)}
			if role := ptr(a.Attributes.Role); role != "" {
				r["role"] = role
			}
			if !a.Attributes.Active {
				r["inactive"] = true
			}
			out = append(out, r)
			if a.Attributes.Type == "asset" && a.Attributes.Active {
				if totals[a.Attributes.CurrencyCode] == nil {
					totals[a.Attributes.CurrencyCode] = new(big.Rat)
				}
				totals[a.Attributes.CurrencyCode].Add(totals[a.Attributes.CurrencyCode], sum(a.Attributes.CurrentBalance))
			}
		}
		res := map[string]any{"accounts": out}
		if len(totals) > 0 {
			tt := map[string]string{}
			for k, v := range totals {
				tt[k] = v.FloatString(2)
			}
			res["assetTotals"] = tt
		}
		return sdk.JSON(res)

	case "transactions":
		if err := checkDate(p.Start); err != nil {
			return sdk.Result{}, err
		}
		if err := checkDate(p.End); err != nil {
			return sdk.Result{}, err
		}
		if p.Account < 0 {
			return sdk.Result{}, errors.New("the account is an account id (see accounts)")
		}
		q := url.Values{}
		switch p.Type {
		case "", "all":
		case "withdrawal", "deposit", "transfer":
			q.Set("type", p.Type)
		default:
			return sdk.Result{}, errors.New("type is withdrawal, deposit, transfer or all")
		}
		if p.Start != "" {
			q.Set("start", p.Start)
		}
		if p.End != "" {
			q.Set("end", p.End)
		}
		n := p.Limit
		if n <= 0 || n > 100 {
			n = 25
		}
		q.Set("limit", strconv.Itoa(n))
		q.Set("page", "1")
		path := "/transactions"
		if p.Account > 0 {
			path = "/accounts/" + strconv.Itoa(p.Account) + "/transactions"
		}
		var l list[group]
		if err := c.do(ctx, http.MethodGet, path, q, nil, &l); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) && p.Account > 0 {
				return sdk.Result{}, fmt.Errorf("there's no account %d", p.Account)
			}
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, r := range l.Data {
			out = append(out, c.txSummary(r))
		}
		return sdk.JSON(map[string]any{"total": l.Meta.Pagination.Total, "transactions": out})

	case "budgets":
		return c.budgets(ctx, p.Month)
	case "bills":
		return c.bills(ctx, p.Month)
	case "create_transaction":
		return c.create(ctx, call, p)

	case "delete_transaction":
		if p.ID <= 0 {
			return sdk.Result{}, errors.New("enter the transaction id")
		}
		var one struct {
			Data resource[group] `json:"data"`
		}
		if err := c.do(ctx, http.MethodGet, "/transactions/"+strconv.Itoa(p.ID), nil, nil, &one); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no transaction %d", p.ID)
			}
			return sdk.Result{}, err
		}
		s := c.txSummary(one.Data)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete transaction %d %q from your books", p.ID, s["description"]),
				Changes: []sdk.Change{{Target: fmt.Sprintf("transaction %d", p.ID), Op: "delete", Before: mustJSON(s)}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/transactions/"+strconv.Itoa(p.ID), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": p.ID})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) budgets(ctx context.Context, month string) (sdk.Result, error) {
	start, end, err := c.month(month)
	if err != nil {
		return sdk.Result{}, err
	}
	q := url.Values{"start": {day(start)}, "end": {day(end)}}
	type budget struct {
		Name   string `json:"name"`
		Active bool   `json:"active"`
		Spent  []struct {
			Sum          string `json:"sum"`
			CurrencyCode string `json:"currency_code"`
		} `json:"spent"`
	}
	bs, err := all[budget](ctx, c, "/budgets", url.Values{"start": {day(start)}, "end": {day(end)}}, 200)
	if err != nil {
		return sdk.Result{}, err
	}
	type limit struct {
		BudgetID     string `json:"budget_id"`
		Amount       string `json:"amount"`
		CurrencyCode string `json:"currency_code"`
	}
	limits := map[string][]limit{}
	if ls, err := all[limit](ctx, c, "/budget-limits", url.Values{"start": {day(start)}, "end": {day(end)}}, 1000); err == nil {
		for _, l := range ls {
			limits[l.Attributes.BudgetID] = append(limits[l.Attributes.BudgetID], l.Attributes)
		}
	}
	out := []map[string]any{}
	for _, b := range bs {
		if !b.Attributes.Active {
			continue
		}
		r := map[string]any{"id": b.ID, "name": b.Attributes.Name}
		spent := map[string]*big.Rat{}
		for _, s := range b.Attributes.Spent {
			if spent[s.CurrencyCode] == nil {
				spent[s.CurrencyCode] = new(big.Rat)
			}
			spent[s.CurrencyCode].Add(spent[s.CurrencyCode], sum(s.Sum))
		}
		var rows []map[string]any
		seen := map[string]bool{}
		for _, l := range limits[b.ID] {
			cur := l.CurrencyCode
			seen[cur] = true
			sp := spent[cur]
			if sp == nil {
				sp = new(big.Rat)
			}
			left := new(big.Rat).Add(sum(l.Amount), sp) // spent is negative
			rows = append(rows, map[string]any{"currency": cur, "limit": sum(l.Amount).FloatString(2), "spent": new(big.Rat).Neg(sp).FloatString(2), "left": left.FloatString(2)})
		}
		for cur, sp := range spent {
			if !seen[cur] {
				rows = append(rows, map[string]any{"currency": cur, "spent": new(big.Rat).Neg(sp).FloatString(2)})
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i]["currency"].(string) < rows[j]["currency"].(string) })
		if rows == nil {
			rows = []map[string]any{}
		}
		r["amounts"] = rows
		out = append(out, r)
	}
	res := map[string]any{"start": day(start), "end": day(end), "budgets": out}
	var basic map[string]struct {
		Key          string `json:"key"`
		Title        string `json:"title"`
		CurrencyCode string `json:"currency_code"`
		Value        any    `json:"monetary_value"`
		Parsed       string `json:"value_parsed"`
	}
	if err := c.do(ctx, http.MethodGet, "/summary/basic", q, nil, &basic); err == nil {
		summary := map[string]map[string]string{}
		for key, v := range basic {
			for _, k := range []string{"spent", "earned", "balance", "left-to-spend", "bills-unpaid", "bills-paid", "net-worth"} {
				if strings.HasPrefix(key, k+"-in-") {
					cur := strings.TrimPrefix(key, k+"-in-")
					if summary[cur] == nil {
						summary[cur] = map[string]string{}
					}
					summary[cur][k] = fmt.Sprint(v.Value)
				}
			}
		}
		res["summary"] = summary
	}
	return sdk.JSON(res)
}

func (c *conn) bills(ctx context.Context, month string) (sdk.Result, error) {
	start, end, err := c.month(month)
	if err != nil {
		return sdk.Result{}, err
	}
	type bill struct {
		Name         string   `json:"name"`
		Active       bool     `json:"active"`
		AmountMin    string   `json:"amount_min"`
		AmountMax    string   `json:"amount_max"`
		CurrencyCode string   `json:"currency_code"`
		RepeatFreq   string   `json:"repeat_freq"`
		NextExpected *string  `json:"next_expected_match"`
		PayDates     []string `json:"pay_dates"`
		PaidDates    []struct {
			Date    string `json:"date"`
			GroupID string `json:"transaction_group_id"`
		} `json:"paid_dates"`
	}
	bs, err := all[bill](ctx, c, "/bills", url.Values{"start": {day(start)}, "end": {day(end)}}, 500)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, b := range bs {
		a := b.Attributes
		if !a.Active {
			continue
		}
		due := []string{}
		for _, d := range a.PayDates {
			if len(d) >= 10 {
				d = d[:10]
			}
			due = append(due, d)
		}
		r := map[string]any{"id": b.ID, "name": a.Name, "currency": a.CurrencyCode, "repeats": a.RepeatFreq,
			"expected": due, "paid": len(a.PaidDates), "unpaid": len(a.PayDates) > len(a.PaidDates), "url": c.link("bills", b.ID)}
		if a.AmountMin == a.AmountMax {
			r["amount"] = a.AmountMin
		} else {
			r["amount"] = a.AmountMin + "–" + a.AmountMax
		}
		if n := ptr(a.NextExpected); n != "" {
			if len(n) >= 10 {
				n = n[:10]
			}
			r["nextExpected"] = n
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := out[i]["expected"].([]string)
		b, _ := out[j]["expected"].([]string)
		switch {
		case len(a) == 0:
			return false
		case len(b) == 0:
			return true
		}
		return a[0] < b[0]
	})
	return sdk.JSON(map[string]any{"start": day(start), "end": day(end), "bills": out})
}

// accountRef turns an account id or name into the API's fields, with a name
// for the preview.
func (c *conn) accountRef(ctx context.Context, side, ref string) (map[string]any, string, error) {
	if idRe.MatchString(ref) {
		var one struct {
			Data resource[account] `json:"data"`
		}
		if err := c.do(ctx, http.MethodGet, "/accounts/"+ref, nil, nil, &one); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return nil, "", fmt.Errorf("there's no account %s", ref)
			}
			return nil, "", err
		}
		return map[string]any{side + "_id": ref}, one.Data.Attributes.Name, nil
	}
	return map[string]any{side + "_name": ref}, ref, nil
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	switch p.Type {
	case "withdrawal", "deposit", "transfer":
	default:
		return sdk.Result{}, errors.New("type is withdrawal, deposit or transfer")
	}
	amount := strings.TrimSpace(p.Amount)
	if !amountRe.MatchString(amount) || sum(amount).Sign() <= 0 {
		return sdk.Result{}, errors.New("amount is a positive decimal like 12.50")
	}
	desc := strings.TrimSpace(p.Description)
	if desc == "" || len([]rune(desc)) > maxText {
		return sdk.Result{}, fmt.Errorf("the description is 1 to %d characters", maxText)
	}
	src, dst := strings.TrimSpace(p.Source), strings.TrimSpace(p.Destination)
	if src == "" || dst == "" || len(src) > 255 || len(dst) > 255 {
		return sdk.Result{}, errors.New("give the source and destination accounts (ids or names)")
	}
	if src == dst {
		return sdk.Result{}, errors.New("the source and destination are the same account")
	}
	if p.Type == "transfer" && (!idRe.MatchString(src) || !idRe.MatchString(dst)) {
		return sdk.Result{}, errors.New("a transfer is between two of your accounts: give both as ids (see accounts)")
	}
	date := p.Date
	if date == "" {
		date = day(c.now())
	}
	if err := checkDate(date); err != nil {
		return sdk.Result{}, err
	}
	if p.Currency != "" && !currRe.MatchString(p.Currency) {
		return sdk.Result{}, errors.New("currency is an ISO code like EUR")
	}
	if len([]rune(p.Category)) > 255 || len([]rune(p.Notes)) > 10000 || p.Budget < 0 {
		return sdk.Result{}, errors.New("the category, notes or budget isn't valid")
	}
	if len(p.Tags) > maxTags {
		return sdk.Result{}, fmt.Errorf("at most %d tags", maxTags)
	}
	tags := []string{}
	for _, t := range p.Tags {
		t = strings.TrimSpace(t)
		if t == "" || len([]rune(t)) > 255 {
			return sdk.Result{}, errors.New("tags are 1 to 255 characters")
		}
		tags = append(tags, t)
	}
	split := map[string]any{"type": p.Type, "amount": amount, "description": desc, "date": date}
	sf, srcName, err := c.accountRef(ctx, "source", src)
	if err != nil {
		return sdk.Result{}, err
	}
	df, dstName, err := c.accountRef(ctx, "destination", dst)
	if err != nil {
		return sdk.Result{}, err
	}
	for k, v := range sf {
		split[k] = v
	}
	for k, v := range df {
		split[k] = v
	}
	if p.Currency != "" {
		split["currency_code"] = p.Currency
	}
	if cat := strings.TrimSpace(p.Category); cat != "" {
		split["category_name"] = cat
	}
	if p.Budget > 0 {
		split["budget_id"] = strconv.Itoa(p.Budget)
	}
	if len(tags) > 0 {
		split["tags"] = tags
	}
	if n := strings.TrimSpace(p.Notes); n != "" {
		split["notes"] = n
	}
	cur := p.Currency
	if cur != "" {
		cur = " " + cur
	}
	summary := fmt.Sprintf("Record a %s of %s%s from %s to %s on %s (books only, no money moves)", p.Type, amount, cur, srcName, dstName, date)
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "transaction " + strconv.Quote(desc), Op: "create", After: mustJSON(split)}}}}, nil
	}
	body := map[string]any{"error_if_duplicate_hash": true, "apply_rules": true, "fire_webhooks": true, "transactions": []any{split}}
	var created struct {
		Data resource[group] `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, "/transactions", nil, body, &created); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(c.txSummary(created.Data))
	if idRe.MatchString(created.Data.ID) {
		id, _ := strconv.Atoi(created.Data.ID)
		// The undo is logged in the clear, so it names the id only.
		res.Undo = sdk.UndoWith("delete_transaction", map[string]any{"id": id}, fmt.Sprintf("Delete transaction %d from your books", id))
	}
	return res, err
}
