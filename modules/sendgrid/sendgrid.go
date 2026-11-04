// Package sendgrid reads a Twilio SendGrid account through its v3 API:
// delivery stats, the suppression lists (bounces, blocks, spam reports,
// invalid emails, global unsubscribes) and templates. It can remove an
// address from a suppression list.
//
// Suppression lists name recipients, so reading them is sensitive (kept out
// of the audit log). Removing a suppression lets mail reach someone who
// bounced, blocked, reported spam or unsubscribed again, so it is
// destructive.
package sendgrid

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

// Config is one SendGrid account (or subuser).
type Config struct {
	Key    string `json:"key"`    // secret:// API key (SG.…)
	Region string `json:"region"` // global (default) or eu
}

var bases = map[string]string{"global": "https://api.sendgrid.com", "eu": "https://api.eu.sendgrid.com"}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces the region's API address (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the SendGrid module.
func New() *Module { return &Module{} }

func (m *Module) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

var (
	keyRe   = regexp.MustCompile(`^SG\.[A-Za-z0-9_-]{8,100}\.[A-Za-z0-9_-]{8,100}$`)
	emailRe = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+=?^_{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)
)

// lists maps a suppression list to its API path.
var lists = map[string]string{
	"bounces":        "/v3/suppression/bounces",
	"blocks":         "/v3/suppression/blocks",
	"spam_reports":   "/v3/suppression/spam_reports",
	"invalid_emails": "/v3/suppression/invalid_emails",
	"unsubscribes":   "/v3/suppression/unsubscribes",
}

var listNames = map[string]string{"bounces": "bounce list", "blocks": "block list", "spam_reports": "spam report list", "invalid_emails": "invalid email list", "unsubscribes": "global unsubscribe list"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	list := `"list":{"type":"string","enum":["bounces","blocks","spam_reports","invalid_emails","unsubscribes"]}`
	return sdk.Manifest{
		ID: "sendgrid", Name: "SendGrid", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "A SendGrid account: delivery stats, suppression lists (bounces, blocks, spam reports, unsubscribes), templates; remove a suppression with a preview.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"key":{"type":"string","x-secret":true,"description":"A SendGrid API key (SG.…) with restricted access: Stats, Suppressions and Templates read; Suppressions full access only if agents may remove suppressions"},
			"region":{"type":"string","enum":["global","eu"],"default":"global","description":"eu for an EU regional subuser"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "stats", Title: "Delivery stats", Description: "Requests, delivered, bounces, blocks, spam reports, opens and clicks over the last days, with daily rows.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","default":7,"minimum":1,"maximum":90}}}`)},
			{Name: "suppressions", Title: "Suppressions", Description: "Addresses SendGrid won't send to, from one list (bounces, blocks, spam reports, invalid emails, global unsubscribes), newest first, with the reason.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["list"],"properties":{` + list + `,"limit":{"type":"integer","default":50,"minimum":1,"maximum":500}}}`)},
			{Name: "delete_suppression", Title: "Remove a suppression", Description: "Removes an address from a suppression list, so mail reaches it again: someone who bounced, blocked, reported spam or unsubscribed. The preview shows the entry.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["list","email"],"properties":{` + list + `,"email":{"type":"string"}}}`)},
			{Name: "templates", Title: "Templates", Description: "Transactional templates (dynamic and legacy) with their active version.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":50,"minimum":1,"maximum":200}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Key, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	region := strings.ToLower(strings.TrimSpace(c.Region))
	if region == "" {
		region = "global"
	}
	base, ok := bases[region]
	if !ok {
		return errors.New("the region is global or eu")
	}
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 30*time.Second)
	}
	ref := c.Key
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		k = strings.TrimSpace(k)
		if !keyRe.MatchString(k) {
			return errors.New("the stored key doesn't look like a SendGrid API key (SG.…)")
		}
		r.Header.Set("Authorization", "Bearer "+k)
		return nil
	})
	api.HTTP = rest.SameHostOnly(hc)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("SendGrid refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("SendGrid: %v (give the API key the permission this needs)", err)
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, method, path, q, nil, out)
	return friendly(err)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s struct {
		Scopes []string `json:"scopes"`
	}
	if err := c.do(ctx, http.MethodGet, "/v3/scopes", nil, &s); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	has := map[string]bool{}
	full := false
	for _, sc := range s.Scopes {
		has[sc] = true
		// Only full-access keys can manage API keys.
		full = full || sc == "api_keys.create"
	}
	if !has["stats.read"] {
		return sdk.Health{Status: "degraded", Message: "connected, but the key can't read stats; give it Stats read access"}
	}
	if full {
		return sdk.Health{Status: "ok", Message: "connected with a full-access key; a restricted key is safer"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("connected (%d permissions)", len(s.Scopes))}
}

type input struct {
	Days  int    `json:"days"`
	List  string `json:"list"`
	Limit int    `json:"limit"`
	Email string `json:"email"`
}

func limitOf(n, def, max int) string {
	if n <= 0 || n > max {
		n = def
	}
	return strconv.Itoa(n)
}

func ts(sec int64) string {
	if sec == 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

type suppression struct {
	Email   string `json:"email"`
	Created int64  `json:"created"`
	Reason  string `json:"reason"`
	Status  string `json:"status"`
}

func (s suppression) out() map[string]any {
	o := map[string]any{"email": s.Email, "created": ts(s.Created)}
	if s.Reason != "" {
		o["reason"] = clip(s.Reason, 300)
	}
	if s.Status != "" {
		o["status"] = s.Status
	}
	return o
}

var metricNames = []string{"requests", "processed", "delivered", "deferred", "bounces", "bounce_drops", "blocks", "spam_reports", "spam_report_drops", "invalid_emails", "unsubscribes", "unsubscribe_drops", "opens", "unique_opens", "clicks", "unique_clicks"}

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
	case "stats":
		days := p.Days
		if days <= 0 || days > 90 {
			days = 7
		}
		end := m.now().UTC()
		start := end.AddDate(0, 0, -(days - 1))
		q := url.Values{"start_date": {start.Format("2006-01-02")}, "end_date": {end.Format("2006-01-02")}, "aggregated_by": {"day"}}
		var s []struct {
			Date  string `json:"date"`
			Stats []struct {
				Metrics map[string]int64 `json:"metrics"`
			} `json:"stats"`
		}
		if err := c.do(ctx, http.MethodGet, "/v3/stats", q, &s); err != nil {
			return sdk.Result{}, err
		}
		tot := map[string]int64{}
		rows := []map[string]any{}
		for _, d := range s {
			row := map[string]any{"date": d.Date}
			for _, st := range d.Stats {
				for _, k := range metricNames {
					tot[k] += st.Metrics[k]
					n, _ := row[k].(int64)
					row[k] = n + st.Metrics[k]
				}
			}
			rows = append(rows, row)
		}
		totals := map[string]any{}
		for _, k := range metricNames {
			totals[k] = tot[k]
		}
		if tot["requests"] > 0 {
			totals["deliveredRate"] = fmt.Sprintf("%.1f%%", 100*float64(tot["delivered"])/float64(tot["requests"]))
		}
		return sdk.JSON(map[string]any{"start": q.Get("start_date"), "end": q.Get("end_date"), "totals": totals, "daily": rows})

	case "suppressions":
		path, ok := lists[p.List]
		if !ok {
			return sdk.Result{}, errors.New("list is bounces, blocks, spam_reports, invalid_emails or unsubscribes")
		}
		var l []suppression
		if err := c.do(ctx, http.MethodGet, path, url.Values{"limit": {limitOf(p.Limit, 50, 500)}, "offset": {"0"}}, &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range l {
			out = append(out, s.out())
		}
		return sdk.JSON(map[string]any{"list": p.List, "items": out})

	case "delete_suppression":
		return c.deleteSuppression(ctx, call, p)

	case "templates":
		var t struct {
			Result []struct {
				ID         string `json:"id"`
				Name       string `json:"name"`
				Generation string `json:"generation"`
				UpdatedAt  string `json:"updated_at"`
				Versions   []struct {
					ID        string `json:"id"`
					Name      string `json:"name"`
					Active    int    `json:"active"`
					UpdatedAt string `json:"updated_at"`
				} `json:"versions"`
			} `json:"result"`
		}
		q := url.Values{"generations": {"legacy,dynamic"}, "page_size": {limitOf(p.Limit, 50, 200)}}
		if err := c.do(ctx, http.MethodGet, "/v3/templates", q, &t); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, tp := range t.Result {
			o := map[string]any{"id": tp.ID, "name": tp.Name, "generation": tp.Generation, "updated": tp.UpdatedAt, "versions": len(tp.Versions)}
			for _, v := range tp.Versions {
				if v.Active == 1 {
					o["activeVersion"] = map[string]any{"id": v.ID, "name": v.Name, "updated": v.UpdatedAt}
				}
			}
			out = append(out, o)
		}
		return sdk.JSON(map[string]any{"items": out})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) deleteSuppression(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if _, ok := lists[p.List]; !ok {
		return sdk.Result{}, errors.New("list is bounces, blocks, spam_reports, invalid_emails or unsubscribes")
	}
	email := strings.TrimSpace(p.Email)
	if len(email) > 254 || !emailRe.MatchString(email) {
		return sdk.Result{}, errors.New("the email is one plain email address")
	}
	// Global unsubscribes live under asm; the others under suppression.
	item := lists[p.List] + "/" + url.PathEscape(email)
	if p.List == "unsubscribes" {
		item = "/v3/asm/suppressions/global/" + url.PathEscape(email)
	}
	var entry map[string]any
	notFound := func() (sdk.Result, error) {
		return sdk.JSON(map[string]any{"list": p.List, "email": email, "note": "it isn't on the " + listNames[p.List]})
	}
	if p.List == "unsubscribes" {
		var g struct {
			RecipientEmail string `json:"recipient_email"`
		}
		if err := c.do(ctx, http.MethodGet, item, nil, &g); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return notFound()
			}
			return sdk.Result{}, err
		}
		if g.RecipientEmail == "" {
			return notFound()
		}
		entry = map[string]any{"email": g.RecipientEmail}
	} else {
		var l []suppression
		if err := c.do(ctx, http.MethodGet, item, nil, &l); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return notFound()
			}
			return sdk.Result{}, err
		}
		if len(l) == 0 {
			return notFound()
		}
		entry = l[0].out()
	}
	if call.DryRun {
		why := map[string]string{"bounces": "it bounced", "blocks": "it was blocked", "spam_reports": "they reported spam", "invalid_emails": "it was found invalid", "unsubscribes": "they unsubscribed"}[p.List]
		before, _ := json.Marshal(entry)
		return sdk.Result{Plan: &sdk.Plan{
			Summary: fmt.Sprintf("Remove %s from the %s: SendGrid will send to it again, though %s", email, listNames[p.List], why),
			Changes: []sdk.Change{{Target: email, Op: "delete", Before: before}},
		}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, item, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"list": p.List, "email": email, "removed": true})
}
