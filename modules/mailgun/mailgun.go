// Package mailgun reads a Mailgun account through its API, in the US or EU
// region: sending domains with their state, delivery stats (delivered,
// failed, bounced), the event log and the suppression lists (bounces,
// unsubscribes, complaints). It can remove an address from a suppression
// list.
//
// Events and suppressions name recipients, so they are sensitive (kept out
// of the audit log). Removing a suppression lets mail reach someone who
// bounced, unsubscribed or reported spam again, so it is destructive.
package mailgun

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

// Config is one Mailgun account.
type Config struct {
	Key    string `json:"key"`    // secret:// private API key
	Region string `json:"region"` // us (default) or eu
	Domain string `json:"domain"` // default sending domain for the per-domain actions
}

var bases = map[string]string{"us": "https://api.mailgun.net", "eu": "https://api.eu.mailgun.net"}

type conn struct {
	api    *rest.Client
	region string
	domain string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces the region's API address (tests).
	Base string
}

// New returns the Mailgun module.
func New() *Module { return &Module{} }

var (
	domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	emailRe  = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+=?^_{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)
)

// lists maps a suppression list to its API path.
var lists = map[string]string{"bounces": "bounces", "unsubscribes": "unsubscribes", "complaints": "complaints"}

var eventTypes = map[string]bool{"accepted": true, "rejected": true, "delivered": true, "failed": true, "opened": true, "clicked": true, "unsubscribed": true, "complained": true, "stored": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	dom := `"domain":{"type":"string","description":"Sending domain (default: the one in settings)"}`
	return sdk.Manifest{
		ID: "mailgun", Name: "Mailgun", Version: "0.1.0", Category: "Communication", Icon: "mail",
		Description: "A Mailgun account (US or EU): domains, delivery stats, events and suppression lists; remove an address from a suppression list with a preview.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"key":{"type":"string","x-secret":true,"description":"A Mailgun private API key (Account, API keys)"},
			"region":{"type":"string","enum":["us","eu"],"default":"us","description":"Where the account's domains live"},
			"domain":{"type":"string","description":"Default sending domain for stats, events and suppressions, e.g. mg.example.com"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "domains", Title: "Domains", Description: "Sending domains with their state (active, unverified, disabled) and type.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":100,"minimum":1,"maximum":1000}}}`)},
			{Name: "stats", Title: "Delivery stats", Description: "Accepted, delivered, failed (permanent and temporary), bounced and complained counts for a domain over the last days, with daily rows.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + dom + `,"days":{"type":"integer","default":7,"minimum":1,"maximum":90}}}`)},
			{Name: "events", Title: "Events", Description: "Recent events for a domain, newest first: recipient, event, subject, delivery status and reason.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + dom + `,"event":{"type":"string","enum":["","accepted","rejected","delivered","failed","opened","clicked","unsubscribed","complained","stored"]},"recipient":{"type":"string","description":"Only events for this address"},"limit":{"type":"integer","default":25,"minimum":1,"maximum":300}}}`)},
			{Name: "suppressions", Title: "Suppressions", Description: "Addresses Mailgun won't send to: bounces (with the error), unsubscribes (with tags) or spam complaints.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["list"],"properties":{` + dom + `,"list":{"type":"string","enum":["bounces","unsubscribes","complaints"]},"limit":{"type":"integer","default":50,"minimum":1,"maximum":1000}}}`)},
			{Name: "delete_suppression", Title: "Remove a suppression", Description: "Removes an address from a suppression list, so mail reaches it again: someone who bounced, unsubscribed or reported spam. The preview shows the entry.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["list","address"],"properties":{` + dom + `,"list":{"type":"string","enum":["bounces","unsubscribes","complaints"]},"address":{"type":"string"}}}`)},
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
		region = "us"
	}
	base, ok := bases[region]
	if !ok {
		return errors.New("the region is us or eu")
	}
	dom := strings.ToLower(strings.TrimSpace(c.Domain))
	if dom != "" && (len(dom) > 253 || !domainRe.MatchString(dom)) {
		return errors.New("the domain is a sending domain name like mg.example.com")
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
		if len(k) < 16 || strings.ContainsAny(k, " \t\r\n:") {
			return errors.New("the stored key doesn't look like a Mailgun API key")
		}
		r.SetBasicAuth("api", k)
		return nil
	})
	api.HTTP = rest.SameHostOnly(hc)
	m.set.Put(id, &conn{api: api, region: region, domain: dom})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err)
}

func friendly(err error) error {
	if rest.IsStatus(err, http.StatusUnauthorized) {
		return errors.New("Mailgun refused the API key")
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var d struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"items"`
	}
	if err := c.get(ctx, "/v4/domains", url.Values{"limit": {"1000"}}, &d); err != nil {
		if rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "Mailgun refused the API key (is it a private key, and the right region?)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if c.domain != "" {
		for _, it := range d.Items {
			if it.Name == c.domain {
				if it.State != "active" {
					return sdk.Health{Status: "degraded", Message: fmt.Sprintf("connected (%s); domain %s is %s", strings.ToUpper(c.region), c.domain, it.State)}
				}
				return sdk.Health{Status: "ok", Message: fmt.Sprintf("connected (%s): %d domains, %s active", strings.ToUpper(c.region), d.TotalCount, c.domain)}
			}
		}
		if len(d.Items) < d.TotalCount {
			return sdk.Health{Status: "ok", Message: fmt.Sprintf("connected (%s): %d domains", strings.ToUpper(c.region), d.TotalCount)}
		}
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("connected (%s), but there's no domain %s in this region", strings.ToUpper(c.region), c.domain)}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("connected (%s): %d domains", strings.ToUpper(c.region), d.TotalCount)}
}

type input struct {
	Domain    string `json:"domain"`
	Days      int    `json:"days"`
	Event     string `json:"event"`
	Recipient string `json:"recipient"`
	Limit     int    `json:"limit"`
	List      string `json:"list"`
	Address   string `json:"address"`
}

func (c *conn) domainOf(p input) (string, error) {
	d := strings.ToLower(strings.TrimSpace(p.Domain))
	if d == "" {
		d = c.domain
	}
	if d == "" {
		return "", errors.New("say which domain, or set a default domain in this instance's settings")
	}
	if len(d) > 253 || !domainRe.MatchString(d) {
		return "", errors.New("the domain is a sending domain name like mg.example.com")
	}
	return d, nil
}

func limitOf(n, def, max int) string {
	if n <= 0 || n > max {
		n = def
	}
	return strconv.Itoa(n)
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// count reads a number out of a stats object, at a path like
// failed.permanent.bounce.
func count(m map[string]any, path ...string) int64 {
	var v any = m
	for _, k := range path {
		o, ok := v.(map[string]any)
		if !ok {
			return 0
		}
		v = o[k]
	}
	f, _ := v.(float64)
	return int64(f)
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
	case "domains":
		var d struct {
			TotalCount int `json:"total_count"`
			Items      []struct {
				Name       string `json:"name"`
				State      string `json:"state"`
				Type       string `json:"type"`
				CreatedAt  string `json:"created_at"`
				IsDisabled bool   `json:"is_disabled"`
				SpamAction string `json:"spam_action"`
			} `json:"items"`
		}
		if err := c.get(ctx, "/v4/domains", url.Values{"limit": {limitOf(p.Limit, 100, 1000)}}, &d); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, it := range d.Items {
			o := map[string]any{"name": it.Name, "state": it.State, "type": it.Type, "created": it.CreatedAt}
			if it.IsDisabled {
				o["disabled"] = true
			}
			if it.SpamAction != "" {
				o["spamAction"] = it.SpamAction
			}
			out = append(out, o)
		}
		return sdk.JSON(map[string]any{"items": out, "total": d.TotalCount})

	case "stats":
		dom, err := c.domainOf(p)
		if err != nil {
			return sdk.Result{}, err
		}
		days := p.Days
		if days <= 0 || days > 90 {
			days = 7
		}
		q := url.Values{"event": {"accepted", "delivered", "failed", "complained"}, "duration": {strconv.Itoa(days) + "d"}, "resolution": {"day"}}
		var s struct {
			Stats []map[string]any `json:"stats"`
			Start string           `json:"start"`
			End   string           `json:"end"`
		}
		if err := c.get(ctx, "/v3/"+dom+"/stats/total", q, &s); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no domain %s in the %s region", dom, strings.ToUpper(c.region))
			}
			return sdk.Result{}, err
		}
		tot := map[string]int64{}
		rows := []map[string]any{}
		for _, st := range s.Stats {
			row := map[string]any{
				"date":              st["time"],
				"accepted":          count(st, "accepted", "total"),
				"delivered":         count(st, "delivered", "total"),
				"failedPermanent":   count(st, "failed", "permanent", "total"),
				"failedTemporary":   count(st, "failed", "temporary", "total"),
				"bounced":           count(st, "failed", "permanent", "bounce"),
				"suppressedBounces": count(st, "failed", "permanent", "suppress-bounce"),
				"complained":        count(st, "complained", "total"),
			}
			for k, v := range row {
				if n, ok := v.(int64); ok {
					tot[k] += n
				}
			}
			rows = append(rows, row)
		}
		totals := map[string]any{}
		for k, v := range tot {
			totals[k] = v
		}
		if tot["accepted"] > 0 {
			totals["deliveredRate"] = fmt.Sprintf("%.1f%%", 100*float64(tot["delivered"])/float64(tot["accepted"]))
		}
		return sdk.JSON(map[string]any{"domain": dom, "days": days, "start": s.Start, "end": s.End, "totals": totals, "daily": rows})

	case "events":
		dom, err := c.domainOf(p)
		if err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{"limit": {limitOf(p.Limit, 25, 300)}, "ascending": {"no"}}
		if p.Event != "" {
			if !eventTypes[p.Event] {
				return sdk.Result{}, fmt.Errorf("event %q isn't a Mailgun event type", p.Event)
			}
			q.Set("event", p.Event)
		}
		if r := strings.TrimSpace(p.Recipient); r != "" {
			if len(r) > 254 || !emailRe.MatchString(r) {
				return sdk.Result{}, errors.New("recipient is one plain email address")
			}
			q.Set("recipient", r)
		}
		var e struct {
			Items []struct {
				ID        string   `json:"id"`
				Event     string   `json:"event"`
				Timestamp float64  `json:"timestamp"`
				Recipient string   `json:"recipient"`
				Severity  string   `json:"severity"`
				Reason    string   `json:"reason"`
				Tags      []string `json:"tags"`
				Message   struct {
					Headers struct {
						Subject   string `json:"subject"`
						From      string `json:"from"`
						MessageID string `json:"message-id"`
					} `json:"headers"`
				} `json:"message"`
				DeliveryStatus struct {
					Code        int    `json:"code"`
					Message     string `json:"message"`
					Description string `json:"description"`
				} `json:"delivery-status"`
			} `json:"items"`
		}
		if err := c.get(ctx, "/v3/"+dom+"/events", q, &e); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, it := range e.Items {
			o := map[string]any{"id": it.ID, "event": it.Event, "time": time.Unix(int64(it.Timestamp), 0).UTC().Format(time.RFC3339), "recipient": it.Recipient}
			if s := it.Message.Headers.Subject; s != "" {
				o["subject"] = clip(s, 200)
			}
			if s := it.Message.Headers.From; s != "" {
				o["from"] = s
			}
			if s := it.Message.Headers.MessageID; s != "" {
				o["messageId"] = s
			}
			if it.Severity != "" {
				o["severity"] = it.Severity
			}
			if it.Reason != "" {
				o["reason"] = it.Reason
			}
			if ds := it.DeliveryStatus; ds.Code != 0 || ds.Message != "" || ds.Description != "" {
				o["deliveryStatus"] = strings.TrimSpace(fmt.Sprintf("%d %s %s", ds.Code, clip(ds.Message, 300), clip(ds.Description, 300)))
			}
			if len(it.Tags) > 0 {
				o["tags"] = it.Tags
			}
			out = append(out, o)
		}
		return sdk.JSON(map[string]any{"domain": dom, "items": out})

	case "suppressions":
		dom, err := c.domainOf(p)
		if err != nil {
			return sdk.Result{}, err
		}
		path, ok := lists[p.List]
		if !ok {
			return sdk.Result{}, errors.New("list is bounces, unsubscribes or complaints")
		}
		var s struct {
			Items []suppression `json:"items"`
		}
		if err := c.get(ctx, "/v3/"+dom+"/"+path, url.Values{"limit": {limitOf(p.Limit, 50, 1000)}}, &s); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, it := range s.Items {
			out = append(out, it.out())
		}
		return sdk.JSON(map[string]any{"domain": dom, "list": p.List, "items": out})

	case "delete_suppression":
		return c.deleteSuppression(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type suppression struct {
	Address   string   `json:"address"`
	Code      string   `json:"code"`
	Error     string   `json:"error"`
	Tags      []string `json:"tags"`
	CreatedAt string   `json:"created_at"`
}

func (s suppression) out() map[string]any {
	o := map[string]any{"address": s.Address, "created": s.CreatedAt}
	if s.Code != "" {
		o["code"] = s.Code
	}
	if s.Error != "" {
		o["error"] = clip(s.Error, 300)
	}
	if len(s.Tags) > 0 {
		o["tags"] = s.Tags
	}
	return o
}

var listNames = map[string]string{"bounces": "bounce list", "unsubscribes": "unsubscribe list", "complaints": "complaint list"}

func (c *conn) deleteSuppression(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	dom, err := c.domainOf(p)
	if err != nil {
		return sdk.Result{}, err
	}
	path, ok := lists[p.List]
	if !ok {
		return sdk.Result{}, errors.New("list is bounces, unsubscribes or complaints")
	}
	addr := strings.TrimSpace(p.Address)
	if len(addr) > 254 || !emailRe.MatchString(addr) {
		return sdk.Result{}, errors.New("the address is one plain email address")
	}
	item := "/v3/" + dom + "/" + path + "/" + url.PathEscape(addr)
	var s suppression
	if err := c.get(ctx, item, nil, &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.JSON(map[string]any{"domain": dom, "list": p.List, "address": addr, "note": "it isn't on the " + listNames[p.List]})
		}
		return sdk.Result{}, err
	}
	if call.DryRun {
		why := map[string]string{"bounces": "it bounced", "unsubscribes": "they unsubscribed", "complaints": "they reported spam"}[p.List]
		before, _ := json.Marshal(s.out())
		return sdk.Result{Plan: &sdk.Plan{
			Summary: fmt.Sprintf("Remove %s from the %s of %s: Mailgun will send to it again, though %s", addr, listNames[p.List], dom, why),
			Changes: []sdk.Change{{Target: addr + " on " + dom, Op: "delete", Before: before}},
		}}, nil
	}
	if _, err := c.api.Do(ctx, http.MethodDelete, item, nil, nil, nil); err != nil {
		return sdk.Result{}, friendly(err)
	}
	return sdk.JSON(map[string]any{"domain": dom, "list": p.List, "address": addr, "removed": true})
}
