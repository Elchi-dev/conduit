// Package porkbun works with domains registered at Porkbun through its API
// v3: domains with expiry and auto-renew, DNS records, adding records (fresh
// names only at write risk) and deleting them.
package porkbun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Porkbun account's API key pair.
type Config struct {
	APIKey       string `json:"apiKey"`       // secret:// API key (pk1_…)
	SecretAPIKey string `json:"secretApiKey"` // secret:// secret API key (sk1_…)
}

type conn struct {
	api        *rest.Client
	host       sdk.Host
	key, secKy string // references
	now        func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.porkbun.com/api/json/v3 (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Porkbun module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.porkbun.com/api/json/v3"

var (
	labelRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
	idRe    = regexp.MustCompile(`^[0-9]{1,20}$`)
	// printable is one line of record content.
	printable = regexp.MustCompile(`^[^\x00-\x1f\x7f]+$`)
)

// writeTypes are the types add_record (write) may add. Every other type
// delegates, redirects, takes mail or controls certificates, and goes
// through add_record_any (destructive).
var writeTypes = map[string]bool{"A": true, "AAAA": true, "TXT": true, "CNAME": true}

// anyTypes are the record types Porkbun's API accepts.
var anyTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "ALIAS": true, "TXT": true, "NS": true, "MX": true, "SRV": true,
	"TLSA": true, "CAA": true, "HTTPS": true, "SVCB": true, "SSHFP": true}

// prioTypes take a priority.
var prioTypes = map[string]bool{"MX": true, "SRV": true}

func types(set map[string]bool) string {
	var ts []string
	for t := range set {
		ts = append(ts, t)
	}
	sort.Strings(ts)
	b, _ := json.Marshal(ts)
	return string(b)
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	domain := `"domain":{"type":"string","description":"The domain, e.g. example.com"}`
	name := `"name":{"type":"string","description":"Record name: relative (www), @ or empty for the domain itself, or the full name (www.example.com)"}`
	fields := `"content":{"type":"string","maxLength":2048,"description":"The record's content, e.g. 192.0.2.10, target.example.net, \"v=spf1 -all\""},"ttl":{"type":"integer","minimum":600,"maximum":604800,"default":600},"prio":{"type":"integer","minimum":0,"maximum":65535,"description":"Priority (MX and SRV)"}`
	return sdk.Manifest{
		ID: "porkbun", Name: "Porkbun", Version: "0.1.0", Category: "Infrastructure", Icon: "dns",
		Description: "Domains registered at Porkbun: expiry and auto-renew, DNS records, adding records with previews and undo, deleting them.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey","secretApiKey"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"The API key (Account, API Access; pk1_…). Turn API access on for each domain Conduit should manage (domain, Details, API access)"},
			"secretApiKey":{"type":"string","x-secret":true,"description":"The secret API key shown with it (sk1_…)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "domains", Title: "Domains", Description: "Every domain with status, expiry date, days left, auto-renew, lock and WHOIS privacy.", Risk: sdk.RiskRead},
			{Name: "renewals", Title: "Renewals", Description: "Domains expiring within the next days, soonest first, and whether each renews automatically.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":730,"default":60}}}`)},
			{Name: "records", Title: "DNS records", Description: "A domain's DNS records, optionally only one name or type. Needs API access on for the domain.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["domain"],"properties":{` + domain + `,` + name + `,"type":{"type":"string"}}}`)},
			{Name: "add_record", Title: "Add a record", Description: "Creates an A, AAAA, TXT or CNAME record at a new name that nothing answers for yet. Refused: the domain itself, _acme-challenge and _domainkey names, wildcards, names a wildcard covers, names that already have records of any type, and names at or below a delegation (use add_record_any). Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["domain","name","type","content"],"properties":{` + domain + `,` + name + `,"type":{"type":"string","enum":` + types(writeTypes) + `},` + fields + `}}`)},
			{Name: "add_record_any", Title: "Add a record of any type", Description: "Creates a record of any type (NS, MX, CAA, TLSA, HTTPS, SRV, ALIAS, …) or at a name add_record refuses, also next to existing records of the same name: these can delegate a subdomain, take mail, allow certificates or override a wildcard. The preview says what it overrides. Undo deletes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["domain","name","type","content"],"properties":{` + domain + `,` + name + `,"type":{"type":"string","enum":` + types(anyTypes) + `},` + fields + `}}`)},
			{Name: "delete_record", Title: "Delete a record", Description: "Deletes one record by its id. The preview shows the record. Undo adds it again (with a new id).", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["domain","id"],"properties":{` + domain + `,"id":{"type":"string","description":"Record id (from DNS records)"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.APIKey, "secret://") || !strings.HasPrefix(c.SecretAPIKey, "secret://") {
		return errors.New("store the API key and the secret API key in the vault and enter their secret:// references")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	api := rest.New(base, nil)
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	// The keys travel in the request body, which a 307 or 308 redirect
	// sends again: never to another host.
	api.HTTP = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, host: h, key: c.APIKey, secKy: c.SecretAPIKey, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// call POSTs to the API with the key pair added to the body, and checks
// Porkbun's "status".
func (c *conn) call(ctx context.Context, path string, body map[string]any, out any) error {
	k, err := c.host.Secret(ctx, c.key)
	if err != nil {
		return err
	}
	s, err := c.host.Secret(ctx, c.secKy)
	if err != nil {
		return err
	}
	b := map[string]any{}
	for key, v := range body {
		b[key] = v
	}
	b["apikey"] = strings.TrimSpace(k)
	b["secretapikey"] = strings.TrimSpace(s)
	var raw json.RawMessage
	if _, err := c.api.Do(ctx, http.MethodPost, path, nil, b, &raw); err != nil {
		var e *rest.Error
		switch {
		case errors.As(err, &e) && strings.Contains(strings.ToLower(e.Message), "invalid api key"):
			return errors.New("Porkbun refused the API key pair")
		case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
			return errors.New("Porkbun refused the API key pair (or API access is off for this domain)")
		case rest.IsStatus(err, http.StatusTooManyRequests), rest.IsStatus(err, http.StatusServiceUnavailable):
			return errors.New("Porkbun's rate limit was hit; try again in a minute")
		}
		return err
	}
	var st struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("unexpected answer from Porkbun: %w", err)
	}
	if st.Status != "SUCCESS" {
		msg := rest.Redact(st.Message)
		if msg == "" {
			msg = "status " + st.Status
		}
		return errors.New("Porkbun: " + msg)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// flex reads a JSON string, number or null as a string (Porkbun mixes them).
type flex string

func (f *flex) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*f = flex(s)
		return nil
	}
	if string(b) == "null" {
		*f = ""
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flex(n.String())
	return nil
}

func (f flex) on() bool { return f == "1" || strings.EqualFold(string(f), "yes") || f == "true" }

type domainInfo struct {
	Domain       string `json:"domain"`
	Status       string `json:"status"`
	Expire       string `json:"expireDate"`
	AutoRenew    flex   `json:"autoRenew"`
	SecurityLock flex   `json:"securityLock"`
	WhoisPrivacy flex   `json:"whoisPrivacy"`
}

func (c *conn) domains(ctx context.Context) ([]domainInfo, error) {
	var out []domainInfo
	for start := 0; start < 20000; start += 1000 {
		var r struct {
			Domains []domainInfo `json:"domains"`
		}
		if err := c.call(ctx, "/domain/listAll", map[string]any{"start": strconv.Itoa(start)}, &r); err != nil {
			return nil, err
		}
		out = append(out, r.Domains...)
		if len(r.Domains) < 1000 {
			break
		}
	}
	return out, nil
}

type record struct {
	ID      flex `json:"id"`
	Name    flex `json:"name"`
	Type    flex `json:"type"`
	Content flex `json:"content"`
	TTL     flex `json:"ttl"`
	Prio    flex `json:"prio"`
}

func (c *conn) records(ctx context.Context, domain string) ([]record, error) {
	var r struct {
		Records []record `json:"records"`
	}
	err := c.call(ctx, "/dns/retrieve/"+domain, nil, &r)
	for i := range r.Records {
		r.Records[i].Name = flex(strings.ToLower(strings.TrimSuffix(string(r.Records[i].Name), ".")))
		r.Records[i].Type = flex(strings.ToUpper(string(r.Records[i].Type)))
	}
	return r.Records, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	if err := c.call(ctx, "/ping", nil, nil); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "connected"}
}

// dnsName checks a domain or host name and writes it lowercase without the
// trailing dot. A wildcard is allowed as the first label when wild is set.
func dnsName(s string, wild bool) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	bad := fmt.Errorf("%q isn't a DNS name", s)
	if s == "" || len(s) > 253 {
		return "", bad
	}
	for i, l := range strings.Split(s, ".") {
		if l == "*" && i == 0 && wild {
			continue
		}
		if !labelRe.MatchString(l) {
			return "", bad
		}
	}
	return s, nil
}

func checkDomain(s string) (string, error) {
	d, err := dnsName(s, false)
	if err != nil {
		return "", errors.New("which domain? (e.g. example.com)")
	}
	if !strings.Contains(d, ".") || strings.Contains(d, "_") {
		return "", fmt.Errorf("%q isn't a registered domain name", d)
	}
	return d, nil
}

// owner turns a record name (relative, @, empty or full) into the full
// name inside domain and the part before the domain ("" for the domain).
func owner(name, domain string) (full, sub string, err error) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	switch {
	case n == "" || n == "@" || n == domain:
		return domain, "", nil
	case strings.HasSuffix(n, "."+domain):
		n = strings.TrimSuffix(n, "."+domain)
	}
	if _, err := dnsName(n, true); err != nil {
		return "", "", err
	}
	full = n + "." + domain
	if len(full) > 253 {
		return "", "", fmt.Errorf("%q is too long", full)
	}
	return full, n, nil
}

func parent(n string) string {
	if i := strings.Index(n, "."); i >= 0 && i+1 < len(n) {
		return n[i+1:]
	}
	return ""
}

// overrides lists what adding a record at full would take over
// beyond a fresh name: the domain itself, ACME and DKIM names, wildcards,
// a wildcard that answers for the name today, records already at the name,
// and a delegation at or above it. add_record refuses all of these.
func overrides(recs []record, full, domain string) []string {
	var out []string
	if full == domain {
		out = append(out, "it is the domain itself (mail, certificates and delegation hang off it)")
	}
	for _, l := range strings.Split(strings.TrimSuffix(strings.TrimSuffix(full, domain), "."), ".") {
		switch {
		case strings.HasPrefix(l, "_acme-challenge"):
			out = append(out, "it is an _acme-challenge name (it proves control for certificates)")
		case l == "_domainkey":
			out = append(out, "it is a DKIM key name (it lets mail be signed for the domain)")
		}
	}
	if strings.HasPrefix(full, "*.") {
		out = append(out, "it is a wildcard (it answers for every name below it that doesn't exist)")
	}
	have := map[string]bool{}
	for _, r := range recs {
		if string(r.Name) == full {
			have[string(r.Type)] = true
		}
	}
	if len(have) > 0 {
		var ts []string
		for t := range have {
			ts = append(ts, t)
		}
		sort.Strings(ts)
		out = append(out, "the name already has "+strings.Join(ts, ", ")+" records")
	}
	// A wildcard answers only for names that have no records at all.
	for a := parent(full); len(have) == 0 && a != "" && (a == domain || strings.HasSuffix(a, "."+domain)); a = parent(a) {
		var wild []string
		for _, r := range recs {
			if string(r.Name) == "*."+a {
				wild = append(wild, string(r.Type))
			}
		}
		if len(wild) > 0 {
			sort.Strings(wild)
			out = append(out, "the wildcard *."+a+" ("+strings.Join(wild, ", ")+") may answer for it now")
		}
		if a == domain {
			break
		}
	}
	seen := map[string]bool{}
	for _, r := range recs {
		n := string(r.Name)
		if r.Type == "NS" && n != domain && !seen[n] && (n == full || strings.HasSuffix(full, "."+n)) {
			seen[n] = true
			out = append(out, n+" is delegated (NS), so the name belongs to another server")
		}
	}
	return out
}

// checkContent validates a record's content for its type.
func checkContent(typ, content string) (string, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return "", errors.New("the record needs content")
	}
	if len(content) > 2048 || !printable.MatchString(content) {
		return "", errors.New("the content is one line of up to 2048 characters")
	}
	switch typ {
	case "A":
		if ip := net.ParseIP(content); ip == nil || ip.To4() == nil || strings.Contains(content, ":") {
			return "", fmt.Errorf("%q isn't an IPv4 address", content)
		}
	case "AAAA":
		if ip := net.ParseIP(content); ip == nil || !strings.Contains(content, ":") {
			return "", fmt.Errorf("%q isn't an IPv6 address", content)
		}
	case "CNAME", "ALIAS", "NS", "MX":
		n, err := dnsName(content, false)
		if err != nil || !strings.Contains(n, ".") {
			return "", fmt.Errorf("a %s record points to a host name, and %q isn't one", typ, content)
		}
		content = n
	}
	return content, nil
}

type input struct {
	Domain  string `json:"domain"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Prio    *int   `json:"prio"`
	ID      string `json:"id"`
	Days    int    `json:"days"`
}

func daysLeft(expire string, now time.Time) *int {
	t, err := time.Parse("2006-01-02 15:04:05", expire)
	if err != nil {
		return nil
	}
	d := int(t.Sub(now).Hours() / 24)
	return &d
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
	case "domains", "renewals":
		within := p.Days
		if within == 0 {
			within = 60
		}
		if call.Action == "renewals" && (within < 1 || within > 730) {
			return sdk.Result{}, errors.New("days is 1 to 730")
		}
		list, err := c.domains(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			Domain       string `json:"domain"`
			Status       string `json:"status,omitempty"`
			Expires      string `json:"expires"`
			DaysLeft     *int   `json:"daysLeft,omitempty"`
			AutoRenew    bool   `json:"autoRenew"`
			SecurityLock bool   `json:"securityLock"`
			WhoisPrivacy bool   `json:"whoisPrivacy"`
		}
		now := c.now()
		out := []row{}
		for _, d := range list {
			r := row{Domain: d.Domain, Status: d.Status, Expires: d.Expire, DaysLeft: daysLeft(d.Expire, now),
				AutoRenew: d.AutoRenew.on(), SecurityLock: d.SecurityLock.on(), WhoisPrivacy: d.WhoisPrivacy.on()}
			if call.Action == "renewals" && (r.DaysLeft == nil || *r.DaysLeft > within) {
				continue
			}
			out = append(out, r)
		}
		if call.Action == "domains" {
			return sdk.JSON(out)
		}
		sort.SliceStable(out, func(i, j int) bool { return *out[i].DaysLeft < *out[j].DaysLeft })
		lapse := []string{}
		for _, r := range out {
			if !r.AutoRenew {
				lapse = append(lapse, r.Domain)
			}
		}
		return sdk.JSON(map[string]any{"within": within, "expiring": out, "notAutoRenewing": lapse})

	case "records":
		domain, err := checkDomain(p.Domain)
		if err != nil {
			return sdk.Result{}, err
		}
		var full string
		if strings.TrimSpace(p.Name) != "" {
			if full, _, err = owner(p.Name, domain); err != nil {
				return sdk.Result{}, err
			}
		}
		typ := strings.ToUpper(strings.TrimSpace(p.Type))
		if typ != "" && !anyTypes[typ] && typ != "SOA" {
			return sdk.Result{}, fmt.Errorf("unknown record type %q", p.Type)
		}
		recs, err := c.records(ctx, domain)
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Type    string `json:"type"`
			Content string `json:"content"`
			TTL     string `json:"ttl"`
			Prio    string `json:"prio,omitempty"`
		}
		out := []row{}
		for _, r := range recs {
			if (full != "" && string(r.Name) != full) || (typ != "" && string(r.Type) != typ) {
				continue
			}
			pr := string(r.Prio)
			if pr == "0" && !prioTypes[string(r.Type)] {
				pr = ""
			}
			out = append(out, row{ID: string(r.ID), Name: string(r.Name), Type: string(r.Type), Content: string(r.Content), TTL: string(r.TTL), Prio: pr})
		}
		return sdk.JSON(out)

	case "add_record", "add_record_any":
		return c.add(ctx, call, p)

	case "delete_record":
		domain, err := checkDomain(p.Domain)
		if err != nil {
			return sdk.Result{}, err
		}
		if !idRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("which record? (its id, from DNS records)")
		}
		recs, err := c.records(ctx, domain)
		if err != nil {
			return sdk.Result{}, err
		}
		var rec *record
		for i := range recs {
			if string(recs[i].ID) == p.ID {
				rec = &recs[i]
			}
		}
		if rec == nil {
			return sdk.Result{}, fmt.Errorf("%s has no record %s", domain, p.ID)
		}
		label := string(rec.Name) + " " + string(rec.Type)
		before, _ := json.Marshal(map[string]string{"content": string(rec.Content), "ttl": string(rec.TTL), "prio": string(rec.Prio)})
		if call.DryRun {
			summary := "Delete " + label + " " + string(rec.Content)
			if string(rec.Name) == domain || rec.Type == "NS" || rec.Type == "MX" {
				summary += " (the domain's mail or delegation may depend on it)"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: label, Op: "delete", Before: before}}}}, nil
		}
		if err := c.call(ctx, "/dns/delete/"+domain+"/"+p.ID, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		res, _ := sdk.JSON(map[string]string{"deleted": p.ID, "record": label, "content": string(rec.Content)})
		sub := "@"
		if string(rec.Name) != domain {
			sub = strings.TrimSuffix(string(rec.Name), "."+domain)
		}
		undo := map[string]any{"domain": domain, "name": sub, "type": string(rec.Type), "content": string(rec.Content)}
		if ttl, err := strconv.Atoi(string(rec.TTL)); err == nil && ttl >= 600 {
			undo["ttl"] = ttl
		}
		if pr, err := strconv.Atoi(string(rec.Prio)); err == nil && prioTypes[string(rec.Type)] {
			undo["prio"] = pr
		}
		if anyTypes[string(rec.Type)] {
			res.Undo = sdk.UndoWith("add_record_any", undo, "Add "+label+" again")
		}
		return res, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) add(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	domain, err := checkDomain(p.Domain)
	if err != nil {
		return sdk.Result{}, err
	}
	full, sub, err := owner(p.Name, domain)
	if err != nil {
		return sdk.Result{}, err
	}
	typ := strings.ToUpper(strings.TrimSpace(p.Type))
	if call.Action == "add_record" && !writeTypes[typ] {
		return sdk.Result{}, fmt.Errorf("add_record adds only A, AAAA, TXT and CNAME records; a %s record can delegate, redirect, take mail or allow certificates, so it needs add_record_any", typ)
	}
	if !anyTypes[typ] {
		return sdk.Result{}, fmt.Errorf("Porkbun doesn't take %q records", p.Type)
	}
	content, err := checkContent(typ, p.Content)
	if err != nil {
		return sdk.Result{}, err
	}
	ttl := p.TTL
	if ttl == 0 {
		ttl = 600
	}
	if ttl < 600 || ttl > 604800 {
		return sdk.Result{}, errors.New("ttl is 600 (Porkbun's minimum) to 604800 seconds")
	}
	prio := -1
	if p.Prio != nil {
		if !prioTypes[typ] {
			return sdk.Result{}, fmt.Errorf("a %s record has no priority", typ)
		}
		if *p.Prio < 0 || *p.Prio > 65535 {
			return sdk.Result{}, errors.New("prio is 0 to 65535")
		}
		prio = *p.Prio
	} else if prioTypes[typ] {
		return sdk.Result{}, fmt.Errorf("a %s record needs a priority (prio)", typ)
	}
	recs, err := c.records(ctx, domain)
	if err != nil {
		return sdk.Result{}, err
	}
	label := full + " " + typ
	over := overrides(recs, full, domain)
	if call.Action == "add_record" && len(over) > 0 {
		return sdk.Result{}, fmt.Errorf("add_record only adds a name nothing answers for yet, and %s: %s. Use add_record_any", full, strings.Join(over, "; "))
	}
	for _, r := range recs {
		if string(r.Name) != full {
			continue
		}
		switch {
		case r.Type == "CNAME":
			return sdk.Result{}, fmt.Errorf("%s is a CNAME; a name with a CNAME can't have other records", full)
		case typ == "CNAME":
			return sdk.Result{}, fmt.Errorf("%s already has %s records; a CNAME can't sit next to other records", full, r.Type)
		case string(r.Type) == typ && strings.EqualFold(strings.TrimSuffix(string(r.Content), "."), strings.TrimSuffix(content, ".")):
			return sdk.Result{}, fmt.Errorf("%s already has this record (id %s)", label, r.ID)
		}
	}
	rec := map[string]any{"ttl": ttl, "content": content}
	if prio >= 0 {
		rec["prio"] = prio
	}
	if call.DryRun {
		summary := "Create " + label + " " + content
		if len(over) > 0 {
			summary += ". It overrides: " + strings.Join(over, "; ")
			rec["overrides"] = over
		}
		after, _ := json.Marshal(rec)
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: label, Op: "create", After: after}}}}, nil
	}
	body := map[string]any{"name": sub, "type": typ, "content": content, "ttl": strconv.Itoa(ttl)}
	if prio >= 0 {
		body["prio"] = strconv.Itoa(prio)
	}
	var r struct {
		ID flex `json:"id"`
	}
	if err := c.call(ctx, "/dns/create/"+domain, body, &r); err != nil {
		return sdk.Result{}, err
	}
	res, _ := sdk.JSON(map[string]any{"id": string(r.ID), "record": label, "content": content, "ttl": ttl})
	if idRe.MatchString(string(r.ID)) {
		res.Undo = sdk.UndoWith("delete_record", map[string]string{"domain": domain, "id": string(r.ID)}, "Delete "+label)
	}
	return res, nil
}
