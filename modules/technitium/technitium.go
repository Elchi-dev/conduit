// Package technitium works with a Technitium DNS Server through its HTTP
// API (an API token): dashboard statistics, zones and records, the custom
// blocked and allowed lists (block, unblock, allow and drop domains, each
// undoable and destructive: blocking can take down resolution, and the
// server's own zones, single labels and public suffixes are refused),
// flushing the cache and pausing blocking for a while. The token
// is sent in the form body of POST requests, never in a URL, so it can't
// end up in a proxy log or an error message.
package technitium

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"golang.org/x/net/publicsuffix"
)

// Config is one Technitium DNS Server.
type Config struct {
	URL                string `json:"url"`   // the web console, e.g. http://dns.lan:5380
	Token              string `json:"token"` // secret://, an API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	host  sdk.Host
	token string
	base  string
	http  *http.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Technitium module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	domainRe = regexp.MustCompile(`^(?i)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$`)
	// Fields of record data that can hold credentials (a forwarder's proxy
	// password, TSIG secrets).
	secretField = regexp.MustCompile(`(?i)password|secret|tsig`)
	periods     = []string{"LastHour", "LastDay", "LastWeek", "LastMonth", "LastYear"}
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	domain := `{"type":"object","required":["domain"],"properties":{"domain":{"type":"string","description":"e.g. ads.example.com (subdomains are included)"}}}`
	list := `{"type":"object","properties":{"search":{"type":"string"},"limit":{"type":"integer","default":200,"maximum":2000}}}`
	return sdk.Manifest{
		ID: "technitium", Name: "Technitium DNS", Version: "0.1.0", Category: "Network", Icon: "dns",
		Description: "A Technitium DNS Server: query stats, zones and records, block or allow domains, flush the cache, pause blocking.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The web console's address, e.g. http://dns.lan:5380"},
			"token":{"type":"string","x-secret":true,"description":"An API token (Administration, Sessions, Create Token) for a user allowed to view the dashboard and zones and change the blocked and allowed lists"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the console's certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "stats", Title: "Stats", Description: "Queries, blocked, cached, NXDOMAIN and failures, clients, top domains and top blocked domains.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"period":{"type":"string","enum":["LastHour","LastDay","LastWeek","LastMonth","LastYear"],"default":"LastDay"}}}`)},
			{Name: "zones", Title: "Zones", Description: "Name, type, DNSSEC status, serial and whether each is disabled or failing to sync.", Risk: sdk.RiskRead},
			{Name: "records", Title: "Records", Description: "A zone's records, or one name's (fields that can hold passwords, and DNS apps' configuration, are left out).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["zone"],"properties":{"zone":{"type":"string"},"domain":{"type":"string","description":"Only this name (default: the whole zone)"}}}`)},
			{Name: "blocked", Title: "Blocked domains", Description: "The custom blocked list (not the downloaded block lists).", Risk: sdk.RiskRead, Input: sdk.Schema(list)},
			{Name: "allowed", Title: "Allowed domains", Description: "The allowed list, which wins over every block list.", Risk: sdk.RiskRead, Input: sdk.Schema(list)},
			{Name: "block_domain", Title: "Block a domain", Description: "Adds it, and its subdomains, to the blocked list, so they stop resolving for every client. Single labels, public suffixes and the server's own zones are refused (block those in Technitium's console). Undo unblocks it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(domain)},
			{Name: "unblock_domain", Title: "Unblock a domain", Description: "Takes it off the blocked list. Undo blocks it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(domain)},
			{Name: "allow_domain", Title: "Allow a domain", Description: "Lets it, and its subdomains, through every block list. Single labels and public suffixes are refused. Undo drops it from the allowed list.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(domain)},
			{Name: "drop_allowed_domain", Title: "Drop an allowed domain", Description: "Takes it off the allowed list, so block lists apply to it again (which can stop it resolving). Single labels, public suffixes and the server's own zones are refused. Undo allows it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(domain)},
			{Name: "flush_cache", Title: "Flush the cache", Description: "Drops every cached answer; the next queries are resolved afresh.", Risk: sdk.RiskWrite},
			{Name: "disable_blocking", Title: "Pause blocking", Description: "Turns blocking off for some minutes; it comes back on by itself. Undo turns it back on now.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"minutes":{"type":"integer","default":5,"minimum":1,"maximum":1440}}}`)},
			{Name: "enable_blocking", Title: "Turn blocking back on", Risk: sdk.RiskWrite},
		},
		Resources: []sdk.ResourceSpec{
			{Kind: "zone", Title: "Zones", ListAction: "zones", GetAction: "records", ViewHint: "table"},
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
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is the web console's, like http://dns.lan:5380")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	p := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	m.set.Put(id, &conn{host: h, token: c.Token, base: u.Scheme + "://" + u.Host + p + "/api", http: rest.SameHostOnly(client)})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// raw POSTs a form (with the token) and returns the body.
func (c *conn) raw(ctx context.Context, path string, form url.Values) ([]byte, string, error) {
	tok, err := c.host.Secret(ctx, c.token)
	if err != nil {
		return nil, "", err
	}
	f := url.Values{}
	for k, v := range form {
		f[k] = v
	}
	f.Set("token", strings.TrimSpace(tok))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, strings.NewReader(f.Encode()))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	res, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, rest.ErrCrossHostRedirect) {
			return nil, "", rest.ErrCrossHostRedirect
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			return nil, "", fmt.Errorf("can't reach Technitium: %v", ue.Err)
		}
		return nil, "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return nil, "", err
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, "", &rest.Error{Status: 404, Message: "Technitium doesn't have " + path + " (an older version?)"}
	}
	if res.StatusCode >= 300 {
		return nil, "", &rest.Error{Status: res.StatusCode, Message: "Technitium answered " + res.Status}
	}
	return body, res.Header.Get("Content-Type"), nil
}

// call POSTs a form and decodes {"status":"ok","response":...} into out.
func (c *conn) call(ctx context.Context, path string, form url.Values, out any) error {
	body, _, err := c.raw(ctx, path, form)
	if err != nil {
		return err
	}
	return envelope(body, out)
}

// envelope reads {"status":"ok","response":...} into out, or the error.
func envelope(body []byte, out any) error {
	var env struct {
		Status   string          `json:"status"`
		Error    string          `json:"errorMessage"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return errors.New("unexpected answer from Technitium (is this its web console address?)")
	}
	switch env.Status {
	case "ok":
	case "invalid-token":
		return errors.New("Technitium refused the API token")
	case "2fa-required":
		return errors.New("Technitium wants a 2FA code: use an API token instead of a session")
	default:
		msg := env.Error
		if msg == "" {
			msg = "status " + env.Status
		}
		if strings.Contains(strings.ToLower(msg), "access was denied") {
			return fmt.Errorf("the token's user isn't allowed to do this (%s)", rest.Redact(msg))
		}
		return errors.New("Technitium: " + rest.Redact(msg))
	}
	if out != nil && len(env.Response) > 0 {
		if err := json.Unmarshal(env.Response, out); err != nil {
			return fmt.Errorf("unexpected answer from Technitium: %w", err)
		}
	}
	return nil
}

func domainOf(s string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if d == "" || len(d) > 253 || !domainRe.MatchString(d) {
		return "", errors.New("give a domain such as ads.example.com")
	}
	return d, nil
}

// broad refuses names whose blocking (or allowing) reaches far beyond one
// site: a single label (a TLD, or a local name such as lan) and a public
// suffix (co.uk, in-addr.arpa, github.io).
func broad(d string) error {
	if !strings.Contains(d, ".") {
		return fmt.Errorf("%s is a single label: it covers a whole top-level domain or local namespace; change that in Technitium's console", d)
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(d); err != nil {
		return fmt.Errorf("%s is a public suffix: it covers every domain registered under it; change that in Technitium's console", d)
	}
	return nil
}

// ownZone refuses a name inside, or above, one of the server's own zones:
// blocking it would stop the server answering for names it is the
// authority for. It fails closed when the zones can't be read.
func (c *conn) ownZone(ctx context.Context, d string) error {
	var z struct {
		Zones []struct {
			Name string `json:"name"`
		} `json:"zones"`
	}
	if err := c.call(ctx, "/zones/list", nil, &z); err != nil {
		return fmt.Errorf("can't check %s against the server's zones: %w", d, err)
	}
	for _, x := range z.Zones {
		n := strings.ToLower(strings.TrimSuffix(x.Name, "."))
		if n == "" {
			continue
		}
		if d == n || strings.HasSuffix(d, "."+n) || strings.HasSuffix(n, "."+d) {
			return fmt.Errorf("%s is part of the server's own zone %s; change its blocking in Technitium's console", d, n)
		}
	}
	return nil
}

// list reads the blocked or allowed list (an export, one domain a line).
func (c *conn) list(ctx context.Context, which string) ([]string, error) {
	body, ctype, err := c.raw(ctx, "/"+which+"/export", nil)
	if err != nil {
		return nil, err
	}
	if strings.Contains(ctype, "json") || bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		// An error comes back as JSON.
		if err := envelope(body, nil); err != nil {
			return nil, err
		}
		return nil, errors.New("unexpected answer from Technitium")
	}
	out := []string{}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, strings.ToLower(l))
	}
	sort.Strings(out)
	return out, sc.Err()
}

func has(xs []string, s string) bool {
	i := sort.SearchStrings(xs, s)
	return i < len(xs) && xs[i] == s
}

type blocking struct {
	Enabled bool   `json:"enableBlocking"`
	Till    string `json:"temporaryDisableBlockingTill"`
}

// blockingState reads just the two blocking fields of the settings; the
// rest (which include proxy and TSIG credentials) is never decoded.
func (c *conn) blockingState(ctx context.Context) (blocking, error) {
	var b blocking
	err := c.call(ctx, "/settings/get", nil, &b)
	return b, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s struct {
		Stats struct {
			Queries int64 `json:"totalQueries"`
			Blocked int64 `json:"totalBlocked"`
			Zones   int64 `json:"zones"`
		} `json:"stats"`
	}
	if err := c.call(ctx, "/dashboard/stats/get", url.Values{"type": {"LastHour"}}, &s); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%d queries in the last hour, %d blocked · %d zones", s.Stats.Queries, s.Stats.Blocked, s.Stats.Zones)
	if b, err := c.blockingState(ctx); err == nil && !b.Enabled {
		if b.Till != "" {
			return sdk.Health{Status: "degraded", Message: "blocking paused until " + b.Till + " · " + msg}
		}
		return sdk.Health{Status: "degraded", Message: "blocking is off · " + msg}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// scrub drops record data fields that can hold credentials.
func scrub(v map[string]any) map[string]any {
	out := map[string]any{}
	for k, x := range v {
		if secretField.MatchString(k) {
			continue
		}
		out[k] = x
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
		Period  string `json:"period"`
		Zone    string `json:"zone"`
		Domain  string `json:"domain"`
		Search  string `json:"search"`
		Limit   int    `json:"limit"`
		Minutes *int   `json:"minutes"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "stats":
		period := p.Period
		if period == "" {
			period = "LastDay"
		}
		ok := false
		for _, x := range periods {
			ok = ok || x == period
		}
		if !ok {
			return sdk.Result{}, errors.New("the period is one of " + strings.Join(periods, ", "))
		}
		type top struct {
			Name string `json:"name"`
			Hits int64  `json:"hits"`
		}
		var s struct {
			Stats             map[string]int64 `json:"stats"`
			TopClients        []top            `json:"topClients"`
			TopDomains        []top            `json:"topDomains"`
			TopBlockedDomains []top            `json:"topBlockedDomains"`
		}
		if err := c.call(ctx, "/dashboard/stats/get", url.Values{"type": {period}}, &s); err != nil {
			return sdk.Result{}, err
		}
		cut := func(t []top) []top {
			if t == nil {
				return []top{}
			}
			if len(t) > 10 {
				return t[:10]
			}
			return t
		}
		return sdk.JSON(map[string]any{"period": period, "stats": s.Stats, "topClients": cut(s.TopClients), "topDomains": cut(s.TopDomains), "topBlockedDomains": cut(s.TopBlockedDomains)})

	case "zones":
		var z struct {
			Zones []struct {
				Name         string `json:"name"`
				Type         string `json:"type"`
				Internal     bool   `json:"internal"`
				DNSSEC       string `json:"dnssecStatus"`
				Serial       int64  `json:"soaSerial"`
				Disabled     bool   `json:"disabled"`
				SyncFailed   bool   `json:"syncFailed"`
				Expired      bool   `json:"isExpired"`
				LastModified string `json:"lastModified"`
			} `json:"zones"`
		}
		if err := c.call(ctx, "/zones/list", nil, &z); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range z.Zones {
			if x.Internal {
				continue
			}
			out = append(out, map[string]any{"name": x.Name, "type": x.Type, "dnssec": x.DNSSEC, "serial": x.Serial, "disabled": x.Disabled,
				"syncFailed": x.SyncFailed, "expired": x.Expired, "lastModified": x.LastModified})
		}
		return sdk.JSON(out)

	case "records":
		zone, err := domainOf(p.Zone)
		if err != nil {
			return sdk.Result{}, errors.New("the zone is a name like home.lan")
		}
		domain := zone
		if strings.TrimSpace(p.Domain) != "" {
			if domain, err = domainOf(p.Domain); err != nil {
				return sdk.Result{}, err
			}
			if domain != zone && !strings.HasSuffix(domain, "."+zone) {
				return sdk.Result{}, fmt.Errorf("%s isn't inside the zone %s", domain, zone)
			}
		}
		form := url.Values{"zone": {zone}, "domain": {domain}}
		if domain == zone {
			form.Set("listZone", "true")
		}
		var r struct {
			Records []struct {
				Name     string         `json:"name"`
				Type     string         `json:"type"`
				TTL      int            `json:"ttl"`
				Disabled bool           `json:"disabled"`
				RData    map[string]any `json:"rData"`
				Comments string         `json:"comments"`
			} `json:"records"`
		}
		if err := c.call(ctx, "/zones/records/get", form, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range r.Records {
			data := scrub(x.RData)
			if strings.EqualFold(x.Type, "APP") {
				// A DNS app's record data is the app's own JSON
				// configuration, which can hold API keys: keep only which
				// app it is.
				app := map[string]any{}
				for _, k := range []string{"appName", "classPath"} {
					if v, ok := data[k].(string); ok {
						app[k] = rest.Redact(v)
					}
				}
				data = app
			}
			row := map[string]any{"name": x.Name, "type": x.Type, "ttl": x.TTL, "disabled": x.Disabled, "data": data}
			if x.Comments != "" {
				row["comments"] = rest.Redact(x.Comments)
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"zone": zone, "records": out})

	case "blocked", "allowed":
		search := strings.ToLower(strings.TrimSpace(p.Search))
		if len(search) > 253 || strings.ContainsAny(search, " \t\r\n") {
			return sdk.Result{}, errors.New("search for part of a domain")
		}
		n := p.Limit
		if n <= 0 || n > 2000 {
			n = 200
		}
		all, err := c.list(ctx, call.Action)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []string{}
		for _, d := range all {
			if search == "" || strings.Contains(d, search) {
				out = append(out, d)
			}
		}
		total := len(out)
		if len(out) > n {
			out = out[:n]
		}
		return sdk.JSON(map[string]any{"total": total, "domains": out})

	case "block_domain", "unblock_domain", "allow_domain", "drop_allowed_domain":
		d, err := domainOf(p.Domain)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.Action != "unblock_domain" {
			if err := broad(d); err != nil {
				return sdk.Result{}, err
			}
		}
		if call.Action == "block_domain" || call.Action == "drop_allowed_domain" {
			if err := c.ownZone(ctx, d); err != nil {
				return sdk.Result{}, err
			}
		}
		which, adding := "blocked", true
		switch call.Action {
		case "unblock_domain":
			adding = false
		case "allow_domain":
			which = "allowed"
		case "drop_allowed_domain":
			which, adding = "allowed", false
		}
		cur, err := c.list(ctx, which)
		if err != nil {
			return sdk.Result{}, err
		}
		if adding && has(cur, d) {
			return sdk.Result{}, fmt.Errorf("%s is already on the %s list", d, which)
		}
		if !adding && !has(cur, d) {
			return sdk.Result{}, fmt.Errorf("%s isn't on the %s list", d, which)
		}
		if call.DryRun {
			var msg string
			op := "create"
			switch call.Action {
			case "allow_domain":
				msg = "Allow " + d + " and its subdomains past every block list"
				if blocked, err := c.list(ctx, "blocked"); err == nil && has(blocked, d) {
					msg += " (it's on the blocked list too; allowing wins)"
				}
			case "block_domain":
				msg = "Block " + d + " and its subdomains: they stop resolving for every client of this server"
			case "unblock_domain":
				msg, op = "Unblock "+d+" and its subdomains", "delete"
			case "drop_allowed_domain":
				msg, op = "Take "+d+" off the allowed list: block lists apply to it and its subdomains again, so they may stop resolving", "delete"
			}
			ch := sdk.Change{Target: which + " list", Op: op}
			if op == "create" {
				ch.After = json.RawMessage(strconv.Quote(d))
			} else {
				ch.Before = json.RawMessage(strconv.Quote(d))
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: msg, Changes: []sdk.Change{ch}}}, nil
		}
		op := "add"
		if !adding {
			op = "delete"
		}
		if err := c.call(ctx, "/"+which+"/"+op, url.Values{"domain": {d}}, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"domain": d, "list": which, "on": adding})
		in := map[string]string{"domain": d}
		switch call.Action {
		case "block_domain":
			res.Undo = sdk.UndoWith("unblock_domain", in, "Unblock "+d)
		case "unblock_domain":
			res.Undo = sdk.UndoWith("block_domain", in, "Block "+d+" again")
		case "allow_domain":
			res.Undo = sdk.UndoWith("drop_allowed_domain", in, "Take "+d+" off the allowed list")
		case "drop_allowed_domain":
			res.Undo = sdk.UndoWith("allow_domain", in, "Allow "+d+" again")
		}
		return res, err

	case "flush_cache":
		if err := c.call(ctx, "/cache/flush", nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]bool{"flushed": true})

	case "disable_blocking":
		mins := 5
		if p.Minutes != nil {
			mins = *p.Minutes
		}
		if mins < 1 || mins > 1440 {
			return sdk.Result{}, errors.New("pause for 1 to 1440 minutes")
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Turn blocking off for %d minutes; every client gets ads and trackers until then", mins),
				Changes: []sdk.Change{{Target: "blocking", Op: "disable", Before: json.RawMessage(`"on"`), After: json.RawMessage(strconv.Quote(fmt.Sprintf("off for %d minutes", mins)))}}}}, nil
		}
		var r struct {
			Till string `json:"temporaryDisableBlockingTill"`
		}
		if err := c.call(ctx, "/settings/temporaryDisableBlocking", url.Values{"minutes": {strconv.Itoa(mins)}}, &r); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"blocking": false, "until": r.Till})
		res.Undo = sdk.UndoWith("enable_blocking", map[string]string{}, "Turn blocking back on")
		return res, err

	case "enable_blocking":
		// Only enableBlocking is sent, so no other setting changes; the
		// answer (every setting) is discarded.
		if err := c.call(ctx, "/settings/set", url.Values{"enableBlocking": {"true"}}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]bool{"blocking": true})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
