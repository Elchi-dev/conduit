// Package powerdns works with a PowerDNS Authoritative server through its
// HTTP API (X-API-Key): zones and their records, adding an address, text
// or alias record at a fresh name (write, undoable), adding any other record
// or at a name that already answers (destructive), replacing and deleting
// record sets (with a preview and undo), and sending NOTIFY or rectifying a
// zone.
package powerdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/dnsctl"
	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one PowerDNS server.
type Config struct {
	URL                string `json:"url"`    // the webserver, e.g. http://ns1.example.com:8081
	APIKey             string `json:"apiKey"` // secret://, the api-key setting
	Server             string `json:"server"` // server id, "localhost" unless it's a cluster
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the PowerDNS module.
func New() *Module { return &Module{} }

var (
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	serverRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	labelRe  = regexp.MustCompile(`^(?i)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
	caaRe    = regexp.MustCompile(`^[0-9]{1,3} [A-Za-z0-9]{1,15} "[^"\\]*"$`)
)

// Record types that can be changed from here. SOA and the DNSSEC types
// PowerDNS manages itself are left out.
var editable = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true, "SRV": true, "NS": true, "CAA": true,
	"PTR": true, "ALIAS": true, "SSHFP": true, "TLSA": true, "HTTPS": true, "SVCB": true, "NAPTR": true, "DS": true, "LOC": true, "SPF": true}

// writeTypes are the types add_record (write) may add. Every other type
// delegates, redirects, takes mail or controls certificates, and goes
// through add_record_any (destructive).
var writeTypes = map[string]bool{"A": true, "AAAA": true, "TXT": true, "CNAME": true}

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
	zone := `"zone":{"type":"string","description":"Zone name, e.g. example.com"}`
	name := `"name":{"type":"string","description":"Record name: relative (www), @ for the zone itself, or absolute (www.example.com.)"}`
	typ := `"type":{"type":"string","enum":` + types(editable) + `}`
	wtyp := `"type":{"type":"string","enum":` + types(writeTypes) + `}`
	ttl := `"ttl":{"type":"integer","minimum":30,"maximum":604800}`
	contents := `"contents":{"type":"array","items":{"type":"string"},"maxItems":50,"description":"Record contents in zone file form, e.g. 192.0.2.10, \"10 mail.example.com.\", \"v=spf1 -all\""}`
	return sdk.Manifest{
		ID: "powerdns", Name: "PowerDNS", Version: "0.1.0", Category: "Network", Icon: "dns",
		Description: "A PowerDNS Authoritative server: zones and records; add, replace and delete record sets with previews and undo.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"PowerDNS's webserver, e.g. http://ns1.example.com:8081 (webserver=yes, api=yes)"},
			"apiKey":{"type":"string","x-secret":true,"description":"The api-key from pdns.conf"},
			"server":{"type":"string","default":"localhost","description":"Server id; localhost unless you run something else"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the certificate, when the API is behind a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "zones", Title: "Zones", Description: "Name, kind (native, primary, secondary), serial and DNSSEC.", Risk: sdk.RiskRead},
			{Name: "records", Title: "Records", Description: "A zone's record sets, optionally only one name or type.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["zone"],"properties":{` + zone + `,` + name + `,"type":{"type":"string"}}}`)},
			{Name: "add_record", Title: "Add a record", Description: "Creates an A, AAAA, TXT or CNAME record at a new name that nothing answers for yet. Refused: the zone apex, names with a label starting with _ (ACME, DKIM, DMARC, MTA-STS, TLS reporting, SRV, ownership proofs), mta-sts, autodiscover, autoconfig and wpad hosts, wildcards, names a wildcard covers, names that already have records of any type, and names at or below a delegation (use add_record_any). Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["zone","name","type"],"properties":{` + zone + `,` + name + `,` + wtyp + `,"content":{"type":"string","description":"One record's content"},` + contents + `,` + ttl + `}}`)},
			{Name: "add_record_any", Title: "Add a record of any type", Description: "Creates a record set of any type (NS, DS, MX, CAA, TLSA, HTTPS, SRV, …) or at a name add_record refuses: these can delegate a subtree, take mail, allow certificates or override a wildcard. The preview says what it overrides. An existing name and type is refused (replace it instead). Undo deletes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["zone","name","type"],"properties":{` + zone + `,` + name + `,` + typ + `,"content":{"type":"string","description":"One record's content"},` + contents + `,` + ttl + `}}`)},
			{Name: "replace_rrset", Title: "Replace a record set", Description: "Sets every record of a name and type at once. The preview shows the old and new records. Undo puts the old ones back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["zone","name","type","contents"],"properties":{` + zone + `,` + name + `,` + typ + `,` + contents + `,` + ttl + `}}`)},
			{Name: "delete_rrset", Title: "Delete a record set", Description: "Removes every record of a name and type. Undo puts them back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["zone","name","type"],"properties":{` + zone + `,` + name + `,` + typ + `}}`)},
			{Name: "notify", Title: "Notify secondaries", Description: "Sends NOTIFY for a primary zone so its secondaries fetch it.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["zone"],"properties":{` + zone + `}}`)},
			{Name: "rectify", Title: "Rectify a zone", Description: "Recomputes DNSSEC ordering and auth data for a signed zone.", Risk: sdk.RiskWrite,
				Input: sdk.Schema(`{"type":"object","required":["zone"],"properties":{` + zone + `}}`)},
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
		return errors.New("the address is PowerDNS's webserver, like http://ns1.example.com:8081")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	server := strings.TrimSpace(c.Server)
	if server == "" {
		server = "localhost"
	}
	if !serverRe.MatchString(server) {
		return errors.New("the server id is like localhost")
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
	p := strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1"), "/api")
	ref := c.APIKey
	api := rest.New(u.Scheme+"://"+u.Host+p+"/api/v1/servers/"+server, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-API-Key", strings.TrimSpace(k))
		return nil
	})
	// X-API-Key is a custom header, which Go would forward on a redirect.
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, body, out any) error {
	_, err := c.api.Do(ctx, method, path, nil, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
		return errors.New("PowerDNS refused the API key")
	}
	return err
}

// canonical checks a DNS name and writes it lowercase with a trailing dot.
// A wildcard is allowed as the first label when wild is set.
func canonical(s string, wild bool) (string, error) {
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
	return s + ".", nil
}

// owner turns a record name (relative, @ or absolute) into an absolute
// name inside zone.
func owner(name, zone string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || n == "@" || n == zone || n+"." == zone {
		return zone, nil
	}
	abs := strings.HasSuffix(n, ".") || strings.HasSuffix(n, "."+strings.TrimSuffix(zone, "."))
	if !abs {
		n += "." + zone
	}
	c, err := canonical(n, true)
	if err != nil {
		return "", err
	}
	if c != zone && !strings.HasSuffix(c, "."+zone) {
		return "", fmt.Errorf("%s isn't inside the zone %s", c, zone)
	}
	return c, nil
}

func target(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "." {
		return s, nil
	}
	return canonical(s, false)
}

func uint16s(fields []string) bool {
	for _, f := range fields {
		if n, err := strconv.Atoi(f); err != nil || n < 0 || n > 65535 {
			return false
		}
	}
	return true
}

// quoteTXT writes TXT text as quoted strings of at most 255 bytes, unless
// it is quoted already.
func quoteTXT(s string) (string, error) {
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		return s, nil
	}
	s = strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`)
	var parts []string
	for len(s) > 255 {
		cut := 255
		for cut > 0 && s[cut-1] == '\\' { // don't split an escape
			cut--
		}
		if cut == 0 {
			return "", errors.New("the TXT text can't be split")
		}
		parts = append(parts, `"`+s[:cut]+`"`)
		s = s[cut:]
	}
	return strings.Join(append(parts, `"`+s+`"`), " "), nil
}

// content checks one record's content for its type and writes it the way
// PowerDNS stores it.
func content(typ, s string) (string, error) {
	s = strings.TrimSpace(s)
	bad := fmt.Errorf("%q isn't valid content for a %s record", s, typ)
	if s == "" || len(s) > 4000 || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", bad
	}
	f := strings.Fields(s)
	switch typ {
	case "A":
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			return ip.To4().String(), nil
		}
		return "", bad
	case "AAAA":
		if ip := net.ParseIP(s); ip != nil && ip.To4() == nil {
			return ip.String(), nil
		}
		return "", bad
	case "CNAME", "NS", "PTR", "ALIAS":
		t, err := target(s)
		if err != nil || t == "." {
			return "", bad
		}
		return t, nil
	case "MX":
		if len(f) != 2 || !uint16s(f[:1]) {
			return "", bad
		}
		t, err := target(f[1])
		if err != nil {
			return "", bad
		}
		return f[0] + " " + t, nil
	case "SRV":
		if len(f) != 4 || !uint16s(f[:3]) {
			return "", bad
		}
		t, err := target(f[3])
		if err != nil {
			return "", bad
		}
		return strings.Join(f[:3], " ") + " " + t, nil
	case "TXT", "SPF":
		return quoteTXT(s)
	case "CAA":
		if !caaRe.MatchString(s) {
			return "", bad
		}
		return s, nil
	}
	return s, nil
}

// Zone is one zone row.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Serial int64  `json:"serial"`
	DNSSEC bool   `json:"dnssec"`
}

type record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type comment struct {
	Content string `json:"content"`
	Account string `json:"account"`
}

type rrset struct {
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	TTL      int       `json:"ttl"`
	Records  []record  `json:"records"`
	Comments []comment `json:"comments"`
}

type zoneDetail struct {
	Zone
	RRsets []rrset `json:"rrsets"`
}

func (c *conn) zone(ctx context.Context, name string) (zoneDetail, error) {
	var z zoneDetail
	err := c.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(name), nil, &z)
	if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusUnprocessableEntity) {
		return z, fmt.Errorf("PowerDNS has no zone %s", name)
	}
	return z, err
}

func (z zoneDetail) find(name, typ string) *rrset {
	for i, r := range z.RRsets {
		if strings.EqualFold(r.Name, name) && r.Type == typ {
			return &z.RRsets[i]
		}
	}
	return nil
}

// parent returns the name one label up, or "" at the root.
func parent(n string) string {
	if i := strings.Index(n, "."); i >= 0 && i+1 < len(n) {
		return n[i+1:]
	}
	return ""
}

// overrides lists what adding ch would take over beyond a fresh name: the
// zone apex, ACME and DKIM names, wildcards, a wildcard at an ancestor that
// answers for the name today, other record types at the name, and a
// delegation at or above it. add_record refuses all of these.
func (z zoneDetail) overrides(ch change) []string {
	var out []string
	if ch.name == ch.zone {
		out = append(out, "it is the zone apex (mail, certificates and delegation hang off it)")
	}
	out = append(out, dnsctl.Reasons(strings.TrimSuffix(strings.TrimSuffix(ch.name, ch.zone), "."))...)
	if strings.HasPrefix(ch.name, "*.") {
		out = append(out, "it is a wildcard (it answers for every name below it that doesn't exist)")
	}
	types := map[string]bool{}
	for _, r := range z.RRsets {
		n := strings.ToLower(r.Name)
		if n == ch.name && r.Type != ch.typ {
			types[r.Type] = true
		}
	}
	if len(types) > 0 {
		var ts []string
		for t := range types {
			ts = append(ts, t)
		}
		sort.Strings(ts)
		out = append(out, "the name already has "+strings.Join(ts, ", ")+" records")
	}
	// A wildcard answers only for names that have no records at all.
	for a := parent(ch.name); len(types) == 0 && z.find(ch.name, ch.typ) == nil && a != "" && (a == ch.zone || strings.HasSuffix(a, "."+ch.zone)); a = parent(a) {
		var wild []string
		for _, r := range z.RRsets {
			if strings.EqualFold(r.Name, "*."+a) {
				wild = append(wild, r.Type)
			}
		}
		if len(wild) > 0 {
			sort.Strings(wild)
			out = append(out, "the wildcard *."+a+" ("+strings.Join(wild, ", ")+") may answer for it now")
		}
		if a == ch.zone {
			break
		}
	}
	for _, r := range z.RRsets {
		n := strings.ToLower(r.Name)
		if r.Type == "NS" && n != ch.zone && (n == ch.name || strings.HasSuffix(ch.name, "."+n)) {
			out = append(out, n+" is delegated (NS), so the name belongs to another server")
		}
	}
	return out
}

type input struct {
	Zone     string   `json:"zone"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Content  string   `json:"content"`
	Contents []string `json:"contents"`
	Records  []record `json:"records"` // undo: contents with their disabled flags
	TTL      int      `json:"ttl"`
}

// change is a validated record set change.
type change struct {
	zone, name, typ string
	ttl             int
	records         []record
}

func (p input) change(needRecords bool) (change, error) {
	zone, err := canonical(p.Zone, false)
	if err != nil {
		return change{}, errors.New("the zone is a name like example.com")
	}
	name, err := owner(p.Name, zone)
	if err != nil {
		return change{}, err
	}
	typ := strings.ToUpper(strings.TrimSpace(p.Type))
	if !editable[typ] {
		return change{}, fmt.Errorf("%q records can't be changed from here (SOA and DNSSEC keys are PowerDNS's to manage)", p.Type)
	}
	if p.TTL != 0 && (p.TTL < 30 || p.TTL > 604800) {
		return change{}, errors.New("the TTL is 30 to 604800 seconds")
	}
	ch := change{zone: zone, name: name, typ: typ, ttl: p.TTL}
	raw := append([]record{}, p.Records...)
	for _, s := range p.Contents {
		raw = append(raw, record{Content: s})
	}
	if p.Content != "" {
		raw = append(raw, record{Content: p.Content})
	}
	if !needRecords {
		if len(raw) > 0 {
			return change{}, errors.New("deleting takes no contents")
		}
		return ch, nil
	}
	if len(raw) == 0 {
		return change{}, errors.New("give the record's content")
	}
	if len(raw) > 50 {
		return change{}, errors.New("at most 50 records in one set")
	}
	seen := map[string]bool{}
	for _, r := range raw {
		c, err := content(typ, r.Content)
		if err != nil {
			return change{}, err
		}
		if seen[c] {
			return change{}, fmt.Errorf("%s is given twice", c)
		}
		seen[c] = true
		ch.records = append(ch.records, record{Content: c, Disabled: r.Disabled})
	}
	if (typ == "CNAME" || typ == "ALIAS") && len(ch.records) > 1 {
		return change{}, fmt.Errorf("a name has at most one %s record", typ)
	}
	return ch, nil
}

func contentsOf(rs []record) []string {
	out := []string{}
	for _, r := range rs {
		s := r.Content
		if r.Disabled {
			s += " (disabled)"
		}
		out = append(out, s)
	}
	return out
}

func (c *conn) patch(ctx context.Context, zone string, set map[string]any) error {
	return c.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(zone), map[string]any{"rrsets": []any{set}}, nil)
}

func (c *conn) apply(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	del := call.Action == "delete_rrset"
	ch, err := p.change(!del)
	if err != nil {
		return sdk.Result{}, err
	}
	z, err := c.zone(ctx, ch.zone)
	if err != nil {
		return sdk.Result{}, err
	}
	if k := strings.ToLower(z.Kind); k == "slave" || k == "secondary" || k == "consumer" {
		return sdk.Result{}, fmt.Errorf("%s is a %s zone: its records come from the primary and would be overwritten", ch.zone, z.Kind)
	}
	old := z.find(ch.name, ch.typ)
	label := ch.name + " " + ch.typ
	var over []string
	switch call.Action {
	case "add_record", "add_record_any":
		over = z.overrides(ch)
		if call.Action == "add_record" {
			if !writeTypes[ch.typ] {
				return sdk.Result{}, fmt.Errorf("add_record adds only A, AAAA, TXT and CNAME records; a %s record can delegate, redirect, take mail or allow certificates, so it needs add_record_any", ch.typ)
			}
			if len(over) > 0 {
				return sdk.Result{}, fmt.Errorf("add_record only adds a name nothing answers for yet, and %s: %s. Use add_record_any", label, strings.Join(over, "; "))
			}
		}
		if old != nil {
			return sdk.Result{}, fmt.Errorf("%s already has %d record(s): %s. Use replace_rrset to change them", label, len(old.Records), strings.Join(contentsOf(old.Records), ", "))
		}
		for _, r := range z.RRsets {
			if !strings.EqualFold(r.Name, ch.name) {
				continue
			}
			if r.Type == "CNAME" {
				return sdk.Result{}, fmt.Errorf("%s is a CNAME; a name with a CNAME can't have other records", ch.name)
			}
			if ch.typ == "CNAME" {
				return sdk.Result{}, fmt.Errorf("%s already has %s records; a CNAME can't sit next to other records", ch.name, r.Type)
			}
		}
	case "delete_rrset":
		if old == nil {
			return sdk.Result{}, fmt.Errorf("%s has no records", label)
		}
	}
	if ch.ttl == 0 {
		ch.ttl = 3600
		if old != nil && old.TTL > 0 {
			ch.ttl = old.TTL
		}
	}
	if call.DryRun {
		var before, after json.RawMessage
		op := "create"
		if old != nil {
			before, _ = json.Marshal(map[string]any{"ttl": old.TTL, "records": contentsOf(old.Records)})
			op = "update"
		}
		if del {
			op = "delete"
		} else {
			after, _ = json.Marshal(map[string]any{"ttl": ch.ttl, "records": contentsOf(ch.records)})
		}
		verb := map[string]string{"create": "Create", "update": "Replace", "delete": "Delete"}[op]
		summary := fmt.Sprintf("%s %s in %s", verb, label, ch.zone)
		if len(over) > 0 {
			summary += ". It overrides: " + strings.Join(over, "; ")
			after, _ = json.Marshal(map[string]any{"ttl": ch.ttl, "records": contentsOf(ch.records), "overrides": over})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary,
			Changes: []sdk.Change{{Target: label, Op: op, Before: before, After: after}}}}, nil
	}
	set := map[string]any{"name": ch.name, "type": ch.typ}
	if del {
		set["changetype"] = "DELETE"
	} else {
		set["changetype"] = "REPLACE"
		set["ttl"] = ch.ttl
		set["records"] = ch.records
	}
	if err := c.patch(ctx, ch.zone, set); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"zone": ch.zone, "name": ch.name, "type": ch.typ}
	if del {
		out["deleted"] = contentsOf(old.Records)
	} else {
		out["ttl"], out["records"] = ch.ttl, contentsOf(ch.records)
	}
	res, err := sdk.JSON(out)
	key := map[string]any{"zone": ch.zone, "name": ch.name, "type": ch.typ}
	if old == nil {
		res.Undo = sdk.UndoWith("delete_rrset", key, "Delete "+label)
	} else {
		key["records"], key["ttl"] = old.Records, old.TTL
		if old.TTL < 30 || old.TTL > 604800 {
			delete(key, "ttl")
		}
		res.Undo = sdk.UndoWith("replace_rrset", key, "Put back the previous "+label+" records")
	}
	return res, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s struct {
		DaemonType string `json:"daemon_type"`
		Version    string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "", nil, &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no PowerDNS API here (is api=yes, and the server id right?)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if s.DaemonType != "" && s.DaemonType != "authoritative" {
		return sdk.Health{Status: "degraded", Message: "this is a PowerDNS " + s.DaemonType + ", not the authoritative server"}
	}
	return sdk.Health{Status: "ok", Message: "PowerDNS Authoritative " + s.Version}
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
	case "zones":
		var zs []Zone
		if err := c.do(ctx, http.MethodGet, "/zones", nil, &zs); err != nil {
			return sdk.Result{}, err
		}
		if zs == nil {
			zs = []Zone{}
		}
		return sdk.JSON(zs)

	case "records":
		zone, err := canonical(p.Zone, false)
		if err != nil {
			return sdk.Result{}, errors.New("the zone is a name like example.com")
		}
		name := ""
		if strings.TrimSpace(p.Name) != "" {
			if name, err = owner(p.Name, zone); err != nil {
				return sdk.Result{}, err
			}
		}
		typ := strings.ToUpper(strings.TrimSpace(p.Type))
		if len(typ) > 10 {
			return sdk.Result{}, errors.New("the type is like A, MX or TXT")
		}
		z, err := c.zone(ctx, zone)
		if err != nil {
			return sdk.Result{}, err
		}
		sets := []map[string]any{}
		for _, r := range z.RRsets {
			if (name != "" && !strings.EqualFold(r.Name, name)) || (typ != "" && r.Type != typ) {
				continue
			}
			row := map[string]any{"name": r.Name, "type": r.Type, "ttl": r.TTL, "records": contentsOf(r.Records)}
			if len(r.Comments) > 0 {
				cs := []string{}
				for _, c := range r.Comments {
					cs = append(cs, c.Content)
				}
				row["comments"] = cs
			}
			sets = append(sets, row)
		}
		sort.SliceStable(sets, func(i, j int) bool { return sets[i]["name"].(string) < sets[j]["name"].(string) })
		return sdk.JSON(map[string]any{"zone": z.Name, "kind": z.Kind, "serial": z.Serial, "dnssec": z.DNSSEC, "rrsets": sets})

	case "add_record", "add_record_any", "replace_rrset", "delete_rrset":
		return c.apply(ctx, call, p)

	case "notify", "rectify":
		zone, err := canonical(p.Zone, false)
		if err != nil {
			return sdk.Result{}, errors.New("the zone is a name like example.com")
		}
		var r struct {
			Result string `json:"result"`
		}
		if err := c.do(ctx, http.MethodPut, "/zones/"+url.PathEscape(zone)+"/"+call.Action, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"zone": zone, "result": r.Result})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
