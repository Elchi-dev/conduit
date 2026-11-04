// Package cloudflare manages Cloudflare DNS: zones, records and cache purges.
// Record changes preview as a diff and can be undone. It also reads Zero
// Trust tunnels (cloudflared): their health, connectors and routes.
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/dnsctl"
	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Cloudflare account's settings.
type Config struct {
	Token string `json:"token"` // secret:// API token
	API   string `json:"api"`   // default https://api.cloudflare.com/client/v4 (tests)
	// AccountID is the account whose tunnels to read; when empty, the only
	// account the token can see.
	AccountID string `json:"accountId"`
}

type account struct {
	api       *rest.Client
	accountID string
}

var (
	accountRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	uuidRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[account]
	HTTP *http.Client
}

// New returns the Cloudflare module.
func New() *Module { return &Module{} }

const recordProps = `"zone":{"type":"string","description":"Zone name, e.g. example.com"},
	"type":{"type":"string","enum":["A","AAAA","CNAME","TXT","MX","NS","SRV","CAA"]},
	"name":{"type":"string","description":"Full name, e.g. www.example.com, or @ for the zone apex"},
	"content":{"type":"string","description":"Address, target or text"},
	"ttl":{"type":"integer","description":"Seconds; 1 means automatic","default":1},
	"proxied":{"type":"boolean","title":"Proxied through Cloudflare"},
	"priority":{"type":"integer","description":"MX and SRV only"}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "cloudflare", Name: "Cloudflare", Version: "0.1.0", Category: "Infrastructure", Icon: "globe",
		Description: "DNS zones and records, and cache purges, with previews and undo; Zero Trust tunnels and their connectors.",
		Presets:     []string{"developer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"API token with Zone:Read and DNS:Edit (Cache Purge to purge, Account: Cloudflare Tunnel: Read for tunnels)"},
			"accountId":{"type":"string","description":"Account ID for tunnels (from the dashboard's overview page); not needed when the token sees one account"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "zones", Title: "Zones", Risk: sdk.RiskRead},
			{Name: "records", Title: "DNS records", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["zone"],"properties":{"zone":{"type":"string"},"type":{"type":"string"},"name":{"type":"string"}}}`)},
			{Name: "set_record", Title: "Create or change a record", Description: "Changes the record with this type and name, or creates it. Names that carry control over the domain (a label starting with _, or mta-sts, autodiscover, autoconfig and wpad hosts) need set_record_any.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["zone","type","name","content"],"properties":{` + recordProps + `}}`)},
			{Name: "delete_record", Title: "Delete a record", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["zone","type","name"],"properties":{"zone":{"type":"string"},"type":{"type":"string"},"name":{"type":"string"}}}`)},
			{Name: "restore_record", Title: "Restore a record", Description: "Puts back a record exactly as it was (used by undo).", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["zone","record"],"properties":{"zone":{"type":"string"},"record":{"type":"object","additionalProperties":true},"replace":{"type":"string"}}}`)},
			{Name: "set_record_any", Title: "Create or change a control record", Description: "set_record for names that carry control over the domain: any label starting with _ (ACME, DKIM, DMARC, MTA-STS, TLS reporting, SRV, ownership proofs) and mta-sts, autodiscover, autoconfig and wpad hosts. The preview says what it controls.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["zone","type","name","content"],"properties":{` + recordProps + `}}`)},
			{Name: "restore_record_any", Title: "Restore a control record", Description: "restore_record for the names set_record_any is for (used by undo).", Risk: sdk.RiskDestructive, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["zone","record"],"properties":{"zone":{"type":"string"},"record":{"type":"object","additionalProperties":true},"replace":{"type":"string"}}}`)},
			{Name: "purge_cache", Title: "Purge cache", Description: "Specific URLs, or everything when none are given. Purging drops the cached copies, so every visitor hits the origin until the cache fills again (destructive).", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["zone"],"properties":{"zone":{"type":"string"},"files":{"type":"array","items":{"type":"string"}}}}`)},
			{Name: "tunnels", Title: "Tunnels", Description: "Zero Trust (cloudflared) tunnels: healthy, degraded, down or inactive, with their connections.", Risk: sdk.RiskRead},
			{Name: "tunnel", Title: "Tunnel", Description: "One tunnel's connectors (cloudflared version, platform, edge locations) and, for dashboard-managed tunnels, its public hostnames.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["tunnel"],"properties":{"tunnel":{"type":"string","description":"Tunnel name or id"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.Token == "" {
		return errors.New("add an API token (stored in the vault)")
	}
	if c.API == "" {
		c.API = "https://api.cloudflare.com/client/v4"
	}
	c.AccountID = strings.ToLower(strings.TrimSpace(c.AccountID))
	if c.AccountID != "" && !accountRe.MatchString(c.AccountID) {
		return errors.New("the account ID is 32 hexadecimal characters")
	}
	tok := c.Token
	api := rest.New(c.API, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
	// The bearer token is dropped on other hosts by Go, but refuse the
	// redirect outright, like the other API modules.
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &account{api: api, accountID: c.AccountID})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

type envelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (a *account) call(ctx context.Context, method, path string, q url.Values, body, out any) error {
	var e envelope
	if _, err := a.api.Do(ctx, method, path, q, body, &e); err != nil {
		return err
	}
	if !e.Success {
		if len(e.Errors) > 0 {
			return errors.New(e.Errors[0].Message)
		}
		return errors.New("Cloudflare refused the request")
	}
	if out != nil {
		return json.Unmarshal(e.Result, out)
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	a, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Status string `json:"status"`
	}
	if err := a.call(ctx, "GET", "/user/tokens/verify", nil, nil, &v); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if v.Status != "active" {
		return sdk.Health{Status: "down", Message: "The token is " + v.Status}
	}
	return sdk.Health{Status: "ok", Message: "Token active"}
}

// Zone is a zone row.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Plan   string `json:"plan"`
}

// Record is a DNS record.
type Record struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Proxied  bool   `json:"proxied"`
	Priority *int   `json:"priority,omitempty"`
}

func (r Record) body() map[string]any {
	b := map[string]any{"type": r.Type, "name": r.Name, "content": r.Content, "ttl": r.TTL, "proxied": r.Proxied}
	if r.TTL == 0 {
		b["ttl"] = 1
	}
	if r.Priority != nil {
		b["priority"] = *r.Priority
	}
	if r.Type != "A" && r.Type != "AAAA" && r.Type != "CNAME" {
		delete(b, "proxied") // only these can be proxied
	}
	return b
}

var zoneRe = regexp.MustCompile(`^[a-z0-9.-]+\.[a-z]{2,}$`)

func (a *account) zoneID(ctx context.Context, zone string) (string, error) {
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	if !zoneRe.MatchString(zone) {
		return "", fmt.Errorf("%q isn't a zone name", zone)
	}
	var zs []Zone
	if err := a.call(ctx, "GET", "/zones", url.Values{"name": {zone}}, nil, &zs); err != nil {
		return "", err
	}
	if len(zs) == 0 {
		return "", fmt.Errorf("no zone %s in this account (or the token can't see it)", zone)
	}
	return zs[0].ID, nil
}

// fqdn expands "@" and relative names within the zone.
// controls says why a record at name carries control over zone (see
// dnsctl), or nil for a plain host name.
func controls(name, zone string) []string {
	if name == zone || !strings.HasSuffix(name, "."+zone) {
		return nil
	}
	return dnsctl.Reasons(strings.TrimSuffix(name, "."+zone))
}

// restoreAction is the undo for a change at name: restoring a control
// record is as destructive as setting one.
func restoreAction(name, zone string) string {
	if len(controls(strings.ToLower(strings.TrimSuffix(name, ".")), zone)) > 0 {
		return "restore_record_any"
	}
	return "restore_record"
}

func fqdn(name, zone string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if name == "@" || name == "" {
		return zone
	}
	if name == zone || strings.HasSuffix(name, "."+zone) {
		return name
	}
	return name + "." + zone
}

func (a *account) find(ctx context.Context, zid, typ, name string) ([]Record, error) {
	q := url.Values{"per_page": {"100"}}
	if typ != "" {
		q.Set("type", strings.ToUpper(typ))
	}
	if name != "" {
		q.Set("name", name)
	}
	var rs []Record
	err := a.call(ctx, "GET", "/zones/"+zid+"/dns_records", q, nil, &rs)
	return rs, err
}

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	a, err := m.set.Get(c.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Zone     string   `json:"zone"`
		Type     string   `json:"type"`
		Name     string   `json:"name"`
		Content  string   `json:"content"`
		TTL      int      `json:"ttl"`
		Proxied  bool     `json:"proxied"`
		Priority *int     `json:"priority"`
		Files    []string `json:"files"`
		Record   *Record  `json:"record"`
		Replace  string   `json:"replace"`
	}
	if err := sdk.Decode(c, &p); err != nil {
		return sdk.Result{}, err
	}
	if c.Action == "zones" {
		var zs []struct {
			Zone
			PlanInfo struct {
				Name string `json:"name"`
			} `json:"plan"`
		}
		if err := a.call(ctx, "GET", "/zones", url.Values{"per_page": {"50"}}, nil, &zs); err != nil {
			return sdk.Result{}, err
		}
		out := []Zone{}
		for _, z := range zs {
			out = append(out, Zone{ID: z.ID, Name: z.Name, Status: z.Status, Plan: z.PlanInfo.Name})
		}
		return sdk.JSON(out)
	}
	if c.Action == "tunnels" || c.Action == "tunnel" {
		return a.tunnels(ctx, c)
	}
	zid, err := a.zoneID(ctx, p.Zone)
	if err != nil {
		return sdk.Result{}, err
	}
	zone := strings.ToLower(strings.TrimSuffix(p.Zone, "."))
	switch c.Action {
	case "records":
		name := ""
		if p.Name != "" {
			name = fqdn(p.Name, zone)
		}
		rs, err := a.find(ctx, zid, p.Type, name)
		if err != nil {
			return sdk.Result{}, err
		}
		if rs == nil {
			rs = []Record{}
		}
		return sdk.JSON(rs)

	case "set_record", "set_record_any":
		want := Record{Type: strings.ToUpper(p.Type), Name: fqdn(p.Name, zone), Content: strings.TrimSpace(p.Content), TTL: p.TTL, Proxied: p.Proxied, Priority: p.Priority}
		control := controls(want.Name, zone)
		if c.Action == "set_record" && len(control) > 0 {
			return sdk.Result{}, fmt.Errorf("%s carries control over the domain (%s), so it needs set_record_any", want.Name, strings.Join(control, "; "))
		}
		if want.TTL == 0 {
			want.TTL = 1
		}
		if want.Type == "" || want.Content == "" {
			return sdk.Result{}, errors.New("type and content are required")
		}
		existing, err := a.find(ctx, zid, want.Type, want.Name)
		if err != nil {
			return sdk.Result{}, err
		}
		if len(existing) > 1 {
			return sdk.Result{}, fmt.Errorf("%d %s records named %s exist; change them one by one in Cloudflare", len(existing), want.Type, want.Name)
		}
		target := want.Type + " " + want.Name
		if c.DryRun {
			ch := sdk.Change{Target: target, Op: "create", After: raw(want.body())}
			if len(existing) == 1 {
				ch.Op, ch.Before = "update", raw(existing[0].body())
			}
			summary := fmt.Sprintf("%s %s → %s", map[string]string{"create": "Create", "update": "Change"}[ch.Op], target, want.Content)
			if len(control) > 0 {
				summary += ". It controls: " + strings.Join(control, "; ")
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{ch}}}, nil
		}
		var got Record
		if len(existing) == 1 {
			old := existing[0]
			if err := a.call(ctx, "PUT", "/zones/"+zid+"/dns_records/"+old.ID, nil, want.body(), &got); err != nil {
				return sdk.Result{}, err
			}
			r, _ := sdk.JSON(got)
			old.ID = ""
			r.Undo = sdk.UndoWith(restoreAction(old.Name, zone), map[string]any{"zone": zone, "record": old, "replace": got.ID}, "Put back "+target+" → "+old.Content)
			return r, nil
		}
		if err := a.call(ctx, "POST", "/zones/"+zid+"/dns_records", nil, want.body(), &got); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(got)
		r.Undo = sdk.UndoWith("delete_record", map[string]any{"zone": zone, "type": got.Type, "name": got.Name}, "Remove "+target)
		return r, nil

	case "delete_record":
		name := fqdn(p.Name, zone)
		existing, err := a.find(ctx, zid, p.Type, name)
		if err != nil {
			return sdk.Result{}, err
		}
		if len(existing) == 0 {
			return sdk.Result{}, fmt.Errorf("no %s record named %s", strings.ToUpper(p.Type), name)
		}
		if len(existing) > 1 {
			return sdk.Result{}, fmt.Errorf("%d records match; delete them one by one in Cloudflare", len(existing))
		}
		old := existing[0]
		if c.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Delete " + old.Type + " " + old.Name, Changes: []sdk.Change{{Target: old.Type + " " + old.Name, Op: "delete", Before: raw(old.body())}}}}, nil
		}
		if err := a.call(ctx, "DELETE", "/zones/"+zid+"/dns_records/"+old.ID, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"deleted": old.Type + " " + old.Name})
		old.ID = ""
		r.Undo = sdk.UndoWith(restoreAction(old.Name, zone), map[string]any{"zone": zone, "record": old}, "Restore "+old.Type+" "+old.Name)
		return r, nil

	case "restore_record", "restore_record_any":
		if p.Record == nil {
			return sdk.Result{}, errors.New("record is required")
		}
		if c.Action == "restore_record" && len(controls(fqdn(p.Record.Name, zone), zone)) > 0 {
			return sdk.Result{}, fmt.Errorf("%s carries control over the domain, so it needs restore_record_any", p.Record.Name)
		}
		var got Record
		if p.Replace != "" {
			if err := a.call(ctx, "PUT", "/zones/"+zid+"/dns_records/"+p.Replace, nil, p.Record.body(), &got); err != nil {
				return sdk.Result{}, err
			}
		} else if err := a.call(ctx, "POST", "/zones/"+zid+"/dns_records", nil, p.Record.body(), &got); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(got)
		r.Undo = sdk.UndoWith("delete_record", map[string]any{"zone": zone, "type": got.Type, "name": got.Name}, "Remove "+got.Type+" "+got.Name)
		if p.Replace != "" {
			r.Undo = nil // putting back a changed value; changing it again is a new edit
		}
		return r, nil

	case "purge_cache":
		body := map[string]any{"purge_everything": true}
		if len(p.Files) > 0 {
			body = map[string]any{"files": p.Files}
		}
		if err := a.call(ctx, "POST", "/zones/"+zid+"/purge_cache", nil, body, nil); err != nil {
			return sdk.Result{}, err
		}
		what := "everything"
		if len(p.Files) > 0 {
			what = fmt.Sprintf("%d URLs", len(p.Files))
		}
		return sdk.JSON(map[string]string{"purged": what})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}
