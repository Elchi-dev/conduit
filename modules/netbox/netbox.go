// Package netbox works with a NetBox source of truth through its REST API
// (an API token): searching, devices, IP addresses, prefixes and their
// available addresses, sites and VLANs; reserving the next free address in
// a prefix (undoable) and changing a device's status (undoable). Custom
// fields, config contexts and anything else free-form are left out of the
// answers, since people keep all sorts in them.
package netbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one NetBox.
type Config struct {
	URL                string `json:"url"`   // e.g. https://netbox.example.com
	Token              string `json:"token"` // secret://, a v1 token or a v2 nbt_ token
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

// New returns the NetBox module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	slugRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)
	dnsRe  = regexp.MustCompile(`^(?i)[a-z0-9*]([a-z0-9_-]{0,61}[a-z0-9])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?)*$`)
)

// Device statuses NetBox ships with; IP statuses an address can be reserved with.
var (
	deviceStatuses = []string{"offline", "active", "planned", "staged", "failed", "inventory", "decommissioning"}
	ipStatuses     = []string{"active", "reserved", "dhcp", "slaac", "deprecated"}
)

func oneOf(s string, xs []string) bool {
	for _, x := range xs {
		if s == x {
			return true
		}
	}
	return false
}

func enum(xs []string) string { b, _ := json.Marshal(xs); return string(b) }

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	list := `"q":{"type":"string","description":"Search text"},"site":{"type":"string","description":"Site slug"},"limit":{"type":"integer","default":50,"maximum":500}`
	prefix := `"prefix":{"type":"string","description":"The prefix in CIDR form, e.g. 10.0.20.0/24"},"prefix_id":{"type":"integer","description":"The prefix's id, when the same prefix exists in several VRFs"}`
	return sdk.Manifest{
		ID: "netbox", Name: "NetBox", Version: "0.1.0", Category: "Network", Icon: "network",
		Description: "NetBox: devices, IP addresses, prefixes and free addresses, sites and VLANs; reserve the next free IP, set a device's status.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"NetBox's address, e.g. https://netbox.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API token (your profile, API Tokens); read-only is enough unless agents reserve addresses or change device status"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "search", Title: "Search", Description: "Devices, IP addresses, prefixes, sites and VLANs matching some text.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["q"],"properties":{"q":{"type":"string"},"limit":{"type":"integer","default":10,"maximum":50}}}`)},
			{Name: "devices", Title: "Devices", Description: "Name, status, role, type, site, rack and primary IP.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + list + `,"status":{"type":"string","enum":` + enum(deviceStatuses) + `},"role":{"type":"string","description":"Role slug"}}}`)},
			{Name: "device", Title: "Device", Description: "One device with its interfaces and their addresses.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"id":{"type":"integer"},"name":{"type":"string"}}}`)},
			{Name: "ip_addresses", Title: "IP addresses", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + list + `,"parent":{"type":"string","description":"Only addresses inside this prefix (CIDR)"},"status":{"type":"string","enum":` + enum(ipStatuses) + `}}}`)},
			{Name: "prefixes", Title: "Prefixes", Description: "With site, VLAN, status and how much of each is used.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + list + `}}`)},
			{Name: "available_ips", Title: "Free addresses in a prefix", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + prefix + `,"limit":{"type":"integer","default":10,"maximum":100}}}`)},
			{Name: "sites", Title: "Sites", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","properties":{"q":{"type":"string"},"limit":{"type":"integer","default":50,"maximum":500}}}`)},
			{Name: "vlans", Title: "VLANs", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + list + `,"vid":{"type":"integer","minimum":1,"maximum":4094}}}`)},
			{Name: "reserve_ip", Title: "Reserve the next free IP", Description: "Records the next free address of a prefix in NetBox (nothing on the network changes). Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + prefix + `,"status":{"type":"string","enum":` + enum(ipStatuses) + `,"default":"reserved"},"dns_name":{"type":"string"},"description":{"type":"string","maxLength":200}}}`)},
			{Name: "delete_ip_address", Title: "Delete an IP address", Description: "Removes the address record from NetBox.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"integer"}}}`)},
			{Name: "set_device_status", Title: "Set a device's status", Description: "Undo puts the previous status back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["status"],"properties":{"id":{"type":"integer"},"name":{"type":"string"},"status":{"type":"string","enum":` + enum(deviceStatuses) + `}}}`)},
		},
		Resources: []sdk.ResourceSpec{
			{Kind: "device", Title: "Devices", ListAction: "devices", GetAction: "device", ViewHint: "table"},
			{Kind: "prefix", Title: "Prefixes", ListAction: "prefixes", GetAction: "available_ips", ViewHint: "table"},
			{Kind: "ip", Title: "IP addresses", ListAction: "ip_addresses", ViewHint: "table"},
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
		return errors.New("the address is like https://netbox.example.com")
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
	ref := c.Token
	api := rest.New(u.Scheme+"://"+u.Host+p+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		// NetBox 4.5's v2 tokens are nbt_<key>.<token> and use Bearer.
		if strings.HasPrefix(t, "nbt_") {
			r.Header.Set("Authorization", "Bearer "+t)
		} else {
			r.Header.Set("Authorization", "Token "+t)
		}
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) || (rest.IsStatus(err, http.StatusForbidden) && strings.Contains(strings.ToLower(err.Error()), "token")) {
		return errors.New("NetBox refused the API token")
	}
	if rest.IsStatus(err, http.StatusForbidden) {
		return fmt.Errorf("the token isn't allowed to do this (%s); it may be read-only, or its user lacks the permission", rest.Redact(err.Error()))
	}
	return err
}

// ref is a nested object; NetBox writes name, display or address.
type ref struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Slug    string `json:"slug"`
	Display string `json:"display"`
	Address string `json:"address"`
	Model   string `json:"model"`
	VID     int    `json:"vid"`
}

func (r *ref) label() string {
	if r == nil {
		return ""
	}
	for _, s := range []string{r.Name, r.Model, r.Address, r.Display} {
		if s != "" {
			return s
		}
	}
	return ""
}

type choice struct {
	Value string `json:"value"`
}

func (c *choice) v() string {
	if c == nil {
		return ""
	}
	return c.Value
}

type page[T any] struct {
	Count   int `json:"count"`
	Results []T `json:"results"`
}

// Device is a device row.
type device struct {
	ID         int     `json:"id"`
	Name       string  `json:"name"`
	Status     *choice `json:"status"`
	Role       *ref    `json:"role"`
	DeviceRole *ref    `json:"device_role"` // NetBox 3.x
	DeviceType *ref    `json:"device_type"`
	Site       *ref    `json:"site"`
	Rack       *ref    `json:"rack"`
	Tenant     *ref    `json:"tenant"`
	Platform   *ref    `json:"platform"`
	PrimaryIP  *ref    `json:"primary_ip"`
	Serial     string  `json:"serial"`
	AssetTag   *string `json:"asset_tag"`
	Desc       string  `json:"description"`
}

func (d device) out() map[string]any {
	role := d.Role
	if role == nil {
		role = d.DeviceRole
	}
	o := map[string]any{"id": d.ID, "name": d.Name, "status": d.Status.v(), "role": role.label(), "type": d.DeviceType.label(),
		"site": d.Site.label(), "rack": d.Rack.label(), "primaryIP": d.PrimaryIP.label(), "platform": d.Platform.label(), "tenant": d.Tenant.label()}
	if d.Serial != "" {
		o["serial"] = d.Serial
	}
	if d.Desc != "" {
		o["description"] = d.Desc
	}
	return o
}

type ipAddr struct {
	ID          int     `json:"id"`
	Address     string  `json:"address"`
	Status      *choice `json:"status"`
	Role        *choice `json:"role"`
	DNSName     string  `json:"dns_name"`
	Description string  `json:"description"`
	VRF         *ref    `json:"vrf"`
	Tenant      *ref    `json:"tenant"`
	Assigned    *struct {
		Name   string `json:"name"`
		Device *ref   `json:"device"`
		VM     *ref   `json:"virtual_machine"`
	} `json:"assigned_object"`
}

func (a ipAddr) out() map[string]any {
	o := map[string]any{"id": a.ID, "address": a.Address, "status": a.Status.v(), "dnsName": a.DNSName, "description": a.Description, "vrf": a.VRF.label()}
	if r := a.Role.v(); r != "" {
		o["role"] = r
	}
	if a.Assigned != nil {
		on := a.Assigned.Device.label()
		if on == "" {
			on = a.Assigned.VM.label()
		}
		o["assignedTo"] = strings.Trim(on+" "+a.Assigned.Name, " ")
	}
	return o
}

type prefix struct {
	ID          int     `json:"id"`
	Prefix      string  `json:"prefix"`
	Status      *choice `json:"status"`
	Site        *ref    `json:"site"`
	Scope       *ref    `json:"scope"` // NetBox 4.2+
	VRF         *ref    `json:"vrf"`
	VLAN        *ref    `json:"vlan"`
	Role        *ref    `json:"role"`
	IsPool      bool    `json:"is_pool"`
	Description string  `json:"description"`
}

func (p prefix) out() map[string]any {
	site := p.Site.label()
	if site == "" {
		site = p.Scope.label()
	}
	o := map[string]any{"id": p.ID, "prefix": p.Prefix, "status": p.Status.v(), "site": site, "vrf": p.VRF.label(), "role": p.Role.label(), "isPool": p.IsPool, "description": p.Description}
	if p.VLAN != nil {
		o["vlan"] = strings.TrimSpace(fmt.Sprintf("%d %s", p.VLAN.VID, p.VLAN.Name))
	}
	return o
}

type site struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Slug        string  `json:"slug"`
	Status      *choice `json:"status"`
	Region      *ref    `json:"region"`
	Facility    string  `json:"facility"`
	Description string  `json:"description"`
	Devices     *int    `json:"device_count"`
}

type vlan struct {
	ID          int     `json:"id"`
	VID         int     `json:"vid"`
	Name        string  `json:"name"`
	Status      *choice `json:"status"`
	Site        *ref    `json:"site"`
	Group       *ref    `json:"group"`
	Role        *ref    `json:"role"`
	Description string  `json:"description"`
}

type input struct {
	Q           string `json:"q"`
	Site        string `json:"site"`
	Role        string `json:"role"`
	Status      string `json:"status"`
	Limit       int    `json:"limit"`
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Parent      string `json:"parent"`
	Prefix      string `json:"prefix"`
	PrefixID    int    `json:"prefix_id"`
	VID         int    `json:"vid"`
	DNSName     string `json:"dns_name"`
	Description string `json:"description"`
}

func clean(s string, max int, what string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > max || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", fmt.Errorf("the %s is one line of up to %d characters", what, max)
	}
	return s, nil
}

// query builds a list query from the common filters.
func (p input) query(def, max int) (url.Values, error) {
	q := url.Values{}
	n := p.Limit
	if n <= 0 {
		n = def
	}
	if n > max {
		n = max
	}
	q.Set("limit", strconv.Itoa(n))
	s, err := clean(p.Q, 100, "search")
	if err != nil {
		return nil, err
	}
	if s != "" {
		q.Set("q", s)
	}
	if p.Site != "" {
		if !slugRe.MatchString(p.Site) {
			return nil, errors.New("the site is its slug, e.g. hq")
		}
		q.Set("site", p.Site)
	}
	if p.Role != "" {
		if !slugRe.MatchString(p.Role) {
			return nil, errors.New("the role is its slug, e.g. core-switch")
		}
		q.Set("role", p.Role)
	}
	return q, nil
}

func (c *conn) devices(ctx context.Context, q url.Values) (page[device], error) {
	var pg page[device]
	err := c.do(ctx, http.MethodGet, "/dcim/devices/", q, nil, &pg)
	return pg, err
}

// device finds one device by id or exact name.
func (c *conn) device(ctx context.Context, id int, name string) (device, error) {
	if id < 0 {
		return device{}, errors.New("the id is a positive number")
	}
	if id > 0 {
		var d device
		err := c.do(ctx, http.MethodGet, "/dcim/devices/"+strconv.Itoa(id)+"/", nil, nil, &d)
		if rest.IsStatus(err, http.StatusNotFound) {
			return device{}, fmt.Errorf("no device %d", id)
		}
		return d, err
	}
	name, err := clean(name, 64, "device name")
	if err != nil {
		return device{}, err
	}
	if name == "" {
		return device{}, errors.New("give the device's id or name")
	}
	pg, err := c.devices(ctx, url.Values{"name": {name}, "limit": {"5"}})
	if err != nil {
		return device{}, err
	}
	switch len(pg.Results) {
	case 0:
		return device{}, fmt.Errorf("no device named %s", name)
	case 1:
		return pg.Results[0], nil
	}
	return device{}, fmt.Errorf("%d devices are named %s (one per site or tenant); give the id", len(pg.Results), name)
}

// prefix finds one prefix by id or CIDR.
func (c *conn) prefix(ctx context.Context, id int, cidr string) (prefix, error) {
	if id < 0 {
		return prefix{}, errors.New("the prefix id is a positive number")
	}
	if id > 0 {
		var p prefix
		err := c.do(ctx, http.MethodGet, "/ipam/prefixes/"+strconv.Itoa(id)+"/", nil, nil, &p)
		if rest.IsStatus(err, http.StatusNotFound) {
			return prefix{}, fmt.Errorf("no prefix %d", id)
		}
		return p, err
	}
	cidr = strings.TrimSpace(cidr)
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return prefix{}, errors.New("give the prefix in CIDR form (10.0.20.0/24) or its id")
	}
	var pg page[prefix]
	if err := c.do(ctx, http.MethodGet, "/ipam/prefixes/", url.Values{"prefix": {n.String()}, "limit": {"5"}}, nil, &pg); err != nil {
		return prefix{}, err
	}
	switch len(pg.Results) {
	case 0:
		return prefix{}, fmt.Errorf("NetBox has no prefix %s", n)
	case 1:
		return pg.Results[0], nil
	}
	return prefix{}, fmt.Errorf("%s exists %d times (in different VRFs); give prefix_id", n, len(pg.Results))
}

type freeIP struct {
	Address string `json:"address"`
	VRF     *ref   `json:"vrf"`
}

func (c *conn) available(ctx context.Context, p prefix, n int) ([]freeIP, error) {
	var out []freeIP
	err := c.do(ctx, http.MethodGet, "/ipam/prefixes/"+strconv.Itoa(p.ID)+"/available-ips/", url.Values{"limit": {strconv.Itoa(n)}}, nil, &out)
	return out, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s struct {
		Version string `json:"netbox-version"`
		Workers int    `json:"rq-workers-running"`
	}
	if err := c.do(ctx, http.MethodGet, "/status/", nil, nil, &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no NetBox API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	// The status page can be public; a listing proves the token works.
	var pg page[site]
	if err := c.do(ctx, http.MethodGet, "/dcim/sites/", url.Values{"limit": {"1"}}, nil, &pg); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("NetBox %s · %d sites", s.Version, pg.Count)}
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
	case "search":
		if strings.TrimSpace(p.Q) == "" {
			return sdk.Result{}, errors.New("enter something to search for")
		}
		q, err := input{Q: p.Q, Limit: p.Limit}.query(10, 50)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{}
		var ds page[device]
		if err := c.do(ctx, http.MethodGet, "/dcim/devices/", q, nil, &ds); err != nil {
			return sdk.Result{}, err
		}
		var ips page[ipAddr]
		var pfx page[prefix]
		var sites page[site]
		var vlans page[vlan]
		for path, dst := range map[string]any{"/ipam/ip-addresses/": &ips, "/ipam/prefixes/": &pfx, "/dcim/sites/": &sites, "/ipam/vlans/": &vlans} {
			if err := c.do(ctx, http.MethodGet, path, q, nil, dst); err != nil {
				return sdk.Result{}, err
			}
		}
		out["devices"], out["ipAddresses"], out["prefixes"], out["sites"], out["vlans"] = rows(ds.Results, device.out), rows(ips.Results, ipAddr.out), rows(pfx.Results, prefix.out), rows(sites.Results, siteOut), rows(vlans.Results, vlanOut)
		return sdk.JSON(out)

	case "devices":
		q, err := p.query(50, 500)
		if err != nil {
			return sdk.Result{}, err
		}
		if p.Status != "" {
			if !oneOf(p.Status, deviceStatuses) {
				return sdk.Result{}, errors.New("the status is one of " + strings.Join(deviceStatuses, ", "))
			}
			q.Set("status", p.Status)
		}
		pg, err := c.devices(ctx, q)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"count": pg.Count, "devices": rows(pg.Results, device.out)})

	case "device":
		d, err := c.device(ctx, p.ID, p.Name)
		if err != nil {
			return sdk.Result{}, err
		}
		var ifs page[struct {
			ID      int     `json:"id"`
			Name    string  `json:"name"`
			Type    *choice `json:"type"`
			Enabled bool    `json:"enabled"`
			MAC     *string `json:"mac_address"`
			Desc    string  `json:"description"`
		}]
		q := url.Values{"device_id": {strconv.Itoa(d.ID)}, "limit": {"500"}}
		if err := c.do(ctx, http.MethodGet, "/dcim/interfaces/", q, nil, &ifs); err != nil {
			return sdk.Result{}, err
		}
		var ips page[ipAddr]
		if err := c.do(ctx, http.MethodGet, "/ipam/ip-addresses/", q, nil, &ips); err != nil {
			return sdk.Result{}, err
		}
		out := d.out()
		list := []map[string]any{}
		for _, i := range ifs.Results {
			addrs := []string{}
			for _, a := range ips.Results {
				if a.Assigned != nil && a.Assigned.Name == i.Name {
					addrs = append(addrs, a.Address)
				}
			}
			row := map[string]any{"name": i.Name, "type": i.Type.v(), "enabled": i.Enabled, "addresses": addrs}
			if i.MAC != nil {
				row["mac"] = *i.MAC
			}
			list = append(list, row)
		}
		out["interfaces"] = list
		return sdk.JSON(out)

	case "ip_addresses":
		q, err := p.query(50, 500)
		if err != nil {
			return sdk.Result{}, err
		}
		if p.Parent != "" {
			_, n, err := net.ParseCIDR(strings.TrimSpace(p.Parent))
			if err != nil {
				return sdk.Result{}, errors.New("the parent is a prefix in CIDR form, e.g. 10.0.20.0/24")
			}
			q.Set("parent", n.String())
		}
		if p.Status != "" {
			if !oneOf(p.Status, ipStatuses) {
				return sdk.Result{}, errors.New("the status is one of " + strings.Join(ipStatuses, ", "))
			}
			q.Set("status", p.Status)
		}
		var pg page[ipAddr]
		if err := c.do(ctx, http.MethodGet, "/ipam/ip-addresses/", q, nil, &pg); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"count": pg.Count, "ipAddresses": rows(pg.Results, ipAddr.out)})

	case "prefixes":
		q, err := p.query(50, 500)
		if err != nil {
			return sdk.Result{}, err
		}
		var pg page[prefix]
		if err := c.do(ctx, http.MethodGet, "/ipam/prefixes/", q, nil, &pg); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"count": pg.Count, "prefixes": rows(pg.Results, prefix.out)})

	case "available_ips":
		pf, err := c.prefix(ctx, p.PrefixID, p.Prefix)
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.Limit
		if n <= 0 || n > 100 {
			n = 10
		}
		free, err := c.available(ctx, pf, n)
		if err != nil {
			return sdk.Result{}, err
		}
		addrs := []string{}
		for _, f := range free {
			addrs = append(addrs, f.Address)
		}
		return sdk.JSON(map[string]any{"prefix": pf.Prefix, "prefixId": pf.ID, "vrf": pf.VRF.label(), "available": addrs})

	case "sites":
		q, err := input{Q: p.Q, Limit: p.Limit}.query(50, 500)
		if err != nil {
			return sdk.Result{}, err
		}
		var pg page[site]
		if err := c.do(ctx, http.MethodGet, "/dcim/sites/", q, nil, &pg); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"count": pg.Count, "sites": rows(pg.Results, siteOut)})

	case "vlans":
		q, err := p.query(50, 500)
		if err != nil {
			return sdk.Result{}, err
		}
		if p.VID != 0 {
			if p.VID < 1 || p.VID > 4094 {
				return sdk.Result{}, errors.New("the VLAN id is 1 to 4094")
			}
			q.Set("vid", strconv.Itoa(p.VID))
		}
		var pg page[vlan]
		if err := c.do(ctx, http.MethodGet, "/ipam/vlans/", q, nil, &pg); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"count": pg.Count, "vlans": rows(pg.Results, vlanOut)})

	case "reserve_ip":
		st := p.Status
		if st == "" {
			st = "reserved"
		}
		if !oneOf(st, ipStatuses) {
			return sdk.Result{}, errors.New("the status is one of " + strings.Join(ipStatuses, ", "))
		}
		dns := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.DNSName), "."))
		if dns != "" && (len(dns) > 255 || !dnsRe.MatchString(dns)) {
			return sdk.Result{}, errors.New("the DNS name is a host name like nas.lan")
		}
		desc, err := clean(p.Description, 200, "description")
		if err != nil {
			return sdk.Result{}, err
		}
		if desc == "" {
			desc = "reserved by Conduit"
		}
		pf, err := c.prefix(ctx, p.PrefixID, p.Prefix)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			free, err := c.available(ctx, pf, 1)
			if err != nil {
				return sdk.Result{}, err
			}
			if len(free) == 0 {
				return sdk.Result{}, fmt.Errorf("%s has no free addresses", pf.Prefix)
			}
			after, _ := json.Marshal(map[string]string{"address": free[0].Address, "status": st, "dns_name": dns, "description": desc})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Reserve %s in %s (%s)", free[0].Address, pf.Prefix, st),
				Changes: []sdk.Change{{Target: "prefix " + pf.Prefix, Op: "create", After: after}}}}, nil
		}
		body := map[string]string{"status": st, "description": desc}
		if dns != "" {
			body["dns_name"] = dns
		}
		// NetBox picks the address and creates it in one locked step, so two
		// callers never get the same one.
		var got ipAddr
		if err := c.do(ctx, http.MethodPost, "/ipam/prefixes/"+strconv.Itoa(pf.ID)+"/available-ips/", nil, body, &got); err != nil {
			if rest.IsStatus(err, http.StatusConflict) || rest.IsStatus(err, http.StatusNoContent) {
				return sdk.Result{}, fmt.Errorf("%s has no free addresses", pf.Prefix)
			}
			return sdk.Result{}, err
		}
		if got.ID <= 0 {
			return sdk.Result{}, errors.New("unexpected answer from NetBox")
		}
		res, err := sdk.JSON(got.out())
		res.Undo = sdk.UndoWith("delete_ip_address", map[string]int{"id": got.ID}, "Delete "+got.Address+" from NetBox")
		return res, err

	case "delete_ip_address":
		if p.ID <= 0 {
			return sdk.Result{}, errors.New("give the address's id")
		}
		var a ipAddr
		if err := c.do(ctx, http.MethodGet, "/ipam/ip-addresses/"+strconv.Itoa(p.ID)+"/", nil, nil, &a); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("no IP address %d", p.ID)
			}
			return sdk.Result{}, err
		}
		if call.DryRun {
			before, _ := json.Marshal(a.out())
			return sdk.Result{Plan: &sdk.Plan{Summary: "Delete " + a.Address + " from NetBox", Changes: []sdk.Change{{Target: "ip address " + a.Address, Op: "delete", Before: before}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/ipam/ip-addresses/"+strconv.Itoa(a.ID)+"/", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": a.Address, "id": a.ID})

	case "set_device_status":
		if !oneOf(p.Status, deviceStatuses) {
			return sdk.Result{}, errors.New("the status is one of " + strings.Join(deviceStatuses, ", "))
		}
		d, err := c.device(ctx, p.ID, p.Name)
		if err != nil {
			return sdk.Result{}, err
		}
		old := d.Status.v()
		if old == p.Status {
			return sdk.Result{}, fmt.Errorf("%s is already %s", d.Name, old)
		}
		if call.DryRun {
			b, _ := json.Marshal(old)
			a, _ := json.Marshal(p.Status)
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Set %s from %s to %s", d.Name, old, p.Status),
				Changes: []sdk.Change{{Target: "device " + d.Name, Op: "update", Before: b, After: a}}}}, nil
		}
		var nd device
		if err := c.do(ctx, http.MethodPatch, "/dcim/devices/"+strconv.Itoa(d.ID)+"/", nil, map[string]string{"status": p.Status}, &nd); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"device": d.Name, "id": d.ID, "status": nd.Status.v(), "was": old})
		if old != "" {
			res.Undo = sdk.UndoWith("set_device_status", map[string]any{"id": d.ID, "status": old}, "Set "+d.Name+" back to "+old)
		}
		return res, err
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func rows[T any](xs []T, f func(T) map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, x := range xs {
		out = append(out, f(x))
	}
	return out
}

func siteOut(s site) map[string]any {
	o := map[string]any{"id": s.ID, "name": s.Name, "slug": s.Slug, "status": s.Status.v(), "region": s.Region.label(), "facility": s.Facility, "description": s.Description}
	if s.Devices != nil {
		o["devices"] = *s.Devices
	}
	return o
}

func vlanOut(v vlan) map[string]any {
	return map[string]any{"id": v.ID, "vid": v.VID, "name": v.Name, "status": v.Status.v(), "site": v.Site.label(), "group": v.Group.label(), "role": v.Role.label(), "description": v.Description}
}
