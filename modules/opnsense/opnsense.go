// Package opnsense works with an OPNsense firewall through its API (an API
// key and secret): firmware and update status, interfaces, gateways, DHCP
// leases, firewall aliases (with adding and removing entries, undoable),
// and restarting the firewall.
package opnsense

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one OPNsense.
type Config struct {
	URL                string `json:"url"`    // e.g. https://192.168.1.1
	Key                string `json:"key"`    // secret:// API key
	Secret             string `json:"secret"` // secret:// API secret
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api  *rest.Client
	base string
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the OPNsense module.
func New() *Module { return &Module{} }

var (
	aliasRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)
	hostRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*\.?$`)
	portRe  = regexp.MustCompile(`^[0-9]{1,5}(:[0-9]{1,5})?$`)
)

// Alias types whose entries this module can change. Content-based types
// are edited in the configuration and applied; "external" aliases are
// filled at run time, which is what OPNsense's alias_util API is for.
var editable = map[string]bool{"host": true, "network": true, "port": true, "mac": true, "external": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	entry := `{"type":"object","required":["alias","entry"],"properties":{"alias":{"type":"string","description":"Alias name, e.g. blocklist"},"entry":{"type":"string","description":"An address, network (CIDR), host name, port or MAC address, as the alias type takes"}}}`
	return sdk.Manifest{
		ID: "opnsense", Name: "OPNsense", Version: "0.1.0", Category: "Network", Icon: "shield",
		Description: "An OPNsense firewall: updates, interfaces, gateways, DHCP leases and firewall aliases.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","key","secret"],"properties":{
			"url":{"type":"string","description":"The firewall's web address, e.g. https://192.168.1.1"},
			"key":{"type":"string","x-secret":true,"description":"API key (System, Access, Users, your user, API keys)"},
			"secret":{"type":"string","x-secret":true,"description":"The API secret from the same downloaded file"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the firewall's certificate, to trust its own self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "firmware", Title: "Firmware", Description: "Version, and whether updates are waiting or a restart is needed (from the last check).", Risk: sdk.RiskRead},
			{Name: "interfaces", Title: "Interfaces", Description: "Each interface's device, state and addresses.", Risk: sdk.RiskRead},
			{Name: "gateways", Title: "Gateways", Description: "Online or down, with loss and latency.", Risk: sdk.RiskRead},
			{Name: "leases", Title: "DHCP leases", Description: "From ISC DHCP, Kea or Dnsmasq, whichever runs.", Risk: sdk.RiskRead},
			{Name: "aliases", Title: "Firewall aliases", Risk: sdk.RiskRead},
			{Name: "alias_entries", Title: "Alias entries", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["alias"],"properties":{"alias":{"type":"string"}}}`)},
			{Name: "add_alias_entry", Title: "Add to an alias", Description: "Applies at once to every rule using the alias. Undo removes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(entry)},
			{Name: "remove_alias_entry", Title: "Remove from an alias", Description: "Applies at once to every rule using the alias. Undo adds it back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(entry)},
			{Name: "reboot", Title: "Restart the firewall", Description: "The network behind it is cut off for a few minutes.", Risk: sdk.RiskDestructive, DryRun: true},
		},
		Resources: []sdk.ResourceSpec{
			{Kind: "alias", Title: "Aliases", ListAction: "aliases", GetAction: "alias_entries", ViewHint: "table"},
			{Kind: "lease", Title: "DHCP leases", ListAction: "leases", ViewHint: "table"},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(c.URL), "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || (u.Path != "" && u.Path != "/api") {
		return errors.New("the address is the firewall's web address, like https://192.168.1.1")
	}
	if !strings.HasPrefix(c.Key, "secret://") || !strings.HasPrefix(c.Secret, "secret://") {
		return errors.New("store the API key and secret in the vault and enter their secret:// references")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h)
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	key, sec := c.Key, c.Secret
	base := u.Scheme + "://" + u.Host
	api := rest.New(base+"/api", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, key)
		if err != nil {
			return err
		}
		s, err := h.Secret(ctx, sec)
		if err != nil {
			return err
		}
		r.SetBasicAuth(strings.TrimSpace(k), strings.TrimSpace(s))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, base: base})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	if method == http.MethodPost && body == nil {
		body = map[string]any{}
	}
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		return errors.New("OPNsense refused the API key and secret")
	}
	if rest.IsStatus(err, http.StatusForbidden) {
		return fmt.Errorf("the API key's user isn't allowed to use %s (add the privilege under System, Access)", path)
	}
	return err
}

// str reads values OPNsense sends as strings or numbers.
type str string

func (s *str) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case string:
		*s = str(x)
	case float64:
		*s = str(strconv.FormatFloat(x, 'f', -1, 64))
	case bool:
		*s = str(strconv.FormatBool(x))
	default:
		*s = ""
	}
	return nil
}

// Firmware is the update status.
type Firmware struct {
	Product     string `json:"product"`
	Version     string `json:"version"`
	Status      string `json:"status"` // none, update, upgrade, error
	Message     string `json:"message,omitempty"`
	Updates     string `json:"updates,omitempty"`
	NeedsReboot bool   `json:"needsReboot"`
	LastCheck   string `json:"lastCheck,omitempty"`
}

func (c *conn) firmware(ctx context.Context) (Firmware, error) {
	type product struct {
		Name    str `json:"product_name"`
		Version str `json:"product_version"`
		Check   *struct {
			LastCheck   str `json:"last_check"`
			NeedsReboot str `json:"needs_reboot"`
		} `json:"product_check"`
	}
	var r struct {
		product
		Product     *product `json:"product"`
		Status      str      `json:"status"`
		StatusMsg   str      `json:"status_msg"`
		Updates     str      `json:"updates"`
		NeedsReboot str      `json:"needs_reboot"`
		LastCheck   str      `json:"last_check"`
	}
	if err := c.do(ctx, http.MethodGet, "/core/firmware/status", nil, nil, &r); err != nil {
		return Firmware{}, err
	}
	p := r.product
	if r.Product != nil {
		p = *r.Product
	}
	f := Firmware{Product: string(p.Name), Version: string(p.Version), Status: string(r.Status), Message: string(r.StatusMsg),
		Updates: string(r.Updates), NeedsReboot: r.NeedsReboot == "1" || r.NeedsReboot == "true", LastCheck: string(r.LastCheck)}
	if p.Check != nil {
		if f.LastCheck == "" {
			f.LastCheck = string(p.Check.LastCheck)
		}
		f.NeedsReboot = f.NeedsReboot || p.Check.NeedsReboot == "1"
	}
	if f.Product == "" {
		f.Product = "OPNsense"
	}
	return f, nil
}

// Gateway is one gateway's state.
type Gateway struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Status  string `json:"status"` // online, down, loss, delay...
	Loss    string `json:"loss,omitempty"`
	Delay   string `json:"delay,omitempty"`
	Monitor string `json:"monitor,omitempty"`
}

func (c *conn) gateways(ctx context.Context) ([]Gateway, error) {
	var r struct {
		Items []struct {
			Name       str `json:"name"`
			Address    str `json:"address"`
			Status     str `json:"status"`
			Translated str `json:"status_translated"`
			Loss       str `json:"loss"`
			Delay      str `json:"delay"`
			Monitor    str `json:"monitor"`
		} `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/routes/gateway/status", nil, nil, &r); err != nil {
		return nil, err
	}
	out := []Gateway{}
	for _, g := range r.Items {
		st := string(g.Status)
		if st == "none" {
			st = "online"
		}
		out = append(out, Gateway{Name: string(g.Name), Address: string(g.Address), Status: st, Loss: string(g.Loss), Delay: string(g.Delay), Monitor: string(g.Monitor)})
	}
	return out, nil
}

// alias is one alias row.
type alias struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Enabled     string `json:"enabled"`
	Content     string `json:"content"`
}

func (c *conn) aliases(ctx context.Context, phrase string) ([]alias, error) {
	q := url.Values{"current": {"1"}, "rowCount": {"-1"}}
	if phrase != "" {
		q.Set("searchPhrase", phrase)
	}
	var r struct {
		Rows []struct {
			UUID        str `json:"uuid"`
			Name        str `json:"name"`
			Type        str `json:"type"`
			Description str `json:"description"`
			Enabled     str `json:"enabled"`
			Content     str `json:"content"`
		} `json:"rows"`
	}
	if err := c.do(ctx, http.MethodGet, "/firewall/alias/searchItem", q, nil, &r); err != nil {
		return nil, err
	}
	out := []alias{}
	for _, a := range r.Rows {
		out = append(out, alias{UUID: string(a.UUID), Name: string(a.Name), Type: strings.ToLower(string(a.Type)), Description: string(a.Description), Enabled: string(a.Enabled), Content: string(a.Content)})
	}
	return out, nil
}

func (c *conn) alias(ctx context.Context, name string) (alias, error) {
	if !aliasRe.MatchString(name) {
		return alias{}, errors.New("the alias is its name: letters, digits and _ (up to 32)")
	}
	as, err := c.aliases(ctx, name)
	if err != nil {
		return alias{}, err
	}
	for _, a := range as {
		if a.Name == name {
			// The type column can be a translated label; trust getItem.
			return a, nil
		}
	}
	return alias{}, fmt.Errorf("no alias %s", name)
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)

// stored reads an alias's configured type and entries.
func (c *conn) stored(ctx context.Context, a alias) (string, []string, error) {
	if !uuidRe.MatchString(a.UUID) {
		return "", nil, errors.New("unexpected alias id from OPNsense")
	}
	var r struct {
		Alias struct {
			Type    json.RawMessage `json:"type"`
			Content json.RawMessage `json:"content"`
		} `json:"alias"`
	}
	if err := c.do(ctx, http.MethodGet, "/firewall/alias/getItem/"+a.UUID, nil, nil, &r); err != nil {
		return "", nil, err
	}
	return selected(r.Alias.Type, a.Type), entries(r.Alias.Content), nil
}

// selected picks the chosen option of an OPNsense option list (or a plain
// string).
func selected(raw json.RawMessage, fallback string) string {
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		return strings.ToLower(s)
	}
	var opts map[string]struct {
		Selected any `json:"selected"`
	}
	if json.Unmarshal(raw, &opts) == nil {
		for k, o := range opts {
			if o.Selected == true || o.Selected == float64(1) || o.Selected == "1" {
				return strings.ToLower(k)
			}
		}
	}
	return fallback
}

// entries reads alias content: an option map of the entries (selected ones
// count), or newline / comma separated text.
func entries(raw json.RawMessage) []string {
	out := []string{}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		for _, e := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' }) {
			if e = strings.TrimSpace(e); e != "" {
				out = append(out, e)
			}
		}
		return out
	}
	var opts map[string]struct {
		Value    string `json:"value"`
		Selected any    `json:"selected"`
	}
	if json.Unmarshal(raw, &opts) == nil {
		for k, o := range opts {
			if k == "" || !(o.Selected == true || o.Selected == float64(1) || o.Selected == "1") {
				continue
			}
			out = append(out, k)
		}
		sort.Strings(out)
	}
	return out
}

// validEntry checks an entry against the alias type, so nothing but one
// entry (no separators) can reach the configuration.
func validEntry(typ, e string) (string, error) {
	e = strings.TrimSpace(e)
	bad := fmt.Errorf("%q isn't a valid entry for a %s alias", e, typ)
	if e == "" || len(e) > 255 || strings.ContainsAny(e, " \t\r\n,;") {
		return "", bad
	}
	switch typ {
	case "port":
		if !portRe.MatchString(e) {
			return "", bad
		}
		for _, p := range strings.Split(e, ":") {
			if n, _ := strconv.Atoi(p); n < 1 || n > 65535 {
				return "", bad
			}
		}
	case "mac":
		if _, err := net.ParseMAC(e); err != nil {
			return "", bad
		}
	case "host", "network", "external":
		if net.ParseIP(e) != nil {
			return e, nil
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			if typ == "host" {
				return "", bad
			}
			return n.String(), nil
		}
		if typ == "external" || !hostRe.MatchString(e) {
			return "", bad
		}
	default:
		return "", fmt.Errorf("entries of %s aliases can't be changed from here", typ)
	}
	return e, nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// current lists an alias's entries: the live table for external aliases,
// the configuration for the rest.
func (c *conn) current(ctx context.Context, a alias) (string, []string, error) {
	typ, list, err := c.stored(ctx, a)
	if err != nil {
		return "", nil, err
	}
	if typ == "external" {
		var r struct {
			Rows []struct {
				IP str `json:"ip"`
			} `json:"rows"`
		}
		if err := c.do(ctx, http.MethodGet, "/firewall/alias_util/list/"+a.Name, nil, nil, &r); err != nil {
			return "", nil, err
		}
		list = []string{}
		for _, x := range r.Rows {
			list = append(list, string(x.IP))
		}
	}
	return typ, list, nil
}

func (c *conn) change(ctx context.Context, call sdk.Call, name, entry string) (sdk.Result, error) {
	add := call.Action == "add_alias_entry"
	a, err := c.alias(ctx, name)
	if err != nil {
		return sdk.Result{}, err
	}
	typ, list, err := c.current(ctx, a)
	if err != nil {
		return sdk.Result{}, err
	}
	if !editable[typ] {
		return sdk.Result{}, fmt.Errorf("%s is a %s alias; only host, network, port, MAC and external aliases can be changed from here", name, typ)
	}
	e, err := validEntry(typ, entry)
	if err != nil {
		return sdk.Result{}, err
	}
	has := contains(list, e)
	if add && has {
		return sdk.Result{}, fmt.Errorf("%s is already in %s", e, name)
	}
	if !add && !has {
		return sdk.Result{}, fmt.Errorf("%s isn't in %s", e, name)
	}
	next := []string{}
	for _, x := range list {
		if !strings.EqualFold(x, e) {
			next = append(next, x)
		}
	}
	if add {
		next = append(next, e)
	}
	if call.DryRun {
		before, _ := json.Marshal(list)
		after, _ := json.Marshal(next)
		verb, op := "Add "+e+" to", "update"
		if !add {
			verb = "Remove " + e + " from"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("%s alias %s (%s, %d entries now)", verb, name, typ, len(list)),
			Changes: []sdk.Change{{Target: "alias " + name, Op: op, Before: before, After: after}}}}, nil
	}
	if typ == "external" {
		op := "add"
		if !add {
			op = "delete"
		}
		var r struct {
			Status str `json:"status"`
		}
		if err := c.do(ctx, http.MethodPost, "/firewall/alias_util/"+op+"/"+name, nil, map[string]string{"address": e}, &r); err != nil {
			return sdk.Result{}, err
		}
		if r.Status != "done" {
			return sdk.Result{}, fmt.Errorf("OPNsense didn't change %s (%s)", name, r.Status)
		}
	} else {
		var r struct {
			Result      str            `json:"result"`
			Validations map[string]any `json:"validations"`
		}
		body := map[string]any{"alias": map[string]string{"content": strings.Join(next, "\n")}}
		if err := c.do(ctx, http.MethodPost, "/firewall/alias/setItem/"+a.UUID, nil, body, &r); err != nil {
			return sdk.Result{}, err
		}
		if r.Result != "saved" {
			for _, v := range r.Validations {
				return sdk.Result{}, fmt.Errorf("OPNsense refused the change: %v", v)
			}
			return sdk.Result{}, fmt.Errorf("OPNsense didn't save %s (%s)", name, r.Result)
		}
		var ap struct {
			Status str `json:"status"`
		}
		if err := c.do(ctx, http.MethodPost, "/firewall/alias/reconfigure", nil, nil, &ap); err != nil {
			return sdk.Result{}, fmt.Errorf("saved, but applying failed: %w", err)
		}
	}
	res, err := sdk.JSON(map[string]any{"alias": name, "entries": next})
	in := map[string]string{"alias": name, "entry": e}
	if add {
		res.Undo = sdk.UndoWith("remove_alias_entry", in, "Remove "+e+" from "+name)
	} else {
		res.Undo = sdk.UndoWith("add_alias_entry", in, "Add "+e+" back to "+name)
	}
	return res, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	f, err := c.firmware(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := strings.TrimSpace(f.Product + " " + f.Version)
	if f.Status == "update" || f.Status == "upgrade" {
		msg += " · updates waiting"
	}
	if f.NeedsReboot {
		msg += " · needs a restart"
	}
	if gws, err := c.gateways(ctx); err == nil {
		var down []string
		for _, g := range gws {
			if g.Status == "down" || g.Status == "force_down" {
				down = append(down, g.Name)
			}
		}
		if len(down) > 0 {
			return sdk.Health{Status: "degraded", Message: "gateway down: " + strings.Join(down, ", ") + " · " + msg}
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Alias string `json:"alias"`
		Entry string `json:"entry"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "firmware":
		f, err := c.firmware(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(f)

	case "gateways":
		gws, err := c.gateways(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(gws)

	case "interfaces":
		var r struct {
			Rows []struct {
				Identifier  str `json:"identifier"`
				Description str `json:"description"`
				Device      str `json:"device"`
				Status      str `json:"status"`
				Enabled     str `json:"enabled"`
				Addr4       str `json:"addr4"`
				Addr6       str `json:"addr6"`
				MAC         str `json:"macaddr"`
				LinkType    str `json:"link_type"`
				Gateways    any `json:"gateways"`
			} `json:"rows"`
		}
		if err := c.do(ctx, http.MethodGet, "/interfaces/overview/interfacesInfo", nil, nil, &r); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, errors.New("this OPNsense doesn't have the interfaces overview API (needs 23.7 or later)")
			}
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range r.Rows {
			out = append(out, map[string]any{"name": string(x.Description), "id": string(x.Identifier), "device": string(x.Device), "status": string(x.Status),
				"enabled": x.Enabled == "true" || x.Enabled == "1", "ipv4": string(x.Addr4), "ipv6": string(x.Addr6), "mac": string(x.MAC), "type": string(x.LinkType)})
		}
		return sdk.JSON(out)

	case "leases":
		type row struct {
			Address  str `json:"address"`
			MAC      str `json:"mac"`
			HWAddr   str `json:"hwaddr"`
			Hostname str `json:"hostname"`
			State    str `json:"state"`
			Status   str `json:"status"`
			Ends     str `json:"ends"`
			Expire   str `json:"expire"`
			Iface    str `json:"if_descr"`
			Type     str `json:"type"`
		}
		var lastErr error
		for _, src := range []struct{ name, path string }{
			{"isc", "/dhcpv4/leases/searchLease"}, {"kea", "/kea/leases4/search"}, {"dnsmasq", "/dnsmasq/leases/search"},
		} {
			var r struct {
				Rows []row `json:"rows"`
			}
			err := c.do(ctx, http.MethodGet, src.path, url.Values{"current": {"1"}, "rowCount": {"-1"}}, nil, &r)
			if rest.IsStatus(err, http.StatusNotFound) {
				lastErr = err
				continue
			}
			if err != nil {
				return sdk.Result{}, err
			}
			if len(r.Rows) == 0 && src.name != "dnsmasq" {
				// The service may be installed but unused; try the next.
				lastErr = nil
				continue
			}
			out := []map[string]string{}
			for _, x := range r.Rows {
				mac, ends := x.MAC, x.Ends
				if mac == "" {
					mac = x.HWAddr
				}
				if ends == "" {
					ends = x.Expire
				}
				if n, err := strconv.ParseInt(string(ends), 10, 64); err == nil && n > 1e9 {
					ends = str(time.Unix(n, 0).UTC().Format(time.RFC3339))
				}
				st := x.State
				if st == "" {
					st = x.Status
				}
				out = append(out, map[string]string{"address": string(x.Address), "mac": string(mac), "hostname": string(x.Hostname),
					"state": string(st), "ends": string(ends), "interface": string(x.Iface), "type": string(x.Type), "server": src.name})
			}
			return sdk.JSON(out)
		}
		if lastErr != nil {
			return sdk.Result{}, errors.New("no DHCP server's lease API answered (ISC DHCP, Kea or Dnsmasq)")
		}
		return sdk.JSON([]map[string]string{})

	case "aliases":
		as, err := c.aliases(ctx, "")
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, a := range as {
			out = append(out, map[string]any{"name": a.Name, "type": a.Type, "description": a.Description, "enabled": a.Enabled == "1",
				"entries": len(entries(json.RawMessage(strconv.Quote(a.Content))))})
		}
		return sdk.JSON(out)

	case "alias_entries":
		a, err := c.alias(ctx, p.Alias)
		if err != nil {
			return sdk.Result{}, err
		}
		typ, list, err := c.current(ctx, a)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"alias": a.Name, "type": typ, "entries": list, "editable": editable[typ]})

	case "add_alias_entry", "remove_alias_entry":
		if !aliasRe.MatchString(p.Alias) {
			return sdk.Result{}, errors.New("the alias is its name: letters, digits and _ (up to 32)")
		}
		if strings.TrimSpace(p.Entry) == "" || strings.ContainsAny(p.Entry, "\r\n,;") {
			return sdk.Result{}, errors.New("enter one entry")
		}
		return c.change(ctx, call, p.Alias, p.Entry)

	case "reboot":
		f, err := c.firmware(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		target := strings.TrimSpace(f.Product + " " + f.Version + " at " + c.base)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Restart " + target, Changes: []sdk.Change{{Target: target, Op: "restart"}}}}, nil
		}
		var r struct {
			Status str `json:"status"`
		}
		if err := c.do(ctx, http.MethodPost, "/core/system/reboot", nil, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"rebooting": target})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
