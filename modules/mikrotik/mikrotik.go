// Package mikrotik works with a MikroTik router through the RouterOS v7 REST
// API (/rest, basic auth): system resources and identity, interfaces with
// their traffic, DHCP leases, firewall address lists (adding and removing
// entries, undoable), how many wireless clients are connected, and
// restarting the router. It never reads users, PPP secrets, wireless
// security profiles or anything else that holds a password or key.
package mikrotik

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Config is one router.
type Config struct {
	URL                string `json:"url"`      // e.g. https://192.168.88.1
	Username           string `json:"username"` // a RouterOS user with the rest-api policy
	Password           string `json:"password"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	host  sdk.Host
	cfg   Config
	base  string // https://192.168.88.1/rest
	where string // https://192.168.88.1
	http  *http.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the MikroTik module.
func New() *Module { return &Module{} }

var (
	listRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
	hostRe    = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	timeoutRe = regexp.MustCompile(`^([0-9]{1,4}[wdhms]){1,5}$|^[0-9]{1,3}:[0-5][0-9]:[0-5][0-9]$`)
	idRe      = regexp.MustCompile(`^\*[0-9A-Fa-f]{1,8}$`)
	userRe    = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	entry := `{"type":"object","required":["list","address"],"properties":{
		"list":{"type":"string","description":"Address list name, e.g. blocked"},
		"address":{"type":"string","description":"An IP address, a network (CIDR), a range (a-b) or a DNS name"}%s}}`
	addExtra := `,"comment":{"type":"string","maxLength":200},"timeout":{"type":"string","description":"Remove it automatically after this long, e.g. 1h, 1d12h or 01:00:00"}`
	return sdk.Manifest{
		ID: "mikrotik", Name: "MikroTik", Version: "0.1.0", Category: "Network", Icon: "router",
		Description: "A MikroTik router (RouterOS 7): resources, interfaces and traffic, DHCP leases, firewall address lists, wireless clients.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"The router's web address with www-ssl (or www) enabled, e.g. https://192.168.88.1"},
			"username":{"type":"string","description":"A RouterOS user whose group has the read, rest-api (and for changes write and reboot) policies"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the router's certificate, to trust its own self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "system", Title: "System", Description: "Identity, RouterOS version, board, uptime, CPU load, memory and disk.", Risk: sdk.RiskRead},
			{Name: "interfaces", Title: "Interfaces", Description: "Each interface's type, whether it's running or disabled, MAC address and traffic since boot.", Risk: sdk.RiskRead},
			{Name: "leases", Title: "DHCP leases", Description: "Address, MAC, host name, status and server of each lease.", Risk: sdk.RiskRead},
			{Name: "address_lists", Title: "Firewall address lists", Description: "Each address list with its number of entries (dynamic ones counted apart).", Risk: sdk.RiskRead},
			{Name: "address_list_entries", Title: "Address list entries", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["list"],"properties":{"list":{"type":"string"}}}`)},
			{Name: "add_address_list_entry", Title: "Add to an address list", Description: "Applies at once to every firewall rule using the list. Undo removes it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(fmt.Sprintf(entry, addExtra))},
			{Name: "remove_address_list_entry", Title: "Remove from an address list", Description: "Applies at once to every firewall rule using the list. Undo adds it back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(fmt.Sprintf(entry, ""))},
			{Name: "wireless_clients", Title: "Wireless clients", Description: "How many clients are connected, per interface (wifi, wireless and CAPsMAN registration tables).", Risk: sdk.RiskRead},
			{Name: "reboot", Title: "Restart the router", Description: "The network behind it is cut off for a minute or two.", Risk: sdk.RiskDestructive, DryRun: true},
		},
		Resources: []sdk.ResourceSpec{
			{Kind: "interface", Title: "Interfaces", ListAction: "interfaces", ViewHint: "table"},
			{Kind: "lease", Title: "DHCP leases", ListAction: "leases", ViewHint: "table"},
			{Kind: "address-list", Title: "Address lists", ListAction: "address_lists", GetAction: "address_list_entries", ViewHint: "table"},
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
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/rest") {
		return errors.New("the address is the router's web address, like https://192.168.88.1")
	}
	c.Username = strings.TrimSpace(c.Username)
	if !userRe.MatchString(c.Username) {
		return errors.New("enter the RouterOS user name")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
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
	where := u.Scheme + "://" + u.Host
	m.set.Put(id, &conn{host: h, cfg: c, base: where + "/rest", where: where, http: rest.SameHostOnly(client)})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// do calls the REST API. RouterOS answers errors as
// {"error":400,"message":"Bad Request","detail":"failure: ..."}; the detail
// is what says what went wrong, so it's passed on (redacted).
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	pw, err := c.host.Secret(ctx, c.cfg.Password)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.cfg.Username, pw)
	res, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			if errors.Is(err, rest.ErrCrossHostRedirect) {
				return rest.ErrCrossHostRedirect
			}
			return fmt.Errorf("can't reach the router at %s: %v", c.where, ue.Err)
		}
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return errors.New("RouterOS refused the user name and password")
	case res.StatusCode == http.StatusForbidden:
		return fmt.Errorf("the user isn't allowed to use %s (its group needs the rest-api policy, and write or reboot for changes)", path)
	case res.StatusCode >= 300:
		var e struct {
			Message string `json:"message"`
			Detail  string `json:"detail"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := strings.TrimSpace(strings.TrimSpace(e.Message + ": " + e.Detail))
		msg = strings.Trim(msg, ": ")
		if msg == "" {
			msg = res.Status
		}
		return &rest.Error{Status: res.StatusCode, Message: "RouterOS: " + rest.Redact(msg)}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("unexpected answer from the router: %w", err)
		}
	}
	return nil
}

// RouterOS sends every value as a string.
func num(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }
func yes(s string) bool  { return s == "true" || s == "yes" }

// System is the router's identity and resources.
type System struct {
	Identity     string `json:"identity"`
	Version      string `json:"version"`
	Board        string `json:"board,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Uptime       string `json:"uptime"`
	CPULoad      int64  `json:"cpuLoadPercent"`
	CPUCount     int64  `json:"cpuCount,omitempty"`
	MemoryFree   int64  `json:"memoryFreeBytes"`
	MemoryTotal  int64  `json:"memoryTotalBytes"`
	DiskFree     int64  `json:"diskFreeBytes"`
	DiskTotal    int64  `json:"diskTotalBytes"`
}

func (c *conn) system(ctx context.Context) (System, error) {
	var r map[string]string
	if err := c.do(ctx, http.MethodGet, "/system/resource", nil, nil, &r); err != nil {
		return System{}, err
	}
	var id struct {
		Name string `json:"name"`
	}
	_ = c.do(ctx, http.MethodGet, "/system/identity", nil, nil, &id)
	return System{Identity: id.Name, Version: r["version"], Board: r["board-name"], Architecture: r["architecture-name"], Uptime: r["uptime"],
		CPULoad: num(r["cpu-load"]), CPUCount: num(r["cpu-count"]), MemoryFree: num(r["free-memory"]), MemoryTotal: num(r["total-memory"]),
		DiskFree: num(r["free-hdd-space"]), DiskTotal: num(r["total-hdd-space"])}, nil
}

// entry is one address list row.
type entry struct {
	ID       string `json:".id"`
	List     string `json:"list"`
	Address  string `json:"address"`
	Comment  string `json:"comment"`
	Timeout  string `json:"timeout"`
	Dynamic  string `json:"dynamic"`
	Disabled string `json:"disabled"`
	Created  string `json:"creation-time"`
}

func (e entry) out() map[string]any {
	o := map[string]any{"address": e.Address, "dynamic": yes(e.Dynamic), "disabled": yes(e.Disabled)}
	for k, v := range map[string]string{"comment": e.Comment, "timeout": e.Timeout, "created": e.Created} {
		if v != "" {
			o[k] = v
		}
	}
	return o
}

func (c *conn) entries(ctx context.Context, list string) ([]entry, error) {
	var es []entry
	q := url.Values{}
	if list != "" {
		q.Set("list", list)
	}
	if err := c.do(ctx, http.MethodGet, "/ip/firewall/address-list", q, nil, &es); err != nil {
		return nil, err
	}
	if list == "" {
		return es, nil
	}
	out := es[:0]
	for _, e := range es {
		if e.List == list {
			out = append(out, e)
		}
	}
	return out, nil
}

// validAddress checks one address list entry: an address, a network, a
// range or a DNS name, nothing else. Networks are written in their
// canonical form, the way RouterOS shows them.
func validAddress(s string) (string, error) {
	s = strings.TrimSpace(s)
	bad := fmt.Errorf("%q isn't an address, network, range or DNS name", s)
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " \t\r\n,;\"'") {
		return "", bad
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), nil
	}
	if ip, n, err := net.ParseCIDR(s); err == nil {
		if ones, bits := n.Mask.Size(); ones == bits {
			return ip.String(), nil
		}
		return n.String(), nil
	}
	if a, b, ok := strings.Cut(s, "-"); ok {
		x, y := net.ParseIP(a), net.ParseIP(b)
		if x != nil && y != nil && (x.To4() == nil) == (y.To4() == nil) {
			return x.String() + "-" + y.String(), nil
		}
	}
	if hostRe.MatchString(s) {
		return strings.ToLower(s), nil
	}
	return "", bad
}

func sameAddress(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "/32"), strings.TrimSuffix(b, "/32"))
}

type changeIn struct {
	List    string `json:"list"`
	Address string `json:"address"`
	Comment string `json:"comment"`
	Timeout string `json:"timeout"`
}

// check validates an address list change before anything is asked of the
// router.
func (p *changeIn) check() error {
	p.List = strings.TrimSpace(p.List)
	if !listRe.MatchString(p.List) {
		return errors.New("the list is its name: letters, digits, _ . - (up to 63)")
	}
	a, err := validAddress(p.Address)
	if err != nil {
		return err
	}
	p.Address = a
	p.Comment = strings.TrimSpace(p.Comment)
	if len(p.Comment) > 200 || strings.ContainsFunc(p.Comment, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errors.New("the comment is one line of up to 200 characters")
	}
	p.Timeout = strings.TrimSpace(p.Timeout)
	if p.Timeout != "" && !timeoutRe.MatchString(p.Timeout) {
		return errors.New("the timeout is like 1h, 1d12h or 01:00:00")
	}
	return nil
}

func (c *conn) change(ctx context.Context, call sdk.Call, p changeIn) (sdk.Result, error) {
	add := call.Action == "add_address_list_entry"
	if err := p.check(); err != nil {
		return sdk.Result{}, err
	}
	es, err := c.entries(ctx, p.List)
	if err != nil {
		return sdk.Result{}, err
	}
	var found *entry
	before := []string{}
	for i, e := range es {
		before = append(before, e.Address)
		if found == nil && sameAddress(e.Address, p.Address) {
			found = &es[i]
		}
	}
	if add && found != nil {
		return sdk.Result{}, fmt.Errorf("%s is already in %s", p.Address, p.List)
	}
	if !add && found == nil {
		return sdk.Result{}, fmt.Errorf("%s isn't in %s", p.Address, p.List)
	}
	after := []string{}
	for _, a := range before {
		if !sameAddress(a, p.Address) {
			after = append(after, a)
		}
	}
	if add {
		after = append(after, p.Address)
	}
	if call.DryRun {
		b, _ := json.Marshal(before)
		a, _ := json.Marshal(after)
		verb := "Add " + p.Address + " to"
		if !add {
			verb = "Remove " + p.Address + " from"
		}
		sum := fmt.Sprintf("%s address list %s (%d entries now)", verb, p.List, len(before))
		if add && p.Timeout != "" {
			sum += ", for " + p.Timeout
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "address list " + p.List, Op: "update", Before: b, After: a}}}}, nil
	}
	undoIn := map[string]string{"list": p.List, "address": p.Address}
	if add {
		body := map[string]string{"list": p.List, "address": p.Address}
		if p.Comment != "" {
			body["comment"] = p.Comment
		}
		if p.Timeout != "" {
			body["timeout"] = p.Timeout
		}
		var created entry
		if err := c.do(ctx, http.MethodPut, "/ip/firewall/address-list", nil, body, &created); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"list": p.List, "added": p.Address, "entries": len(after)})
		res.Undo = sdk.UndoWith("remove_address_list_entry", undoIn, "Remove "+p.Address+" from "+p.List)
		return res, err
	}
	if !idRe.MatchString(found.ID) {
		return sdk.Result{}, errors.New("unexpected entry id from the router")
	}
	if err := c.do(ctx, http.MethodDelete, "/ip/firewall/address-list/"+found.ID, nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"list": p.List, "removed": p.Address, "entries": len(after)})
	if found.Comment != "" {
		undoIn["comment"] = found.Comment
	}
	res.Undo = sdk.UndoWith("add_address_list_entry", undoIn, "Add "+p.Address+" back to "+p.List)
	return res, err
}

// wireless counts registered clients per interface across the wireless
// packages RouterOS 7 can run: wifi (wave2), the older wireless package and
// CAPsMAN. Missing packages answer 400 or 404 and are skipped.
func (c *conn) wireless(ctx context.Context) (map[string]any, error) {
	type reg struct {
		Interface string `json:"interface"`
	}
	per := map[string]int{}
	var sources []string
	total := 0
	for _, src := range []struct{ name, path string }{
		{"wifi", "/interface/wifi/registration-table"},
		{"wifiwave2", "/interface/wifiwave2/registration-table"},
		{"wireless", "/interface/wireless/registration-table"},
		{"capsman", "/caps-man/registration-table"},
	} {
		var rs []reg
		err := c.do(ctx, http.MethodGet, src.path, nil, nil, &rs)
		if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		sources = append(sources, src.name)
		for _, r := range rs {
			per[r.Interface]++
			total++
		}
	}
	if len(sources) == 0 {
		return nil, errors.New("this router has no wireless package (wifi, wireless or CAPsMAN)")
	}
	rows := []map[string]any{}
	for name, n := range per {
		rows = append(rows, map[string]any{"interface": name, "clients": n})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i]["interface"].(string) < rows[j]["interface"].(string) })
	return map[string]any{"total": total, "interfaces": rows, "sources": sources}, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.system(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no REST API at this address (RouterOS 7.1 or later, with the www-ssl or www service on)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := strings.TrimSpace(s.Identity + " · RouterOS " + s.Version + " · up " + s.Uptime)
	if s.CPULoad >= 90 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("CPU at %d%% · %s", s.CPULoad, msg)}
	}
	if s.MemoryTotal > 0 && s.MemoryFree*20 < s.MemoryTotal {
		return sdk.Health{Status: "degraded", Message: "memory almost full · " + msg}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p changeIn
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "system":
		s, err := c.system(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(s)

	case "interfaces":
		var rs []map[string]string
		if err := c.do(ctx, http.MethodGet, "/interface", nil, nil, &rs); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, r := range rs {
			out = append(out, map[string]any{"name": r["name"], "type": r["type"], "running": yes(r["running"]), "disabled": yes(r["disabled"]),
				"mac": r["mac-address"], "comment": r["comment"], "mtu": r["actual-mtu"],
				"rxBytes": num(r["rx-byte"]), "txBytes": num(r["tx-byte"]), "rxErrors": num(r["rx-error"]), "txErrors": num(r["tx-error"]),
				"lastLinkUp": r["last-link-up-time"], "linkDowns": num(r["link-downs"])})
		}
		return sdk.JSON(out)

	case "leases":
		var rs []map[string]string
		if err := c.do(ctx, http.MethodGet, "/ip/dhcp-server/lease", nil, nil, &rs); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, r := range rs {
			out = append(out, map[string]any{"address": r["address"], "mac": r["mac-address"], "hostname": r["host-name"], "status": r["status"],
				"server": r["server"], "dynamic": yes(r["dynamic"]), "disabled": yes(r["disabled"]), "expiresAfter": r["expires-after"],
				"lastSeen": r["last-seen"], "comment": r["comment"]})
		}
		return sdk.JSON(out)

	case "address_lists":
		es, err := c.entries(ctx, "")
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			List    string `json:"list"`
			Entries int    `json:"entries"`
			Dynamic int    `json:"dynamic"`
		}
		by := map[string]*row{}
		for _, e := range es {
			r := by[e.List]
			if r == nil {
				r = &row{List: e.List}
				by[e.List] = r
			}
			r.Entries++
			if yes(e.Dynamic) {
				r.Dynamic++
			}
		}
		out := []row{}
		for _, r := range by {
			out = append(out, *r)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].List < out[j].List })
		return sdk.JSON(out)

	case "address_list_entries":
		p.List = strings.TrimSpace(p.List)
		if !listRe.MatchString(p.List) {
			return sdk.Result{}, errors.New("the list is its name: letters, digits, _ . - (up to 63)")
		}
		es, err := c.entries(ctx, p.List)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, e := range es {
			out = append(out, e.out())
		}
		return sdk.JSON(map[string]any{"list": p.List, "entries": out})

	case "add_address_list_entry", "remove_address_list_entry":
		return c.change(ctx, call, p)

	case "wireless_clients":
		w, err := c.wireless(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(w)

	case "reboot":
		s, err := c.system(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		target := strings.TrimSpace(s.Identity + " (RouterOS " + s.Version + ") at " + c.where)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Restart " + target + ", up " + s.Uptime, Changes: []sdk.Change{{Target: target, Op: "restart"}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/system/reboot", nil, map[string]any{}, nil); err != nil {
			// The router may drop the connection as it goes down.
			if !strings.Contains(err.Error(), "EOF") {
				return sdk.Result{}, err
			}
		}
		return sdk.JSON(map[string]string{"rebooting": target})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
