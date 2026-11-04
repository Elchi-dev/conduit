// Package ntopng reads an ntopng traffic monitor through its REST API v2
// with an API token: monitored interfaces and their traffic, the busiest
// hosts, and alerts.
package ntopng

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// Config is one ntopng.
type Config struct {
	URL                string `json:"url"`   // e.g. https://ntop.example.com:3000
	Token              string `json:"token"` // secret:// API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the ntopng module.
func New() *Module { return &Module{} }

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// Alert families ntopng keeps apart.
var families = []string{"host", "flow", "interface", "network", "system", "mac", "snmp_device", "active_monitoring", "user"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	ifid := `"interface":{"type":"integer","description":"Interface id (from interfaces); default the first one"}`
	return sdk.Manifest{
		ID: "ntopng", Name: "ntopng", Version: "0.1.0", Category: "Monitoring", Icon: "chart",
		Description: "An ntopng traffic monitor: interfaces and their traffic, the busiest hosts, alerts.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"ntopng's address, e.g. http://192.168.1.5:3000"},
			"token":{"type":"string","x-secret":true,"description":"An API token (your user menu, then API Token); it acts with that user's rights"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of ntopng's certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "interfaces", Title: "Interfaces", Description: "Each monitored interface with its throughput, hosts, devices, flows, traffic and drops since start, and engaged alerts.", Risk: sdk.RiskRead},
			{Name: "top_hosts", Title: "Top hosts", Description: "The hosts with the most traffic on an interface: address, name, traffic sent and received, throughput, flows, score, local or remote, country. It names people's devices, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + ifid + `,"limit":{"type":"integer","default":10,"maximum":100},"localOnly":{"type":"boolean","default":false,"description":"Only hosts on the local networks"}}}`)},
			{Name: "alerts", Title: "Alerts", Description: "Engaged (still going on) or past alerts of one family, newest first: time, severity, type, score, the host or entity and the message. Alerts name hosts, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + ifid + `,"family":{"type":"string","enum":["host","flow","interface","network","system","mac","snmp_device","active_monitoring","user"],"default":"host"},"engaged":{"type":"boolean","default":true,"description":"Alerts still going on (true) or past ones (false)"},"limit":{"type":"integer","default":25,"maximum":200}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is ntopng's, like http://192.168.1.5:3000")
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
	ref := c.Token
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/")+"/lua/rest/v2", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Token "+strings.TrimSpace(t))
		return nil
	})
	hc := rest.SameHostOnly(client)
	// ntopng answers a refused token with a redirect to its login page:
	// stop there instead of reading the page as an answer.
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.HasSuffix(req.URL.Path, "/login.lua") || strings.HasSuffix(req.URL.Path, "/authorize.html") {
			return http.ErrUseLastResponse
		}
		return rest.SameHostRedirects(req, via)
	}
	api.HTTP = hc
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// get calls one endpoint and decodes its rsp.
func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	var r struct {
		RC    int             `json:"rc"`
		RCStr string          `json:"rc_str"`
		Rsp   json.RawMessage `json:"rsp"`
	}
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, &r)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusFound), rest.IsStatus(err, http.StatusSeeOther):
		return errors.New("ntopng refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the token's user isn't allowed to see this in ntopng")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no ntopng REST API v2 at this address (ntopng 5 or later)")
	case err != nil:
		return err
	}
	if r.RC != 0 {
		msg := strings.ToLower(strings.ReplaceAll(r.RCStr, "_", " "))
		if msg == "" {
			msg = fmt.Sprintf("error %d", r.RC)
		}
		if r.RC == -2 || strings.Contains(msg, "not granted") {
			return errors.New("the token's user isn't allowed to see this in ntopng")
		}
		return fmt.Errorf("ntopng: %s", rest.Redact(msg))
	}
	if out != nil && len(r.Rsp) > 0 {
		if err := json.Unmarshal(r.Rsp, out); err != nil {
			return fmt.Errorf("unexpected answer from ntopng: %w", err)
		}
	}
	return nil
}

type ifaceRef struct {
	ID   int    `json:"ifid"`
	Name string `json:"ifname"`
	Desc string `json:"name"`
}

func (c *conn) interfaces(ctx context.Context) ([]ifaceRef, error) {
	var is []ifaceRef
	if err := c.get(ctx, "/get/ntopng/interfaces.lua", nil, &is); err != nil {
		return nil, err
	}
	sort.Slice(is, func(i, j int) bool { return is[i].ID < is[j].ID })
	return is, nil
}

// ifid checks an interface id against the ones ntopng has, or picks the
// first.
func (c *conn) ifid(ctx context.Context, want *int) (ifaceRef, error) {
	is, err := c.interfaces(ctx)
	if err != nil {
		return ifaceRef{}, err
	}
	if len(is) == 0 {
		return ifaceRef{}, errors.New("ntopng monitors no interface")
	}
	if want == nil {
		return is[0], nil
	}
	for _, i := range is {
		if i.ID == *want {
			return i, nil
		}
	}
	return ifaceRef{}, fmt.Errorf("there's no interface %d (see interfaces)", *want)
}

// num reads a number ntopng sends as a number or a string.
func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	case map[string]any:
		for _, k := range []string{"total", "value", "bps"} {
			if y, ok := x[k]; ok {
				return num(y)
			}
		}
	}
	return 0
}

// label reads a value ntopng sends as text or as {label, value, name}.
func label(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case map[string]any:
		for _, k := range []string{"label", "name", "title", "descr", "value"} {
			if y, ok := x[k]; ok && y != nil {
				if s := label(y); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func sub(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	is, err := c.interfaces(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	names := []string{}
	for _, i := range is {
		names = append(names, firstOf(i.Desc, i.Name))
	}
	if len(is) == 0 {
		return sdk.Health{Status: "degraded", Message: "ntopng monitors no interface"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("monitoring %s", strings.Join(names, ", "))}
}

func firstOf(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Interface *int   `json:"interface"`
		Limit     int    `json:"limit"`
		LocalOnly bool   `json:"localOnly"`
		Family    string `json:"family"`
		Engaged   *bool  `json:"engaged"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if p.Interface != nil && (*p.Interface < -1 || *p.Interface > 4096) {
		return sdk.Result{}, errors.New("the interface is its id from interfaces")
	}
	switch call.Action {
	case "interfaces":
		is, err := c.interfaces(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, i := range is {
			row := map[string]any{"id": i.ID, "name": firstOf(i.Desc, i.Name), "device": i.Name}
			var d map[string]any
			if c.get(ctx, "/get/interface/data.lua", url.Values{"ifid": {strconv.Itoa(i.ID)}}, &d) == nil {
				row["throughputBitsPerSecond"] = num(firstAny(d["throughput_bps"], sub(d, "throughput", "bps")))
				row["hosts"], row["localHosts"], row["devices"], row["flows"] = num(d["num_hosts"]), num(d["num_local_hosts"]), num(d["num_devices"]), num(d["num_flows"])
				row["bytes"], row["packets"], row["drops"] = num(d["bytes"]), num(d["packets"]), num(d["drops"])
				row["engagedAlerts"], row["alertedFlows"] = num(d["engaged_alerts"]), num(d["alerted_flows"])
				if s := label(d["speed"]); s != "" {
					row["speedMbps"] = num(d["speed"])
				}
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "top_hosts":
		if p.Limit <= 0 || p.Limit > 100 {
			p.Limit = 10
		}
		i, err := c.ifid(ctx, p.Interface)
		if err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{"ifid": {strconv.Itoa(i.ID)}, "sortColumn": {"traffic"}, "sortOrder": {"desc"}, "perPage": {strconv.Itoa(p.Limit)}, "currentPage": {"1"}}
		if p.LocalOnly {
			q.Set("mode", "local")
		}
		var r struct {
			Data []map[string]any `json:"data"`
		}
		if err := c.get(ctx, "/get/host/active.lua", q, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, h := range r.Data {
			row := map[string]any{"ip": label(h["ip"]), "name": label(h["name"]),
				"bytesSent": num(firstAny(sub(h, "bytes", "sent"), h["bytes.sent"])), "bytesReceived": num(firstAny(sub(h, "bytes", "rcvd"), h["bytes.rcvd"])),
				"bytesTotal": num(h["bytes"]), "throughputBitsPerSecond": num(firstAny(sub(h, "thpt", "bps"), h["thpt"])),
				"flows": num(h["num_flows"]), "score": num(h["score"]), "local": h["is_localhost"] == true || h["localhost"] == true}
			for k, src := range map[string]string{"country": "country", "os": "os", "vlan": "vlan", "mac": "mac"} {
				if s := label(h[src]); s != "" && s != "0" {
					row[k] = s
				}
			}
			out = append(out, row)
			if len(out) >= p.Limit {
				break
			}
		}
		sort.SliceStable(out, func(a, b int) bool { return out[a]["bytesTotal"].(float64) > out[b]["bytesTotal"].(float64) })
		return sdk.JSON(map[string]any{"interface": firstOf(i.Desc, i.Name), "hosts": out})

	case "alerts":
		if p.Limit <= 0 || p.Limit > 200 {
			p.Limit = 25
		}
		if p.Family == "" {
			p.Family = "host"
		}
		known := false
		for _, f := range families {
			known = known || f == p.Family
		}
		if !known {
			return sdk.Result{}, fmt.Errorf("the family is one of %s", strings.Join(families, ", "))
		}
		i, err := c.ifid(ctx, p.Interface)
		if err != nil {
			return sdk.Result{}, err
		}
		status := "engaged"
		if p.Engaged != nil && !*p.Engaged {
			status = "historical"
		}
		q := url.Values{"ifid": {strconv.Itoa(i.ID)}, "status": {status}, "start": {"0"}, "length": {strconv.Itoa(p.Limit)},
			"sort": {"tstamp"}, "order": {"desc"}, "epoch_begin": {strconv.FormatInt(time.Now().Add(-7*24*time.Hour).Unix(), 10)}, "epoch_end": {strconv.FormatInt(time.Now().Unix(), 10)}}
		var r json.RawMessage
		if err := c.get(ctx, "/get/"+url.PathEscape(p.Family)+"/alert/list.lua", q, &r); err != nil {
			return sdk.Result{}, err
		}
		var rows []map[string]any
		if json.Unmarshal(r, &rows) != nil {
			var wrapped struct {
				Records []map[string]any `json:"records"`
				Data    []map[string]any `json:"data"`
			}
			_ = json.Unmarshal(r, &wrapped)
			rows = append(wrapped.Records, wrapped.Data...)
		}
		out := []map[string]any{}
		for _, a := range rows {
			row := map[string]any{"time": label(firstAny(sub(a, "tstamp", "value"), a["tstamp"])), "severity": label(a["severity"]), "type": label(a["alert_id"]),
				"score": num(a["score"]), "message": rest.Redact(label(firstAny(sub(a, "msg", "descr"), a["msg"])))}
			for k, src := range map[string]string{"entity": "entity_val", "ip": "ip", "name": "name", "client": "cli_ip", "server": "srv_ip"} {
				if s := label(a[src]); s != "" {
					row[k] = s
				}
			}
			out = append(out, row)
			if len(out) >= p.Limit {
				break
			}
		}
		return sdk.JSON(map[string]any{"interface": firstOf(i.Desc, i.Name), "family": p.Family, "status": status, "alerts": out})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func firstAny(vs ...any) any {
	for _, v := range vs {
		if v != nil {
			return v
		}
	}
	return nil
}
