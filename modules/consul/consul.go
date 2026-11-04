// Package consul works with a HashiCorp Consul cluster through its HTTP API:
// members, services and their health checks, the KV store (listing keys,
// reading a value, writing and deleting one with check-and-set) and
// deregistering a service instance.
package consul

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Consul agent (and the cluster behind it).
type Config struct {
	Address            string `json:"address"`    // e.g. https://consul.example.com:8501
	Token              string `json:"token"`      // secret:// ACL token; empty when ACLs are off
	Datacenter         string `json:"datacenter"` // empty for the agent's own
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api   *rest.Client
	dc    string
	token bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Consul module.
func New() *Module { return &Module{} }

const maxValue = 512 << 10 // Consul's default KV value limit

var (
	dcRe      = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	serviceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	idRe      = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,256}$`)
	nodeRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	segRe     = regexp.MustCompile(`^[A-Za-z0-9_.@+=:,~ -]{1,256}$`)
	states    = map[string]bool{"any": true, "passing": true, "warning": true, "critical": true}
)

// kvPath checks a KV key (or, with folder, a prefix that may be empty or end
// in "/") and returns it escaped segment by segment.
func kvPath(s string, folder bool) (string, error) {
	if folder {
		s = strings.TrimPrefix(s, "/")
		if s == "" {
			return "", nil
		}
	}
	trail := strings.HasSuffix(s, "/")
	if trail && !folder {
		return "", errors.New("a key doesn't end in /")
	}
	s = strings.TrimSuffix(s, "/")
	if s == "" || len(s) > 512 {
		return "", errors.New("the key is like config/app/db")
	}
	parts := strings.Split(s, "/")
	for i, p := range parts {
		if p == "." || p == ".." || !segRe.MatchString(p) || strings.TrimSpace(p) != p {
			return "", fmt.Errorf("%q isn't a valid key (letters, digits and _ . @ + = : , ~ - between slashes)", s)
		}
		parts[i] = url.PathEscape(p)
	}
	out := strings.Join(parts, "/")
	if trail {
		out += "/"
	}
	return out, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	dc := `"datacenter":{"type":"string","description":"Datacenter (the instance's when empty)"}`
	key := `"key":{"type":"string","description":"KV key, e.g. config/app/db"}`
	return sdk.Manifest{
		ID: "consul", Name: "Consul", Version: "0.1.0", Category: "Infrastructure", Icon: "network",
		Description: "HashiCorp Consul: members, services and health checks, KV keys and values, writing and deleting a key, deregistering a service.",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["address"],"properties":{
			"address":{"type":"string","description":"The Consul HTTP API of an agent, e.g. https://consul.example.com:8501"},
			"token":{"type":"string","x-secret":true,"description":"ACL token (secret ID); leave empty when ACLs are off. Its policy decides what works"},
			"datacenter":{"type":"string","description":"Datacenter; empty for the agent's own"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "members", Title: "Members", Description: "Cluster members (LAN gossip) with address, status, role and version.", Risk: sdk.RiskRead},
			{Name: "services", Title: "Services", Description: "Services in the catalog with tags, instance count and checks passing, warning and critical.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + dc + `}}`)},
			{Name: "service_health", Title: "Service health", Description: "Each instance of a service: node, address, port, tags and its checks with status and output.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["service"],"properties":{` + dc + `,"service":{"type":"string"},"passingOnly":{"type":"boolean"}}}`)},
			{Name: "checks", Title: "Health checks", Description: "Checks in a state (critical by default; any, passing, warning) with node, service and output.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + dc + `,"state":{"type":"string","enum":["any","passing","warning","critical"],"default":"critical"}}}`)},
			{Name: "kv_list", Title: "List KV keys", Description: "Keys and folders under a prefix. Never values.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + dc + `,"prefix":{"type":"string","description":"Folder, e.g. config/ (the top when empty)"},"recurse":{"type":"boolean","description":"Every key below, not only the next level"}}}`)},
			{Name: "kv_get", Title: "Read a KV value", Description: "One key's value (text, or base64 for binary), flags, index and lock session.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["key"],"properties":{` + dc + `,` + key + `}}`)},
			{Name: "kv_put", Title: "Write a KV value", Description: "Sets a key's value, refused if the key changed since it was looked at. The preview shows sizes, never values. Undo puts back the old value (or deletes a new key).", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["key","value"],"properties":{` + dc + `,` + key + `,"value":{"type":"string"},"base64":{"type":"boolean","description":"The value is base64 (binary)"},"cas":{"type":"integer","minimum":0,"description":"Only if the key's modify index is still this (0: only if it doesn't exist)"}}}`)},
			{Name: "kv_delete", Title: "Delete a KV key", Description: "Deletes one key (never a whole tree), refused if it changed since it was looked at. Undo puts it back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["key"],"properties":{` + dc + `,` + key + `,"cas":{"type":"integer","minimum":1,"description":"Only if the key's modify index is still this"}}}`)},
			{Name: "deregister_service", Title: "Deregister a service", Description: "Removes one service instance from the catalog (through its own agent when that's the one configured). The preview shows the instance and its checks.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["service"],"properties":{` + dc + `,"service":{"type":"string","description":"Service name"},"id":{"type":"string","description":"Service instance ID, needed when there are several"},"node":{"type":"string","description":"Node the instance is on"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.Address))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return errors.New("the address is like https://consul.example.com:8501")
	}
	if c.Token != "" && !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the ACL token in the vault and enter its secret:// reference")
	}
	dc := strings.TrimSpace(c.Datacenter)
	if dc != "" && !dcRe.MatchString(dc) {
		return errors.New("the datacenter is its name, like dc1")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	tok := c.Token
	api := rest.New(u.Scheme+"://"+u.Host, func(ctx context.Context, r *http.Request) error {
		if tok == "" {
			return nil
		}
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("X-Consul-Token", strings.TrimSpace(t))
		return nil
	})
	// The token is a custom header, which Go would forward on a redirect.
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, dc: dc, token: tok != ""})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusForbidden), rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Consul refused: permission denied (check the ACL token and its policy)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	}
	return err
}

func (c *conn) q(dc string) url.Values {
	q := url.Values{}
	if dc != "" {
		q.Set("dc", dc)
	} else if c.dc != "" {
		q.Set("dc", c.dc)
	}
	return q
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var leader string
	if err := c.do(ctx, http.MethodGet, "/v1/status/leader", c.q(""), nil, &leader); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "leader").Error()}
	}
	if leader == "" {
		return sdk.Health{Status: "degraded", Message: "the cluster has no leader"}
	}
	msg := "leader " + leader
	if c.token {
		var self struct {
			Description string `json:"Description"`
		}
		err := c.do(ctx, http.MethodGet, "/v1/acl/token/self", nil, nil, &self)
		switch {
		case err == nil:
			msg += " · token " + self.Description
		case strings.Contains(strings.ToLower(err.Error()), "acl support disabled"):
			msg += " · ACLs are off"
		case rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusUnauthorized):
			return sdk.Health{Status: "down", Message: "Consul refused the ACL token"}
		default:
			return sdk.Health{Status: "down", Message: err.Error()}
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Datacenter  string  `json:"datacenter"`
	Service     string  `json:"service"`
	PassingOnly bool    `json:"passingOnly"`
	State       string  `json:"state"`
	Prefix      string  `json:"prefix"`
	Recurse     bool    `json:"recurse"`
	Key         string  `json:"key"`
	Value       *string `json:"value"`
	Base64      bool    `json:"base64"`
	CAS         *uint64 `json:"cas"`
	ID          string  `json:"id"`
	Node        string  `json:"node"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func clip(s string, k int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > k {
		return string(r[:k]) + "…"
	}
	return string(r)
}

type check struct {
	Node        string `json:"Node"`
	CheckID     string `json:"CheckID"`
	Name        string `json:"Name"`
	Status      string `json:"Status"`
	Output      string `json:"Output"`
	ServiceID   string `json:"ServiceID"`
	ServiceName string `json:"ServiceName"`
	Type        string `json:"Type"`
}

func (k check) summary() map[string]any {
	e := map[string]any{"node": k.Node, "check": k.Name, "id": k.CheckID, "status": k.Status, "output": clip(k.Output, 300)}
	if k.ServiceName != "" {
		e["service"] = k.ServiceName
		e["serviceId"] = k.ServiceID
	}
	if k.Type != "" {
		e["type"] = k.Type
	}
	return e
}

type instance struct {
	Node struct {
		Node       string `json:"Node"`
		Address    string `json:"Address"`
		Datacenter string `json:"Datacenter"`
	} `json:"Node"`
	Service struct {
		ID      string   `json:"ID"`
		Service string   `json:"Service"`
		Address string   `json:"Address"`
		Port    int      `json:"Port"`
		Tags    []string `json:"Tags"`
	} `json:"Service"`
	Checks []check `json:"Checks"`
}

func (in instance) label() string {
	addr := in.Service.Address
	if addr == "" {
		addr = in.Node.Address
	}
	return fmt.Sprintf("%s on %s (%s:%d)", in.Service.ID, in.Node.Node, addr, in.Service.Port)
}

func datacenter(p input) (string, error) {
	dc := strings.TrimSpace(p.Datacenter)
	if dc != "" && !dcRe.MatchString(dc) {
		return "", fmt.Errorf("%q isn't a datacenter name", dc)
	}
	return dc, nil
}

type kvPair struct {
	Key         string  `json:"Key"`
	Value       *string `json:"Value"` // base64
	Flags       uint64  `json:"Flags"`
	CreateIndex uint64  `json:"CreateIndex"`
	ModifyIndex uint64  `json:"ModifyIndex"`
	LockIndex   uint64  `json:"LockIndex"`
	Session     string  `json:"Session"`
}

func (p kvPair) bytes() []byte {
	if p.Value == nil {
		return nil
	}
	b, _ := base64.StdEncoding.DecodeString(*p.Value)
	return b
}

// getKV returns a key, or found false when it doesn't exist.
func (c *conn) getKV(ctx context.Context, esc string, q url.Values) (kvPair, bool, error) {
	var pairs []kvPair
	err := c.do(ctx, http.MethodGet, "/v1/kv/"+esc, q, nil, &pairs)
	if rest.IsStatus(err, http.StatusNotFound) {
		return kvPair{}, false, nil
	}
	if err != nil {
		return kvPair{}, false, friendly(err, "key")
	}
	if len(pairs) != 1 {
		return kvPair{}, false, errors.New("unexpected answer from Consul")
	}
	return pairs[0], true, nil
}

// send makes a KV write or delete and reports Consul's true or false.
func (c *conn) send(ctx context.Context, method, esc string, q url.Values, body []byte) (bool, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	res, err := c.api.Send(ctx, method, "/v1/kv/"+esc, q, rd, http.Header{"Content-Type": {"application/octet-stream"}})
	if err != nil {
		return false, friendly(err, "key")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return false, fmt.Errorf("Consul answered %s", res.Status)
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 64))
	return strings.TrimSpace(string(b)) == "true", nil
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
	dc, err := datacenter(p)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "members":
		var ms []struct {
			Name   string            `json:"Name"`
			Addr   string            `json:"Addr"`
			Port   int               `json:"Port"`
			Status int               `json:"Status"`
			Tags   map[string]string `json:"Tags"`
		}
		if err := c.do(ctx, http.MethodGet, "/v1/agent/members", nil, nil, &ms); err != nil {
			return sdk.Result{}, friendly(err, "member")
		}
		status := []string{"none", "alive", "leaving", "left", "failed"}
		out := []map[string]any{}
		for _, mb := range ms {
			st := "unknown"
			if mb.Status >= 0 && mb.Status < len(status) {
				st = status[mb.Status]
			}
			role := mb.Tags["role"]
			if role == "node" {
				role = "client"
			}
			if role == "consul" {
				role = "server"
			}
			out = append(out, map[string]any{"name": mb.Name, "address": mb.Addr, "status": st, "role": role, "datacenter": mb.Tags["dc"], "version": mb.Tags["build"]})
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
		return sdk.JSON(out)

	case "services":
		var svcs map[string][]string
		if err := c.do(ctx, http.MethodGet, "/v1/catalog/services", c.q(dc), nil, &svcs); err != nil {
			return sdk.Result{}, friendly(err, "datacenter "+dc)
		}
		var checks []check
		if err := c.do(ctx, http.MethodGet, "/v1/health/state/any", c.q(dc), nil, &checks); err != nil {
			return sdk.Result{}, friendly(err, "datacenter "+dc)
		}
		type agg struct {
			ids                        map[string]bool
			passing, warning, critical int
		}
		by := map[string]*agg{}
		for _, k := range checks {
			if k.ServiceName == "" {
				continue
			}
			a := by[k.ServiceName]
			if a == nil {
				a = &agg{ids: map[string]bool{}}
				by[k.ServiceName] = a
			}
			a.ids[k.Node+"/"+k.ServiceID] = true
			switch k.Status {
			case "passing":
				a.passing++
			case "warning":
				a.warning++
			case "critical":
				a.critical++
			}
		}
		names := make([]string, 0, len(svcs))
		for n := range svcs {
			names = append(names, n)
		}
		sort.Strings(names)
		out := []map[string]any{}
		for _, n := range names {
			e := map[string]any{"service": n, "tags": svcs[n]}
			if a := by[n]; a != nil {
				e["instances"] = len(a.ids)
				e["checks"] = map[string]int{"passing": a.passing, "warning": a.warning, "critical": a.critical}
				st := "passing"
				if a.critical > 0 {
					st = "critical"
				} else if a.warning > 0 {
					st = "warning"
				}
				e["status"] = st
			} else {
				e["status"] = "no checks"
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "service_health":
		ins, err := c.instances(ctx, dc, p.Service, p.PassingOnly)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, in := range ins {
			var cs []map[string]any
			for _, k := range in.Checks {
				cs = append(cs, k.summary())
			}
			out = append(out, map[string]any{"id": in.Service.ID, "node": in.Node.Node, "address": firstNonEmpty(in.Service.Address, in.Node.Address), "port": in.Service.Port, "tags": in.Service.Tags, "checks": cs})
		}
		return sdk.JSON(out)

	case "checks":
		st := p.State
		if st == "" {
			st = "critical"
		}
		if !states[st] {
			return sdk.Result{}, errors.New("the state is any, passing, warning or critical")
		}
		var checks []check
		if err := c.do(ctx, http.MethodGet, "/v1/health/state/"+st, c.q(dc), nil, &checks); err != nil {
			return sdk.Result{}, friendly(err, "datacenter "+dc)
		}
		out := []map[string]any{}
		for i, k := range checks {
			if i == 500 {
				break
			}
			out = append(out, k.summary())
		}
		return sdk.JSON(out)

	case "kv_list":
		esc, err := kvPath(p.Prefix, true)
		if err != nil {
			return sdk.Result{}, err
		}
		if esc != "" && !strings.HasSuffix(esc, "/") {
			esc += "/"
		}
		q := c.q(dc)
		q.Set("keys", "")
		if !p.Recurse {
			q.Set("separator", "/")
		}
		var ks []string
		err = c.do(ctx, http.MethodGet, "/v1/kv/"+esc, q, nil, &ks)
		if err != nil && !rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, friendly(err, "prefix")
		}
		keys, folders := []string{}, []string{}
		for i, k := range ks {
			if i == 1000 {
				break
			}
			if strings.HasSuffix(k, "/") {
				folders = append(folders, k)
			} else {
				keys = append(keys, k)
			}
		}
		out := map[string]any{"prefix": p.Prefix, "keys": keys, "folders": folders}
		if len(ks) > 1000 {
			out["truncated"] = len(ks)
		}
		return sdk.JSON(out)

	case "kv_get":
		esc, err := kvPath(p.Key, false)
		if err != nil {
			return sdk.Result{}, err
		}
		kv, found, err := c.getKV(ctx, esc, c.q(dc))
		if err != nil {
			return sdk.Result{}, err
		}
		if !found {
			return sdk.Result{}, fmt.Errorf("there's no key %s", p.Key)
		}
		out := map[string]any{"name": kv.Key, "flags": kv.Flags, "modifyIndex": kv.ModifyIndex, "createIndex": kv.CreateIndex}
		b := kv.bytes()
		if utf8.Valid(b) {
			out["value"] = string(b)
		} else {
			out["base64"] = base64.StdEncoding.EncodeToString(b)
		}
		out["bytes"] = len(b)
		if kv.Session != "" {
			out["lockedBySession"] = kv.Session
		}
		return sdk.JSON(out)

	case "kv_put":
		return c.put(ctx, call, dc, p)
	case "kv_delete":
		return c.del(ctx, call, dc, p)
	case "deregister_service":
		return c.deregister(ctx, call, dc, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (c *conn) instances(ctx context.Context, dc, name string, passing bool) ([]instance, error) {
	name = strings.TrimSpace(name)
	if !serviceRe.MatchString(name) {
		return nil, errors.New("the service is its name (see services)")
	}
	q := c.q(dc)
	if passing {
		q.Set("passing", "true")
	}
	var ins []instance
	if err := c.do(ctx, http.MethodGet, "/v1/health/service/"+url.PathEscape(name), q, nil, &ins); err != nil {
		return nil, friendly(err, "service "+name)
	}
	return ins, nil
}

// undoValue is the input that puts a key back as it was.
func undoValue(key, dc string, old kvPair, cas uint64) map[string]any {
	in := map[string]any{"key": key, "cas": cas}
	if dc != "" {
		in["datacenter"] = dc
	}
	b := old.bytes()
	if utf8.Valid(b) {
		in["value"] = string(b)
	} else {
		in["value"], in["base64"] = base64.StdEncoding.EncodeToString(b), true
	}
	return in
}

func (c *conn) put(ctx context.Context, call sdk.Call, dc string, p input) (sdk.Result, error) {
	key := strings.TrimSpace(p.Key)
	esc, err := kvPath(key, false)
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Value == nil {
		return sdk.Result{}, errors.New("give the value")
	}
	val := []byte(*p.Value)
	if p.Base64 {
		if val, err = base64.StdEncoding.DecodeString(*p.Value); err != nil {
			return sdk.Result{}, errors.New("the value isn't valid base64")
		}
	}
	if len(val) > maxValue {
		return sdk.Result{}, fmt.Errorf("the value is over %d KiB", maxValue>>10)
	}
	old, found, err := c.getKV(ctx, esc, c.q(dc))
	if err != nil {
		return sdk.Result{}, err
	}
	idx := uint64(0)
	if found {
		idx = old.ModifyIndex
	}
	if p.CAS != nil && *p.CAS != idx {
		return sdk.Result{}, fmt.Errorf("%s changed since (its index is %d, not %d), so this is refused", key, idx, *p.CAS)
	}
	if call.DryRun {
		sum := fmt.Sprintf("Create %s (%d bytes)", key, len(val))
		op := "create"
		before := map[string]any{"exists": false}
		if found {
			ob := old.bytes()
			op = "update"
			sum = fmt.Sprintf("Replace the value of %s (%d bytes → %d bytes)", key, len(ob), len(val))
			if bytes.Equal(ob, val) {
				sum = fmt.Sprintf("Write %s with the value it already has", key)
			}
			before = map[string]any{"exists": true, "bytes": len(ob), "modifyIndex": old.ModifyIndex}
			if old.Session != "" {
				sum += "; the key is LOCKED by a session, and writing it may break whoever holds the lock"
			}
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "key " + key, Op: op, Before: mustJSON(before), After: mustJSON(map[string]any{"bytes": len(val)})}}}}, nil
	}
	q := c.q(dc)
	q.Set("cas", strconv.FormatUint(idx, 10))
	if found && old.Flags != 0 {
		q.Set("flags", strconv.FormatUint(old.Flags, 10))
	}
	ok, err := c.send(ctx, http.MethodPut, esc, q, val)
	if err != nil {
		return sdk.Result{}, err
	}
	if !ok {
		return sdk.Result{}, fmt.Errorf("%s changed while this ran; look again and retry", key)
	}
	now, _, err := c.getKV(ctx, esc, c.q(dc))
	if err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"name": key, "bytes": len(val), "modifyIndex": now.ModifyIndex, "created": !found})
	if found {
		res.Undo = sdk.UndoWith("kv_put", undoValue(key, dc, old, now.ModifyIndex), "Put back the old value of "+key)
	} else {
		in := map[string]any{"key": key, "cas": now.ModifyIndex}
		if dc != "" {
			in["datacenter"] = dc
		}
		res.Undo = sdk.UndoWith("kv_delete", in, "Delete "+key+" again")
	}
	return res, err
}

func (c *conn) del(ctx context.Context, call sdk.Call, dc string, p input) (sdk.Result, error) {
	key := strings.TrimSpace(p.Key)
	esc, err := kvPath(key, false)
	if err != nil {
		return sdk.Result{}, err
	}
	old, found, err := c.getKV(ctx, esc, c.q(dc))
	if err != nil {
		return sdk.Result{}, err
	}
	if !found {
		return sdk.Result{}, fmt.Errorf("there's no key %s", key)
	}
	if p.CAS != nil && *p.CAS != old.ModifyIndex {
		return sdk.Result{}, fmt.Errorf("%s changed since (its index is %d, not %d), so this is refused", key, old.ModifyIndex, *p.CAS)
	}
	if call.DryRun {
		sum := fmt.Sprintf("Delete %s (%d bytes); undo puts it back", key, len(old.bytes()))
		if old.Session != "" {
			sum += "; the key is LOCKED by a session"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "key " + key, Op: "delete", Before: mustJSON(map[string]any{"bytes": len(old.bytes()), "modifyIndex": old.ModifyIndex})}}}}, nil
	}
	q := c.q(dc)
	q.Set("cas", strconv.FormatUint(old.ModifyIndex, 10))
	ok, err := c.send(ctx, http.MethodDelete, esc, q, nil)
	if err != nil {
		return sdk.Result{}, err
	}
	if !ok {
		return sdk.Result{}, fmt.Errorf("%s changed while this ran; look again and retry", key)
	}
	res, err := sdk.JSON(map[string]any{"name": key, "deleted": true})
	res.Undo = sdk.UndoWith("kv_put", undoValue(key, dc, old, 0), "Put "+key+" back")
	return res, err
}

func (c *conn) deregister(ctx context.Context, call sdk.Call, dc string, p input) (sdk.Result, error) {
	id := strings.TrimSpace(p.ID)
	if id != "" && !idRe.MatchString(id) {
		return sdk.Result{}, errors.New("the id is the service instance's ID (see service_health)")
	}
	node := strings.TrimSpace(p.Node)
	if node != "" && !nodeRe.MatchString(node) {
		return sdk.Result{}, errors.New("the node is its name (see members)")
	}
	ins, err := c.instances(ctx, dc, p.Service, false)
	if err != nil {
		return sdk.Result{}, err
	}
	var match []instance
	for _, in := range ins {
		if (id == "" || in.Service.ID == id) && (node == "" || in.Node.Node == node) {
			match = append(match, in)
		}
	}
	switch {
	case len(match) == 0:
		return sdk.Result{}, fmt.Errorf("%s has no such instance", p.Service)
	case len(match) > 1:
		var ls []string
		for _, in := range match {
			ls = append(ls, in.label())
		}
		return sdk.Result{}, fmt.Errorf("%s has %d instances (%s); give the id and node", p.Service, len(match), strings.Join(ls, ", "))
	}
	in := match[0]
	if !idRe.MatchString(in.Service.ID) || strings.Trim(in.Service.ID, ".") == "" || !nodeRe.MatchString(in.Node.Node) {
		return sdk.Result{}, errors.New("unexpected service instance from Consul")
	}
	var self struct {
		Config struct {
			NodeName   string `json:"NodeName"`
			Datacenter string `json:"Datacenter"`
		} `json:"Config"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/agent/self", nil, nil, &self); err != nil {
		return sdk.Result{}, friendly(err, "agent")
	}
	target := dc
	if target == "" {
		target = c.dc
	}
	local := self.Config.NodeName == in.Node.Node && (target == "" || target == self.Config.Datacenter)
	if call.DryRun {
		sum := fmt.Sprintf("Deregister %s of %s", in.label(), p.Service)
		if local {
			sum += " through its agent, which also drops its checks"
		} else {
			sum += " from the catalog; if the agent on " + in.Node.Node + " still has it registered, it adds it back at its next sync"
		}
		var cs []string
		for _, k := range in.Checks {
			if k.ServiceID == in.Service.ID {
				cs = append(cs, k.Name+": "+k.Status)
			}
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "service " + in.label(), Op: "deregister",
			Before: mustJSON(map[string]any{"tags": in.Service.Tags, "checks": cs})}}}}, nil
	}
	if local {
		err = c.do(ctx, http.MethodPut, "/v1/agent/service/deregister/"+url.PathEscape(in.Service.ID), nil, nil, nil)
	} else {
		body := map[string]any{"Node": in.Node.Node, "ServiceID": in.Service.ID}
		if target != "" {
			body["Datacenter"] = target
		}
		err = c.do(ctx, http.MethodPut, "/v1/catalog/deregister", c.q(dc), body, nil)
	}
	if err != nil {
		return sdk.Result{}, friendly(err, "service instance")
	}
	how := "catalog"
	if local {
		how = "agent"
	}
	return sdk.JSON(map[string]any{"service": p.Service, "id": in.Service.ID, "node": in.Node.Node, "deregistered": true, "via": how})
}
