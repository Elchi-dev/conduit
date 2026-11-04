// Package proxmox manages a Proxmox VE cluster through its API: nodes,
// virtual machines and containers, power actions, snapshots and storage.
package proxmox

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Proxmox VE connection.
type Config struct {
	URL         string `json:"url"`         // https://pve.lan:8006
	TokenID     string `json:"tokenId"`     // user@realm!tokenid
	TokenSecret string `json:"tokenSecret"` // secret:// token value
	// Fingerprint pins the server certificate by its SHA-256 fingerprint
	// (as shown under Datacenter, Certificates), for the self-signed
	// certificate Proxmox uses by default. Preferred over skipping checks.
	Fingerprint string `json:"fingerprint"`
	// InsecureSkipVerify turns off certificate checks. Discouraged.
	InsecureSkipVerify bool `json:"insecureSkipVerify"`
}

type conn struct {
	cfg  Config
	base string
	http *http.Client
	host sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client (tests that don't exercise TLS).
	HTTP *http.Client
}

// New returns the Proxmox module.
func New() *Module { return &Module{} }

var (
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9._@-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+$`)
	nameRe  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,39}$`) // snapshot names
)

const vmidProp = `"vmid":{"type":"integer","minimum":100,"description":"The guest's id, e.g. 101"}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	vm := sdk.Schema(`{"type":"object","required":["vmid"],"properties":{` + vmidProp + `}}`)
	return sdk.Manifest{
		ID: "proxmox", Name: "Proxmox VE", Version: "0.1.0", Category: "Infrastructure", Icon: "server",
		Description: "Nodes, virtual machines and containers of a Proxmox cluster: power, snapshots and storage.",
		Presets:     []string{"homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","tokenId","tokenSecret"],"properties":{
			"url":{"type":"string","format":"uri","description":"e.g. https://pve.lan:8006"},
			"tokenId":{"type":"string","description":"API token id, user@realm!name (Datacenter, Permissions, API Tokens)"},
			"tokenSecret":{"type":"string","x-secret":true,"description":"The token's secret"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, to trust Proxmox's own self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "nodes", Title: "Nodes", Description: "CPU, memory and uptime of each node.", Risk: sdk.RiskRead},
			{Name: "guests", Title: "VMs and containers", Description: "Every guest across the cluster with its state.", Risk: sdk.RiskRead},
			{Name: "start", Title: "Start a guest", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: vm},
			{Name: "shutdown", Title: "Shut down a guest", Description: "A clean shutdown through the guest's OS. The guest's services go down until it's started (destructive).", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: vm},
			{Name: "reboot", Title: "Reboot a guest", Risk: sdk.RiskDestructive, DryRun: true, Input: vm},
			{Name: "stop", Title: "Stop a guest now", Description: "Like pulling the plug; unsaved work in the guest is lost.", Risk: sdk.RiskDestructive, DryRun: true, Input: vm},
			{Name: "snapshots", Title: "Snapshots", Risk: sdk.RiskRead, Input: vm},
			{Name: "snapshot", Title: "Take a snapshot", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["vmid","name"],"properties":{` + vmidProp + `,"name":{"type":"string","pattern":"^[A-Za-z][A-Za-z0-9_-]{0,39}$"},"description":{"type":"string"}}}`)},
			{Name: "delete_snapshot", Title: "Delete a snapshot", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["vmid","name"],"properties":{` + vmidProp + `,"name":{"type":"string"}}}`)},
			{Name: "storage", Title: "Storage", Description: "Used and free space of each storage on each node.", Risk: sdk.RiskRead},
		},
	}
}

// normFingerprint turns "AB:CD:…" or "abcd…" into lowercase hex.
func normFingerprint(s string) (string, error) {
	h := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	if b, err := hex.DecodeString(h); err != nil || len(b) != sha256.Size {
		return "", errors.New("the fingerprint is a SHA-256 fingerprint: 32 bytes in hex, like AB:CD:…")
	}
	return h, nil
}

// pinned accepts exactly the certificate with this fingerprint.
func pinned(fp string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // replaced by the pin check below
		VerifyPeerCertificate: func(certs [][]byte, _ [][]*x509.Certificate) error {
			if len(certs) == 0 {
				return errors.New("proxmox: no certificate")
			}
			sum := sha256.Sum256(certs[0])
			if hex.EncodeToString(sum[:]) != fp {
				return errors.New("proxmox: the server certificate doesn't match the pinned fingerprint")
			}
			return nil
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("the address is https://host:8006")
	}
	if !tokenRe.MatchString(c.TokenID) {
		return errors.New("the token id looks like user@pam!conduit")
	}
	if c.TokenSecret == "" {
		return errors.New("add the token secret (stored in the vault)")
	}
	cn := &conn{cfg: c, base: u.Scheme + "://" + u.Host + "/api2/json", host: h}
	switch {
	case m.HTTP != nil:
		cn.http = m.HTTP
	case c.Fingerprint != "":
		fp, err := normFingerprint(c.Fingerprint)
		if err != nil {
			return err
		}
		cn.http = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: pinned(fp)}}
	default:
		tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.InsecureSkipVerify} //nolint:gosec // opt-in, documented
		cn.http = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment}}
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// do calls the API; form is sent url-encoded, as Proxmox expects. The
// answer's "data" field is decoded into out.
func (c *conn) do(ctx context.Context, method, path string, form url.Values, out any) error {
	var body io.Reader
	u := c.base + path
	if method == "GET" || method == "DELETE" {
		if len(form) > 0 {
			u += "?" + form.Encode()
		}
	} else {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	sec, err := c.host.Secret(ctx, c.cfg.TokenSecret)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "PVEAPIToken="+c.cfg.TokenID+"="+strings.TrimSpace(sec))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return rest.TransportError(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		var e struct {
			Errors  map[string]string `json:"errors"`
			Message string            `json:"message"`
		}
		msg := strings.TrimSpace(res.Status)
		if json.Unmarshal(b, &e) == nil {
			for k, v := range e.Errors {
				msg += "; " + k + ": " + strings.TrimSpace(v)
			}
		}
		return errors.New("proxmox: " + msg)
	}
	if out == nil {
		return nil
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return fmt.Errorf("proxmox: unexpected answer: %w", err)
	}
	return json.Unmarshal(env.Data, out)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := c.do(ctx, "GET", "/version", nil, &v); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "Proxmox VE " + v.Version}
}

// guest is an entry of /cluster/resources?type=vm.
type guest struct {
	VMID   int     `json:"vmid"`
	Name   string  `json:"name"`
	Node   string  `json:"node"`
	Type   string  `json:"type"` // qemu or lxc
	Status string  `json:"status"`
	CPU    float64 `json:"cpu"`
	MaxCPU float64 `json:"maxcpu"`
	Mem    int64   `json:"mem"`
	MaxMem int64   `json:"maxmem"`
	Uptime int64   `json:"uptime"`
	Tags   string  `json:"tags"`
}

func (c *conn) guests(ctx context.Context) ([]guest, error) {
	var gs []guest
	err := c.do(ctx, "GET", "/cluster/resources", url.Values{"type": {"vm"}}, &gs)
	return gs, err
}

func (c *conn) find(ctx context.Context, vmid int) (guest, error) {
	if vmid < 100 {
		return guest{}, errors.New("give the guest's id (vmid, 100 or more)")
	}
	gs, err := c.guests(ctx)
	if err != nil {
		return guest{}, err
	}
	for _, g := range gs {
		if g.VMID == vmid {
			return g, nil
		}
	}
	return guest{}, fmt.Errorf("no guest %d in this cluster", vmid)
}

func (g guest) path() string {
	return "/nodes/" + url.PathEscape(g.Node) + "/" + g.Type + "/" + strconv.Itoa(g.VMID)
}

func (g guest) label() string {
	kind := map[string]string{"qemu": "VM", "lxc": "container"}[g.Type]
	if g.Name != "" {
		return fmt.Sprintf("%s %d (%s) on %s", kind, g.VMID, g.Name, g.Node)
	}
	return fmt.Sprintf("%s %d on %s", kind, g.VMID, g.Node)
}

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func pct(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return float64(int(a/b*1000)) / 10
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		VMID        int    `json:"vmid"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "nodes":
		var ns []struct {
			Node   string  `json:"node"`
			Status string  `json:"status"`
			CPU    float64 `json:"cpu"`
			MaxCPU int     `json:"maxcpu"`
			Mem    int64   `json:"mem"`
			MaxMem int64   `json:"maxmem"`
			Uptime int64   `json:"uptime"`
		}
		if err := c.do(ctx, "GET", "/nodes", nil, &ns); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, n := range ns {
			out = append(out, map[string]any{"node": n.Node, "status": n.Status, "cpuPercent": pct(n.CPU, 1), "cpus": n.MaxCPU,
				"memPercent": pct(float64(n.Mem), float64(n.MaxMem)), "memGiB": float64(n.MaxMem>>20) / 1024, "uptimeHours": n.Uptime / 3600})
		}
		return sdk.JSON(out)

	case "guests":
		gs, err := c.guests(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.Slice(gs, func(i, j int) bool { return gs[i].VMID < gs[j].VMID })
		out := []map[string]any{}
		for _, g := range gs {
			out = append(out, map[string]any{"vmid": g.VMID, "name": g.Name, "kind": map[string]string{"qemu": "vm", "lxc": "container"}[g.Type],
				"node": g.Node, "status": g.Status, "cpuPercent": pct(g.CPU, 1), "memPercent": pct(float64(g.Mem), float64(g.MaxMem)), "tags": g.Tags})
		}
		return sdk.JSON(out)

	case "start", "shutdown", "reboot", "stop":
		g, err := c.find(ctx, p.VMID)
		if err != nil {
			return sdk.Result{}, err
		}
		want := map[string]string{"start": "running", "shutdown": "stopped", "stop": "stopped", "reboot": "running"}[call.Action]
		verb := map[string]string{"start": "Start", "shutdown": "Shut down", "stop": "Stop (hard)", "reboot": "Reboot"}[call.Action]
		if call.Action == "reboot" && g.Status != "running" {
			return sdk.Result{}, fmt.Errorf("%s isn't running", g.label())
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + g.label(), Changes: []sdk.Change{{Target: g.label(), Op: call.Action,
				Before: raw(map[string]string{"status": g.Status}), After: raw(map[string]string{"status": want})}}}}, nil
		}
		if g.Status == want && call.Action != "reboot" {
			return sdk.JSON(map[string]any{"vmid": g.VMID, "status": g.Status, "changed": false})
		}
		var task string
		if err := c.do(ctx, "POST", g.path()+"/status/"+call.Action, nil, &task); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"vmid": g.VMID, "task": task, "changed": true})
		switch call.Action {
		case "start":
			r.Undo = sdk.UndoWith("shutdown", map[string]int{"vmid": g.VMID}, "Shut it down again")
		case "shutdown":
			r.Undo = sdk.UndoWith("start", map[string]int{"vmid": g.VMID}, "Start it again")
		}
		return r, nil

	case "snapshots":
		g, err := c.find(ctx, p.VMID)
		if err != nil {
			return sdk.Result{}, err
		}
		var ss []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			SnapTime    int64  `json:"snaptime"`
			Parent      string `json:"parent"`
		}
		if err := c.do(ctx, "GET", g.path()+"/snapshot", nil, &ss); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range ss {
			if s.Name == "current" {
				continue // "You are here", not a snapshot
			}
			e := map[string]any{"name": s.Name, "description": strings.TrimSpace(s.Description)}
			if s.SnapTime > 0 {
				e["taken"] = time.Unix(s.SnapTime, 0).UTC().Format(time.RFC3339)
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "snapshot", "delete_snapshot":
		if !nameRe.MatchString(p.Name) {
			return sdk.Result{}, errors.New("a snapshot name starts with a letter and has letters, digits, - and _ (up to 40)")
		}
		g, err := c.find(ctx, p.VMID)
		if err != nil {
			return sdk.Result{}, err
		}
		target := "snapshot " + p.Name + " of " + g.label()
		if call.DryRun {
			op := map[string]string{"snapshot": "create", "delete_snapshot": "delete"}[call.Action]
			return sdk.Result{Plan: &sdk.Plan{Summary: map[string]string{"create": "Take ", "delete": "Delete "}[op] + target,
				Changes: []sdk.Change{{Target: target, Op: op}}}}, nil
		}
		var task string
		if call.Action == "snapshot" {
			f := url.Values{"snapname": {p.Name}}
			if p.Description != "" {
				f.Set("description", p.Description)
			}
			if err := c.do(ctx, "POST", g.path()+"/snapshot", f, &task); err != nil {
				return sdk.Result{}, err
			}
			r, _ := sdk.JSON(map[string]any{"vmid": g.VMID, "snapshot": p.Name, "task": task})
			r.Undo = sdk.UndoWith("delete_snapshot", map[string]any{"vmid": g.VMID, "name": p.Name}, "Delete the snapshot")
			return r, nil
		}
		if err := c.do(ctx, "DELETE", g.path()+"/snapshot/"+url.PathEscape(p.Name), nil, &task); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"vmid": g.VMID, "deleted": p.Name, "task": task})

	case "storage":
		var ns []struct {
			Node string `json:"node"`
		}
		if err := c.do(ctx, "GET", "/nodes", nil, &ns); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, n := range ns {
			var ss []struct {
				Storage string `json:"storage"`
				Type    string `json:"type"`
				Content string `json:"content"`
				Used    int64  `json:"used"`
				Total   int64  `json:"total"`
				Avail   int64  `json:"avail"`
				Active  int    `json:"active"`
			}
			if err := c.do(ctx, "GET", "/nodes/"+url.PathEscape(n.Node)+"/storage", nil, &ss); err != nil {
				return sdk.Result{}, err
			}
			for _, s := range ss {
				out = append(out, map[string]any{"node": n.Node, "storage": s.Storage, "type": s.Type, "content": s.Content, "active": s.Active == 1,
					"usedPercent": pct(float64(s.Used), float64(s.Total)), "freeGiB": float64(s.Avail>>20) / 1024, "totalGiB": float64(s.Total>>20) / 1024})
			}
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
