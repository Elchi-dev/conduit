// Package ovhcloud works with the OVHcloud API (also Kimsufi and So you
// Start) through an application key, application secret and consumer key,
// signing each request as OVHcloud requires: dedicated servers, VPS, Public
// Cloud projects and instances, power actions and domains.
package ovhcloud

import (
	"context"
	"crypto/sha1"
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
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one OVHcloud application and consumer key.
type Config struct {
	Endpoint          string `json:"endpoint"`          // ovh-eu (default), ovh-ca, ovh-us, kimsufi-eu, …
	ApplicationKey    string `json:"applicationKey"`    // the application's public key
	ApplicationSecret string `json:"applicationSecret"` // secret://
	ConsumerKey       string `json:"consumerKey"`       // secret://
}

type conn struct {
	cfg  Config
	host sdk.Host
	api  *rest.Client
	pub  *rest.Client // unsigned, for /auth/time
	now  func() time.Time

	mu    sync.Mutex
	delta time.Duration // server clock minus ours
	known bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces the endpoint's API address (tests).
	Base string
}

// New returns the OVHcloud module.
func New() *Module { return &Module{} }

var endpoints = map[string]string{
	"ovh-eu":        "https://eu.api.ovh.com/1.0",
	"ovh-ca":        "https://ca.api.ovh.com/1.0",
	"ovh-us":        "https://api.us.ovhcloud.com/1.0",
	"kimsufi-eu":    "https://eu.api.kimsufi.com/1.0",
	"kimsufi-ca":    "https://ca.api.kimsufi.com/1.0",
	"soyoustart-eu": "https://eu.api.soyoustart.com/1.0",
	"soyoustart-ca": "https://ca.api.soyoustart.com/1.0",
}

var (
	appKeyRe   = regexp.MustCompile(`^[A-Za-z0-9]{8,64}$`)
	serviceRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
	projectRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	instanceRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// maxDetails caps the per-service lookups a listing makes.
const maxDetails = 50

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	vps := sdk.Schema(`{"type":"object","required":["vps"],"properties":{"vps":{"type":"string","description":"VPS name, e.g. vps-1a2b3c4d.vps.ovh.net (from vps)"}}}`)
	ci := sdk.Schema(`{"type":"object","required":["project","instance"],"properties":{"project":{"type":"string","description":"Project id (from cloud_projects)"},"instance":{"type":"string","description":"Instance id (from cloud_instances)"}}}`)
	return sdk.Manifest{
		ID: "ovhcloud", Name: "OVHcloud", Version: "0.1.0", Category: "Infrastructure", Icon: "server",
		Description: "OVHcloud dedicated servers, VPS and Public Cloud instances: state, start, stop and reboot; and your domains.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["applicationKey","applicationSecret","consumerKey"],"properties":{
			"endpoint":{"type":"string","default":"ovh-eu","enum":["ovh-eu","ovh-ca","ovh-us","kimsufi-eu","kimsufi-ca","soyoustart-eu","soyoustart-ca"],"description":"Where the account is"},
			"applicationKey":{"type":"string","description":"The application key from creating an application (createToken)"},
			"applicationSecret":{"type":"string","x-secret":true,"description":"The application secret"},
			"consumerKey":{"type":"string","x-secret":true,"description":"A consumer key whose rules allow the calls Conduit makes (see the docs)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "dedicated_servers", Title: "Dedicated servers", Description: "Name, IP, reverse, datacenter, state, power state, range and OS.", Risk: sdk.RiskRead},
			{Name: "reboot_dedicated", Title: "Reboot a dedicated server", Description: "Hard-reboots a dedicated server (power cycle); its services go down while it restarts.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["server"],"properties":{"server":{"type":"string","description":"Server name, e.g. ns1234567.ip-1-2-3.eu (from dedicated_servers)"}}}`)},
			{Name: "vps", Title: "VPS", Description: "Name, display name, state, zone, model, cores and memory.", Risk: sdk.RiskRead},
			{Name: "start_vps", Title: "Start a VPS", Description: "Starts a stopped VPS. Undo stops it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: vps},
			{Name: "stop_vps", Title: "Stop a VPS", Description: "Stops a running VPS; its services go down until it's started (it's still billed). Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: vps},
			{Name: "reboot_vps", Title: "Reboot a VPS", Description: "Reboots a running VPS; its services go down while it restarts.", Risk: sdk.RiskDestructive, DryRun: true, Input: vps},
			{Name: "cloud_projects", Title: "Public Cloud projects", Description: "Id, name, description and status.", Risk: sdk.RiskRead},
			{Name: "cloud_instances", Title: "Public Cloud instances", Description: "A project's instances: id, name, status, region, flavor and addresses.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{"project":{"type":"string","description":"Project id (from cloud_projects)"}}}`)},
			{Name: "start_instance", Title: "Start an instance", Description: "Starts a stopped Public Cloud instance. Undo stops it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: ci},
			{Name: "stop_instance", Title: "Stop an instance", Description: "Shuts a Public Cloud instance down; its services go down until it's started, and it's still billed. Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: ci},
			{Name: "reboot_instance", Title: "Reboot an instance", Description: "Soft-reboots a running Public Cloud instance; its services go down while it restarts.", Risk: sdk.RiskDestructive, DryRun: true, Input: ci},
			{Name: "domains", Title: "Domains", Description: "The domain names on the account.", Risk: sdk.RiskRead},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.Endpoint = strings.TrimSpace(c.Endpoint)
	if c.Endpoint == "" {
		c.Endpoint = "ovh-eu"
	}
	base, ok := endpoints[c.Endpoint]
	if !ok {
		return errors.New("the endpoint is one of ovh-eu, ovh-ca, ovh-us, kimsufi-eu, kimsufi-ca, soyoustart-eu and soyoustart-ca")
	}
	if m.Base != "" {
		base = m.Base
	}
	c.ApplicationKey = strings.TrimSpace(c.ApplicationKey)
	if strings.HasPrefix(c.ApplicationKey, "secret://") {
		return errors.New("enter the application key as it is; the application secret and consumer key go in the vault")
	}
	if !appKeyRe.MatchString(c.ApplicationKey) {
		return errors.New("the application key is letters and digits, as OVHcloud shows it")
	}
	if !strings.HasPrefix(c.ApplicationSecret, "secret://") || !strings.HasPrefix(c.ConsumerKey, "secret://") {
		return errors.New("store the application secret and consumer key in the vault and enter their secret:// references")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	client = rest.SameHostOnly(client)
	cn := &conn{cfg: c, host: h, now: time.Now}
	cn.api = rest.New(base, cn.sign)
	cn.api.HTTP = client
	cn.pub = rest.New(base, nil)
	cn.pub.HTTP = client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// timestamp is the server's clock, learned once from /auth/time: OVHcloud
// refuses a signature whose timestamp is off.
func (c *conn) timestamp(ctx context.Context) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.known {
		var t int64
		if _, err := c.pub.Do(ctx, http.MethodGet, "/auth/time", nil, nil, &t); err != nil {
			return 0, err
		}
		c.delta, c.known = time.Unix(t, 0).Sub(c.now()), true
	}
	return c.now().Add(c.delta).Unix(), nil
}

// sign adds OVHcloud's signature: "$1$" and the SHA-1 of the application
// secret, consumer key, method, full URL, body and timestamp joined by "+".
func (c *conn) sign(ctx context.Context, r *http.Request) error {
	as, err := c.host.Secret(ctx, c.cfg.ApplicationSecret)
	if err != nil {
		return err
	}
	ck, err := c.host.Secret(ctx, c.cfg.ConsumerKey)
	if err != nil {
		return err
	}
	as, ck = strings.TrimSpace(as), strings.TrimSpace(ck)
	ts, err := c.timestamp(ctx)
	if err != nil {
		return err
	}
	var body []byte
	if r.GetBody != nil {
		rd, err := r.GetBody()
		if err != nil {
			return err
		}
		body, _ = io.ReadAll(rd)
		rd.Close()
	}
	sum := sha1.Sum([]byte(strings.Join([]string{as, ck, r.Method, r.URL.String(), string(body), strconv.FormatInt(ts, 10)}, "+")))
	r.Header.Set("X-Ovh-Application", c.cfg.ApplicationKey)
	r.Header.Set("X-Ovh-Consumer", ck)
	r.Header.Set("X-Ovh-Timestamp", strconv.FormatInt(ts, 10))
	r.Header.Set("X-Ovh-Signature", "$1$"+hex.EncodeToString(sum[:]))
	return nil
}

func friendly(err error, what string) error {
	var e *rest.Error
	if !errors.As(err, &e) {
		return err
	}
	msg := strings.ToLower(e.Message)
	switch {
	case strings.Contains(msg, "signature"):
		return errors.New("OVHcloud refused the request signature (check the application secret and consumer key)")
	case strings.Contains(msg, "not been granted"):
		return errors.New("the consumer key's rules don't allow this call (see the docs for the rules Conduit needs)")
	case e.Status == http.StatusForbidden || e.Status == http.StatusUnauthorized:
		return errors.New("OVHcloud refused the application or consumer key (invalid, expired or not validated)")
	case e.Status == http.StatusNotFound:
		return fmt.Errorf("there's no %s", what)
	case e.Status == http.StatusConflict:
		return fmt.Errorf("OVHcloud refused: %s is busy (another task is running on it)", what)
	case e.Status == http.StatusTooManyRequests:
		return errors.New("OVHcloud's rate limit was hit; try again in a moment")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, body, out any, what string) error {
	_, err := c.api.Do(ctx, method, path, nil, body, out)
	return friendly(err, what)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var cr struct {
		Status     string  `json:"status"`
		Expiration *string `json:"expiration"`
	}
	if err := c.do(ctx, http.MethodGet, "/auth/currentCredential", nil, &cr, "credential"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if cr.Status != "validated" {
		return sdk.Health{Status: "down", Message: "the consumer key is " + cr.Status + " (open its validation link)"}
	}
	if cr.Expiration == nil || *cr.Expiration == "" {
		return sdk.Health{Status: "ok", Message: "consumer key validated, no expiry"}
	}
	if t, err := time.Parse(time.RFC3339, *cr.Expiration); err == nil && t.Sub(c.now()) < 7*24*time.Hour {
		return sdk.Health{Status: "degraded", Message: "consumer key expires " + *cr.Expiration}
	}
	return sdk.Health{Status: "ok", Message: "consumer key validated, expires " + *cr.Expiration}
}

func state(s string) json.RawMessage { b, _ := json.Marshal(map[string]string{"state": s}); return b }

func validService(s string) bool { return serviceRe.MatchString(s) && !strings.Contains(s, "..") }

// names lists a collection of ids, sorted.
func (c *conn) names(ctx context.Context, path string) ([]string, error) {
	var ns []string
	if err := c.do(ctx, http.MethodGet, path, nil, &ns, path); err != nil {
		return nil, err
	}
	sort.Strings(ns)
	return ns, nil
}

type input struct {
	Server   string `json:"server"`
	VPS      string `json:"vps"`
	Project  string `json:"project"`
	Instance string `json:"instance"`
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
	p.Server, p.VPS, p.Project, p.Instance = strings.TrimSpace(p.Server), strings.TrimSpace(p.VPS), strings.TrimSpace(p.Project), strings.TrimSpace(p.Instance)
	switch call.Action {
	case "dedicated_servers":
		ns, err := c.names(ctx, "/dedicated/server")
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, n := range ns {
			if len(out) == maxDetails {
				break
			}
			if !validService(n) {
				continue // a name Conduit won't put in a path
			}
			var s struct {
				Name       string `json:"name"`
				IP         string `json:"ip"`
				Reverse    string `json:"reverse"`
				Datacenter string `json:"datacenter"`
				State      string `json:"state"`
				PowerState string `json:"powerState"`
				Range      string `json:"commercialRange"`
				OS         string `json:"os"`
				Monitoring bool   `json:"monitoring"`
			}
			if err := c.do(ctx, http.MethodGet, "/dedicated/server/"+url.PathEscape(n), nil, &s, "server "+n); err != nil {
				return sdk.Result{}, err
			}
			out = append(out, map[string]any{"name": s.Name, "ip": s.IP, "reverse": s.Reverse, "datacenter": s.Datacenter, "state": s.State,
				"powerState": s.PowerState, "range": s.Range, "os": s.OS, "monitoring": s.Monitoring})
		}
		return list(out, len(ns))

	case "reboot_dedicated":
		if !validService(p.Server) {
			return sdk.Result{}, errors.New("which server? (its name, from dedicated_servers)")
		}
		path := "/dedicated/server/" + url.PathEscape(p.Server)
		var s struct {
			Name       string `json:"name"`
			PowerState string `json:"powerState"`
		}
		if err := c.do(ctx, http.MethodGet, path, nil, &s, "server "+p.Server); err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Reboot " + p.Server,
				Changes: []sdk.Change{{Target: p.Server, Op: "restart", Before: state(s.PowerState), After: state("poweron")}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, path+"/reboot", nil, nil, "server "+p.Server); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"server": p.Server, "requested": "reboot"})

	case "vps":
		ns, err := c.names(ctx, "/vps")
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, n := range ns {
			if len(out) == maxDetails {
				break
			}
			if !validService(n) {
				continue // a name Conduit won't put in a path
			}
			v, err := c.vps(ctx, n)
			if err != nil {
				return sdk.Result{}, err
			}
			out = append(out, map[string]any{"name": v.Name, "displayName": v.DisplayName, "state": v.State, "zone": v.Zone, "model": v.Model.Name,
				"cores": v.VCore, "memoryMb": v.Memory, "offer": v.Offer})
		}
		return list(out, len(ns))

	case "start_vps", "stop_vps", "reboot_vps":
		if !validService(p.VPS) {
			return sdk.Result{}, errors.New("which VPS? (its name, from vps)")
		}
		return c.vpsPower(ctx, call, p.VPS)

	case "cloud_projects":
		ns, err := c.names(ctx, "/cloud/project")
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, n := range ns {
			if len(out) == maxDetails {
				break
			}
			if !projectRe.MatchString(n) {
				continue // a name Conduit won't put in a path
			}
			var pr struct {
				ID          string `json:"project_id"`
				Name        string `json:"projectName"`
				Description string `json:"description"`
				Status      string `json:"status"`
				Created     string `json:"creationDate"`
			}
			if err := c.do(ctx, http.MethodGet, "/cloud/project/"+n, nil, &pr, "project "+n); err != nil {
				return sdk.Result{}, err
			}
			out = append(out, map[string]any{"id": n, "name": pr.Name, "description": pr.Description, "status": pr.Status, "created": pr.Created})
		}
		return list(out, len(ns))

	case "cloud_instances":
		if !projectRe.MatchString(p.Project) {
			return sdk.Result{}, errors.New("which project? (its id, from cloud_projects)")
		}
		var is []cloudInstance
		if err := c.do(ctx, http.MethodGet, "/cloud/project/"+p.Project+"/instance", nil, &is, "project "+p.Project); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, i := range is {
			out = append(out, i.row())
		}
		return sdk.JSON(out)

	case "start_instance", "stop_instance", "reboot_instance":
		if !projectRe.MatchString(p.Project) {
			return sdk.Result{}, errors.New("which project? (its id, from cloud_projects)")
		}
		if !instanceRe.MatchString(p.Instance) {
			return sdk.Result{}, errors.New("which instance? (its id, from cloud_instances)")
		}
		return c.instancePower(ctx, call, p)

	case "domains":
		ns, err := c.names(ctx, "/domain")
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(ns)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// list returns rows, saying when the account has more than were looked up.
func list(rows []map[string]any, total int) (sdk.Result, error) {
	if total > len(rows) {
		return sdk.JSON(map[string]any{"items": rows, "total": total, "note": fmt.Sprintf("showing the first %d", len(rows))})
	}
	return sdk.JSON(rows)
}

type vps struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
	Zone        string `json:"zone"`
	VCore       int    `json:"vcore"`
	Memory      int    `json:"memoryLimit"`
	Offer       string `json:"offerType"`
	Model       struct {
		Name string `json:"name"`
	} `json:"model"`
}

func (c *conn) vps(ctx context.Context, name string) (vps, error) {
	var v vps
	err := c.do(ctx, http.MethodGet, "/vps/"+url.PathEscape(name), nil, &v, "VPS "+name)
	return v, err
}

func (c *conn) vpsPower(ctx context.Context, call sdk.Call, name string) (sdk.Result, error) {
	v, err := c.vps(ctx, name)
	if err != nil {
		return sdk.Result{}, err
	}
	op := strings.TrimSuffix(call.Action, "_vps")
	was, want := v.State, "running"
	switch op {
	case "start":
		if was == "running" {
			return sdk.JSON(map[string]any{"vps": name, "state": was, "note": "nothing to change"})
		}
		if was != "stopped" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a stopped VPS can be started", name, was)
		}
	case "stop":
		if was == "stopped" {
			return sdk.JSON(map[string]any{"vps": name, "state": was, "note": "nothing to change"})
		}
		if was != "running" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a running VPS can be stopped", name, was)
		}
		want = "stopped"
	case "reboot":
		if was != "running" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a running VPS can be rebooted", name, was)
		}
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: strings.ToUpper(op[:1]) + op[1:] + " " + name,
			Changes: []sdk.Change{{Target: name, Op: op, Before: state(was), After: state(want)}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, "/vps/"+url.PathEscape(name)+"/"+op, nil, nil, "VPS "+name); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"vps": name, "was": was, "requested": op})
	switch op {
	case "start":
		res.Undo = sdk.UndoWith("stop_vps", map[string]string{"vps": name}, "Stop "+name+" again")
	case "stop":
		res.Undo = sdk.UndoWith("start_vps", map[string]string{"vps": name}, "Start "+name+" again")
	}
	return res, err
}

// cloudInstance holds only what's shown: SSH key and image details and
// monthly billing aren't decoded.
type cloudInstance struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Region  string `json:"region"`
	Flavor  string `json:"flavorId"`
	Plan    string `json:"planCode"`
	Created string `json:"created"`
	IPs     []struct {
		IP      string `json:"ip"`
		Type    string `json:"type"`
		Version int    `json:"version"`
	} `json:"ipAddresses"`
}

func (i cloudInstance) row() map[string]any {
	ips := []string{}
	for _, a := range i.IPs {
		ips = append(ips, a.IP+" ("+a.Type+")")
	}
	return map[string]any{"id": i.ID, "name": i.Name, "status": i.Status, "region": i.Region, "flavor": i.Flavor, "plan": i.Plan, "created": i.Created, "addresses": ips}
}

func (c *conn) instancePower(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	path := "/cloud/project/" + p.Project + "/instance/" + p.Instance
	what := "instance " + p.Instance
	var i cloudInstance
	if err := c.do(ctx, http.MethodGet, path, nil, &i, what); err != nil {
		return sdk.Result{}, err
	}
	if i.ID != p.Instance {
		return sdk.Result{}, fmt.Errorf("OVHcloud answered with another instance for %s", p.Instance)
	}
	op := strings.TrimSuffix(call.Action, "_instance")
	was, want := i.Status, "ACTIVE"
	target := i.Name + " (" + p.Instance + ")"
	switch op {
	case "start":
		if was == "ACTIVE" {
			return sdk.JSON(map[string]any{"instance": target, "status": was, "note": "nothing to change"})
		}
		if was != "SHUTOFF" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a stopped (SHUTOFF) instance can be started", target, was)
		}
	case "stop":
		if was == "SHUTOFF" {
			return sdk.JSON(map[string]any{"instance": target, "status": was, "note": "nothing to change"})
		}
		if was != "ACTIVE" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only an active instance can be stopped", target, was)
		}
		want = "SHUTOFF"
	case "reboot":
		if was != "ACTIVE" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only an active instance can be rebooted", target, was)
		}
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: strings.ToUpper(op[:1]) + op[1:] + " " + target,
			Changes: []sdk.Change{{Target: target, Op: op, Before: state(was), After: state(want)}}}}, nil
	}
	var body any
	if op == "reboot" {
		body = map[string]string{"type": "soft"}
	}
	if err := c.do(ctx, http.MethodPost, path+"/"+op, body, nil, what); err != nil {
		return sdk.Result{}, err
	}
	in := map[string]string{"project": p.Project, "instance": p.Instance}
	res, err := sdk.JSON(map[string]any{"instance": target, "was": was, "requested": op})
	switch op {
	case "start":
		res.Undo = sdk.UndoWith("stop_instance", in, "Stop "+i.Name+" again")
	case "stop":
		res.Undo = sdk.UndoWith("start_instance", in, "Start "+i.Name+" again")
	}
	return res, err
}
