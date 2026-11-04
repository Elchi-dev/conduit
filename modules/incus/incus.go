// Package incus works with an Incus (or LXD) server through its REST API
// over HTTPS with a client certificate kept in the vault: instances and
// their state, starting, stopping and restarting them, and listing and
// taking snapshots. Console, exec, file access and deleting instances are
// not offered.
package incus

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Incus server.
type Config struct {
	URL string `json:"url"` // https://incus.lan:8443
	// ClientCert is a secret:// reference to the client certificate and its
	// private key, both PEM, in one value.
	ClientCert string `json:"clientCert"`
	// TrustToken is an optional secret:// reference to a trust token
	// (incus config trust add), used once to add the certificate to the
	// server's trust store.
	TrustToken         string `json:"trustToken"`
	Project            string `json:"project"`
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api      *rest.Client
	project  string
	host     sdk.Host
	tokenRef string

	mu      sync.Mutex
	trusted bool
	// tokenSpent is set once Incus has answered the trust token: a token
	// is single use, so it isn't sent again.
	tokenSpent bool
}

// Module implements sdk.Module.
type Module struct{ set inst.Set[conn] }

// New returns the Incus module.
func New() *Module { return &Module{} }

var (
	// Instance names are host names: letters, digits and '-', not
	// starting with a digit or '-', not ending with '-'.
	nameRe    = regexp.MustCompile(`^[A-Za-z]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	snapRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	projectRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	opRe      = regexp.MustCompile(`^/1\.0/operations/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
)

// opWait is how long a call waits for Incus to finish an operation; it
// stays under the client's 30-second timeout.
var opWait = 25

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	instProp := `"instance":{"type":"string","description":"Instance name (from instances)"}`
	one := sdk.Schema(`{"type":"object","required":["instance"],"properties":{` + instProp + `}}`)
	snap := sdk.Schema(`{"type":"object","required":["instance","name"],"properties":{` + instProp + `,"name":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$","description":"Snapshot name"}}}`)
	return sdk.Manifest{
		ID: "incus", Name: "Incus", Version: "0.1.0", Category: "Infrastructure", Icon: "box",
		Description: "Incus and LXD: containers and virtual machines with their state, start, stop and restart, and snapshots.",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","clientCert"],"properties":{
			"url":{"type":"string","format":"uri","description":"e.g. https://incus.lan:8443 (core.https_address)"},
			"clientCert":{"type":"string","x-secret":true,"description":"The client certificate and its private key, both PEM, in one secret"},
			"trustToken":{"type":"string","x-secret":true,"description":"Optional: a trust token from incus config trust add, to add the certificate to the server's trust store on first use"},
			"project":{"type":"string","default":"default","description":"The project to work in"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate (incus info shows it), to trust Incus's own self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip server certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "instances", Title: "Instances", Description: "Containers and VMs with state, type, cluster member, architecture, profiles, description, created and last used. Never their configuration (it can hold cloud-init data).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"state":{"type":"string","enum":["Running","Stopped","Frozen","Error"],"description":"Only instances in this state"}}}`)},
			{Name: "start", Title: "Start an instance", Description: "Undo stops it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: one},
			{Name: "stop", Title: "Stop an instance", Description: "A clean shutdown (or, with force, an immediate one: unsaved work is lost). Its services go down until it's started (destructive). Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["instance"],"properties":{` + instProp + `,"force":{"type":"boolean","default":false,"description":"Kill it at once instead of a clean shutdown"}}}`)},
			{Name: "restart", Title: "Restart an instance", Description: "Only a running instance; its services are down meanwhile.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["instance"],"properties":{` + instProp + `,"force":{"type":"boolean","default":false}}}`)},
			{Name: "snapshots", Title: "Snapshots", Description: "An instance's snapshots, newest first: name, when taken, expiry, size and whether it holds the running state.", Risk: sdk.RiskRead, Input: one},
			{Name: "snapshot", Title: "Take a snapshot", Description: "A snapshot of the instance's disks (not its memory). Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: snap},
			{Name: "delete_snapshot", Title: "Delete a snapshot", Description: "Deletes one snapshot for good; the instance itself is untouched.", Risk: sdk.RiskDestructive, DryRun: true, Input: snap},
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
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return errors.New("the address is like https://incus.lan:8443")
	}
	if !strings.HasPrefix(c.ClientCert, "secret://") {
		return errors.New("store the client certificate and key (PEM) in the vault and enter its secret:// reference")
	}
	if c.TrustToken != "" && !strings.HasPrefix(c.TrustToken, "secret://") {
		return errors.New("store the trust token in the vault and enter its secret:// reference")
	}
	if c.Project == "" {
		c.Project = "default"
	}
	if !projectRe.MatchString(c.Project) {
		return errors.New("a project name has letters, digits, '.', '_' and '-'")
	}
	if c.TrustToken != "" && c.Fingerprint == "" && c.InsecureSkipVerify {
		// Whoever reads the token can add their own certificate: it only
		// goes to a server whose certificate was checked.
		return errors.New("a trust token is only sent to a verified server: set the fingerprint instead of skipping certificate checks")
	}
	tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
	if err != nil {
		return err
	}
	ref := c.ClientCert
	tc.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		ctx := info.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		pem, err := h.Secret(ctx, ref)
		if err != nil {
			return nil, errors.New("the client certificate couldn't be read from the vault")
		}
		return keyPair(pem)
	}
	tr := sdk.Transport(h)
	tr.TLSClientConfig = tc
	api := rest.New(u.Scheme+"://"+u.Host, nil)
	api.HTTP = rest.SameHostOnly(&http.Client{Timeout: 30 * time.Second, Transport: tr})
	m.set.Put(id, &conn{api: api, project: c.Project, host: h, tokenRef: c.TrustToken})
	return nil
}

// keyPair reads the client certificate (and any chain after it) and its
// private key from one PEM value. An encrypted key, a key that doesn't
// match the first certificate, or a value missing either fails with a
// fixed message: the parse error is not passed on, as it can quote the PEM.
func keyPair(s string) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(s), []byte(s))
	if err != nil {
		return nil, errors.New("the client certificate secret needs a PEM certificate and its matching unencrypted PEM private key")
	}
	return &cert, nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// envelope is every Incus answer.
type envelope struct {
	Type      string          `json:"type"`
	Operation string          `json:"operation"`
	Metadata  json.RawMessage `json:"metadata"`
}

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Incus refused this client certificate (add it with incus config trust add-certificate, or set a trust token)")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body any) (envelope, error) {
	var env envelope
	_, err := c.api.Do(ctx, method, path, q, body, &env)
	return env, friendly(err)
}

func (c *conn) proj() url.Values { return url.Values{"project": {c.project}} }

type server struct {
	Auth        string `json:"auth"`
	Environment struct {
		Server        string `json:"server"`
		ServerVersion string `json:"server_version"`
		ServerName    string `json:"server_name"`
	} `json:"environment"`
}

func (c *conn) info(ctx context.Context) (server, error) {
	env, err := c.do(ctx, http.MethodGet, "/1.0", nil, nil)
	if err != nil {
		return server{}, err
	}
	var s server
	if json.Unmarshal(env.Metadata, &s) != nil || s.Auth == "" {
		return server{}, errors.New("no Incus API at this address")
	}
	return s, nil
}

// ensureTrusted checks the server trusts the certificate, adding it with
// the trust token the first time when one is set.
func (c *conn) ensureTrusted(ctx context.Context) (server, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.info(ctx)
	if err != nil || s.Auth == "trusted" {
		c.trusted = err == nil
		return s, err
	}
	if c.tokenRef == "" {
		return s, errors.New("Incus doesn't trust this client certificate yet: add it with incus config trust add-certificate, or set a trust token")
	}
	if c.tokenSpent {
		return s, errors.New("Incus doesn't trust this client certificate, and the trust token was already used: add the certificate with incus config trust add-certificate, or enter a new trust token")
	}
	tok, err := c.host.Secret(ctx, c.tokenRef)
	if err != nil {
		return s, errors.New("the trust token couldn't be read from the vault")
	}
	// No "certificate" field: Incus adds the certificate this connection
	// presented, and nothing else.
	var env envelope
	_, err = c.api.Do(ctx, http.MethodPost, "/1.0/certificates", nil, map[string]any{"type": "client", "name": "conduit", "trust_token": strings.TrimSpace(tok)}, &env)
	var apiErr *rest.Error
	if err == nil || errors.As(err, &apiErr) {
		c.tokenSpent = true
	}
	if err != nil {
		return s, fmt.Errorf("Incus refused the trust token (they're single use and expire): %w", err)
	}
	if s, err = c.info(ctx); err == nil && s.Auth != "trusted" {
		err = errors.New("Incus accepted the trust token but still doesn't trust the certificate")
	}
	c.trusted = err == nil
	return s, err
}

func (c *conn) ready(ctx context.Context) error {
	c.mu.Lock()
	ok := c.trusted
	c.mu.Unlock()
	if ok {
		return nil
	}
	_, err := c.ensureTrusted(ctx)
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	s, err := c.ensureTrusted(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	name := "Incus"
	if strings.EqualFold(s.Environment.Server, "lxd") {
		name = "LXD"
	}
	msg := strings.TrimSpace(name + " " + s.Environment.ServerVersion)
	if s.Environment.ServerName != "" {
		msg += " on " + s.Environment.ServerName
	}
	if env, err := c.do(ctx, http.MethodGet, "/1.0/instances", c.proj(), nil); err == nil {
		var urls []string
		if json.Unmarshal(env.Metadata, &urls) == nil {
			msg += fmt.Sprintf(", %d instances in project %s", len(urls), c.project)
		}
	} else {
		return sdk.Health{Status: "degraded", Message: msg + "; " + err.Error()}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// instance is decoded field by field: config and devices can hold
// cloud-init user data, passwords and keys.
type instance struct {
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	Type         string   `json:"type"`
	Location     string   `json:"location"`
	Architecture string   `json:"architecture"`
	Description  string   `json:"description"`
	Profiles     []string `json:"profiles"`
	Ephemeral    bool     `json:"ephemeral"`
	CreatedAt    string   `json:"created_at"`
	LastUsedAt   string   `json:"last_used_at"`
}

func (i instance) label() string {
	kind := map[string]string{"container": "container", "virtual-machine": "VM"}[i.Type]
	if kind == "" {
		kind = "instance"
	}
	return kind + " " + i.Name
}

func stamp(s string) string {
	if s == "" || strings.HasPrefix(s, "0001-") || strings.HasPrefix(s, "1970-") {
		return ""
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return s
}

type params struct {
	Instance string `json:"instance"`
	Name     string `json:"name"`
	Force    bool   `json:"force"`
	State    string `json:"state"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p params
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	p.Instance, p.Name = strings.TrimSpace(p.Instance), strings.TrimSpace(p.Name)
	switch call.Action {
	case "instances":
	case "start", "stop", "restart", "snapshots", "snapshot", "delete_snapshot":
		if !nameRe.MatchString(p.Instance) {
			return sdk.Result{}, errors.New("an instance name has letters, digits and '-' (see instances)")
		}
		if (call.Action == "snapshot" || call.Action == "delete_snapshot") && !snapRe.MatchString(p.Name) {
			return sdk.Result{}, errors.New("a snapshot name starts with a letter or digit and has letters, digits, '.', '_' and '-' (up to 63)")
		}
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	if err := c.ready(ctx); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "instances":
		env, err := c.do(ctx, http.MethodGet, "/1.0/instances", url.Values{"recursion": {"1"}, "project": {c.project}}, nil)
		if err != nil {
			return sdk.Result{}, err
		}
		var is []instance
		if err := json.Unmarshal(env.Metadata, &is); err != nil {
			return sdk.Result{}, fmt.Errorf("incus: unexpected answer: %w", err)
		}
		sort.Slice(is, func(a, b int) bool { return is[a].Name < is[b].Name })
		out := []map[string]any{}
		for _, i := range is {
			if p.State != "" && !strings.EqualFold(i.Status, p.State) {
				continue
			}
			row := map[string]any{"name": i.Name, "status": i.Status, "type": i.Type, "architecture": i.Architecture, "profiles": i.Profiles,
				"ephemeral": i.Ephemeral, "created": stamp(i.CreatedAt)}
			if l := stamp(i.LastUsedAt); l != "" {
				row["lastUsed"] = l
			}
			if i.Location != "" && i.Location != "none" {
				row["location"] = i.Location
			}
			if i.Description != "" {
				row["description"] = i.Description
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	case "start", "stop", "restart":
		return c.power(ctx, call, p)
	case "snapshots":
		ss, err := c.snapshots(ctx, p.Instance)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range ss {
			row := map[string]any{"name": s.Name, "taken": stamp(s.CreatedAt), "stateful": s.Stateful, "sizeBytes": s.Size}
			if e := stamp(s.ExpiresAt); e != "" {
				row["expires"] = e
			}
			if s.Description != "" {
				row["description"] = s.Description
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	}
	return c.snapshotChange(ctx, call, p)
}

func (c *conn) instance(ctx context.Context, name string) (instance, error) {
	env, err := c.do(ctx, http.MethodGet, "/1.0/instances/"+url.PathEscape(name), c.proj(), nil)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return instance{}, fmt.Errorf("there's no instance %s in project %s", name, c.project)
		}
		return instance{}, err
	}
	var i instance
	if err := json.Unmarshal(env.Metadata, &i); err != nil {
		return instance{}, fmt.Errorf("incus: unexpected answer: %w", err)
	}
	if i.Name != name {
		return instance{}, fmt.Errorf("Incus answered with another instance for %s", name)
	}
	return i, nil
}

// wait follows an async answer's operation to its end.
func (c *conn) wait(ctx context.Context, env envelope) error {
	if env.Type != "async" {
		return nil
	}
	mt := opRe.FindStringSubmatch(env.Operation)
	if mt == nil {
		return errors.New("incus: unexpected operation in the answer")
	}
	res, err := c.do(ctx, http.MethodGet, "/1.0/operations/"+mt[1]+"/wait", url.Values{"timeout": {fmt.Sprint(opWait)}, "project": {c.project}}, nil)
	if err != nil {
		return err
	}
	var op struct {
		Status string `json:"status"`
		Err    string `json:"err"`
	}
	if json.Unmarshal(res.Metadata, &op) != nil {
		return nil
	}
	switch op.Status {
	case "Success", "":
		return nil
	case "Failure", "Cancelled":
		msg := strings.Join(strings.Fields(rest.Redact(op.Err)), " ")
		if r := []rune(msg); len(r) > 300 {
			msg = string(r[:300]) + "…"
		}
		return errors.New("Incus: " + msg)
	}
	return errPending
}

var errPending = errors.New("still running")

func (c *conn) power(ctx context.Context, call sdk.Call, p params) (sdk.Result, error) {
	i, err := c.instance(ctx, p.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	want := map[string]string{"start": "Running", "stop": "Stopped", "restart": "Running"}[call.Action]
	switch {
	case i.Status == "Frozen":
		return sdk.Result{}, fmt.Errorf("%s is frozen; unfreeze it first", i.label())
	case call.Action == "restart" && i.Status != "Running":
		return sdk.Result{}, fmt.Errorf("%s isn't running (it's %s)", i.label(), i.Status)
	}
	if i.Status == want && call.Action != "restart" {
		return sdk.JSON(map[string]any{"instance": i.Name, "status": i.Status, "changed": false, "note": "nothing to change"})
	}
	verb := map[string]string{"start": "Start", "stop": "Stop", "restart": "Restart"}[call.Action]
	if p.Force && call.Action != "start" {
		verb = "Force " + strings.ToLower(verb)
	}
	if call.DryRun {
		before, _ := json.Marshal(map[string]string{"status": i.Status})
		after, _ := json.Marshal(map[string]string{"status": want})
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + i.label(), Changes: []sdk.Change{{Target: i.label() + " in project " + c.project, Op: call.Action, Before: before, After: after}}}}, nil
	}
	body := map[string]any{"action": call.Action, "timeout": opWait - 5, "force": p.Force && call.Action != "start"}
	env, err := c.do(ctx, http.MethodPut, "/1.0/instances/"+url.PathEscape(i.Name)+"/state", c.proj(), body)
	if err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"instance": i.Name, "changed": true}
	if err := c.wait(ctx, env); errors.Is(err, errPending) {
		out["note"] = "Incus is still at it; check again with instances"
	} else if err != nil {
		return sdk.Result{}, err
	}
	// Read the state back.
	if now, err := c.instance(ctx, i.Name); err == nil {
		out["status"] = now.Status
		if now.Status != want && out["note"] == nil {
			return sdk.Result{}, fmt.Errorf("%s is %s after the %s", i.label(), now.Status, call.Action)
		}
	}
	res, err := sdk.JSON(out)
	switch call.Action {
	case "start":
		res.Undo = sdk.UndoWith("stop", map[string]string{"instance": i.Name}, "Stop "+i.label()+" again")
	case "stop":
		res.Undo = sdk.UndoWith("start", map[string]string{"instance": i.Name}, "Start "+i.label()+" again")
	}
	return res, err
}

type snapshot struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
	Stateful    bool   `json:"stateful"`
	Size        int64  `json:"size"`
}

func (c *conn) snapshots(ctx context.Context, name string) ([]snapshot, error) {
	env, err := c.do(ctx, http.MethodGet, "/1.0/instances/"+url.PathEscape(name)+"/snapshots", url.Values{"recursion": {"1"}, "project": {c.project}}, nil)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return nil, fmt.Errorf("there's no instance %s in project %s", name, c.project)
		}
		return nil, err
	}
	var ss []snapshot
	if err := json.Unmarshal(env.Metadata, &ss); err != nil {
		return nil, fmt.Errorf("incus: unexpected answer: %w", err)
	}
	for k := range ss {
		// Older servers name them "instance/snapshot".
		if i := strings.LastIndex(ss[k].Name, "/"); i >= 0 {
			ss[k].Name = ss[k].Name[i+1:]
		}
	}
	sort.Slice(ss, func(a, b int) bool { return ss[a].CreatedAt > ss[b].CreatedAt })
	return ss, nil
}

func (c *conn) snapshotChange(ctx context.Context, call sdk.Call, p params) (sdk.Result, error) {
	i, err := c.instance(ctx, p.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	ss, err := c.snapshots(ctx, i.Name)
	if err != nil {
		return sdk.Result{}, err
	}
	exists := false
	for _, s := range ss {
		if s.Name == p.Name {
			exists = true
		}
	}
	target := "snapshot " + p.Name + " of " + i.label() + " in project " + c.project
	create := call.Action == "snapshot"
	switch {
	case create && exists:
		return sdk.Result{}, fmt.Errorf("%s already has a snapshot %s", i.label(), p.Name)
	case !create && !exists:
		return sdk.JSON(map[string]any{"instance": i.Name, "snapshot": p.Name, "changed": false, "note": "nothing to change: there's no such snapshot"})
	}
	if call.DryRun {
		op, verb := "delete", "Delete "
		if create {
			op, verb = "create", "Take "
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + target, Changes: []sdk.Change{{Target: target, Op: op}}}}, nil
	}
	path := "/1.0/instances/" + url.PathEscape(i.Name) + "/snapshots"
	var env envelope
	if create {
		env, err = c.do(ctx, http.MethodPost, path, c.proj(), map[string]any{"name": p.Name, "stateful": false})
	} else {
		env, err = c.do(ctx, http.MethodDelete, path+"/"+url.PathEscape(p.Name), c.proj(), nil)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"instance": i.Name, "snapshot": p.Name, "changed": true}
	if err := c.wait(ctx, env); errors.Is(err, errPending) {
		out["note"] = "Incus is still at it; check again with snapshots"
	} else if err != nil {
		return sdk.Result{}, err
	}
	if out["note"] == nil {
		// Read back.
		if now, err := c.snapshots(ctx, i.Name); err == nil {
			found := false
			for _, s := range now {
				found = found || s.Name == p.Name
			}
			if found != create {
				return sdk.Result{}, fmt.Errorf("Incus reported success, but the %s is %s", target, map[bool]string{true: "still there", false: "missing"}[found])
			}
		}
	}
	res, err := sdk.JSON(out)
	if create {
		res.Undo = sdk.UndoWith("delete_snapshot", map[string]string{"instance": i.Name, "name": p.Name}, "Delete the snapshot")
	}
	return res, err
}
