// Package nomad works with a HashiCorp Nomad cluster through its HTTP API:
// jobs with their status, allocations, nodes (eligibility and draining),
// deployments (promoting canaries), and restarting, stopping, reverting and
// dispatching jobs.
package nomad

import (
	"context"
	"encoding/base64"
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

// Config is one Nomad cluster (region).
type Config struct {
	Address            string `json:"address"`   // e.g. https://nomad.example.com:4646
	Token              string `json:"token"`     // secret:// ACL token; empty when ACLs are off
	Region             string `json:"region"`    // empty for the agent's region
	Namespace          string `json:"namespace"` // default namespace
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	region string
	ns     string
	token  bool
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Nomad module.
func New() *Module { return &Module{} }

const maxPayload = 16 << 10 // Nomad's dispatch payload limit

var (
	jobRe    = regexp.MustCompile(`^[A-Za-z0-9_.@:/=+-]{1,256}$`)
	nsRe     = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)
	regionRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	prefixRe = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f-]{0,27})?$`)
	groupRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	metaRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

func jobID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !jobRe.MatchString(s) || strings.Contains(s, "..") || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") || strings.Contains(s, "//") {
		return "", errors.New("the job is its ID (see jobs)")
	}
	return s, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	ns := `"namespace":{"type":"string","description":"Namespace (the instance's default when empty)"}`
	nsList := `"namespace":{"type":"string","description":"Namespace, or * for all"}`
	job := `"job":{"type":"string","description":"Job ID"}`
	node := `"node":{"type":"string","description":"Node ID (or its first 8 characters)"}`
	return sdk.Manifest{
		ID: "nomad", Name: "Nomad", Version: "0.1.0", Category: "Infrastructure", Icon: "server",
		Description: "HashiCorp Nomad: jobs and their status, allocations, nodes (drain, eligibility), deployments, restart, stop, revert, dispatch.",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["address"],"properties":{
			"address":{"type":"string","description":"The Nomad HTTP API, e.g. https://nomad.example.com:4646"},
			"token":{"type":"string","x-secret":true,"description":"ACL token (secret ID); leave empty when ACLs are off. Its policy decides what works"},
			"region":{"type":"string","description":"Region; empty for the agent's own"},
			"namespace":{"type":"string","default":"default","description":"Default namespace"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "jobs", Title: "Jobs", Description: "Jobs with type, status and allocation counts per state (running, failed, lost, …).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + nsList + `,"prefix":{"type":"string"}}}`)},
			{Name: "job", Title: "Job status", Description: "One job: version, status, groups with counts and drivers, parameters for dispatch, and the latest deployment. Never the task config or environment.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["job"],"properties":{` + ns + `,` + job + `}}`)},
			{Name: "allocations", Title: "Allocations", Description: "Allocations of a job (or the namespace) with node, client status, task states and restarts.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + nsList + `,` + job + `,"all":{"type":"boolean","description":"Include stopped and finished ones"}}}`)},
			{Name: "nodes", Title: "Nodes", Description: "Client nodes with status, scheduling eligibility, drain, datacenter, pool and version.", Risk: sdk.RiskRead},
			{Name: "deployments", Title: "Deployments", Description: "Deployments with status and, per group, canaries and healthy or unhealthy allocations.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + nsList + `,` + job + `}}`)},
			{Name: "node_eligibility", Title: "Set node eligibility", Description: "Marks a node eligible or ineligible for new placements; what runs there keeps running. Undo sets it back.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["node","eligible"],"properties":{` + node + `,"eligible":{"type":"boolean"}}}`)},
			{Name: "drain_node", Title: "Drain a node", Description: "Migrates the node's allocations elsewhere and stops new ones landing there. The preview lists what moves. Undo stops the drain (moved allocations stay where they went).", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["node"],"properties":{` + node + `,"deadlineMinutes":{"type":"integer","minimum":1,"maximum":1440,"default":60,"description":"After this, remaining allocations are stopped"},"ignoreSystemJobs":{"type":"boolean"}}}`)},
			{Name: "cancel_drain", Title: "Stop draining a node", Description: "Ends a drain and makes the node eligible again.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["node"],"properties":{` + node + `}}`)},
			{Name: "restart_job", Title: "Restart a job", Description: "Restarts the tasks of a job's running allocations in place (or of one group or allocation). The preview lists them.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["job"],"properties":{` + ns + `,` + job + `,"group":{"type":"string"},"allocation":{"type":"string","description":"Only this allocation (ID or first 8 characters)"}}}`)},
			{Name: "stop_job", Title: "Stop a job", Description: "Stops every allocation of the job. Undo reverts to the version that was running. Purging (which also deletes its history) has no undo.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["job"],"properties":{` + ns + `,` + job + `,"purge":{"type":"boolean"}}}`)},
			{Name: "revert_job", Title: "Revert a job", Description: "Re-submits an earlier version of the job (which starts a stopped job again). The preview shows both versions.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["job","version"],"properties":{` + ns + `,` + job + `,"version":{"type":"integer","minimum":0}}}`)},
			{Name: "dispatch_job", Title: "Dispatch a parameterized job", Description: "Starts an instance of a parameterized job with metadata and an optional payload, which runs its code. The preview shows every value.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["job"],"properties":{` + ns + `,` + job + `,"meta":{"type":"object","additionalProperties":{"type":"string"}},"payload":{"type":"string","maxLength":16384,"description":"Text passed to the job as its payload"}}}`)},
			{Name: "promote_deployment", Title: "Promote a deployment", Description: "Promotes a deployment's canaries so the rest of the allocations are replaced with the new version. The preview shows canary health.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["deployment"],"properties":{"deployment":{"type":"string","description":"Deployment ID (or its first 8 characters)"},"groups":{"type":"array","items":{"type":"string"},"description":"Only these groups (all when empty)"}}}`)},
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
		return errors.New("the address is like https://nomad.example.com:4646")
	}
	if c.Token != "" && !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the ACL token in the vault and enter its secret:// reference")
	}
	region := strings.TrimSpace(c.Region)
	if region != "" && !regionRe.MatchString(region) {
		return errors.New("the region is its name, like global")
	}
	ns := strings.TrimSpace(c.Namespace)
	if ns == "" {
		ns = "default"
	}
	if !nsRe.MatchString(ns) {
		return errors.New("the namespace is its name, like default")
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
	tok := c.Token
	api := rest.New(u.Scheme+"://"+u.Host, func(ctx context.Context, r *http.Request) error {
		if tok == "" {
			return nil
		}
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("X-Nomad-Token", strings.TrimSpace(t))
		return nil
	})
	// The token is a custom header, which Go would forward on a redirect.
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, region: region, ns: ns, token: tok != ""})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusForbidden), rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Nomad refused: permission denied (check the ACL token and its policy)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	}
	return err
}

// q returns the query with region and namespace set.
func (c *conn) q(ns string) url.Values {
	q := url.Values{}
	if c.region != "" {
		q.Set("region", c.region)
	}
	if ns != "" {
		q.Set("namespace", ns)
	}
	return q
}

// namespace picks the input's namespace or the default; * only when listing.
func (c *conn) namespace(s string, list bool) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return c.ns, nil
	}
	if s == "*" && list {
		return s, nil
	}
	if !nsRe.MatchString(s) {
		return "", fmt.Errorf("%q isn't a namespace name", s)
	}
	return s, nil
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
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if leader == "" {
		return sdk.Health{Status: "degraded", Message: "the cluster has no leader"}
	}
	msg := "leader " + leader
	if c.token {
		var self struct {
			Name string `json:"Name"`
			Type string `json:"Type"`
		}
		err := c.do(ctx, http.MethodGet, "/v1/acl/token/self", c.q(""), nil, &self)
		switch {
		case err == nil:
			msg += " · token " + self.Name + " (" + self.Type + ")"
		case rest.IsStatus(err, http.StatusForbidden) || rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusNotFound):
			return sdk.Health{Status: "down", Message: "Nomad refused the ACL token"}
		case rest.IsStatus(err, http.StatusBadRequest):
			msg += " · ACLs are off"
		default:
			return sdk.Health{Status: "down", Message: err.Error()}
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Namespace        string            `json:"namespace"`
	Job              string            `json:"job"`
	Prefix           string            `json:"prefix"`
	All              bool              `json:"all"`
	Node             string            `json:"node"`
	Eligible         *bool             `json:"eligible"`
	DeadlineMinutes  int               `json:"deadlineMinutes"`
	IgnoreSystemJobs bool              `json:"ignoreSystemJobs"`
	Group            string            `json:"group"`
	Allocation       string            `json:"allocation"`
	Purge            bool              `json:"purge"`
	Version          *uint64           `json:"version"`
	Meta             map[string]string `json:"meta"`
	Payload          string            `json:"payload"`
	Deployment       string            `json:"deployment"`
	Groups           []string          `json:"groups"`
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

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func when(ns int64) string {
	if ns <= 0 {
		return ""
	}
	return time.Unix(0, ns).UTC().Format(time.RFC3339)
}

type groupSummary struct {
	Queued, Starting, Running, Failed, Complete, Lost, Unknown int
}

type jobStub struct {
	ID               string `json:"ID"`
	Name             string `json:"Name"`
	Namespace        string `json:"Namespace"`
	Type             string `json:"Type"`
	Status           string `json:"Status"`
	Priority         int    `json:"Priority"`
	Stop             bool   `json:"Stop"`
	ParameterizedJob bool   `json:"ParameterizedJob"`
	Periodic         bool   `json:"Periodic"`
	ParentID         string `json:"ParentID"`
	SubmitTime       int64  `json:"SubmitTime"`
	JobSummary       *struct {
		Summary map[string]groupSummary `json:"Summary"`
	} `json:"JobSummary"`
}

func counts(s map[string]groupSummary) map[string]int {
	t := map[string]int{}
	for _, g := range s {
		for k, v := range map[string]int{"queued": g.Queued, "starting": g.Starting, "running": g.Running, "failed": g.Failed, "complete": g.Complete, "lost": g.Lost, "unknown": g.Unknown} {
			if v > 0 {
				t[k] += v
			}
		}
	}
	return t
}

type job struct {
	ID          string   `json:"ID"`
	Namespace   string   `json:"Namespace"`
	Type        string   `json:"Type"`
	Status      string   `json:"Status"`
	Stop        bool     `json:"Stop"`
	Version     uint64   `json:"Version"`
	Priority    int      `json:"Priority"`
	Datacenters []string `json:"Datacenters"`
	NodePool    string   `json:"NodePool"`
	TaskGroups  []struct {
		Name  string `json:"Name"`
		Count int    `json:"Count"`
		Tasks []struct {
			Name   string `json:"Name"`
			Driver string `json:"Driver"`
		} `json:"Tasks"`
	} `json:"TaskGroups"`
	Parameterized *struct {
		Payload      string   `json:"Payload"`
		MetaRequired []string `json:"MetaRequired"`
		MetaOptional []string `json:"MetaOptional"`
	} `json:"ParameterizedJob"`
	Periodic *struct {
		Spec    string `json:"Spec"`
		Enabled bool   `json:"Enabled"`
	} `json:"Periodic"`
	SubmitTime int64 `json:"SubmitTime"`
}

func (c *conn) getJob(ctx context.Context, ns, raw string) (job, error) {
	var j job
	id, err := jobID(raw)
	if err != nil {
		return j, err
	}
	if err := c.do(ctx, http.MethodGet, "/v1/job/"+url.PathEscape(id), c.q(ns), nil, &j); err != nil {
		return j, friendly(err, fmt.Sprintf("job %s in namespace %s", id, ns))
	}
	if j.ID != id {
		return j, errors.New("unexpected job from Nomad")
	}
	return j, nil
}

type alloc struct {
	ID            string `json:"ID"`
	Name          string `json:"Name"`
	JobID         string `json:"JobID"`
	JobVersion    uint64 `json:"JobVersion"`
	TaskGroup     string `json:"TaskGroup"`
	NodeID        string `json:"NodeID"`
	NodeName      string `json:"NodeName"`
	ClientStatus  string `json:"ClientStatus"`
	DesiredStatus string `json:"DesiredStatus"`
	CreateTime    int64  `json:"CreateTime"`
	ModifyTime    int64  `json:"ModifyTime"`
	JobType       string `json:"JobType"`
	TaskStates    map[string]struct {
		State    string `json:"State"`
		Failed   bool   `json:"Failed"`
		Restarts int    `json:"Restarts"`
	} `json:"TaskStates"`
}

func (a alloc) live() bool {
	return a.DesiredStatus == "run" && (a.ClientStatus == "running" || a.ClientStatus == "pending")
}

func (a alloc) summary() map[string]any {
	tasks := map[string]any{}
	for name, t := range a.TaskStates {
		e := map[string]any{"state": t.State, "restarts": t.Restarts}
		if t.Failed {
			e["failed"] = true
		}
		tasks[name] = e
	}
	return map[string]any{"id": a.ID, "name": a.Name, "job": a.JobID, "version": a.JobVersion, "group": a.TaskGroup, "node": a.NodeName, "nodeId": short(a.NodeID),
		"clientStatus": a.ClientStatus, "desiredStatus": a.DesiredStatus, "created": when(a.CreateTime), "modified": when(a.ModifyTime), "tasks": tasks}
}

func allocLabel(a alloc) string {
	return fmt.Sprintf("%s (%s on %s)", short(a.ID), a.Name, a.NodeName)
}

type deployment struct {
	ID                string `json:"ID"`
	JobID             string `json:"JobID"`
	Namespace         string `json:"Namespace"`
	JobVersion        uint64 `json:"JobVersion"`
	Status            string `json:"Status"`
	StatusDescription string `json:"StatusDescription"`
	TaskGroups        map[string]struct {
		Promoted        bool     `json:"Promoted"`
		AutoPromote     bool     `json:"AutoPromote"`
		DesiredCanaries int      `json:"DesiredCanaries"`
		PlacedCanaries  []string `json:"PlacedCanaries"`
		DesiredTotal    int      `json:"DesiredTotal"`
		PlacedAllocs    int      `json:"PlacedAllocs"`
		HealthyAllocs   int      `json:"HealthyAllocs"`
		UnhealthyAllocs int      `json:"UnhealthyAllocs"`
	} `json:"TaskGroups"`
}

func (d deployment) summary() map[string]any {
	groups := map[string]any{}
	for name, g := range d.TaskGroups {
		groups[name] = map[string]any{"desiredTotal": g.DesiredTotal, "placed": g.PlacedAllocs, "healthy": g.HealthyAllocs, "unhealthy": g.UnhealthyAllocs,
			"desiredCanaries": g.DesiredCanaries, "placedCanaries": len(g.PlacedCanaries), "promoted": g.Promoted, "autoPromote": g.AutoPromote}
	}
	return map[string]any{"id": d.ID, "job": d.JobID, "namespace": d.Namespace, "version": d.JobVersion, "status": d.Status, "description": clip(d.StatusDescription, 300), "groups": groups}
}

type node struct {
	ID                    string `json:"ID"`
	Name                  string `json:"Name"`
	Datacenter            string `json:"Datacenter"`
	NodeClass             string `json:"NodeClass"`
	NodePool              string `json:"NodePool"`
	Status                string `json:"Status"`
	SchedulingEligibility string `json:"SchedulingEligibility"`
	Drain                 bool   `json:"Drain"`
	Version               string `json:"Version"`
}

// resolve turns a full ID or 8+ character prefix into one full ID, using a
// list endpoint that supports ?prefix=.
func (c *conn) resolve(ctx context.Context, raw, list, what string, q url.Values) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if uuidRe.MatchString(s) {
		return s, nil
	}
	if !prefixRe.MatchString(s) {
		return "", fmt.Errorf("the %s is its ID or at least its first 8 characters", what)
	}
	q.Set("prefix", s)
	var items []struct {
		ID string `json:"ID"`
	}
	if err := c.do(ctx, http.MethodGet, list, q, nil, &items); err != nil {
		return "", friendly(err, what)
	}
	switch len(items) {
	case 0:
		return "", fmt.Errorf("there's no %s %s", what, s)
	case 1:
		if !uuidRe.MatchString(items[0].ID) {
			return "", fmt.Errorf("unexpected %s ID from Nomad", what)
		}
		return items[0].ID, nil
	}
	return "", fmt.Errorf("%d %ss start with %s; give more of the ID", len(items), what, s)
}

func (c *conn) getNode(ctx context.Context, raw string) (node, error) {
	var n node
	id, err := c.resolve(ctx, raw, "/v1/nodes", "node", c.q(""))
	if err != nil {
		return n, err
	}
	if err := c.do(ctx, http.MethodGet, "/v1/node/"+id, c.q(""), nil, &n); err != nil {
		return n, friendly(err, "node "+id)
	}
	// n.ID goes into later request paths (drain, eligibility): it must be
	// the node asked for, not whatever the server answered.
	if n.ID != id || !uuidRe.MatchString(n.ID) {
		return n, errors.New("unexpected node from Nomad")
	}
	return n, nil
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
	list := call.Action == "jobs" || call.Action == "allocations" || call.Action == "deployments"
	ns, err := c.namespace(p.Namespace, list)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "jobs":
		q := c.q(ns)
		if p.Prefix != "" {
			if !jobRe.MatchString(p.Prefix) {
				return sdk.Result{}, errors.New("the prefix is the start of a job ID")
			}
			q.Set("prefix", p.Prefix)
		}
		var jobs []jobStub
		if err := c.do(ctx, http.MethodGet, "/v1/jobs", q, nil, &jobs); err != nil {
			return sdk.Result{}, friendly(err, "namespace "+ns)
		}
		out := []map[string]any{}
		for _, j := range jobs {
			e := map[string]any{"id": j.ID, "namespace": j.Namespace, "type": j.Type, "status": j.Status, "priority": j.Priority, "submitted": when(j.SubmitTime)}
			if j.JobSummary != nil {
				e["allocations"] = counts(j.JobSummary.Summary)
			}
			if j.Stop {
				e["stopped"] = true
			}
			if j.ParameterizedJob {
				e["parameterized"] = true
			}
			if j.Periodic {
				e["periodic"] = true
			}
			if j.ParentID != "" {
				e["parent"] = j.ParentID
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "job":
		j, err := c.getJob(ctx, ns, p.Job)
		if err != nil {
			return sdk.Result{}, err
		}
		groups := []map[string]any{}
		for _, g := range j.TaskGroups {
			var tasks []string
			for _, t := range g.Tasks {
				tasks = append(tasks, t.Name+" ("+t.Driver+")")
			}
			groups = append(groups, map[string]any{"name": g.Name, "count": g.Count, "tasks": tasks})
		}
		out := map[string]any{"id": j.ID, "namespace": j.Namespace, "type": j.Type, "status": j.Status, "stopped": j.Stop, "version": j.Version, "priority": j.Priority,
			"datacenters": j.Datacenters, "nodePool": j.NodePool, "groups": groups, "submitted": when(j.SubmitTime)}
		if pj := j.Parameterized; pj != nil {
			out["parameterized"] = map[string]any{"payload": pj.Payload, "metaRequired": pj.MetaRequired, "metaOptional": pj.MetaOptional}
		}
		if j.Periodic != nil {
			out["periodic"] = map[string]any{"spec": j.Periodic.Spec, "enabled": j.Periodic.Enabled}
		}
		var sum struct {
			Summary map[string]groupSummary `json:"Summary"`
		}
		if c.do(ctx, http.MethodGet, "/v1/job/"+url.PathEscape(j.ID)+"/summary", c.q(ns), nil, &sum) == nil {
			out["allocations"] = counts(sum.Summary)
		}
		var d *deployment
		if c.do(ctx, http.MethodGet, "/v1/job/"+url.PathEscape(j.ID)+"/deployment", c.q(ns), nil, &d) == nil && d != nil {
			out["latestDeployment"] = d.summary()
		}
		return sdk.JSON(out)

	case "allocations":
		var allocs []alloc
		if p.Job != "" {
			id, err := jobID(p.Job)
			if err != nil {
				return sdk.Result{}, err
			}
			q := c.q(ns)
			if p.All {
				q.Set("all", "true")
			}
			if err := c.do(ctx, http.MethodGet, "/v1/job/"+url.PathEscape(id)+"/allocations", q, nil, &allocs); err != nil {
				return sdk.Result{}, friendly(err, "job "+id)
			}
		} else if err := c.do(ctx, http.MethodGet, "/v1/allocations", c.q(ns), nil, &allocs); err != nil {
			return sdk.Result{}, friendly(err, "namespace "+ns)
		}
		sort.SliceStable(allocs, func(i, j int) bool { return allocs[i].CreateTime > allocs[j].CreateTime })
		out := []map[string]any{}
		for _, a := range allocs {
			if !p.All && a.DesiredStatus != "run" && a.ClientStatus != "running" {
				continue
			}
			if len(out) == 200 {
				break
			}
			out = append(out, a.summary())
		}
		return sdk.JSON(out)

	case "nodes":
		var nodes []node
		if err := c.do(ctx, http.MethodGet, "/v1/nodes", c.q(""), nil, &nodes); err != nil {
			return sdk.Result{}, friendly(err, "node")
		}
		out := []map[string]any{}
		for _, n := range nodes {
			out = append(out, map[string]any{"id": n.ID, "name": n.Name, "datacenter": n.Datacenter, "class": n.NodeClass, "pool": n.NodePool, "status": n.Status,
				"eligibility": n.SchedulingEligibility, "draining": n.Drain, "version": n.Version})
		}
		return sdk.JSON(out)

	case "deployments":
		var ds []deployment
		path := "/v1/deployments"
		if p.Job != "" {
			id, err := jobID(p.Job)
			if err != nil {
				return sdk.Result{}, err
			}
			path = "/v1/job/" + url.PathEscape(id) + "/deployments"
		}
		if err := c.do(ctx, http.MethodGet, path, c.q(ns), nil, &ds); err != nil {
			return sdk.Result{}, friendly(err, "job")
		}
		out := []map[string]any{}
		for i, d := range ds {
			if i == 100 {
				break
			}
			out = append(out, d.summary())
		}
		return sdk.JSON(out)

	case "node_eligibility":
		if p.Eligible == nil {
			return sdk.Result{}, errors.New("say whether the node is eligible (true or false)")
		}
		return c.eligibility(ctx, call, p.Node, *p.Eligible)
	case "drain_node":
		return c.drain(ctx, call, p)
	case "cancel_drain":
		n, err := c.getNode(ctx, p.Node)
		if err != nil {
			return sdk.Result{}, err
		}
		if !n.Drain {
			return sdk.JSON(map[string]any{"node": n.Name, "note": "it isn't draining"})
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Stop draining %s and make it eligible again; allocations already moved stay where they are", n.Name),
				Changes: []sdk.Change{{Target: "node " + n.Name, Op: "cancel drain", Before: mustJSON(map[string]any{"draining": true}), After: mustJSON(map[string]any{"draining": false, "eligibility": "eligible"})}}}}, nil
		}
		if err := c.do(ctx, http.MethodPost, "/v1/node/"+n.ID+"/drain", c.q(""), map[string]any{"NodeID": n.ID, "DrainSpec": nil, "MarkEligible": true}, nil); err != nil {
			return sdk.Result{}, friendly(err, "node")
		}
		return sdk.JSON(map[string]any{"node": n.Name, "draining": false})

	case "restart_job":
		return c.restart(ctx, call, ns, p)
	case "stop_job":
		return c.stop(ctx, call, ns, p)
	case "revert_job":
		return c.revert(ctx, call, ns, p)
	case "dispatch_job":
		return c.dispatch(ctx, call, ns, p)
	case "promote_deployment":
		return c.promote(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) eligibility(ctx context.Context, call sdk.Call, raw string, eligible bool) (sdk.Result, error) {
	n, err := c.getNode(ctx, raw)
	if err != nil {
		return sdk.Result{}, err
	}
	want := "ineligible"
	if eligible {
		want = "eligible"
	}
	if n.SchedulingEligibility == want {
		return sdk.JSON(map[string]any{"node": n.Name, "note": "it's already " + want})
	}
	if eligible && n.Drain {
		return sdk.Result{}, fmt.Errorf("%s is draining; use cancel_drain", n.Name)
	}
	if call.DryRun {
		sum := fmt.Sprintf("Mark %s %s for new allocations", n.Name, want)
		if !eligible {
			sum += "; what runs there keeps running"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "node " + n.Name, Op: "update", Before: mustJSON(map[string]any{"eligibility": n.SchedulingEligibility}), After: mustJSON(map[string]any{"eligibility": want})}}}}, nil
	}
	if err := c.do(ctx, http.MethodPost, "/v1/node/"+n.ID+"/eligibility", c.q(""), map[string]any{"NodeID": n.ID, "Eligibility": want}, nil); err != nil {
		return sdk.Result{}, friendly(err, "node")
	}
	res, err := sdk.JSON(map[string]any{"node": n.Name, "eligibility": want})
	res.Undo = sdk.UndoWith("node_eligibility", map[string]any{"node": n.ID, "eligible": !eligible}, fmt.Sprintf("Mark %s %s again", n.Name, n.SchedulingEligibility))
	return res, err
}

func (c *conn) nodeAllocs(ctx context.Context, id string) ([]alloc, error) {
	var allocs []alloc
	if err := c.do(ctx, http.MethodGet, "/v1/node/"+id+"/allocations", c.q(""), nil, &allocs); err != nil {
		return nil, friendly(err, "node")
	}
	return allocs, nil
}

func (c *conn) drain(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	mins := p.DeadlineMinutes
	if mins == 0 {
		mins = 60
	}
	if mins < 1 || mins > 1440 {
		return sdk.Result{}, errors.New("the deadline is between 1 and 1440 minutes")
	}
	n, err := c.getNode(ctx, p.Node)
	if err != nil {
		return sdk.Result{}, err
	}
	if n.Drain {
		return sdk.JSON(map[string]any{"node": n.Name, "note": "it's already draining"})
	}
	if call.DryRun {
		allocs, err := c.nodeAllocs(ctx, n.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		var moving []string
		for _, a := range allocs {
			if a.live() && !(p.IgnoreSystemJobs && a.JobType == "system") {
				moving = append(moving, allocLabel(a))
			}
		}
		sum := fmt.Sprintf("Drain %s: %d allocation(s) are migrated to other nodes; whatever is left after %d minutes is stopped", n.Name, len(moving), mins)
		if p.IgnoreSystemJobs {
			sum += "; system jobs keep running"
		}
		changes := []sdk.Change{{Target: "node " + n.Name, Op: "drain", Before: mustJSON(map[string]any{"eligibility": n.SchedulingEligibility}), After: mustJSON(map[string]any{"eligibility": "ineligible", "deadlineMinutes": mins})}}
		for _, a := range moving {
			changes = append(changes, sdk.Change{Target: "allocation " + a, Op: "migrate"})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: changes}}, nil
	}
	spec := map[string]any{"Deadline": int64(time.Duration(mins) * time.Minute), "IgnoreSystemJobs": p.IgnoreSystemJobs}
	if err := c.do(ctx, http.MethodPost, "/v1/node/"+n.ID+"/drain", c.q(""), map[string]any{"NodeID": n.ID, "DrainSpec": spec, "MarkEligible": false}, nil); err != nil {
		return sdk.Result{}, friendly(err, "node")
	}
	res, err := sdk.JSON(map[string]any{"node": n.Name, "draining": true, "deadlineMinutes": mins})
	res.Undo = sdk.UndoWith("cancel_drain", map[string]any{"node": n.ID}, fmt.Sprintf("Stop draining %s (moved allocations stay where they went)", n.Name))
	return res, err
}

func (c *conn) restart(ctx context.Context, call sdk.Call, ns string, p input) (sdk.Result, error) {
	if p.Group != "" && !groupRe.MatchString(p.Group) {
		return sdk.Result{}, errors.New("the group is a task group name")
	}
	var only string
	if p.Allocation != "" {
		s := strings.ToLower(strings.TrimSpace(p.Allocation))
		if !uuidRe.MatchString(s) && !prefixRe.MatchString(s) {
			return sdk.Result{}, errors.New("the allocation is its ID or its first 8 characters")
		}
		only = s
	}
	j, err := c.getJob(ctx, ns, p.Job)
	if err != nil {
		return sdk.Result{}, err
	}
	var allocs []alloc
	if err := c.do(ctx, http.MethodGet, "/v1/job/"+url.PathEscape(j.ID)+"/allocations", c.q(ns), nil, &allocs); err != nil {
		return sdk.Result{}, friendly(err, "job")
	}
	var targets []alloc
	for _, a := range allocs {
		if !a.live() || a.ClientStatus != "running" || !uuidRe.MatchString(a.ID) {
			continue
		}
		if p.Group != "" && a.TaskGroup != p.Group {
			continue
		}
		if only != "" && !strings.HasPrefix(a.ID, only) {
			continue
		}
		targets = append(targets, a)
	}
	if only != "" && len(targets) > 1 {
		return sdk.Result{}, fmt.Errorf("%d allocations start with %s; give more of the ID", len(targets), only)
	}
	if len(targets) == 0 {
		return sdk.Result{}, fmt.Errorf("%s has no running allocations to restart", j.ID)
	}
	if call.DryRun {
		changes := []sdk.Change{}
		for _, a := range targets {
			changes = append(changes, sdk.Change{Target: "allocation " + allocLabel(a), Op: "restart"})
		}
		sum := fmt.Sprintf("Restart every task of %d running allocation(s) of %s in place; the tasks are briefly down", len(targets), j.ID)
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: changes}}, nil
	}
	done, failed := []string{}, map[string]string{}
	for _, a := range targets {
		if err := c.do(ctx, http.MethodPost, "/v1/client/allocation/"+a.ID+"/restart", c.q(ns), map[string]any{"AllTasks": true}, nil); err != nil {
			failed[short(a.ID)] = friendly(err, "allocation").Error()
			continue
		}
		done = append(done, short(a.ID))
	}
	out := map[string]any{"job": j.ID, "restarted": done}
	if len(failed) > 0 {
		out["failed"] = failed
		if len(done) == 0 {
			return sdk.Result{}, fmt.Errorf("no allocation restarted: %v", failed)
		}
	}
	return sdk.JSON(out)
}

func (c *conn) stop(ctx context.Context, call sdk.Call, ns string, p input) (sdk.Result, error) {
	j, err := c.getJob(ctx, ns, p.Job)
	if err != nil {
		return sdk.Result{}, err
	}
	if j.Stop && !p.Purge {
		return sdk.JSON(map[string]any{"job": j.ID, "note": "it's already stopped"})
	}
	if call.DryRun {
		var allocs []alloc
		if err := c.do(ctx, http.MethodGet, "/v1/job/"+url.PathEscape(j.ID)+"/allocations", c.q(ns), nil, &allocs); err != nil {
			return sdk.Result{}, friendly(err, "job")
		}
		changes := []sdk.Change{{Target: "job " + j.ID, Op: "stop", Before: mustJSON(map[string]any{"status": j.Status, "version": j.Version}), After: mustJSON(map[string]any{"stopped": true, "purge": p.Purge})}}
		live := 0
		for _, a := range allocs {
			if a.live() {
				live++
				changes = append(changes, sdk.Change{Target: "allocation " + allocLabel(a), Op: "stop"})
			}
		}
		sum := fmt.Sprintf("Stop %s (%s, version %d): %d running allocation(s) stop", j.ID, j.Type, j.Version, live)
		if p.Purge {
			sum += "; PURGE deletes the job and its history, so this can't be undone"
		} else {
			sum += fmt.Sprintf("; undo reverts to version %d", j.Version)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: changes}}, nil
	}
	q := c.q(ns)
	q.Set("purge", strconv.FormatBool(p.Purge))
	var ev struct {
		EvalID string `json:"EvalID"`
	}
	if err := c.do(ctx, http.MethodDelete, "/v1/job/"+url.PathEscape(j.ID), q, nil, &ev); err != nil {
		return sdk.Result{}, friendly(err, "job")
	}
	res, err := sdk.JSON(map[string]any{"job": j.ID, "stopped": true, "purged": p.Purge, "evaluation": ev.EvalID})
	if !p.Purge && !j.Stop {
		res.Undo = sdk.UndoWith("revert_job", map[string]any{"job": j.ID, "namespace": ns, "version": j.Version}, fmt.Sprintf("Start %s again at version %d", j.ID, j.Version))
	}
	return res, err
}

func (c *conn) revert(ctx context.Context, call sdk.Call, ns string, p input) (sdk.Result, error) {
	if p.Version == nil {
		return sdk.Result{}, errors.New("give the version to revert to (see job)")
	}
	j, err := c.getJob(ctx, ns, p.Job)
	if err != nil {
		return sdk.Result{}, err
	}
	var vs struct {
		Versions []struct {
			Version    uint64 `json:"Version"`
			Stop       bool   `json:"Stop"`
			SubmitTime int64  `json:"SubmitTime"`
		} `json:"Versions"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/job/"+url.PathEscape(j.ID)+"/versions", c.q(ns), nil, &vs); err != nil {
		return sdk.Result{}, friendly(err, "job")
	}
	found := -1
	for i, v := range vs.Versions {
		if v.Version == *p.Version {
			found = i
		}
	}
	if found < 0 {
		return sdk.Result{}, fmt.Errorf("%s has no version %d (Nomad keeps the last few)", j.ID, *p.Version)
	}
	target := vs.Versions[found]
	if target.Version == j.Version {
		return sdk.Result{}, fmt.Errorf("%s is already at version %d", j.ID, j.Version)
	}
	if call.DryRun {
		sum := fmt.Sprintf("Revert %s from version %d to version %d (submitted %s)", j.ID, j.Version, target.Version, when(target.SubmitTime))
		if j.Stop && !target.Stop {
			sum += "; this starts the stopped job again"
		}
		if target.Stop {
			sum += "; that version is a stopped one, so the job stops"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "job " + j.ID, Op: "revert",
			Before: mustJSON(map[string]any{"version": j.Version, "stopped": j.Stop}), After: mustJSON(map[string]any{"version": target.Version, "stopped": target.Stop})}}}}, nil
	}
	body := map[string]any{"JobID": j.ID, "JobVersion": target.Version, "EnforcePriorVersion": j.Version}
	var ev struct {
		EvalID string `json:"EvalID"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/job/"+url.PathEscape(j.ID)+"/revert", c.q(ns), body, &ev); err != nil {
		return sdk.Result{}, friendly(err, "job")
	}
	return sdk.JSON(map[string]any{"job": j.ID, "from": j.Version, "to": target.Version, "evaluation": ev.EvalID})
}

func (c *conn) dispatch(ctx context.Context, call sdk.Call, ns string, p input) (sdk.Result, error) {
	if len(p.Payload) > maxPayload {
		return sdk.Result{}, fmt.Errorf("the payload is up to %d KiB", maxPayload>>10)
	}
	if len(p.Meta) > 64 {
		return sdk.Result{}, errors.New("up to 64 meta keys")
	}
	for k, v := range p.Meta {
		if !metaRe.MatchString(k) || len(v) > 4096 {
			return sdk.Result{}, fmt.Errorf("%q isn't a valid meta key (or its value is too long)", k)
		}
	}
	j, err := c.getJob(ctx, ns, p.Job)
	if err != nil {
		return sdk.Result{}, err
	}
	pj := j.Parameterized
	if pj == nil {
		return sdk.Result{}, fmt.Errorf("%s isn't a parameterized job", j.ID)
	}
	if j.Stop {
		return sdk.Result{}, fmt.Errorf("%s is stopped", j.ID)
	}
	allowed := map[string]bool{}
	for _, k := range append(append([]string{}, pj.MetaRequired...), pj.MetaOptional...) {
		allowed[k] = true
	}
	for k := range p.Meta {
		if !allowed[k] {
			return sdk.Result{}, fmt.Errorf("%s doesn't take meta %q (it takes %s)", j.ID, k, strings.Join(append(append([]string{}, pj.MetaRequired...), pj.MetaOptional...), ", "))
		}
	}
	for _, k := range pj.MetaRequired {
		if _, ok := p.Meta[k]; !ok {
			return sdk.Result{}, fmt.Errorf("%s needs meta %q", j.ID, k)
		}
	}
	switch {
	case pj.Payload == "required" && p.Payload == "":
		return sdk.Result{}, fmt.Errorf("%s needs a payload", j.ID)
	case pj.Payload == "forbidden" && p.Payload != "":
		return sdk.Result{}, fmt.Errorf("%s doesn't take a payload", j.ID)
	}
	if call.DryRun {
		after := map[string]any{"meta": p.Meta}
		if p.Payload != "" {
			after["payloadBytes"] = len(p.Payload)
			after["payload"] = clip(p.Payload, 500)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Dispatch %s (%s, version %d), which runs its tasks with these values", j.ID, j.Type, j.Version),
			Changes: []sdk.Change{{Target: "job " + j.ID, Op: "dispatch", After: mustJSON(after)}}}}, nil
	}
	body := map[string]any{"Meta": p.Meta}
	if p.Payload != "" {
		body["Payload"] = base64.StdEncoding.EncodeToString([]byte(p.Payload))
	}
	var out struct {
		DispatchedJobID string `json:"DispatchedJobID"`
		EvalID          string `json:"EvalID"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/job/"+url.PathEscape(j.ID)+"/dispatch", c.q(ns), body, &out); err != nil {
		return sdk.Result{}, friendly(err, "job")
	}
	return sdk.JSON(map[string]any{"job": j.ID, "dispatched": out.DispatchedJobID, "evaluation": out.EvalID})
}

func (c *conn) promote(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	for _, g := range p.Groups {
		if !groupRe.MatchString(g) {
			return sdk.Result{}, fmt.Errorf("%q isn't a group name", g)
		}
	}
	// Deployments are looked up across namespaces by ID.
	q := c.q("*")
	id, err := c.resolve(ctx, p.Deployment, "/v1/deployments", "deployment", q)
	if err != nil {
		return sdk.Result{}, err
	}
	var d deployment
	if err := c.do(ctx, http.MethodGet, "/v1/deployment/"+id, c.q(""), nil, &d); err != nil {
		return sdk.Result{}, friendly(err, "deployment "+id)
	}
	// d.ID and d.Namespace go into the promote request: they must be the
	// deployment asked for and a plain namespace name.
	if d.ID != id || !uuidRe.MatchString(d.ID) || (d.Namespace != "" && !nsRe.MatchString(d.Namespace)) {
		return sdk.Result{}, errors.New("unexpected deployment from Nomad")
	}
	if d.Status != "running" {
		return sdk.Result{}, fmt.Errorf("deployment %s is %s, not running", short(d.ID), d.Status)
	}
	want := map[string]bool{}
	for _, g := range p.Groups {
		if _, ok := d.TaskGroups[g]; !ok {
			return sdk.Result{}, fmt.Errorf("deployment %s has no group %s", short(d.ID), g)
		}
		want[g] = true
	}
	var names []string
	for name, g := range d.TaskGroups {
		if g.DesiredCanaries > 0 && !g.Promoted && (len(want) == 0 || want[name]) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return sdk.Result{}, fmt.Errorf("deployment %s has no canaries waiting for promotion", short(d.ID))
	}
	if call.DryRun {
		sum := fmt.Sprintf("Promote %s version %d (deployment %s): the remaining allocations of %s are replaced", d.JobID, d.JobVersion, short(d.ID), strings.Join(names, ", "))
		changes := []sdk.Change{}
		for _, name := range names {
			g := d.TaskGroups[name]
			if g.UnhealthyAllocs > 0 {
				sum += fmt.Sprintf("; %s has %d UNHEALTHY", name, g.UnhealthyAllocs)
			} else if g.HealthyAllocs < len(g.PlacedCanaries) || len(g.PlacedCanaries) < g.DesiredCanaries {
				sum += fmt.Sprintf("; %s's canaries aren't all healthy yet (Nomad refuses until they are)", name)
			}
			changes = append(changes, sdk.Change{Target: "group " + name + " of " + d.JobID, Op: "promote",
				Before: mustJSON(map[string]any{"desiredCanaries": g.DesiredCanaries, "placedCanaries": len(g.PlacedCanaries), "healthy": g.HealthyAllocs, "unhealthy": g.UnhealthyAllocs}),
				After:  mustJSON(map[string]any{"desiredTotal": g.DesiredTotal, "version": d.JobVersion})})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: changes}}, nil
	}
	body := map[string]any{"DeploymentID": d.ID, "All": len(want) == 0}
	if len(want) > 0 {
		body["Groups"] = names
	}
	var ev struct {
		EvalID string `json:"EvalID"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/deployment/promote/"+d.ID, c.q(d.Namespace), body, &ev); err != nil {
		return sdk.Result{}, friendly(err, "deployment")
	}
	return sdk.JSON(map[string]any{"deployment": d.ID, "job": d.JobID, "promoted": names, "evaluation": ev.EvalID})
}
