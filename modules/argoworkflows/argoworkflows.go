// Package argoworkflows works with an Argo Workflows server through its API
// and a bearer token: workflows with their phase, progress and steps,
// workflow templates with their parameters, submitting a workflow from a
// template, and stopping, terminating or retrying workflows.
package argoworkflows

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
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Argo Workflows server.
type Config struct {
	URL                string `json:"url"`       // e.g. https://argo.example.com:2746
	Token              string `json:"token"`     // secret:// bearer token
	Namespace          string `json:"namespace"` // default namespace, "argo" when empty
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
	ns  string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Argo Workflows module.
func New() *Module { return &Module{} }

const (
	maxValueLen = 10000
	maxNodes    = 100
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// Kubernetes names: a namespace is a DNS label, a workflow or template a
	// DNS subdomain.
	nsRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	nameRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	paramRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)
	phases   = map[string]bool{"Pending": true, "Running": true, "Succeeded": true, "Failed": true, "Error": true}
	finished = map[string]bool{"Succeeded": true, "Failed": true, "Error": true}
	// secretNameRe matches parameter names that look like they hold a
	// secret: their values are hidden, and Conduit doesn't pass them.
	secretNameRe = regexp.MustCompile(`(?i)password|passwd|secret|token|key|credential`)
)

func validName(s, what string) (string, error) {
	v := strings.TrimSpace(s)
	if !nameRe.MatchString(v) || strings.Contains(v, "..") {
		return "", fmt.Errorf("the %s is its Kubernetes name, like build-x7k2p", what)
	}
	return v, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	ns := `"namespace":{"type":"string","description":"Namespace (the configured one when left out)"}`
	wf := `"workflow":{"type":"string","description":"Workflow name (see workflows)"}`
	one := `{"type":"object","required":["workflow"],"properties":{` + ns + `,` + wf + `}}`
	return sdk.Manifest{
		ID: "argoworkflows", Name: "Argo Workflows", Version: "0.1.0", Category: "Development", Icon: "pipeline",
		Description: "Argo Workflows: workflows with their phase, progress and steps, workflow templates, submitting from a template, and stopping, terminating or retrying workflows.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The Argo Server's address, e.g. https://argo.example.com:2746"},
			"token":{"type":"string","x-secret":true,"description":"A bearer token: a service account token (kubectl create token, or argo auth token); its RBAC decides what works"},
			"namespace":{"type":"string","default":"argo","description":"The namespace actions use unless they name another"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "workflows", Title: "Workflows", Description: "Workflows in a namespace, newest first: phase, progress, template, start, finish, duration and message.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + ns + `,"phase":{"type":"string","enum":["Pending","Running","Succeeded","Failed","Error"]},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "workflow", Title: "Workflow", Description: "One workflow: phase, progress, message, template, entrypoint, parameters (values hidden for names that look secret) and its steps with their phases.", Risk: sdk.RiskRead, Input: sdk.Schema(one)},
			{Name: "workflow_templates", Title: "Workflow templates", Description: "Workflow templates in a namespace with their entrypoint and parameters: defaults, allowed values and descriptions.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + ns + `}}`)},
			{Name: "submit_workflow", Title: "Submit a workflow", Description: "Submits a new workflow from a workflow template, with values for its declared parameters. It runs the template's containers with their service account and can deploy, so this is destructive. Parameters whose name looks secret can't be passed.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["template"],"properties":{` + ns + `,"template":{"type":"string","description":"Workflow template name (see workflow_templates)"},"parameters":{"type":"object","description":"Values for the template's declared parameters by name; the defaults fill the rest","additionalProperties":{"type":["string","number","boolean"]}}}}`)},
			{Name: "stop_workflow", Title: "Stop a workflow", Description: "Stops a running workflow: its running steps are stopped and exit handlers still run. Destructive: work in flight is cut short.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(one)},
			{Name: "terminate_workflow", Title: "Terminate a workflow", Description: "Terminates a running workflow at once, without running exit handlers. Destructive: cleanup steps are skipped.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(one)},
			{Name: "retry_workflow", Title: "Retry a workflow", Description: "Retries a failed workflow from its failed steps. Destructive: its code runs again with its credentials.", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(one)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "workflow", Title: "Workflows", ListAction: "workflows", GetAction: "workflow", ViewHint: "table"}},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://argo.example.com:2746")
	}
	ns := strings.TrimSpace(c.Namespace)
	if ns == "" {
		ns = "argo"
	}
	if !nsRe.MatchString(ns) {
		return errors.New("the namespace is a Kubernetes namespace name, like argo")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the token in the vault and enter its secret:// reference")
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
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/")+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		// argo auth token prints the token with its scheme.
		t = strings.TrimSpace(t)
		if len(t) > 7 && strings.EqualFold(t[:7], "bearer ") {
			t = strings.TrimSpace(t[7:])
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, ns: ns})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Argo Workflows refused the token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Argo Workflows refused: the token's service account isn't allowed to do this here")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s (or the token can't see it)", what)
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any, what string) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err, what)
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
	if err := c.do(ctx, http.MethodGet, "/version", nil, nil, &v, "Argo Server at this address"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if v.Version == "" {
		return sdk.Health{Status: "down", Message: "no Argo Server at this address"}
	}
	var l struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/workflows/"+c.ns, url.Values{"listOptions.limit": {"1"}, "fields": {"items.metadata.name"}}, nil, &l, "namespace "+c.ns); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "Argo Workflows " + v.Version + " · namespace " + c.ns}
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// text is free text the server passes on (a step's message): redacted
// first, then cut.
func text(s string, n int) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return clip(rest.Redact(s), n)
}

func took(start, end string) string {
	a, err1 := time.Parse(time.RFC3339, start)
	b, err2 := time.Parse(time.RFC3339, end)
	if err1 != nil || err2 != nil || b.Before(a) {
		return ""
	}
	return b.Sub(a).Round(time.Second).String()
}

type paramSpec struct {
	Name        string    `json:"name"`
	Value       *string   `json:"value"`
	Default     *string   `json:"default"`
	Enum        []string  `json:"enum"`
	Description string    `json:"description"`
	ValueFrom   *struct{} `json:"valueFrom"`
}

func (p paramSpec) hidden() bool { return secretNameRe.MatchString(p.Name) }

func (p paramSpec) value() (string, bool) {
	if p.Value != nil {
		return *p.Value, true
	}
	if p.Default != nil {
		return *p.Default, true
	}
	return "", false
}

func paramsOut(ps []paramSpec, withEnum bool) []map[string]any {
	out := []map[string]any{}
	for _, p := range ps {
		row := map[string]any{"name": p.Name}
		if v, ok := p.value(); ok {
			if p.hidden() {
				row["value"] = "[hidden]"
			} else {
				row["value"] = clip(v, 300)
			}
		}
		if withEnum && len(p.Enum) > 0 {
			row["enum"] = p.Enum
		}
		if p.Description != "" {
			row["description"] = text(p.Description, 200)
		}
		if p.ValueFrom != nil {
			row["valueFrom"] = true
		}
		out = append(out, row)
	}
	return out
}

type workflow struct {
	Metadata struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Created   string            `json:"creationTimestamp"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		Entrypoint  string `json:"entrypoint"`
		Suspend     *bool  `json:"suspend"`
		Shutdown    string `json:"shutdown"`
		TemplateRef *struct {
			Name         string `json:"name"`
			ClusterScope bool   `json:"clusterScope"`
		} `json:"workflowTemplateRef"`
		Arguments struct {
			Parameters []paramSpec `json:"parameters"`
		} `json:"arguments"`
	} `json:"spec"`
	Status struct {
		Phase      string `json:"phase"`
		StartedAt  string `json:"startedAt"`
		FinishedAt string `json:"finishedAt"`
		Progress   string `json:"progress"`
		Message    string `json:"message"`
		Nodes      map[string]struct {
			DisplayName  string `json:"displayName"`
			TemplateName string `json:"templateName"`
			Type         string `json:"type"`
			Phase        string `json:"phase"`
			Message      string `json:"message"`
			StartedAt    string `json:"startedAt"`
			FinishedAt   string `json:"finishedAt"`
		} `json:"nodes"`
	} `json:"status"`
}

func (w workflow) template() string {
	if w.Spec.TemplateRef != nil {
		return w.Spec.TemplateRef.Name
	}
	return w.Metadata.Labels["workflows.argoproj.io/workflow-template"]
}

func summary(w workflow) map[string]any {
	row := map[string]any{"name": w.Metadata.Name, "namespace": w.Metadata.Namespace, "phase": w.Status.Phase, "created": w.Metadata.Created}
	if w.Status.Phase == "" {
		row["phase"] = "Pending"
	}
	if t := w.template(); t != "" {
		row["template"] = t
	}
	if w.Status.Progress != "" {
		row["progress"] = w.Status.Progress
	}
	if w.Status.StartedAt != "" {
		row["started"] = w.Status.StartedAt
	}
	if w.Status.FinishedAt != "" {
		row["finished"] = w.Status.FinishedAt
		if d := took(w.Status.StartedAt, w.Status.FinishedAt); d != "" {
			row["duration"] = d
		}
	}
	if w.Status.Message != "" {
		row["message"] = text(w.Status.Message, 300)
	}
	if w.Spec.Suspend != nil && *w.Spec.Suspend {
		row["suspended"] = true
	}
	return row
}

const listFields = "metadata.continue,items.metadata.name,items.metadata.namespace,items.metadata.creationTimestamp,items.metadata.labels,items.spec.workflowTemplateRef,items.spec.suspend,items.status.phase,items.status.startedAt,items.status.finishedAt,items.status.progress,items.status.message"

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Namespace  string         `json:"namespace"`
		Workflow   string         `json:"workflow"`
		Template   string         `json:"template"`
		Phase      string         `json:"phase"`
		Limit      int            `json:"limit"`
		Parameters map[string]any `json:"parameters"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "workflows", "workflow", "workflow_templates", "submit_workflow", "stop_workflow", "terminate_workflow", "retry_workflow":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	ns := c.ns
	if v := strings.TrimSpace(p.Namespace); v != "" {
		if !nsRe.MatchString(v) {
			return sdk.Result{}, errors.New("the namespace is a Kubernetes namespace name, like argo")
		}
		ns = v
	}
	switch call.Action {
	case "workflows":
		n := p.Limit
		if n == 0 {
			n = 20
		}
		if n < 1 || n > 100 {
			return sdk.Result{}, errors.New("limit is between 1 and 100")
		}
		q := url.Values{"listOptions.limit": {strconv.Itoa(n)}, "fields": {listFields}}
		if p.Phase != "" {
			if !phases[p.Phase] {
				return sdk.Result{}, errors.New("phase is Pending, Running, Succeeded, Failed or Error")
			}
			q.Set("listOptions.labelSelector", "workflows.argoproj.io/phase="+p.Phase)
		}
		var l struct {
			Items []workflow `json:"items"`
		}
		if err := c.do(ctx, http.MethodGet, "/workflows/"+ns, q, nil, &l, "namespace "+ns); err != nil {
			return sdk.Result{}, err
		}
		sort.SliceStable(l.Items, func(i, j int) bool { return l.Items[i].Metadata.Created > l.Items[j].Metadata.Created })
		if len(l.Items) > n {
			l.Items = l.Items[:n]
		}
		out := []map[string]any{}
		for _, w := range l.Items {
			out = append(out, summary(w))
		}
		return sdk.JSON(out)

	case "workflow_templates":
		var l struct {
			Items []struct {
				Metadata struct {
					Name    string `json:"name"`
					Created string `json:"creationTimestamp"`
				} `json:"metadata"`
				Spec struct {
					Entrypoint string `json:"entrypoint"`
					Arguments  struct {
						Parameters []paramSpec `json:"parameters"`
					} `json:"arguments"`
				} `json:"spec"`
			} `json:"items"`
		}
		if err := c.do(ctx, http.MethodGet, "/workflow-templates/"+ns, nil, nil, &l, "namespace "+ns); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range l.Items {
			out = append(out, map[string]any{"name": t.Metadata.Name, "created": t.Metadata.Created, "entrypoint": t.Spec.Entrypoint, "parameters": paramsOut(t.Spec.Arguments.Parameters, true)})
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
		return sdk.JSON(out)

	case "submit_workflow":
		return c.submit(ctx, call, ns, p.Template, p.Parameters)
	}

	name, err := validName(p.Workflow, "workflow")
	if err != nil {
		return sdk.Result{}, err
	}
	path := "/workflows/" + ns + "/" + url.PathEscape(name)
	var w workflow
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &w, "workflow "+name+" in "+ns); err != nil {
		return sdk.Result{}, err
	}
	if w.Metadata.Name != name {
		return sdk.Result{}, fmt.Errorf("unexpected answer looking up workflow %s", name)
	}
	if call.Action == "workflow" {
		out := summary(w)
		out["entrypoint"] = w.Spec.Entrypoint
		out["parameters"] = paramsOut(w.Spec.Arguments.Parameters, false)
		type step struct {
			row   map[string]any
			start string
		}
		var steps []step
		for _, n := range w.Status.Nodes {
			switch n.Type {
			case "Pod", "Suspend", "Container", "HTTP", "Plugin", "Skipped":
			default:
				continue
			}
			row := map[string]any{"name": n.DisplayName, "template": n.TemplateName, "type": n.Type, "phase": n.Phase}
			if n.StartedAt != "" {
				row["started"] = n.StartedAt
			}
			if d := took(n.StartedAt, n.FinishedAt); d != "" {
				row["duration"] = d
			}
			if n.Message != "" {
				row["message"] = text(n.Message, 200)
			}
			steps = append(steps, step{row, n.StartedAt})
		}
		sort.SliceStable(steps, func(i, j int) bool {
			if steps[i].start != steps[j].start {
				return steps[i].start < steps[j].start
			}
			return steps[i].row["name"].(string) < steps[j].row["name"].(string)
		})
		list := []map[string]any{}
		for i, s := range steps {
			if i >= maxNodes {
				out["note"] = fmt.Sprintf("the first %d of %d steps", maxNodes, len(steps))
				break
			}
			list = append(list, s.row)
		}
		out["steps"] = list
		return sdk.JSON(out)
	}

	phase := w.Status.Phase
	target := ns + "/" + name
	op := strings.TrimSuffix(call.Action, "_workflow")
	switch call.Action {
	case "stop_workflow", "terminate_workflow":
		if finished[phase] {
			return sdk.JSON(map[string]any{"workflow": name, "namespace": ns, "phase": phase, "note": "nothing to change: it already finished"})
		}
		if w.Spec.Shutdown != "" {
			return sdk.JSON(map[string]any{"workflow": name, "namespace": ns, "phase": phase, "note": "nothing to change: it's already shutting down (" + w.Spec.Shutdown + ")"})
		}
	case "retry_workflow":
		if phase == "Succeeded" {
			return sdk.Result{}, fmt.Errorf("%s succeeded; there's nothing to retry (submit a new one)", target)
		}
		if !finished[phase] {
			return sdk.Result{}, fmt.Errorf("%s is still %s; stop it or wait before retrying", target, strings.ToLower(summary(w)["phase"].(string)))
		}
	}
	if call.DryRun {
		sum := map[string]string{
			"stop":      "Stop " + target + "; running steps stop and exit handlers run",
			"terminate": "Terminate " + target + " at once, without exit handlers",
			"retry":     "Retry " + target + " from its failed steps",
		}[op]
		if t := w.template(); t != "" {
			sum += " (from template " + t + ")"
		}
		before, _ := json.Marshal(map[string]any{"phase": summary(w)["phase"], "progress": w.Status.Progress})
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "workflow " + target, Op: op, Before: before}}}}, nil
	}
	var after workflow
	if err := c.do(ctx, http.MethodPut, path+"/"+op, nil, map[string]string{"name": name, "namespace": ns}, &after, "workflow "+name+" in "+ns); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"workflow": name, "namespace": ns, "done": op, "was": summary(w)["phase"]}
	if after.Status.Phase != "" {
		out["phase"] = after.Status.Phase
	}
	return sdk.JSON(out)
}

func (c *conn) submit(ctx context.Context, call sdk.Call, ns, tmpl string, params map[string]any) (sdk.Result, error) {
	name, err := validName(tmpl, "workflow template")
	if err != nil {
		return sdk.Result{}, err
	}
	names := make([]string, 0, len(params))
	values := map[string]string{}
	for k, raw := range params {
		if !paramRe.MatchString(k) {
			return sdk.Result{}, fmt.Errorf("%q isn't a parameter name", k)
		}
		if secretNameRe.MatchString(k) {
			return sdk.Result{}, fmt.Errorf("%s looks like a secret; Conduit doesn't pass those (keep it in a Kubernetes secret the template reads)", k)
		}
		var v string
		switch x := raw.(type) {
		case string:
			v = x
		case bool:
			v = strconv.FormatBool(x)
		case float64:
			v = strconv.FormatFloat(x, 'f', -1, 64)
		default:
			return sdk.Result{}, fmt.Errorf("parameter %s is a string, number or boolean", k)
		}
		if len(v) > maxValueLen || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			return sdk.Result{}, fmt.Errorf("parameter %s is too long or not text", k)
		}
		names = append(names, k)
		values[k] = v
	}
	sort.Strings(names)
	var t struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Entrypoint string `json:"entrypoint"`
			Arguments  struct {
				Parameters []paramSpec `json:"parameters"`
			} `json:"arguments"`
		} `json:"spec"`
	}
	if err := c.do(ctx, http.MethodGet, "/workflow-templates/"+ns+"/"+url.PathEscape(name), nil, nil, &t, "workflow template "+name+" in "+ns); err != nil {
		return sdk.Result{}, err
	}
	if t.Metadata.Name != name {
		return sdk.Result{}, fmt.Errorf("unexpected answer looking up workflow template %s", name)
	}
	defs := map[string]paramSpec{}
	for _, d := range t.Spec.Arguments.Parameters {
		defs[d.Name] = d
	}
	pairs := []string{}
	shown := map[string]string{}
	for _, k := range names {
		d, ok := defs[k]
		if !ok {
			return sdk.Result{}, fmt.Errorf("%s declares no parameter %q (see workflow_templates)", name, k)
		}
		if d.ValueFrom != nil {
			return sdk.Result{}, fmt.Errorf("%s takes its value from elsewhere (valueFrom) and can't be set", k)
		}
		v := values[k]
		if len(d.Enum) > 0 {
			ok := false
			for _, e := range d.Enum {
				ok = ok || e == v
			}
			if !ok {
				return sdk.Result{}, fmt.Errorf("parameter %s is one of %s", k, strings.Join(d.Enum, ", "))
			}
		}
		pairs = append(pairs, k+"="+v)
		shown[k] = clip(v, 300)
	}
	if call.DryRun {
		sum := "Submit a workflow from template " + name + " in " + ns
		ch := sdk.Change{Target: "workflow template " + ns + "/" + name, Op: "submit"}
		if len(shown) > 0 {
			sum += " with parameters"
			ch.After, _ = json.Marshal(map[string]any{"parameters": shown})
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{ch}}}, nil
	}
	body := map[string]any{"namespace": ns, "resourceKind": "WorkflowTemplate", "resourceName": name, "submitOptions": map[string]any{"parameters": pairs}}
	var w workflow
	if err := c.do(ctx, http.MethodPost, "/workflows/"+ns+"/submit", nil, body, &w, "workflow template "+name+" in "+ns); err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"submitted": true, "workflow": w.Metadata.Name, "namespace": ns, "template": name, "phase": w.Status.Phase}
	if w.Status.Phase == "" {
		out["phase"] = "Pending"
	}
	return sdk.JSON(out)
}
