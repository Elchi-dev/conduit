// Package kubernetes reads and operates a Kubernetes cluster through its API
// server: namespaces, pods, deployments, logs and events; scaling, rollout
// restarts and pod deletion. It speaks the REST API directly, so it needs no
// kubeconfig tooling and no client library.
package kubernetes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one cluster connection.
type Config struct {
	Server string `json:"server"` // https://k8s.example.com:6443
	Token  string `json:"token"`  // secret:// service account token
	// CA is the cluster's CA certificate (PEM), inline or a secret://
	// reference. Empty: the system roots are used.
	CA        string `json:"ca"`
	Namespace string `json:"namespace"` // default namespace, "default" if empty
	// InsecureSkipVerify turns off certificate checks. Discouraged: anyone
	// on the path can then read the token. Prefer CA.
	InsecureSkipVerify bool `json:"insecureSkipVerify"`
}

type conn struct {
	cfg  Config
	http *http.Client
	host sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client (tests).
	HTTP *http.Client
	now  func() time.Time
}

// New returns the Kubernetes module.
func New() *Module { return &Module{now: time.Now} }

// DNS-1123 names, as Kubernetes requires for namespaces, pods, deployments.
var nameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

const nsProp = `"namespace":{"type":"string","description":"Leave empty for the connection's default namespace"}`

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	name := func(desc string) string { return `{"type":"string","description":"` + desc + `"}` }
	return sdk.Manifest{
		ID: "kubernetes", Name: "Kubernetes", Version: "0.1.0", Category: "Infrastructure", Icon: "server",
		Description: "Pods, deployments, logs and events of a cluster; scale and restart workloads.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["server","token"],"properties":{
			"server":{"type":"string","format":"uri","description":"API server address, e.g. https://k8s.example.com:6443"},
			"token":{"type":"string","x-secret":true,"description":"A service account token (kubectl create token <account>)"},
			"ca":{"type":"string","format":"textarea","description":"The cluster's CA certificate (PEM) or a secret:// reference; empty uses the system roots"},
			"namespace":{"type":"string","default":"default"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended: the token can be intercepted)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "namespaces", Title: "Namespaces", Risk: sdk.RiskRead},
			{Name: "pods", Title: "Pods", Description: "Phase, readiness, restarts and node of each pod.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + nsProp + `,"selector":{"type":"string","description":"Label selector, e.g. app=web"}}}`)},
			{Name: "deployments", Title: "Deployments", Description: "Ready and desired replicas.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + nsProp + `}}`)},
			{Name: "logs", Title: "Pod logs", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["pod"],"properties":{` + nsProp + `,"pod":` + name("Pod name") + `,"container":` + name("Container, when the pod has several") +
					`,"tailLines":{"type":"integer","default":200,"maximum":5000},"since":{"type":"string","description":"e.g. 15m or 2h"},"previous":{"type":"boolean","description":"Logs of the previous, crashed container"}}}`)},
			{Name: "events", Title: "Warnings", Description: "Recent warning events, newest first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + nsProp + `,"all":{"type":"boolean","description":"Include normal events too"}}}`)},
			{Name: "scale", Title: "Scale a deployment", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["deployment","replicas"],"properties":{` + nsProp + `,"deployment":` + name("Deployment name") + `,"replicas":{"type":"integer","minimum":0,"maximum":1000}}}`)},
			{Name: "restart", Title: "Restart a deployment", Description: "A rolling restart, like kubectl rollout restart.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["deployment"],"properties":{` + nsProp + `,"deployment":` + name("Deployment name") + `}}`)},
			{Name: "delete_pod", Title: "Delete a pod", Description: "Its controller usually starts a new one.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["pod"],"properties":{` + nsProp + `,"pod":` + name("Pod name") + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(ctx context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(c.Server, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("the server is the API address, e.g. https://k8s.example.com:6443")
	}
	c.Server = u.String()
	if c.Token == "" {
		return errors.New("add a service account token (stored in the vault)")
	}
	if c.Namespace == "" {
		c.Namespace = "default"
	}
	if !nameRe.MatchString(c.Namespace) {
		return errors.New("the namespace isn't a valid Kubernetes name")
	}
	cn := &conn{cfg: c, host: h}
	if m.HTTP != nil {
		cn.http = m.HTTP
	} else {
		tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.InsecureSkipVerify} //nolint:gosec // opt-in, documented
		if c.CA != "" {
			pem := c.CA
			if strings.HasPrefix(pem, "secret://") {
				if pem, err = h.Secret(ctx, pem); err != nil {
					return err
				}
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(pem)) {
				return errors.New("the CA certificate isn't valid PEM")
			}
			tc.RootCAs = pool
		}
		cn.http = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment}}
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// apiError is the API's Status object.
type apiError struct {
	Message string `json:"message"`
	Reason  string `json:"reason"`
}

// do calls the API. ct is the request body's content type.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, ct string, body []byte) ([]byte, error) {
	u := c.cfg.Server + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	tok, err := c.host.Secret(ctx, c.cfg.Token)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(tok))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		var e apiError
		if json.Unmarshal(b, &e) == nil && e.Message != "" {
			return nil, fmt.Errorf("kubernetes: %s", e.Message)
		}
		return nil, fmt.Errorf("kubernetes: %s", res.Status)
	}
	return b, nil
}

func (c *conn) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	b, err := c.do(ctx, "GET", path, q, "", nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := c.getJSON(ctx, "/version", nil, &v); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "Kubernetes " + v.GitVersion}
}

type input struct {
	Namespace  string `json:"namespace"`
	Selector   string `json:"selector"`
	Pod        string `json:"pod"`
	Container  string `json:"container"`
	TailLines  int    `json:"tailLines"`
	Since      string `json:"since"`
	Previous   bool   `json:"previous"`
	All        bool   `json:"all"`
	Deployment string `json:"deployment"`
	Replicas   *int   `json:"replicas"`
}

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

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
	ns := p.Namespace
	if ns == "" {
		ns = c.cfg.Namespace
	}
	if !nameRe.MatchString(ns) {
		return sdk.Result{}, errors.New("the namespace isn't a valid Kubernetes name")
	}
	check := func(kind, v string) error {
		if !nameRe.MatchString(v) {
			return fmt.Errorf("give the %s's name", kind)
		}
		return nil
	}
	base := "/api/v1/namespaces/" + ns
	apps := "/apis/apps/v1/namespaces/" + ns

	switch call.Action {
	case "namespaces":
		var l struct {
			Items []struct {
				Metadata meta `json:"metadata"`
				Status   struct {
					Phase string `json:"phase"`
				} `json:"status"`
			} `json:"items"`
		}
		if err := c.getJSON(ctx, "/api/v1/namespaces", nil, &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]string{}
		for _, n := range l.Items {
			out = append(out, map[string]string{"name": n.Metadata.Name, "status": n.Status.Phase})
		}
		return sdk.JSON(out)

	case "pods":
		q := url.Values{}
		if p.Selector != "" {
			q.Set("labelSelector", p.Selector)
		}
		var l podList
		if err := c.getJSON(ctx, base+"/pods", q, &l); err != nil {
			return sdk.Result{}, err
		}
		type pod struct {
			Name     string `json:"name"`
			Phase    string `json:"phase"`
			Ready    string `json:"ready"`
			Restarts int    `json:"restarts"`
			Node     string `json:"node"`
			Age      string `json:"age"`
			Reason   string `json:"reason,omitempty"`
		}
		out := []pod{}
		for _, x := range l.Items {
			ready, restarts, reason := 0, 0, ""
			for _, s := range x.Status.ContainerStatuses {
				if s.Ready {
					ready++
				}
				restarts += s.RestartCount
				if s.State.Waiting.Reason != "" {
					reason = s.State.Waiting.Reason
				}
			}
			out = append(out, pod{Name: x.Metadata.Name, Phase: x.Status.Phase, Ready: fmt.Sprintf("%d/%d", ready, len(x.Spec.Containers)),
				Restarts: restarts, Node: x.Spec.NodeName, Age: m.age(x.Metadata.Created), Reason: reason})
		}
		return sdk.JSON(out)

	case "deployments":
		var l struct {
			Items []deployment `json:"items"`
		}
		if err := c.getJSON(ctx, apps+"/deployments", nil, &l); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range l.Items {
			out = append(out, map[string]any{"name": d.Metadata.Name, "desired": d.desired(), "ready": d.Status.ReadyReplicas,
				"updated": d.Status.UpdatedReplicas, "available": d.Status.AvailableReplicas, "age": m.age(d.Metadata.Created)})
		}
		return sdk.JSON(out)

	case "logs":
		if err := check("pod", p.Pod); err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{}
		n := p.TailLines
		if n <= 0 {
			n = 200
		}
		if n > 5000 {
			n = 5000
		}
		q.Set("tailLines", strconv.Itoa(n))
		if p.Container != "" {
			if err := check("container", p.Container); err != nil {
				return sdk.Result{}, err
			}
			q.Set("container", p.Container)
		}
		if p.Since != "" {
			d, err := time.ParseDuration(p.Since)
			if err != nil || d <= 0 {
				return sdk.Result{}, errors.New("since is a duration like 15m or 2h")
			}
			q.Set("sinceSeconds", strconv.Itoa(int(d.Seconds())))
		}
		if p.Previous {
			q.Set("previous", "true")
		}
		b, err := c.do(ctx, "GET", base+"/pods/"+p.Pod+"/log", q, "", nil)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"pod": p.Pod, "logs": string(b)})

	case "events":
		var l struct {
			Items []struct {
				Type    string `json:"type"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
				Count   int    `json:"count"`
				Last    string `json:"lastTimestamp"`
				Event   string `json:"eventTime"`
				Object  struct {
					Kind string `json:"kind"`
					Name string `json:"name"`
				} `json:"involvedObject"`
			} `json:"items"`
		}
		q := url.Values{}
		if !p.All {
			q.Set("fieldSelector", "type=Warning")
		}
		if err := c.getJSON(ctx, base+"/events", q, &l); err != nil {
			return sdk.Result{}, err
		}
		type ev struct {
			At      string `json:"at"`
			Type    string `json:"type"`
			Object  string `json:"object"`
			Reason  string `json:"reason"`
			Message string `json:"message"`
			Count   int    `json:"count"`
		}
		out := []ev{}
		for _, e := range l.Items {
			at := e.Last
			if at == "" {
				at = e.Event
			}
			out = append(out, ev{At: at, Type: e.Type, Object: e.Object.Kind + "/" + e.Object.Name, Reason: e.Reason, Message: e.Message, Count: e.Count})
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].At > out[j].At })
		if len(out) > 100 {
			out = out[:100]
		}
		return sdk.JSON(out)

	case "scale":
		if err := check("deployment", p.Deployment); err != nil {
			return sdk.Result{}, err
		}
		if p.Replicas == nil || *p.Replicas < 0 || *p.Replicas > 1000 {
			return sdk.Result{}, errors.New("replicas is a number from 0 to 1000")
		}
		var d deployment
		if err := c.getJSON(ctx, apps+"/deployments/"+p.Deployment, nil, &d); err != nil {
			return sdk.Result{}, err
		}
		old := d.desired()
		target := "deployment " + p.Deployment + " in " + ns
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Scale %s from %d to %d", target, old, *p.Replicas),
				Changes: []sdk.Change{{Target: target, Op: "update", Before: raw(map[string]int{"replicas": old}), After: raw(map[string]int{"replicas": *p.Replicas})}}}}, nil
		}
		patch := raw(map[string]any{"spec": map[string]int{"replicas": *p.Replicas}})
		if _, err := c.do(ctx, "PATCH", apps+"/deployments/"+p.Deployment+"/scale", nil, "application/merge-patch+json", patch); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]any{"deployment": p.Deployment, "namespace": ns, "from": old, "to": *p.Replicas})
		if old != *p.Replicas {
			r.Undo = sdk.UndoWith("scale", map[string]any{"namespace": ns, "deployment": p.Deployment, "replicas": old}, fmt.Sprintf("Scale back to %d", old))
		}
		return r, nil

	case "restart":
		if err := check("deployment", p.Deployment); err != nil {
			return sdk.Result{}, err
		}
		var d deployment
		if err := c.getJSON(ctx, apps+"/deployments/"+p.Deployment, nil, &d); err != nil {
			return sdk.Result{}, err
		}
		target := "deployment " + p.Deployment + " in " + ns
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Restart the %d pods of %s one by one", d.desired(), target),
				Changes: []sdk.Change{{Target: target, Op: "restart"}}}}, nil
		}
		at := m.now().UTC().Format(time.RFC3339)
		patch := raw(map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{
			"annotations": map[string]string{"kubectl.kubernetes.io/restartedAt": at}}}}})
		if _, err := c.do(ctx, "PATCH", apps+"/deployments/"+p.Deployment, nil, "application/strategic-merge-patch+json", patch); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deployment": p.Deployment, "namespace": ns, "restartedAt": at})

	case "delete_pod":
		if err := check("pod", p.Pod); err != nil {
			return sdk.Result{}, err
		}
		target := "pod " + p.Pod + " in " + ns
		if call.DryRun {
			var x podItem
			if err := c.getJSON(ctx, base+"/pods/"+p.Pod, nil, &x); err != nil {
				return sdk.Result{}, err
			}
			owner := "nothing (it won't come back)"
			if len(x.Metadata.Owners) > 0 {
				owner = x.Metadata.Owners[0].Kind + " " + x.Metadata.Owners[0].Name
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: "Delete " + target + "; it is managed by " + owner,
				Changes: []sdk.Change{{Target: target, Op: "delete", Before: raw(map[string]string{"phase": x.Status.Phase, "node": x.Spec.NodeName})}}}}, nil
		}
		if _, err := c.do(ctx, "DELETE", base+"/pods/"+p.Pod, nil, "", nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.Pod, "namespace": ns})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

type meta struct {
	Name    string `json:"name"`
	Created string `json:"creationTimestamp"`
	Owners  []struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"ownerReferences"`
}

type podItem struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		NodeName   string     `json:"nodeName"`
		Containers []struct{} `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase             string `json:"phase"`
		ContainerStatuses []struct {
			Ready        bool `json:"ready"`
			RestartCount int  `json:"restartCount"`
			State        struct {
				Waiting struct {
					Reason string `json:"reason"`
				} `json:"waiting"`
			} `json:"state"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

type podList struct {
	Items []podItem `json:"items"`
}

type deployment struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Replicas *int `json:"replicas"`
	} `json:"spec"`
	Status struct {
		ReadyReplicas     int `json:"readyReplicas"`
		UpdatedReplicas   int `json:"updatedReplicas"`
		AvailableReplicas int `json:"availableReplicas"`
	} `json:"status"`
}

// desired is spec.replicas, which defaults to 1 when unset.
func (d deployment) desired() int {
	if d.Spec.Replicas == nil {
		return 1
	}
	return *d.Spec.Replicas
}

// age renders a creation time as 3d, 5h, 12m.
func (m *Module) age(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ""
	}
	d := m.now().Sub(t)
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}
