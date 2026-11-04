// Package argocd works with an Argo CD server through its REST API and a
// bearer token: applications with their sync and health status, an app's
// resources, and syncing, refreshing, rolling back and stopping operations.
package argocd

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

// Config is one Argo CD server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://argocd.example.com
	Token              string `json:"token"` // secret:// API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	ver    *rest.Client // root + /api, for /api/version
	origin string       // for links to the UI
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Argo CD module.
func New() *Module { return &Module{} }

var (
	// Application and project names are DNS-1123 subdomains, namespaces
	// DNS-1123 labels.
	nameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	nsRe   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	// Resource references go in request bodies, not paths.
	kindRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,62}$`)
	groupRe   = regexp.MustCompile(`^[a-z0-9.-]{0,253}$`)
	resNameRe = regexp.MustCompile(`^[A-Za-z0-9:._@-]{1,253}$`)
	revRe     = regexp.MustCompile(`^[A-Za-z0-9._/@+-]{1,255}$`)
	labelSel  = regexp.MustCompile(`^[A-Za-z0-9._/=!,() -]{1,500}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	app := `"app":{"type":"string","description":"Application name (or namespace/name for apps outside Argo CD's namespace)"}`
	resources := `"resources":{"type":"array","maxItems":100,"description":"Only these resources","items":{"type":"object","required":["kind","name"],"properties":{"group":{"type":"string"},"kind":{"type":"string"},"name":{"type":"string"},"namespace":{"type":"string"}}}}`
	return sdk.Manifest{
		ID: "argocd", Name: "Argo CD", Version: "0.1.0", Category: "Infrastructure", Icon: "pipeline",
		Description: "Argo CD applications: sync and health status, resources, sync with a preview, refresh, roll back, stop an operation.",
		Presets:     []string{"developer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The Argo CD server's address, e.g. https://argocd.example.com (with its root path if it has one)"},
			"token":{"type":"string","x-secret":true,"description":"API token of a local account with apiKey capability (argocd account generate-token), or a project role token; its RBAC decides what works"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "applications", Title: "Applications", Description: "Every application with sync status, health, revision, auto-sync and the last operation.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"project":{"type":"string"},"selector":{"type":"string","description":"Label selector, e.g. team=web"},"problems":{"type":"boolean","description":"Only apps that are out of sync or not healthy"}}}`)},
			{Name: "application", Title: "Application details", Description: "Source, destination, sync policy, conditions, images, recent history and the resources that are out of sync or unhealthy.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["app"],"properties":{` + app + `}}`)},
			{Name: "resource_tree", Title: "Resource tree", Description: "The app's live resources counted by kind and health, with the unhealthy ones listed.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["app"],"properties":{` + app + `}}`)},
			{Name: "sync", Title: "Sync", Description: "Applies the app's target revision to the cluster, without deleting anything (no pruning, no other revision: those are sync_prune and sync_revision). The preview lists the out-of-sync resources.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["app"],"properties":{` + app + `,` + resources + `}}`)},
			{Name: "sync_prune", Title: "Sync and prune", Description: "Applies the app's target revision and deletes the resources no longer in Git. The preview lists every resource that would be deleted.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["app"],"properties":{` + app + `,` + resources + `}}`)},
			{Name: "sync_revision", Title: "Sync to another revision", Description: "Applies a revision other than the app's target (an older commit, another branch or tag), optionally pruning. The preview lists what would change and be deleted.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["app","revision"],"properties":{` + app + `,"revision":{"type":"string","description":"Branch, tag or commit to sync to"},"prune":{"type":"boolean","description":"Delete resources not in that revision"},` + resources + `}}`)},
			{Name: "refresh", Title: "Refresh", Description: "Compares the app with Git and the cluster again now; hard also clears the manifest cache. Changes nothing in the cluster.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["app"],"properties":{` + app + `,"hard":{"type":"boolean"}}}`)},
			{Name: "rollback", Title: "Roll back", Description: "Deploys an earlier revision from the app's history (the previous one unless given). Needs auto-sync off. Undo rolls forward to what was deployed.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["app"],"properties":{` + app + `,"id":{"type":"integer","minimum":0,"description":"History id (see application)"},"prune":{"type":"boolean"}}}`)},
			{Name: "terminate_operation", Title: "Stop the running operation", Description: "Terminates a running sync, which can leave resources half applied.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["app"],"properties":{` + app + `}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is like https://argocd.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
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
	root := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1")
	tok := c.Token
	api := rest.New(root+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	ver := rest.New(root+"/api", api.Auth)
	ver.HTTP = api.HTTP
	m.set.Put(id, &conn{api: api, ver: ver, origin: root})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u struct {
		LoggedIn bool   `json:"loggedIn"`
		Username string `json:"username"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/session/userinfo", nil, nil, &u); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Health{Status: "down", Message: "Argo CD refused the token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if !u.LoggedIn {
		return sdk.Health{Status: "down", Message: "Argo CD refused the token"}
	}
	msg := "signed in as " + u.Username
	var v struct {
		Version string `json:"Version"`
	}
	if _, err := c.ver.Do(ctx, http.MethodGet, "/version", nil, nil, &v); err == nil && v.Version != "" {
		msg += " · Argo CD " + v.Version
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type resStatus struct {
	Group     string `json:"group"`
	Version   string `json:"version"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Health    *struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"health"`
	RequiresPruning bool `json:"requiresPruning"`
}

type history struct {
	ID         int64  `json:"id"`
	Revision   string `json:"revision"`
	DeployedAt string `json:"deployedAt"`
	Source     *struct {
		RepoURL        string `json:"repoURL"`
		TargetRevision string `json:"targetRevision"`
	} `json:"source"`
}

type source struct {
	RepoURL        string `json:"repoURL"`
	Path           string `json:"path"`
	TargetRevision string `json:"targetRevision"`
	Chart          string `json:"chart"`
}

type application struct {
	Metadata struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		Project     string   `json:"project"`
		Source      *source  `json:"source"`
		Sources     []source `json:"sources"`
		Destination struct {
			Server    string `json:"server"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"destination"`
		SyncPolicy *struct {
			Automated *struct {
				Prune    bool `json:"prune"`
				SelfHeal bool `json:"selfHeal"`
			} `json:"automated"`
		} `json:"syncPolicy"`
	} `json:"spec"`
	Status struct {
		Sync struct {
			Status   string `json:"status"`
			Revision string `json:"revision"`
		} `json:"sync"`
		Health struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"health"`
		OperationState *struct {
			Phase      string `json:"phase"`
			Message    string `json:"message"`
			StartedAt  string `json:"startedAt"`
			FinishedAt string `json:"finishedAt"`
			Operation  struct {
				InitiatedBy struct {
					Username  string `json:"username"`
					Automated bool   `json:"automated"`
				} `json:"initiatedBy"`
			} `json:"operation"`
		} `json:"operationState"`
		Resources  []resStatus `json:"resources"`
		History    []history   `json:"history"`
		Conditions []struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"conditions"`
		Summary struct {
			Images []string `json:"images"`
		} `json:"summary"`
		ReconciledAt string `json:"reconciledAt"`
	} `json:"status"`
}

func (a application) autoSync() bool {
	return a.Spec.SyncPolicy != nil && a.Spec.SyncPolicy.Automated != nil
}

func (a application) running() bool {
	o := a.Status.OperationState
	return o != nil && (o.Phase == "Running" || o.Phase == "Terminating")
}

func shortRev(r string) string {
	if len(r) == 40 {
		return r[:8]
	}
	return r
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func (c *conn) link(a application) string {
	u := c.origin + "/applications/"
	if a.Metadata.Namespace != "" {
		u += url.PathEscape(a.Metadata.Namespace) + "/"
	}
	return u + url.PathEscape(a.Metadata.Name)
}

func (c *conn) appSummary(a application) map[string]any {
	out := map[string]any{"name": a.Metadata.Name, "namespace": a.Metadata.Namespace, "project": a.Spec.Project,
		"sync": a.Status.Sync.Status, "health": a.Status.Health.Status, "revision": shortRev(a.Status.Sync.Revision),
		"autoSync": a.autoSync(), "url": c.link(a)}
	if o := a.Status.OperationState; o != nil {
		out["operation"] = map[string]any{"phase": o.Phase, "message": clip(o.Message, 300), "started": o.StartedAt, "finished": o.FinishedAt}
	}
	return out
}

func resName(r resStatus) string {
	k := r.Kind
	if r.Group != "" {
		k += "." + r.Group
	}
	if r.Namespace != "" {
		return k + " " + r.Namespace + "/" + r.Name
	}
	return k + " " + r.Name
}

// appRef splits "name" or "namespace/name" and checks both.
func appRef(s string) (name, ns string, err error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		ns, s = s[:i], s[i+1:]
		if !nsRe.MatchString(ns) {
			return "", "", errors.New("the app's namespace is a Kubernetes namespace name")
		}
	}
	if !nameRe.MatchString(s) {
		return "", "", errors.New("the app is an Argo CD application name (lowercase letters, digits, - and .)")
	}
	return s, ns, nil
}

func (c *conn) getApp(ctx context.Context, ref string, refresh string) (application, string, error) {
	var a application
	name, ns, err := appRef(ref)
	if err != nil {
		return a, "", err
	}
	q := url.Values{}
	if ns != "" {
		q.Set("appNamespace", ns)
	}
	if refresh != "" {
		q.Set("refresh", refresh)
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/applications/"+name, q, nil, &a); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusForbidden) {
			return a, "", fmt.Errorf("there's no application %s (or the token's RBAC doesn't allow it)", ref)
		}
		return a, "", err
	}
	if !nameRe.MatchString(a.Metadata.Name) || (a.Metadata.Namespace != "" && !nsRe.MatchString(a.Metadata.Namespace)) {
		return a, "", errors.New("unexpected application name from Argo CD")
	}
	return a, ns, nil
}

type resRef struct {
	Group     string `json:"group"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type input struct {
	App       string   `json:"app"`
	Project   string   `json:"project"`
	Selector  string   `json:"selector"`
	Problems  bool     `json:"problems"`
	Revision  string   `json:"revision"`
	Prune     bool     `json:"prune"`
	Resources []resRef `json:"resources"`
	Hard      bool     `json:"hard"`
	ID        *int64   `json:"id"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
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
	switch call.Action {
	case "applications":
		q := url.Values{}
		if p.Project != "" {
			if !nameRe.MatchString(p.Project) {
				return sdk.Result{}, errors.New("the project is an Argo CD project name")
			}
			q.Set("projects", p.Project)
		}
		if p.Selector != "" {
			if !labelSel.MatchString(p.Selector) {
				return sdk.Result{}, errors.New("the selector is a Kubernetes label selector, like team=web")
			}
			q.Set("selector", p.Selector)
		}
		var list struct {
			Items []application `json:"items"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/applications", q, nil, &list); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, a := range list.Items {
			if p.Problems && a.Status.Sync.Status == "Synced" && a.Status.Health.Status == "Healthy" {
				continue
			}
			out = append(out, c.appSummary(a))
		}
		return sdk.JSON(out)

	case "application":
		a, _, err := c.getApp(ctx, p.App, "")
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(c.details(a))

	case "resource_tree":
		return c.tree(ctx, p.App)

	case "sync", "sync_prune", "sync_revision":
		return c.sync(ctx, call, p)

	case "refresh":
		mode := "normal"
		if p.Hard {
			mode = "hard"
		}
		if call.DryRun {
			name, _, err := appRef(p.App)
			if err != nil {
				return sdk.Result{}, err
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Refresh %s (%s): compare with Git and the cluster again; nothing is applied", name, mode),
				Changes: []sdk.Change{{Target: "application " + name, Op: "refresh"}}}}, nil
		}
		a, _, err := c.getApp(ctx, p.App, mode)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(c.appSummary(a))

	case "rollback":
		return c.rollback(ctx, call, p)

	case "terminate_operation":
		a, ns, err := c.getApp(ctx, p.App, "")
		if err != nil {
			return sdk.Result{}, err
		}
		if !a.running() {
			return sdk.Result{}, fmt.Errorf("%s has no operation running", a.Metadata.Name)
		}
		o := a.Status.OperationState
		if call.DryRun {
			by := o.Operation.InitiatedBy.Username
			if o.Operation.InitiatedBy.Automated {
				by = "auto-sync"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Stop the operation on %s started %s by %s; resources may be left half applied", a.Metadata.Name, o.StartedAt, by),
				Changes: []sdk.Change{{Target: "application " + a.Metadata.Name, Op: "terminate", Before: mustJSON(map[string]any{"phase": o.Phase, "message": clip(o.Message, 300)})}}}}, nil
		}
		q := url.Values{}
		if ns != "" {
			q.Set("appNamespace", ns)
		}
		if _, err := c.api.Do(ctx, http.MethodDelete, "/applications/"+a.Metadata.Name+"/operation", q, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"app": a.Metadata.Name, "terminated": true})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) details(a application) map[string]any {
	out := c.appSummary(a)
	srcs := a.Spec.Sources
	if a.Spec.Source != nil {
		srcs = append([]source{*a.Spec.Source}, srcs...)
	}
	// Only where the manifests come from: Helm values and plugin
	// parameters can carry secrets.
	sl := []map[string]any{}
	for _, s := range srcs {
		e := map[string]any{"repo": rest.StripUserinfo(s.RepoURL), "targetRevision": s.TargetRevision}
		if s.Path != "" {
			e["path"] = s.Path
		}
		if s.Chart != "" {
			e["chart"] = s.Chart
		}
		sl = append(sl, e)
	}
	out["sources"] = sl
	d := a.Spec.Destination
	out["destination"] = map[string]any{"server": d.Server, "name": d.Name, "namespace": d.Namespace}
	if a.autoSync() {
		out["autoSyncPrune"], out["selfHeal"] = a.Spec.SyncPolicy.Automated.Prune, a.Spec.SyncPolicy.Automated.SelfHeal
	}
	if a.Status.Health.Message != "" {
		out["healthMessage"] = clip(a.Status.Health.Message, 300)
	}
	conds := []map[string]any{}
	for _, cd := range a.Status.Conditions {
		conds = append(conds, map[string]any{"type": cd.Type, "message": clip(cd.Message, 500)})
	}
	out["conditions"] = conds
	out["images"] = a.Status.Summary.Images
	out["reconciled"] = a.Status.ReconciledAt
	hist := []map[string]any{}
	for i := len(a.Status.History) - 1; i >= 0 && len(hist) < 10; i-- {
		h := a.Status.History[i]
		hist = append(hist, map[string]any{"id": h.ID, "revision": shortRev(h.Revision), "deployedAt": h.DeployedAt})
	}
	out["history"] = hist
	var problems []map[string]any
	counts := map[string]int{}
	for _, r := range a.Status.Resources {
		counts[r.Status]++
		bad := r.Status != "Synced" || r.RequiresPruning || (r.Health != nil && r.Health.Status != "Healthy")
		if bad && len(problems) < 50 {
			e := map[string]any{"resource": resName(r), "sync": r.Status}
			if r.Health != nil {
				e["health"] = r.Health.Status
				if r.Health.Message != "" {
					e["message"] = clip(r.Health.Message, 300)
				}
			}
			if r.RequiresPruning {
				e["requiresPruning"] = true
			}
			problems = append(problems, e)
		}
	}
	if problems == nil {
		problems = []map[string]any{}
	}
	out["resourceCounts"] = counts
	out["problemResources"] = problems
	return out
}

func (c *conn) tree(ctx context.Context, ref string) (sdk.Result, error) {
	name, ns, err := appRef(ref)
	if err != nil {
		return sdk.Result{}, err
	}
	q := url.Values{}
	if ns != "" {
		q.Set("appNamespace", ns)
	}
	var t struct {
		Nodes []struct {
			Group     string `json:"group"`
			Kind      string `json:"kind"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
			Health    *struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			} `json:"health"`
			ParentRefs []json.RawMessage `json:"parentRefs"`
		} `json:"nodes"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/applications/"+name+"/resource-tree", q, nil, &t); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusForbidden) {
			return sdk.Result{}, fmt.Errorf("there's no application %s (or the token's RBAC doesn't allow it)", ref)
		}
		return sdk.Result{}, err
	}
	type count struct {
		Kind    string         `json:"kind"`
		Total   int            `json:"total"`
		Top     int            `json:"topLevel"`
		ByState map[string]int `json:"health"`
	}
	byKind := map[string]*count{}
	var unhealthy []map[string]any
	for _, n := range t.Nodes {
		k := n.Kind
		if byKind[k] == nil {
			byKind[k] = &count{Kind: k, ByState: map[string]int{}}
		}
		byKind[k].Total++
		if len(n.ParentRefs) == 0 {
			byKind[k].Top++
		}
		if n.Health != nil {
			byKind[k].ByState[n.Health.Status]++
			if n.Health.Status != "Healthy" && len(unhealthy) < 50 {
				unhealthy = append(unhealthy, map[string]any{"resource": resName(resStatus{Group: n.Group, Kind: n.Kind, Namespace: n.Namespace, Name: n.Name}),
					"health": n.Health.Status, "message": clip(n.Health.Message, 300)})
			}
		}
	}
	kinds := []*count{}
	for _, v := range byKind {
		kinds = append(kinds, v)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i].Kind < kinds[j].Kind })
	if unhealthy == nil {
		unhealthy = []map[string]any{}
	}
	return sdk.JSON(map[string]any{"app": name, "nodes": len(t.Nodes), "kinds": kinds, "unhealthy": unhealthy})
}

// sync applies an app. At write risk ("sync") it neither prunes nor picks a
// revision other than the app's target, since either can delete resources or
// deploy an old commit, which is what the destructive rollback is for:
// sync_prune prunes, sync_revision takes a revision.
func (c *conn) sync(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	switch call.Action {
	case "sync":
		if p.Prune {
			return sdk.Result{}, errors.New("sync doesn't prune; deleting resources no longer in Git is sync_prune (destructive)")
		}
	case "sync_prune":
		if p.Revision != "" {
			return sdk.Result{}, errors.New("sync_prune syncs the target revision; another revision is sync_revision")
		}
		p.Prune = true
	case "sync_revision":
		if p.Revision == "" {
			return sdk.Result{}, errors.New("give the revision to sync to")
		}
	}
	if p.Revision != "" && !revRe.MatchString(p.Revision) {
		return sdk.Result{}, errors.New("the revision is a branch, tag or commit")
	}
	if len(p.Resources) > 100 {
		return sdk.Result{}, errors.New("up to 100 resources")
	}
	for _, r := range p.Resources {
		if !kindRe.MatchString(r.Kind) || !groupRe.MatchString(r.Group) || !resNameRe.MatchString(r.Name) || (r.Namespace != "" && !nsRe.MatchString(r.Namespace)) {
			return sdk.Result{}, errors.New("each resource is a kind, name and optional group and namespace")
		}
	}
	a, ns, err := c.getApp(ctx, p.App, "")
	if err != nil {
		return sdk.Result{}, err
	}
	if call.Action == "sync" && p.Revision != "" {
		if a.Spec.Source == nil || p.Revision != a.Spec.Source.TargetRevision {
			return sdk.Result{}, fmt.Errorf("sync applies %s's target revision only; syncing to %s is sync_revision (destructive)", a.Metadata.Name, p.Revision)
		}
	}
	if a.running() {
		return sdk.Result{}, fmt.Errorf("%s already has an operation %s; wait for it or terminate it", a.Metadata.Name, strings.ToLower(a.Status.OperationState.Phase))
	}
	only := map[string]bool{}
	for _, r := range p.Resources {
		only[resName(resStatus{Group: r.Group, Kind: r.Kind, Namespace: r.Namespace, Name: r.Name})] = true
	}
	var changes []sdk.Change
	prunes := 0
	for _, r := range a.Status.Resources {
		n := resName(r)
		if len(only) > 0 && !only[n] {
			continue
		}
		switch {
		case r.RequiresPruning:
			if p.Prune {
				prunes++
				changes = append(changes, sdk.Change{Target: n, Op: "prune (delete)"})
			} else {
				changes = append(changes, sdk.Change{Target: n, Op: "keep (not in Git; prune is off)"})
			}
		case r.Status == "OutOfSync":
			op := "apply"
			if r.Health != nil && r.Health.Status == "Missing" {
				op = "create"
			}
			changes = append(changes, sdk.Change{Target: n, Op: op})
		}
	}
	target := p.Revision
	if target == "" && a.Spec.Source != nil {
		target = a.Spec.Source.TargetRevision
	}
	if call.DryRun {
		sum := fmt.Sprintf("Sync %s to %s: %d resources out of sync", a.Metadata.Name, firstNonEmpty(target, "its target revision"), len(changes)-countKeep(changes))
		if prunes > 0 {
			sum += fmt.Sprintf(", %d to delete", prunes)
		}
		if a.Status.Sync.Status == "Synced" && len(changes) == 0 {
			sum = fmt.Sprintf("Sync %s: it's in sync as of %s, so this re-applies the same manifests (refresh first if Git changed)", a.Metadata.Name, a.Status.ReconciledAt)
		}
		if changes == nil {
			changes = []sdk.Change{{Target: "application " + a.Metadata.Name, Op: "sync"}}
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: changes}}, nil
	}
	body := map[string]any{"prune": p.Prune}
	if ns != "" {
		body["appNamespace"] = ns
	}
	if p.Revision != "" {
		body["revision"] = p.Revision
	}
	if len(p.Resources) > 0 {
		body["resources"] = p.Resources
	}
	var after application
	if _, err := c.api.Do(ctx, http.MethodPost, "/applications/"+a.Metadata.Name+"/sync", nil, body, &after); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"app": a.Metadata.Name, "started": true, "revision": firstNonEmpty(p.Revision, target), "url": c.link(a)})
}

func countKeep(cs []sdk.Change) int {
	n := 0
	for _, c := range cs {
		if strings.HasPrefix(c.Op, "keep") {
			n++
		}
	}
	return n
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func (c *conn) rollback(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	a, ns, err := c.getApp(ctx, p.App, "")
	if err != nil {
		return sdk.Result{}, err
	}
	if a.autoSync() {
		return sdk.Result{}, fmt.Errorf("%s has auto-sync on, which would undo a rollback; Argo CD refuses it until auto-sync is turned off", a.Metadata.Name)
	}
	if a.running() {
		return sdk.Result{}, fmt.Errorf("%s has an operation running; wait for it or terminate it", a.Metadata.Name)
	}
	h := a.Status.History
	if len(h) == 0 {
		return sdk.Result{}, fmt.Errorf("%s has no deployment history", a.Metadata.Name)
	}
	current := h[len(h)-1]
	var target *history
	if p.ID != nil {
		for i := range h {
			if h[i].ID == *p.ID {
				target = &h[i]
			}
		}
		if target == nil {
			return sdk.Result{}, fmt.Errorf("%s has no history entry %d (see application)", a.Metadata.Name, *p.ID)
		}
	} else {
		if len(h) < 2 {
			return sdk.Result{}, fmt.Errorf("%s has only one deployment, nothing to roll back to", a.Metadata.Name)
		}
		target = &h[len(h)-2]
	}
	if target.ID == current.ID {
		return sdk.JSON(map[string]any{"app": a.Metadata.Name, "note": "that revision is the one deployed"})
	}
	label := func(x history) map[string]any {
		return map[string]any{"id": x.ID, "revision": shortRev(x.Revision), "deployedAt": x.DeployedAt}
	}
	if call.DryRun {
		sum := fmt.Sprintf("Roll %s back from %s to %s (deployed %s)", a.Metadata.Name, shortRev(current.Revision), shortRev(target.Revision), target.DeployedAt)
		if p.Prune {
			sum += ", deleting resources that revision doesn't have"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "application " + a.Metadata.Name, Op: "rollback", Before: mustJSON(label(current)), After: mustJSON(label(*target))}}}}, nil
	}
	body := map[string]any{"id": target.ID, "prune": p.Prune}
	if ns != "" {
		body["appNamespace"] = ns
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/applications/"+a.Metadata.Name+"/rollback", nil, body, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"app": a.Metadata.Name, "from": label(current), "to": label(*target)})
	ref := a.Metadata.Name
	if ns != "" {
		ref = ns + "/" + ref
	}
	res.Undo = sdk.UndoWith("rollback", map[string]any{"app": ref, "id": current.ID}, "Roll "+a.Metadata.Name+" forward to "+shortRev(current.Revision)+" (history "+strconv.FormatInt(current.ID, 10)+")")
	return res, err
}
