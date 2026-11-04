// Package gcp works with Google Cloud through a service-account key: it
// signs a JWT with the key (jwt.go), exchanges it for an access token, and
// calls the REST APIs directly (no SDK). Projects, Compute Engine instances
// (start, stop, reset) and Cloud Run services with their revisions and
// traffic.
package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one service account.
type Config struct {
	Key     string `json:"key"`     // secret:// the service-account JSON key
	Project string `json:"project"` // default project (else the key's)
}

type conn struct {
	cfg   Config
	host  sdk.Host
	apis  map[string]*rest.Client // by service: cloudresourcemanager, compute, run
	login *rest.Client
	path  string // token endpoint path
	aud   string // token endpoint URL, the JWT's audience
	now   func() time.Time

	mu         sync.Mutex
	token      string
	expires    time.Time
	keyProject string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://<service>.googleapis.com for every API (tests).
	Base string
	// TokenURL replaces https://oauth2.googleapis.com/token (tests). The
	// key's own token_uri is never used.
	TokenURL string
}

// New returns the Google Cloud module.
func New() *Module { return &Module{} }

const (
	defaultToken = "https://oauth2.googleapis.com/token"
	scope        = "https://www.googleapis.com/auth/cloud-platform"
)

var (
	projectRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	zoneRe     = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]{1,2}-[a-z]$`)
	regionRe   = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]{1,2}$`)
	nameRe     = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)
	tagRe      = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,44}[a-z0-9])?$`)
	revisionRe = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	proj := `"project":{"type":"string","description":"Project id (default: the instance's, or the key's)"}`
	instance := sdk.Schema(`{"type":"object","required":["zone","instance"],"properties":{` + proj + `,"zone":{"type":"string","description":"e.g. europe-west1-b"},"instance":{"type":"string","description":"Instance name (from instances)"}}}`)
	svc := `"region":{"type":"string","description":"e.g. europe-west1"},"service":{"type":"string","description":"Service name (from run_services)"}`
	return sdk.Manifest{
		ID: "gcp", Name: "Google Cloud", Version: "0.1.0", Category: "Infrastructure", Icon: "cloud",
		Description: "Google Cloud projects, Compute Engine instances (start, stop, reset) and Cloud Run services with their revisions and traffic.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"key":{"type":"string","x-secret":true,"description":"The service account's JSON key file, stored whole in the vault"},
			"project":{"type":"string","description":"The project actions use when none is given (default: the key's project)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Projects the service account can see: id, name, number and state.", Risk: sdk.RiskRead},
			{Name: "instances", Title: "Compute instances", Description: "Name, zone, status, machine type, internal and external addresses. Never metadata (startup scripts, SSH keys).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + proj + `,"zone":{"type":"string","description":"Only this zone"}}}`)},
			{Name: "start_instance", Title: "Start an instance", Description: "Starts a stopped instance; compute billing resumes. Undo stops it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: instance},
			{Name: "stop_instance", Title: "Stop an instance", Description: "Shuts an instance down; its services go down until it's started, and an ephemeral external IP is released. Disks are still billed. Undo starts it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: instance},
			{Name: "reset_instance", Title: "Reset an instance", Description: "Hard-resets a running instance, like pressing the reset button: no clean shutdown.", Risk: sdk.RiskDestructive, DryRun: true, Input: instance},
			{Name: "run_services", Title: "Cloud Run services", Description: "Name, region, URL, ready state, latest revision and where traffic goes. Never environment variables or secrets.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + proj + `,"region":{"type":"string","description":"Only this region (default: all)"}}}`)},
			{Name: "run_revisions", Title: "Cloud Run revisions", Description: "A service's revisions: created, ready, image, scaling and the traffic each one gets.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["region","service"],"properties":{` + proj + `,` + svc + `}}`)},
			{Name: "set_traffic", Title: "Route traffic", Description: "Sets where a Cloud Run service's traffic goes: one revision, the latest, or a split. Users reach other code, so it's destructive. The preview has Google validate the change. Undo restores the split it replaced.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["region","service"],"properties":{` + proj + `,` + svc + `,
					"revision":{"type":"string","description":"Send all traffic to this revision, or to \"latest\""},
					"traffic":{"type":"array","description":"A split instead: entries with revision (or latest: true), percent and an optional tag; percents add up to 100","items":{"type":"object","properties":{"revision":{"type":"string"},"latest":{"type":"boolean"},"percent":{"type":"integer","minimum":0,"maximum":100},"tag":{"type":"string"}}}}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Key, "secret://") {
		return errors.New("store the service-account JSON key in the vault and enter its secret:// reference")
	}
	c.Project = strings.TrimSpace(c.Project)
	if c.Project != "" && !projectRe.MatchString(c.Project) {
		return errors.New("a project id is 6 to 30 lowercase letters, digits and hyphens, such as my-project-123")
	}
	tokenURL := defaultToken
	if m.TokenURL != "" {
		tokenURL = m.TokenURL
	}
	tu, err := url.Parse(tokenURL)
	if err != nil || tu.Host == "" {
		return errors.New("invalid token endpoint")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	client = rest.SameHostOnly(client)
	cn := &conn{cfg: c, host: h, apis: map[string]*rest.Client{}, path: tu.EscapedPath(), aud: tokenURL, now: time.Now}
	cn.login = rest.New(tu.Scheme+"://"+tu.Host, nil)
	cn.login.HTTP = client
	auth := func(ctx context.Context, r *http.Request) error {
		t, err := cn.accessToken(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	}
	for _, svc := range []string{"cloudresourcemanager", "compute", "run"} {
		base := "https://" + svc + ".googleapis.com"
		if m.Base != "" {
			base = m.Base
		}
		api := rest.New(base, auth)
		api.HTTP = client
		cn.apis[svc] = api
	}
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// accessToken returns a cached token, or signs a new JWT with the key and
// exchanges it. Tokens live in memory only, until a minute before expiry.
func (c *conn) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Before(c.expires) {
		return c.token, nil
	}
	raw, err := c.host.Secret(ctx, c.cfg.Key)
	if err != nil {
		return "", err
	}
	sa, key, err := parseKey(raw)
	if err != nil {
		return "", err
	}
	if projectRe.MatchString(sa.ProjectID) {
		c.keyProject = sa.ProjectID
	}
	jwt, err := signJWT(sa, key, c.aud, scope, c.now())
	if err != nil {
		return "", errors.New("couldn't sign with the service-account key")
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {jwt}}
	res, err := c.login.Send(ctx, http.MethodPost, c.path, nil, strings.NewReader(form.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}})
	if err != nil {
		var e *rest.Error
		if errors.As(err, &e) && e.Status >= 400 && e.Status < 500 {
			return "", errors.New("Google refused the service-account key (deleted, disabled, or the account is gone)")
		}
		return "", err
	}
	defer res.Body.Close()
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&t); err != nil || t.AccessToken == "" {
		return "", errors.New("Google's token endpoint answered without a token")
	}
	life := time.Duration(t.ExpiresIn) * time.Second
	if life <= 0 {
		life = 5 * time.Minute
	}
	c.token, c.expires = t.AccessToken, c.now().Add(life-time.Minute)
	return c.token, nil
}

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Google refused the service account's token")
	case rest.IsStatus(err, http.StatusForbidden):
		var e *rest.Error
		if errors.As(err, &e) && (strings.Contains(e.Message, "has not been used") || strings.Contains(e.Message, "is disabled")) {
			return errors.New("the API isn't enabled in this project: " + e.Message)
		}
		return errors.New("the service account isn't allowed to do this (check its IAM roles)")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusConflict), rest.IsStatus(err, http.StatusPreconditionFailed):
		return fmt.Errorf("Google refused: %s changed or is busy (nothing was changed); read it again and retry", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Google's rate limit was hit; try again in a moment")
	}
	return err
}

func (c *conn) do(ctx context.Context, svc, method, path string, q url.Values, body, out any, what string) error {
	_, err := c.apis[svc].Do(ctx, method, path, q, body, out)
	return friendly(err, what)
}

// project picks the input's project, the instance's, or the key's.
func (c *conn) project(ctx context.Context, in string) (string, error) {
	p := strings.TrimSpace(in)
	if p == "" {
		p = c.cfg.Project
	}
	if p == "" {
		if _, err := c.accessToken(ctx); err != nil {
			return "", err
		}
		c.mu.Lock()
		p = c.keyProject
		c.mu.Unlock()
	}
	if p == "" {
		return "", errors.New("which project? (its id, from projects)")
	}
	if !projectRe.MatchString(p) {
		return "", errors.New("a project id is 6 to 30 lowercase letters, digits and hyphens, such as my-project-123")
	}
	return p, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	p, err := c.project(ctx, "")
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var pr project
	if err := c.do(ctx, "cloudresourcemanager", http.MethodGet, "/v1/projects/"+url.PathEscape(p), nil, nil, &pr, "project "+p); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if pr.State != "ACTIVE" {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("project %s is %s", pr.ID, pr.State)}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("project %s (%s)", pr.Name, pr.ID)}
}

type project struct {
	ID      string `json:"projectId"`
	Name    string `json:"name"`
	Number  string `json:"projectNumber"`
	State   string `json:"lifecycleState"`
	Created string `json:"createTime"`
}

type input struct {
	Project  string    `json:"project"`
	Zone     string    `json:"zone"`
	Instance string    `json:"instance"`
	Region   string    `json:"region"`
	Service  string    `json:"service"`
	Revision string    `json:"revision"`
	Traffic  []traffic `json:"traffic"`
}

// last is a resource URL's or name's last path segment.
func last(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// instance holds only what's shown: metadata (startup scripts, SSH keys)
// and service account details are never decoded.
type instance struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Zone        string `json:"zone"`
	Status      string `json:"status"`
	MachineType string `json:"machineType"`
	Created     string `json:"creationTimestamp"`
	Scheduling  struct {
		Preemptible  bool   `json:"preemptible"`
		Provisioning string `json:"provisioningModel"`
	} `json:"scheduling"`
	NICs []struct {
		IP     string `json:"networkIP"`
		Access []struct {
			NatIP string `json:"natIP"`
		} `json:"accessConfigs"`
	} `json:"networkInterfaces"`
}

func (i instance) row() map[string]any {
	internal, external := []string{}, []string{}
	for _, n := range i.NICs {
		if n.IP != "" {
			internal = append(internal, n.IP)
		}
		for _, a := range n.Access {
			if a.NatIP != "" {
				external = append(external, a.NatIP)
			}
		}
	}
	row := map[string]any{"name": i.Name, "id": i.ID, "zone": last(i.Zone), "status": i.Status, "machineType": last(i.MachineType),
		"internalIps": internal, "externalIps": external, "created": i.Created}
	if i.Scheduling.Preemptible || i.Scheduling.Provisioning == "SPOT" {
		row["spot"] = true
	}
	return row
}

func status(s string) json.RawMessage { b, _ := json.Marshal(map[string]string{"status": s}); return b }

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
	p.Zone, p.Instance, p.Region, p.Service, p.Revision = strings.TrimSpace(p.Zone), strings.TrimSpace(p.Instance), strings.TrimSpace(p.Region), strings.TrimSpace(p.Service), strings.TrimSpace(p.Revision)
	if p.Project != "" && !projectRe.MatchString(strings.TrimSpace(p.Project)) {
		return sdk.Result{}, errors.New("a project id is 6 to 30 lowercase letters, digits and hyphens, such as my-project-123")
	}
	// Check the rest of the input before anything reaches Google, the
	// token endpoint included.
	switch call.Action {
	case "instances":
		if p.Zone != "" && !zoneRe.MatchString(p.Zone) {
			return sdk.Result{}, errors.New("a zone looks like europe-west1-b")
		}
	case "start_instance", "stop_instance", "reset_instance":
		if !zoneRe.MatchString(p.Zone) {
			return sdk.Result{}, errors.New("which zone? (like europe-west1-b, from instances)")
		}
		if !nameRe.MatchString(p.Instance) {
			return sdk.Result{}, errors.New("which instance? (its name, from instances)")
		}
	case "run_services":
		if p.Region != "" && !regionRe.MatchString(p.Region) {
			return sdk.Result{}, errors.New("a region looks like europe-west1")
		}
	case "run_revisions", "set_traffic":
		if !regionRe.MatchString(p.Region) {
			return sdk.Result{}, errors.New("which region? (like europe-west1, from run_services)")
		}
		if !nameRe.MatchString(p.Service) {
			return sdk.Result{}, errors.New("which service? (its name, from run_services)")
		}
		if call.Action == "set_traffic" {
			t, err := wantTraffic(p)
			if err != nil {
				return sdk.Result{}, err
			}
			p.Traffic = t
		}
	case "projects":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	if call.Action == "projects" {
		return c.projects(ctx)
	}
	proj, err := c.project(ctx, p.Project)
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "instances":
		return c.instances(ctx, proj, p.Zone)
	case "start_instance", "stop_instance", "reset_instance":
		return c.power(ctx, call, proj, p)
	case "run_services":
		return c.runServices(ctx, proj, p.Region)
	case "run_revisions":
		return c.runRevisions(ctx, proj, p)
	default:
		return c.setTraffic(ctx, call, proj, p)
	}
}

func (c *conn) projects(ctx context.Context) (sdk.Result, error) {
	out := []project{}
	q := url.Values{"pageSize": {"500"}}
	for page := 0; page < 20; page++ {
		var r struct {
			Projects []project `json:"projects"`
			Next     string    `json:"nextPageToken"`
		}
		if err := c.do(ctx, "cloudresourcemanager", http.MethodGet, "/v1/projects", q, nil, &r, "project list"); err != nil {
			return sdk.Result{}, err
		}
		out = append(out, r.Projects...)
		if r.Next == "" {
			break
		}
		q.Set("pageToken", r.Next)
	}
	return sdk.JSON(out)
}

func (c *conn) instances(ctx context.Context, proj, zone string) (sdk.Result, error) {
	out := []map[string]any{}
	pp := "/compute/v1/projects/" + url.PathEscape(proj)
	q := url.Values{"maxResults": {"500"}}
	for page := 0; page < 20; page++ {
		var next string
		if zone != "" {
			var r struct {
				Items []instance `json:"items"`
				Next  string     `json:"nextPageToken"`
			}
			if err := c.do(ctx, "compute", http.MethodGet, pp+"/zones/"+url.PathEscape(zone)+"/instances", q, nil, &r, "zone "+zone+" in "+proj); err != nil {
				return sdk.Result{}, err
			}
			for _, i := range r.Items {
				out = append(out, i.row())
			}
			next = r.Next
		} else {
			var r struct {
				Items map[string]struct {
					Instances []instance `json:"instances"`
				} `json:"items"`
				Next string `json:"nextPageToken"`
			}
			if err := c.do(ctx, "compute", http.MethodGet, pp+"/aggregated/instances", q, nil, &r, "project "+proj); err != nil {
				return sdk.Result{}, err
			}
			for _, z := range r.Items {
				for _, i := range z.Instances {
					out = append(out, i.row())
				}
			}
			next = r.Next
		}
		if next == "" {
			break
		}
		q.Set("pageToken", next)
	}
	sort.Slice(out, func(i, j int) bool {
		return fmt.Sprint(out[i]["zone"], "/", out[i]["name"]) < fmt.Sprint(out[j]["zone"], "/", out[j]["name"])
	})
	return sdk.JSON(out)
}

func (c *conn) power(ctx context.Context, call sdk.Call, proj string, p input) (sdk.Result, error) {
	path := "/compute/v1/projects/" + url.PathEscape(proj) + "/zones/" + url.PathEscape(p.Zone) + "/instances/" + url.PathEscape(p.Instance)
	what := "instance " + p.Instance + " in " + p.Zone
	var i instance
	if err := c.do(ctx, "compute", http.MethodGet, path, nil, nil, &i, what); err != nil {
		return sdk.Result{}, err
	}
	was := i.Status
	target := p.Instance + " (" + p.Zone + ", " + proj + ")"
	in := map[string]string{"project": proj, "zone": p.Zone, "instance": p.Instance}
	op := strings.TrimSuffix(call.Action, "_instance")
	want := "RUNNING"
	switch op {
	case "start":
		if was == "RUNNING" || was == "PROVISIONING" || was == "STAGING" {
			return sdk.JSON(map[string]any{"instance": target, "status": was, "note": "nothing to change"})
		}
		if was != "TERMINATED" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a stopped instance can be started", target, was)
		}
	case "stop":
		if was == "TERMINATED" || was == "STOPPING" {
			return sdk.JSON(map[string]any{"instance": target, "status": was, "note": "nothing to change"})
		}
		if was != "RUNNING" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a running instance can be stopped", target, was)
		}
		want = "TERMINATED"
	case "reset":
		if was != "RUNNING" {
			return sdk.Result{}, fmt.Errorf("%s is %s; only a running instance can be reset", target, was)
		}
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: strings.ToUpper(op[:1]) + op[1:] + " " + target,
			Changes: []sdk.Change{{Target: target, Op: op, Before: status(was), After: status(want)}}}}, nil
	}
	if err := c.do(ctx, "compute", http.MethodPost, path+"/"+op, nil, nil, nil, what); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"instance": target, "was": was, "requested": op})
	switch op {
	case "start":
		res.Undo = sdk.UndoWith("stop_instance", in, "Stop "+p.Instance+" again")
	case "stop":
		res.Undo = sdk.UndoWith("start_instance", in, "Start "+p.Instance+" again")
	}
	return res, err
}

// traffic is one traffic target, as the input and the undo give it.
type traffic struct {
	Revision string `json:"revision,omitempty"`
	Latest   bool   `json:"latest,omitempty"`
	Percent  int    `json:"percent"`
	Tag      string `json:"tag,omitempty"`
}

// apiTraffic is Cloud Run's traffic target.
type apiTraffic struct {
	Type     string `json:"type,omitempty"`
	Revision string `json:"revision,omitempty"`
	Percent  int    `json:"percent,omitempty"`
	Tag      string `json:"tag,omitempty"`
}

const (
	typeLatest   = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
	typeRevision = "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION"
)

func fromAPI(ts []apiTraffic) []traffic {
	out := []traffic{}
	for _, t := range ts {
		out = append(out, traffic{Revision: last(t.Revision), Latest: t.Type == typeLatest, Percent: t.Percent, Tag: t.Tag})
	}
	return out
}

func toAPI(ts []traffic) []apiTraffic {
	out := []apiTraffic{}
	for _, t := range ts {
		a := apiTraffic{Type: typeRevision, Revision: t.Revision, Percent: t.Percent, Tag: t.Tag}
		if t.Latest {
			a.Type, a.Revision = typeLatest, ""
		}
		out = append(out, a)
	}
	return out
}

// wantTraffic checks the requested traffic split.
func wantTraffic(p input) ([]traffic, error) {
	ts := p.Traffic
	switch {
	case p.Revision != "" && len(ts) > 0:
		return nil, errors.New("give either revision or traffic, not both")
	case strings.EqualFold(p.Revision, "latest"):
		ts = []traffic{{Latest: true, Percent: 100}}
	case p.Revision != "":
		ts = []traffic{{Revision: p.Revision, Percent: 100}}
	case len(ts) == 0:
		return nil, errors.New("where should traffic go? (revision, \"latest\", or a traffic split)")
	}
	if len(ts) > 20 {
		return nil, errors.New("a split has at most 20 entries")
	}
	sum := 0
	for i, t := range ts {
		t.Revision, t.Tag = strings.TrimSpace(t.Revision), strings.TrimSpace(t.Tag)
		ts[i] = t
		if t.Latest == (t.Revision != "") {
			return nil, errors.New("each traffic entry names a revision or says latest: true")
		}
		if t.Revision != "" && !revisionRe.MatchString(t.Revision) {
			return nil, errors.New("a revision is its name, such as hello-00012-abc (from run_revisions)")
		}
		if t.Tag != "" && !tagRe.MatchString(t.Tag) {
			return nil, errors.New("a tag is lowercase letters, digits and hyphens")
		}
		if t.Percent < 0 || t.Percent > 100 {
			return nil, errors.New("a percent is 0 to 100")
		}
		sum += t.Percent
	}
	if sum != 100 {
		return nil, fmt.Errorf("the percents add up to %d, not 100", sum)
	}
	return ts, nil
}

func sameTraffic(a, b []traffic) bool {
	key := func(ts []traffic) []string {
		out := []string{}
		for _, t := range ts {
			out = append(out, fmt.Sprintf("%s|%t|%d|%s", t.Revision, t.Latest, t.Percent, t.Tag))
		}
		sort.Strings(out)
		return out
	}
	return strings.Join(key(a), ",") == strings.Join(key(b), ",")
}

// service holds only what's shown: the template (environment variables,
// secret references, the service account) is never decoded.
type service struct {
	Name           string       `json:"name"`
	URI            string       `json:"uri"`
	Ingress        string       `json:"ingress"`
	Updated        string       `json:"updateTime"`
	LatestReady    string       `json:"latestReadyRevision"`
	LatestCreated  string       `json:"latestCreatedRevision"`
	Reconciling    bool         `json:"reconciling"`
	Traffic        []apiTraffic `json:"traffic"`
	TrafficStatus  []apiTraffic `json:"trafficStatuses"`
	TerminalStatus struct {
		State string `json:"state"`
	} `json:"terminalCondition"`
}

func region(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return ""
}

func (c *conn) runServices(ctx context.Context, proj, reg string) (sdk.Result, error) {
	loc := reg
	if loc == "" {
		loc = "-"
	}
	out := []map[string]any{}
	q := url.Values{"pageSize": {"200"}}
	for page := 0; page < 20; page++ {
		var r struct {
			Services []service `json:"services"`
			Next     string    `json:"nextPageToken"`
		}
		if err := c.do(ctx, "run", http.MethodGet, "/v2/projects/"+url.PathEscape(proj)+"/locations/"+url.PathEscape(loc)+"/services", q, nil, &r, "Cloud Run location "+loc+" in "+proj); err != nil {
			return sdk.Result{}, err
		}
		for _, s := range r.Services {
			out = append(out, map[string]any{"name": last(s.Name), "region": region(s.Name), "url": s.URI, "ingress": s.Ingress, "updated": s.Updated,
				"ready": s.TerminalStatus.State == "CONDITION_SUCCEEDED", "reconciling": s.Reconciling,
				"latestReadyRevision": last(s.LatestReady), "latestCreatedRevision": last(s.LatestCreated), "traffic": fromAPI(s.TrafficStatus)})
		}
		if r.Next == "" {
			break
		}
		q.Set("pageToken", r.Next)
	}
	return sdk.JSON(out)
}

func servicePath(proj string, p input) string {
	return "/v2/projects/" + url.PathEscape(proj) + "/locations/" + url.PathEscape(p.Region) + "/services/" + url.PathEscape(p.Service)
}

func (c *conn) runRevisions(ctx context.Context, proj string, p input) (sdk.Result, error) {
	path := servicePath(proj, p)
	what := "Cloud Run service " + p.Service + " in " + p.Region
	var s service
	if err := c.do(ctx, "run", http.MethodGet, path, nil, nil, &s, what); err != nil {
		return sdk.Result{}, err
	}
	share := map[string]int{}
	for _, t := range s.TrafficStatus {
		r := last(t.Revision)
		if t.Type == typeLatest {
			r = last(s.LatestReady)
		}
		share[r] += t.Percent
	}
	var r struct {
		Revisions []struct {
			Name       string `json:"name"`
			Created    string `json:"createTime"`
			Containers []struct {
				Image string `json:"image"`
			} `json:"containers"`
			Scaling struct {
				Min int `json:"minInstanceCount"`
				Max int `json:"maxInstanceCount"`
			} `json:"scaling"`
			Conditions []struct {
				Type  string `json:"type"`
				State string `json:"state"`
			} `json:"conditions"`
		} `json:"revisions"`
	}
	if err := c.do(ctx, "run", http.MethodGet, path+"/revisions", url.Values{"pageSize": {"100"}}, nil, &r, what); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, rv := range r.Revisions {
		images := []string{}
		for _, ct := range rv.Containers {
			images = append(images, ct.Image)
		}
		ready := false
		for _, cd := range rv.Conditions {
			if cd.Type == "Ready" {
				ready = cd.State == "CONDITION_SUCCEEDED"
			}
		}
		n := last(rv.Name)
		out = append(out, map[string]any{"name": n, "created": rv.Created, "ready": ready, "images": images,
			"minInstances": rv.Scaling.Min, "maxInstances": rv.Scaling.Max, "trafficPercent": share[n]})
	}
	return sdk.JSON(map[string]any{"service": p.Service, "region": p.Region, "latestReadyRevision": last(s.LatestReady), "revisions": out})
}

func (c *conn) setTraffic(ctx context.Context, call sdk.Call, proj string, p input) (sdk.Result, error) {
	path := servicePath(proj, p)
	what := "Cloud Run service " + p.Service + " in " + p.Region
	// The whole service is read and sent back with only traffic changed,
	// so nothing else about it moves; it's never shown. updateMask=traffic
	// makes Google apply only the traffic, so a deploy that lands between
	// the read and the write isn't reverted to the template read here, and
	// the etag sent back refuses the write if the service changed.
	var raw map[string]json.RawMessage
	if err := c.do(ctx, "run", http.MethodGet, path, nil, nil, &raw, what); err != nil {
		return sdk.Result{}, err
	}
	if _, ok := raw["name"]; !ok {
		return sdk.Result{}, errors.New("Cloud Run answered without the service")
	}
	var cur []apiTraffic
	if t, ok := raw["traffic"]; ok {
		if err := json.Unmarshal(t, &cur); err != nil {
			return sdk.Result{}, errors.New("Cloud Run answered with traffic Conduit can't read")
		}
	}
	before := fromAPI(cur)
	target := p.Service + " (" + p.Region + ", " + proj + ")"
	if sameTraffic(before, p.Traffic) {
		return sdk.JSON(map[string]any{"service": target, "traffic": before, "note": "nothing to change"})
	}
	nt, _ := json.Marshal(toAPI(p.Traffic))
	raw["traffic"] = nt
	q := url.Values{"updateMask": {"traffic"}}
	if call.DryRun {
		q.Set("validateOnly", "true")
	}
	if err := c.do(ctx, "run", http.MethodPatch, path, q, raw, nil, what); err != nil {
		return sdk.Result{}, err
	}
	b, _ := json.Marshal(map[string]any{"traffic": before})
	a, _ := json.Marshal(map[string]any{"traffic": p.Traffic})
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Route traffic of " + target + " (Google validated the change)",
			Changes: []sdk.Change{{Target: target, Op: "update", Before: b, After: a}}}}, nil
	}
	res, err := sdk.JSON(map[string]any{"service": target, "was": before, "traffic": p.Traffic})
	// The undo is offered only when the split it would restore is one
	// set_traffic accepts (an entry Conduit can't express has no undo).
	if _, verr := wantTraffic(input{Traffic: append([]traffic(nil), before...)}); len(before) > 0 && verr == nil {
		res.Undo = sdk.UndoWith("set_traffic", map[string]any{"project": proj, "region": p.Region, "service": p.Service, "traffic": before}, "Restore the traffic split of "+p.Service)
	}
	return res, err
}
