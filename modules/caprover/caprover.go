// Package caprover works with a CapRover server through its API: apps with
// their domains, instances and deployed versions, deploying an image or an
// earlier version, and scaling. CapRover has no API keys, so the module
// signs in with the dashboard password and keeps the token it hands out.
// Environment variables, repository credentials and SSH keys are never
// returned.
package caprover

import (
	"bytes"
	"context"
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

// Config is one CapRover server.
type Config struct {
	URL                string `json:"url"`      // the dashboard, e.g. https://captain.example.com
	Password           string `json:"password"` // secret:// dashboard password
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api, login *rest.Client
	pass       string // secret:// reference
	h          sdk.Host

	mu    sync.Mutex
	token string
	// refused and refusedAt keep CapRover's last refusal of the password,
	// so it isn't tried again for loginPause.
	refused   error
	refusedAt time.Time
	now       func() time.Time
}

// loginPause is how long the module waits after CapRover refused the
// password before signing in again. CapRover refuses every sign-in, the
// dashboard's too, for 30 seconds after five wrong passwords, so a module
// with a wrong or changed password retrying on every health check and call
// would keep the owner locked out.
const loginPause = 2 * time.Minute

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the CapRover module.
func New() *Module { return &Module{} }

var (
	pathRe  = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	appRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)
	imageRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$`)
)

// maxInstances bounds scale_app; CapRover itself has no limit.
const maxInstances = 50

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	app := `"app":{"type":"string","description":"App name (from apps)"}`
	return sdk.Manifest{
		ID: "caprover", Name: "CapRover", Version: "0.1.0", Category: "Infrastructure", Icon: "deploy",
		Description: "CapRover: apps with domains, instances and deployed versions; deploy an image or an earlier version, and scale apps.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","password"],"properties":{
			"url":{"type":"string","description":"Your CapRover dashboard's address, e.g. https://captain.example.com"},
			"password":{"type":"string","x-secret":true,"description":"The dashboard password (CapRover has a single account)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "apps", Title: "Apps", Description: "Every app: domains and HTTPS, instances, deployed version and image, Git repository and branch, persistent data, container port. Never environment variables or credentials.", Risk: sdk.RiskRead},
			{Name: "app", Title: "App", Description: "One app's details with its latest versions (image, Git commit, time) and whether a build is running or failed.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["app"],"properties":{` + app + `}}`)},
			{Name: "deploy_app", Title: "Deploy an app", Description: "Deploys a Docker image to the app, or deploys one of its earlier versions again (a rollback). Undo deploys the version that ran before.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["app"],"properties":{` + app + `,"image":{"type":"string","description":"An image to deploy, e.g. nginx:1.27 or registry.example.com/shop:2.1"},"version":{"type":"integer","minimum":0,"description":"An earlier version to deploy again (from app)"}}}`)},
			{Name: "scale_app", Title: "Scale an app", Description: "Sets how many instances of the app run; 0 stops it. Undo sets the count back.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(fmt.Sprintf(`{"type":"object","required":["app","instances"],"properties":{%s,"instances":{"type":"integer","minimum":0,"maximum":%d}}}`, app, maxInstances))},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://captain.example.com")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
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
	// The token travels in x-captain-auth, which Go would forward to another host.
	client = rest.SameHostOnly(client)
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/v2"), "/api") + "/api/v2"
	cn := &conn{pass: c.Password, h: h, now: time.Now}
	cn.login = rest.New(base, nil)
	cn.login.HTTP = client
	cn.login.Header.Set("x-namespace", "captain")
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := cn.bearer(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("x-captain-auth", t)
		return nil
	})
	cn.api.HTTP = client
	cn.api.Header.Set("x-namespace", "captain")
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// CapRover answers HTTP 200 with its own status in the body.
const (
	statusOK            = 100
	statusDeployStarted = 101
	statusOKPartially   = 102
	statusNotAuthorized = 1102
	statusWrongPassword = 1105
	statusTokenInvalid  = 1106
	statusNotFound      = 1111
	statusAuthFailed    = 1112
	statusBackOff       = 1113
	statusOTPRequired   = 1114
)

type envelope struct {
	Status      int             `json:"status"`
	Description string          `json:"description"`
	Data        json.RawMessage `json:"data"`
}

// apiError is an error CapRover reported in its answer's status.
type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func isAPI(err error, status int) bool {
	var e *apiError
	return errors.As(err, &e) && e.status == status
}

func check(e envelope) error {
	switch e.Status {
	case statusOK, statusDeployStarted, statusOKPartially:
		return nil
	case statusWrongPassword, statusAuthFailed:
		return &apiError{e.Status, "CapRover refused the password"}
	case statusOTPRequired:
		return &apiError{e.Status, "this CapRover asks for a two-factor code at sign-in, which the module can't give; turn two-factor sign-in off to use it"}
	case statusBackOff:
		return &apiError{e.Status, "CapRover is refusing sign-ins for a while after failed attempts; try again later"}
	case statusNotAuthorized:
		return &apiError{e.Status, "CapRover didn't allow this"}
	}
	msg := strings.TrimSpace(e.Description)
	if msg == "" || len(msg) > 200 {
		msg = fmt.Sprintf("CapRover answered with status %d", e.Status)
	}
	return &apiError{e.Status, rest.Redact(msg)}
}

var errLogin = errors.New("CapRover refused the password")

// bearer returns a token, signing in when there's none.
func (c *conn) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		return c.token, nil
	}
	if c.refused != nil && c.now().Sub(c.refusedAt) < loginPause {
		return "", c.refused
	}
	c.refused = nil
	pw, err := c.h.Secret(ctx, c.pass)
	if err != nil {
		return "", err
	}
	var e envelope
	if _, err := c.login.Do(ctx, http.MethodPost, "/login", nil, map[string]string{"password": pw}, &e); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusForbidden) {
			c.refused, c.refusedAt = errLogin, c.now()
			return "", errLogin
		}
		return "", err
	}
	if err := check(e); err != nil {
		if isAPI(err, statusWrongPassword) || isAPI(err, statusAuthFailed) || isAPI(err, statusBackOff) || isAPI(err, statusOTPRequired) {
			c.refused, c.refusedAt = err, c.now()
		}
		return "", err
	}
	var d struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(e.Data, &d) != nil || d.Token == "" {
		return "", errors.New("CapRover gave no sign-in token")
	}
	c.token = d.Token
	return c.token, nil
}

// do calls the API and decodes its data into out, signing in again once if
// the token was no longer valid.
func (c *conn) do(ctx context.Context, method, path string, body, out any) error {
	call := func() error {
		var e envelope
		if _, err := c.api.Do(ctx, method, path, nil, body, &e); err != nil {
			if rest.IsStatus(err, http.StatusUnauthorized) {
				return &apiError{statusTokenInvalid, "CapRover refused the sign-in token"}
			}
			return err
		}
		if err := check(e); err != nil {
			return err
		}
		if out != nil && len(e.Data) > 0 && string(e.Data) != "null" {
			d := json.NewDecoder(bytes.NewReader(e.Data))
			d.UseNumber()
			if err := d.Decode(out); err != nil {
				return errors.New("unexpected answer from CapRover")
			}
		}
		return nil
	}
	err := call()
	if isAPI(err, statusTokenInvalid) {
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		err = call()
	}
	return err
}

type version struct {
	Version   int    `json:"version"`
	Image     string `json:"deployedImageName"`
	GitHash   string `json:"gitHash"`
	TimeStamp string `json:"timeStamp"`
}

// appDef is decoded field by field: CapRover's answer also carries
// environment variables, the push webhook's token and the repository's
// user, password and SSH key.
type appDef struct {
	Name            string `json:"appName"`
	Description     string `json:"description"`
	Instances       int    `json:"instanceCount"`
	PersistentData  bool   `json:"hasPersistentData"`
	NotWebApp       bool   `json:"notExposeAsWebApp"`
	ContainerPort   int    `json:"containerHttpPort"`
	DefaultSSL      bool   `json:"hasDefaultSubDomainSsl"`
	ForceSSL        bool   `json:"forceSsl"`
	DeployedVersion int    `json:"deployedVersion"`
	CustomDomains   []struct {
		PublicDomain string `json:"publicDomain"`
		HasSSL       bool   `json:"hasSsl"`
	} `json:"customDomain"`
	Push *struct {
		RepoInfo *struct {
			Repo   string `json:"repo"`
			Branch string `json:"branch"`
		} `json:"repoInfo"`
	} `json:"appPushWebhook"`
	Versions []version `json:"versions"`
}

func (a appDef) deployed() *version {
	for i := range a.Versions {
		if a.Versions[i].Version == a.DeployedVersion {
			return &a.Versions[i]
		}
	}
	return nil
}

type definitions struct {
	Apps       []json.RawMessage `json:"appDefinitions"`
	RootDomain string            `json:"rootDomain"`
}

func (c *conn) apps(ctx context.Context) ([]appDef, []json.RawMessage, string, error) {
	var d definitions
	if err := c.do(ctx, http.MethodGet, "/user/apps/appDefinitions", nil, &d); err != nil {
		return nil, nil, "", err
	}
	out := make([]appDef, 0, len(d.Apps))
	for _, raw := range d.Apps {
		var a appDef
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, nil, "", errors.New("unexpected answer from CapRover")
		}
		out = append(out, a)
	}
	return out, d.Apps, d.RootDomain, nil
}

func (c *conn) app(ctx context.Context, name string) (appDef, json.RawMessage, string, error) {
	as, raws, root, err := c.apps(ctx)
	if err != nil {
		return appDef{}, nil, "", err
	}
	for i, a := range as {
		if a.Name == name {
			return a, raws[i], root, nil
		}
	}
	return appDef{}, nil, "", fmt.Errorf("there's no app %s", name)
}

func (a appDef) summary(root string) map[string]any {
	row := map[string]any{"name": a.Name, "instances": a.Instances, "persistentData": a.PersistentData, "deployedVersion": a.DeployedVersion}
	if a.Description != "" {
		row["description"] = a.Description
	}
	if !a.NotWebApp {
		domains := []map[string]any{}
		if root != "" {
			domains = append(domains, map[string]any{"domain": a.Name + "." + root, "https": a.DefaultSSL})
		}
		for _, d := range a.CustomDomains {
			domains = append(domains, map[string]any{"domain": d.PublicDomain, "https": d.HasSSL})
		}
		row["domains"] = domains
		row["forceHttps"] = a.ForceSSL
		if a.ContainerPort > 0 {
			row["containerPort"] = a.ContainerPort
		}
	} else {
		row["webApp"] = false
	}
	if v := a.deployed(); v != nil && v.Image != "" {
		row["image"] = v.Image
	}
	if a.Push != nil && a.Push.RepoInfo != nil && a.Push.RepoInfo.Repo != "" {
		row["gitRepository"] = rest.StripUserinfo(a.Push.RepoInfo.Repo)
		row["gitBranch"] = a.Push.RepoInfo.Branch
	}
	return row
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	as, _, _, err := c.apps(ctx)
	if err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no CapRover API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	stopped := 0
	for _, a := range as {
		if a.Instances == 0 {
			stopped++
		}
	}
	msg := fmt.Sprintf("%d apps", len(as))
	if stopped > 0 {
		msg += fmt.Sprintf(", %d scaled to 0", stopped)
	}
	var v struct {
		Current   string `json:"currentVersion"`
		CanUpdate bool   `json:"canUpdate"`
	}
	if c.do(ctx, http.MethodGet, "/user/system/versioninfo", nil, &v) == nil && v.Current != "" && len(v.Current) < 40 {
		msg += " · CapRover " + v.Current
		if v.CanUpdate {
			msg += " (update available)"
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	App       string `json:"app"`
	Image     string `json:"image"`
	Version   *int   `json:"version"`
	Instances *int   `json:"instances"`
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
	if call.Action == "apps" {
		as, _, root, err := c.apps(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		sort.Slice(as, func(i, j int) bool { return as[i].Name < as[j].Name })
		out := []map[string]any{}
		for _, a := range as {
			out = append(out, a.summary(root))
		}
		return sdk.JSON(out)
	}
	p.App, p.Image = strings.TrimSpace(p.App), strings.TrimSpace(p.Image)
	if !appRe.MatchString(p.App) {
		return sdk.Result{}, errors.New("an app is its name from apps (lowercase letters, digits and -)")
	}
	switch call.Action {
	case "app":
		a, _, root, err := c.app(ctx, p.App)
		if err != nil {
			return sdk.Result{}, err
		}
		row := a.summary(root)
		vs := append([]version{}, a.Versions...)
		sort.Slice(vs, func(i, j int) bool { return vs[i].Version > vs[j].Version })
		versions := []map[string]any{}
		for i, v := range vs {
			if i >= 10 {
				break
			}
			e := map[string]any{"version": v.Version, "image": v.Image, "time": v.TimeStamp}
			if v.GitHash != "" {
				e["gitCommit"] = v.GitHash
			}
			versions = append(versions, e)
		}
		row["versions"] = versions
		// The build log isn't passed on: builds print their environment.
		var b struct {
			Building bool `json:"isAppBuilding"`
			Failed   bool `json:"isBuildFailed"`
		}
		if c.do(ctx, http.MethodGet, "/user/apps/appData/"+url.PathEscape(a.Name), nil, &b) == nil {
			row["building"], row["lastBuildFailed"] = b.Building, b.Failed
		}
		return sdk.JSON(row)
	case "deploy_app":
		return c.deploy(ctx, call, p)
	case "scale_app":
		if p.Instances == nil || *p.Instances < 0 || *p.Instances > maxInstances {
			return sdk.Result{}, fmt.Errorf("instances is between 0 and %d", maxInstances)
		}
		return c.scale(ctx, call, p.App, *p.Instances)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) deploy(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if (p.Image == "") == (p.Version == nil) {
		return sdk.Result{}, errors.New("enter an image to deploy, or an earlier version to deploy again (not both)")
	}
	if p.Image != "" && !imageRe.MatchString(p.Image) {
		return sdk.Result{}, errors.New("the image is like nginx:1.27 or registry.example.com/shop:2.1")
	}
	if p.Version != nil && *p.Version < 0 {
		return sdk.Result{}, errors.New("a version is a number from app")
	}
	a, _, _, err := c.app(ctx, p.App)
	if err != nil {
		return sdk.Result{}, err
	}
	image, from := p.Image, "image "+p.Image
	if p.Version != nil {
		if *p.Version == a.DeployedVersion {
			return sdk.JSON(map[string]any{"app": a.Name, "deployedVersion": a.DeployedVersion, "note": "nothing to change"})
		}
		for _, v := range a.Versions {
			if v.Version == *p.Version {
				image = v.Image
			}
		}
		if image == "" {
			return sdk.Result{}, fmt.Errorf("app %s has no version %d with an image to deploy again", a.Name, *p.Version)
		}
		from = fmt.Sprintf("version %d (%s)", *p.Version, image)
	}
	cur := a.deployed()
	curImage := ""
	if cur != nil {
		curImage = cur.Image
	}
	// The same pinned image again changes nothing; a moving tag such as
	// latest may have newer content, so it's deployed.
	if p.Image != "" && image == curImage && pinned(image) {
		return sdk.JSON(map[string]any{"app": a.Name, "image": image, "note": "nothing to change"})
	}
	if call.DryRun {
		before, _ := json.Marshal(map[string]any{"version": a.DeployedVersion, "image": curImage})
		after, _ := json.Marshal(map[string]any{"image": image})
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Deploy %s to app %s; its %d instances are replaced", from, a.Name, a.Instances),
			Changes: []sdk.Change{{Target: "app " + a.Name, Op: "deploy", Before: before, After: after}}}}, nil
	}
	def, _ := json.Marshal(map[string]any{"schemaVersion": 2, "imageName": image})
	body := map[string]string{"captainDefinitionContent": string(def), "gitHash": ""}
	if err := c.do(ctx, http.MethodPost, "/user/apps/appData/"+url.PathEscape(a.Name)+"?detached=1", body, nil); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"app": a.Name, "deploying": image, "note": "CapRover pulls the image and replaces the app's instances; app shows when it's done"})
	if cur != nil && cur.Image != "" {
		res.Undo = sdk.UndoWith("deploy_app", map[string]any{"app": a.Name, "version": cur.Version}, fmt.Sprintf("Deploy version %d of %s again", cur.Version, a.Name))
	}
	return res, err
}

// pinned reports whether an image names a fixed tag or digest.
func pinned(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return true
	}
	slash := strings.LastIndex(image, "/")
	colon := strings.LastIndex(image, ":")
	return colon > slash && !strings.HasSuffix(image, ":latest")
}

func (c *conn) scale(ctx context.Context, call sdk.Call, name string, n int) (sdk.Result, error) {
	a, raw, _, err := c.app(ctx, name)
	if err != nil {
		return sdk.Result{}, err
	}
	if a.Instances == n {
		return sdk.JSON(map[string]any{"app": a.Name, "instances": n, "note": "nothing to change"})
	}
	if call.DryRun {
		before, _ := json.Marshal(map[string]int{"instances": a.Instances})
		after, _ := json.Marshal(map[string]int{"instances": n})
		summary := fmt.Sprintf("Scale app %s from %d to %d instances", a.Name, a.Instances, n)
		if n == 0 {
			summary = fmt.Sprintf("Scale app %s to 0 instances, which stops it", a.Name)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: "app " + a.Name, Op: "scale", Before: before, After: after}}}}, nil
	}
	// CapRover's partial update changes only the count, so nothing changed
	// meanwhile is overwritten and no settings are sent. An older CapRover
	// answers it with 404; its update replaces every setting, like
	// the dashboard's Save, so everything the app has is sent back with only
	// the count changed.
	err = c.do(ctx, http.MethodPatch, "/user/apps/appDefinitions/update", map[string]any{"appName": a.Name, "instanceCount": n}, nil)
	if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusMethodNotAllowed) {
		var def map[string]any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if err := d.Decode(&def); err != nil {
			return sdk.Result{}, errors.New("unexpected answer from CapRover")
		}
		def["appName"] = a.Name
		def["instanceCount"] = n
		err = c.do(ctx, http.MethodPost, "/user/apps/appDefinitions/update", def, nil)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"app": a.Name, "instances": n, "before": a.Instances})
	res.Undo = sdk.UndoWith("scale_app", map[string]any{"app": a.Name, "instances": a.Instances}, fmt.Sprintf("Scale %s back to %d", a.Name, a.Instances))
	return res, err
}
