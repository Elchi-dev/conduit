// Package teamcity works with a TeamCity server through its REST API and an
// access token: projects, build configurations with their parameters,
// queued, running and finished builds, the tail of a build's log, and
// queueing or cancelling builds.
package teamcity

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
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

// Config is one TeamCity server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://teamcity.example.com
	Token              string `json:"token"` // secret:// access token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the TeamCity module.
func New() *Module { return &Module{} }

const (
	maxLogLines = 2000
	maxLogRead  = 32 << 20 // bytes of a log read to find its tail
	maxLineLen  = 2000
	maxValueLen = 10000
)

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// TeamCity ids start with a letter or underscore (_Root) and hold
	// letters, digits and underscores.
	idRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,224}$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9_./+@#-]{1,255}$`)
	paramRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)
	ansiRe   = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
	// Attributes of a parameter's type spec: data_1='a' checkedValue='yes'.
	specAttrRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)='((?:[^'|]|\|.)*)'`)
	// secretNameRe matches parameter names that look like they hold a secret;
	// their values are hidden like password parameters.
	secretNameRe = regexp.MustCompile(`(?i)password|passwd|secret|token|key|credential`)
	// refRe matches a parameter reference (%name%, %vault:path!/key%), which
	// TeamCity resolves when the build starts; %% is a literal %.
	refRe = regexp.MustCompile(`%[^%]+%`)
)

// validBranch checks a branch name for a request: the characters branchRe
// allows, and nothing Git would read as an option, a forced refspec or a
// range (-x, +refs/..., a..b).
func validBranch(s string) bool {
	return branchRe.MatchString(s) && !strings.ContainsAny(s[:1], "-+/.") && !strings.HasSuffix(s, "/") && !strings.HasSuffix(s, ".") &&
		!strings.Contains(s, "..") && !strings.Contains(s, "//") && !strings.HasSuffix(s, ".lock")
}

// tokenByte is a byte that can be part of a credential (see rest.Redact).
func tokenByte(r rune) bool {
	return r < 0x80 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._~+/=-", r))
}

func validID(s, what string) (string, error) {
	v := strings.TrimSpace(s)
	if !idRe.MatchString(v) {
		return "", fmt.Errorf("the %s is its TeamCity id, like MyProject_Build", what)
	}
	return v, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	bt := `"buildType":{"type":"string","description":"Build configuration id, like MyProject_Build (see build_configurations)"}`
	bid := `"build":{"type":"integer","minimum":1,"description":"Build id (see builds), not its number"}`
	return sdk.Manifest{
		ID: "teamcity", Name: "TeamCity", Version: "0.1.0", Category: "Development", Icon: "pipeline",
		Description: "TeamCity: projects, build configurations, queued, running and finished builds, build log tails, and queueing or cancelling builds.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The TeamCity address, e.g. https://teamcity.example.com (with its context path if it has one)"},
			"token":{"type":"string","x-secret":true,"description":"An access token (your profile, Access Tokens); it acts with its user's permissions"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Projects with their parent, description and whether they're archived.", Risk: sdk.RiskRead},
			{Name: "build_configurations", Title: "Build configurations", Description: "Build configurations, of one project (and its subprojects) or all, with whether they're paused.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"project":{"type":"string","description":"Project id (see projects)"}}}`)},
			{Name: "build_configuration", Title: "Build configuration", Description: "One build configuration with its parameters: type, choices and defaults (never for password parameters or ones whose name looks secret).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["buildType"],"properties":{` + bt + `}}`)},
			{Name: "builds", Title: "Builds", Description: "Queued, running or finished builds, newest first, of one build configuration or the whole server: id, number, state, status, branch, who triggered it and when.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + bt + `,"state":{"type":"string","enum":["queued","running","finished","any"],"default":"any"},"branch":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "build", Title: "Build", Description: "One build: state, status text, branch, agent, revisions, trigger, progress, and why it waits when queued.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["build"],"properties":{` + bid + `}}`)},
			{Name: "build_log", Title: "Build log", Description: "The last lines of a build's log (up to 2000), with anything that looks like a credential redacted. Logs can hold secrets a build printed, so this is sensitive and stays out of the audit log.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["build"],"properties":{` + bid + `,"lines":{"type":"integer","minimum":1,"maximum":2000,"default":200}}}`)},
			{Name: "trigger_build", Title: "Queue a build", Description: "Queues a build of a build configuration, on a branch and with parameter values. A build runs the configuration's code with its credentials and can deploy, so this is destructive. Only declared parameters are accepted, never password ones.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["buildType"],"properties":{` + bt + `,"branch":{"type":"string","description":"Branch to build (the default branch when left out)"},"parameters":{"type":"object","description":"Values for declared parameters by name; the defaults fill the rest","additionalProperties":{"type":["string","number","boolean"]}}}}`)},
			{Name: "cancel_build", Title: "Cancel a build", Description: "Removes a queued build from the queue or stops a running one. Destructive: work in flight stops (a deploy may be left half done).", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["build"],"properties":{` + bid + `}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "build", Title: "Builds", ListAction: "builds", GetAction: "build", ViewHint: "table"}},
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
		return errors.New("the address is like https://teamcity.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
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
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimRight(u.Path, "/"), func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("TeamCity refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("TeamCity refused: the token's user lacks the permission for this")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s (or the token can't see it)", what)
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any, what string) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return friendly(err, what)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var srv struct {
		Version string `json:"version"`
	}
	if err := c.get(ctx, "/app/rest/server", url.Values{"fields": {"version"}}, &srv, "TeamCity at this address"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if srv.Version == "" {
		return sdk.Health{Status: "down", Message: "no TeamCity at this address"}
	}
	var me struct {
		Username string `json:"username"`
	}
	if err := c.get(ctx, "/app/rest/users/current", url.Values{"fields": {"username"}}, &me, "current user"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + me.Username + " · TeamCity " + srv.Version}
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// text is free text the server passes on (a status, a comment): redacted
// first, then cut, so a credential is never half kept.
func text(s string, n int) string {
	return clip(rest.Redact(strings.TrimSpace(s)), n)
}

// when turns TeamCity's 20261104T100000+0000 into RFC 3339.
func when(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse("20060102T150405-0700", s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}

type build struct {
	ID          int64  `json:"id"`
	Number      string `json:"number"`
	Status      string `json:"status"`
	State       string `json:"state"`
	BranchName  string `json:"branchName"`
	BuildTypeID string `json:"buildTypeId"`
	StatusText  string `json:"statusText"`
	QueuedDate  string `json:"queuedDate"`
	StartDate   string `json:"startDate"`
	FinishDate  string `json:"finishDate"`
	WebURL      string `json:"webUrl"`
	Percentage  *int   `json:"percentageComplete"`
	WaitReason  string `json:"waitReason"`
	Triggered   *struct {
		Type string `json:"type"`
		User *struct {
			Username string `json:"username"`
		} `json:"user"`
	} `json:"triggered"`
	Agent *struct {
		Name string `json:"name"`
	} `json:"agent"`
	Revisions *struct {
		Revision []struct {
			Version string `json:"version"`
		} `json:"revision"`
	} `json:"revisions"`
	Canceled *struct {
		User *struct {
			Username string `json:"username"`
		} `json:"user"`
		Text string `json:"text"`
	} `json:"canceledInfo"`
}

const buildFields = "id,number,status,state,branchName,buildTypeId,statusText,queuedDate,startDate,finishDate,webUrl,percentageComplete,waitReason,triggered(type,user(username))"

func summary(b build) map[string]any {
	row := map[string]any{"id": b.ID, "buildType": b.BuildTypeID, "state": b.State, "queued": when(b.QueuedDate), "url": b.WebURL}
	if b.Number != "" {
		row["number"] = b.Number
	}
	if b.Status != "" && b.State != "queued" {
		row["status"] = b.Status
	}
	if b.BranchName != "" {
		row["branch"] = b.BranchName
	}
	if b.StartDate != "" {
		row["started"] = when(b.StartDate)
	}
	if b.FinishDate != "" {
		row["finished"] = when(b.FinishDate)
	}
	if b.StatusText != "" {
		row["statusText"] = text(b.StatusText, 300)
	}
	if b.Percentage != nil && b.State == "running" {
		row["percentComplete"] = *b.Percentage
	}
	if b.WaitReason != "" && b.State == "queued" {
		row["waitReason"] = text(b.WaitReason, 300)
	}
	if b.Triggered != nil {
		row["triggeredBy"] = b.Triggered.Type
		if b.Triggered.User != nil {
			row["triggeredBy"] = b.Triggered.User.Username
		}
	}
	return row
}

func (c *conn) build(ctx context.Context, id int64, fields string) (build, error) {
	if id <= 0 {
		return build{}, errors.New("enter the build id (see builds)")
	}
	var b build
	if err := c.get(ctx, "/app/rest/builds/id:"+strconv.FormatInt(id, 10), url.Values{"fields": {fields}}, &b, fmt.Sprintf("build %d", id)); err != nil {
		return build{}, err
	}
	if b.ID != id {
		return build{}, fmt.Errorf("unexpected answer looking up build %d", id)
	}
	return b, nil
}

type param struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  *struct {
		RawValue string `json:"rawValue"`
	} `json:"type"`
}

type buildType struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ProjectID   string `json:"projectId"`
	ProjectName string `json:"projectName"`
	Paused      bool   `json:"paused"`
	Description string `json:"description"`
	WebURL      string `json:"webUrl"`
	Parameters  *struct {
		Property []param `json:"property"`
	} `json:"parameters"`
}

func (p param) spec() string {
	if p.Type == nil {
		return ""
	}
	return p.Type.RawValue
}

// kind is the parameter's control: text, password, checkbox, select.
func (p param) kind() string {
	k, _, _ := strings.Cut(strings.TrimSpace(p.spec()), " ")
	if k == "" {
		return "text"
	}
	return k
}

func (p param) password() bool { return p.kind() == "password" }

func (p param) hidden() bool { return p.password() || secretNameRe.MatchString(p.Name) }

// attrs reads the type spec's attributes, unescaping TeamCity's |' and ||.
func (p param) attrs() map[string]string {
	out := map[string]string{}
	for _, m := range specAttrRe.FindAllStringSubmatch(p.spec(), -1) {
		out[m[1]] = strings.NewReplacer("||", "|", "|'", "'", "|n", "\n", "|r", "\r", "|[", "[", "|]", "]").Replace(m[2])
	}
	return out
}

// choices are a select parameter's values, in order.
func (p param) choices() []string {
	if p.kind() != "select" {
		return nil
	}
	a := p.attrs()
	type kv struct {
		n int
		v string
	}
	var list []kv
	for k, v := range a {
		if n, ok := strings.CutPrefix(k, "data_"); ok {
			i, err := strconv.Atoi(n)
			if err == nil {
				list = append(list, kv{i, v})
			}
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].n < list[j].n })
	out := []string{}
	for _, x := range list {
		out = append(out, x.v)
	}
	return out
}

func (c *conn) buildType(ctx context.Context, id string) (buildType, error) {
	var bt buildType
	if err := c.get(ctx, "/app/rest/buildTypes/id:"+url.PathEscape(id), url.Values{"fields": {"id,name,projectId,projectName,paused,description,webUrl,parameters(property(name,value,type(rawValue)))"}}, &bt, "build configuration "+id); err != nil {
		return bt, err
	}
	if bt.ID != id {
		return bt, fmt.Errorf("unexpected answer looking up build configuration %s", id)
	}
	return bt, nil
}

func (bt buildType) params() []param {
	if bt.Parameters == nil {
		return nil
	}
	return bt.Parameters.Property
}

type input struct {
	Project    string         `json:"project"`
	BuildType  string         `json:"buildType"`
	State      string         `json:"state"`
	Branch     string         `json:"branch"`
	Limit      int            `json:"limit"`
	Build      int64          `json:"build"`
	Lines      int            `json:"lines"`
	Parameters map[string]any `json:"parameters"`
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
	case "projects":
		var out struct {
			Project []struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				ParentID    string `json:"parentProjectId"`
				Archived    bool   `json:"archived"`
				Description string `json:"description"`
				WebURL      string `json:"webUrl"`
			} `json:"project"`
		}
		if err := c.get(ctx, "/app/rest/projects", url.Values{"fields": {"project(id,name,parentProjectId,archived,description,webUrl)"}}, &out, "projects"); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, x := range out.Project {
			row := map[string]any{"id": x.ID, "name": x.Name, "url": x.WebURL}
			if x.ParentID != "" {
				row["parent"] = x.ParentID
			}
			if x.Description != "" {
				row["description"] = text(x.Description, 300)
			}
			if x.Archived {
				row["archived"] = true
			}
			list = append(list, row)
		}
		return sdk.JSON(list)

	case "build_configurations":
		q := url.Values{"fields": {"buildType(id,name,projectId,projectName,paused,webUrl)"}}
		what := "build configurations"
		if strings.TrimSpace(p.Project) != "" {
			pid, err := validID(p.Project, "project")
			if err != nil {
				return sdk.Result{}, err
			}
			q.Set("locator", "affectedProject:(id:"+pid+")")
			what = "project " + pid
		}
		var out struct {
			BuildType []buildType `json:"buildType"`
		}
		if err := c.get(ctx, "/app/rest/buildTypes", q, &out, what); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, b := range out.BuildType {
			row := map[string]any{"id": b.ID, "name": b.Name, "project": b.ProjectID, "projectName": b.ProjectName, "url": b.WebURL}
			if b.Paused {
				row["paused"] = true
			}
			list = append(list, row)
		}
		return sdk.JSON(list)

	case "build_configuration":
		id, err := validID(p.BuildType, "build configuration")
		if err != nil {
			return sdk.Result{}, err
		}
		bt, err := c.buildType(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		params := []map[string]any{}
		for _, x := range bt.params() {
			row := map[string]any{"name": x.Name, "type": x.kind()}
			if ch := x.choices(); len(ch) > 0 {
				row["choices"] = ch
			}
			if x.hidden() {
				row["default"] = "[hidden]"
			} else {
				row["default"] = clip(rest.Redact(x.Value), 300)
			}
			params = append(params, row)
		}
		out := map[string]any{"id": bt.ID, "name": bt.Name, "project": bt.ProjectID, "projectName": bt.ProjectName, "paused": bt.Paused, "url": bt.WebURL, "parameters": params}
		if bt.Description != "" {
			out["description"] = text(bt.Description, 500)
		}
		return sdk.JSON(out)

	case "builds":
		return c.builds(ctx, p)

	case "build":
		b, err := c.build(ctx, p.Build, buildFields+",agent(name),revisions(revision(version)),canceledInfo(user(username),text)")
		if err != nil {
			return sdk.Result{}, err
		}
		out := summary(b)
		if b.Agent != nil && b.Agent.Name != "" {
			out["agent"] = b.Agent.Name
		}
		if b.Revisions != nil {
			revs := []string{}
			for _, r := range b.Revisions.Revision {
				v := r.Version
				if len(v) > 12 {
					v = v[:12]
				}
				revs = append(revs, v)
			}
			out["revisions"] = revs
		}
		if b.Canceled != nil {
			cn := map[string]any{"comment": text(b.Canceled.Text, 300)}
			if b.Canceled.User != nil {
				cn["by"] = b.Canceled.User.Username
			}
			out["canceled"] = cn
		}
		return sdk.JSON(out)

	case "build_log":
		return c.log(ctx, p)

	case "trigger_build":
		return c.trigger(ctx, call, p)

	case "cancel_build":
		b, err := c.build(ctx, p.Build, buildFields)
		if err != nil {
			return sdk.Result{}, err
		}
		target := fmt.Sprintf("build %d of %s", b.ID, b.BuildTypeID)
		if b.Number != "" {
			target = fmt.Sprintf("build #%s (id %d) of %s", b.Number, b.ID, b.BuildTypeID)
		}
		if b.State != "queued" && b.State != "running" {
			return sdk.JSON(map[string]any{"build": b.ID, "state": b.State, "status": b.Status, "note": "nothing to change: it already finished"})
		}
		if call.DryRun {
			sum := "Remove " + target + " from the queue"
			if b.State == "running" {
				sum = "Stop " + target + ", running since " + when(b.StartDate)
			}
			before, _ := json.Marshal(map[string]any{"state": b.State, "branch": b.BranchName})
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: "cancel", Before: before}}}}, nil
		}
		path := "/app/rest/builds/id:" + strconv.FormatInt(b.ID, 10)
		if b.State == "queued" {
			path = "/app/rest/buildQueue/id:" + strconv.FormatInt(b.ID, 10)
		}
		var after build
		if _, err := c.api.Do(ctx, http.MethodPost, path, nil, map[string]any{"comment": "Cancelled through Conduit", "readdIntoQueue": false}, &after); err != nil {
			return sdk.Result{}, friendly(err, target)
		}
		state := after.State
		if state == "" {
			state = "canceled"
		}
		return sdk.JSON(map[string]any{"cancelled": b.ID, "buildType": b.BuildTypeID, "was": b.State, "state": state})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) builds(ctx context.Context, p input) (sdk.Result, error) {
	limit := p.Limit
	if limit == 0 {
		limit = 20
	}
	if limit < 1 || limit > 100 {
		return sdk.Result{}, errors.New("limit is between 1 and 100")
	}
	var loc []string
	what := "builds"
	if strings.TrimSpace(p.BuildType) != "" {
		id, err := validID(p.BuildType, "build configuration")
		if err != nil {
			return sdk.Result{}, err
		}
		loc = append(loc, "buildType:(id:"+id+")")
		what = "build configuration " + id
	}
	state := p.State
	if state == "" {
		state = "any"
	}
	if state != "queued" && state != "running" && state != "finished" && state != "any" {
		return sdk.Result{}, errors.New("state is queued, running, finished or any")
	}
	if b := strings.TrimSpace(p.Branch); b != "" {
		if !validBranch(b) {
			return sdk.Result{}, errors.New("that isn't a branch name")
		}
		loc = append(loc, "branch:(name:"+b+")")
	} else if state != "queued" {
		loc = append(loc, "branch:(default:any)")
	}
	path := "/app/rest/builds"
	if state == "queued" {
		path = "/app/rest/buildQueue"
	} else {
		loc = append(loc, "state:"+state, "defaultFilter:false")
	}
	loc = append(loc, "count:"+strconv.Itoa(limit))
	var out struct {
		Build []build `json:"build"`
	}
	if err := c.get(ctx, path, url.Values{"locator": {strings.Join(loc, ",")}, "fields": {"build(" + buildFields + ")"}}, &out, what); err != nil {
		return sdk.Result{}, err
	}
	if len(out.Build) > limit {
		out.Build = out.Build[:limit]
	}
	list := []map[string]any{}
	for _, b := range out.Build {
		list = append(list, summary(b))
	}
	return sdk.JSON(list)
}

func (c *conn) log(ctx context.Context, p input) (sdk.Result, error) {
	n := p.Lines
	if n == 0 {
		n = 200
	}
	if n < 1 || n > maxLogLines {
		return sdk.Result{}, fmt.Errorf("lines is between 1 and %d", maxLogLines)
	}
	b, err := c.build(ctx, p.Build, buildFields)
	if err != nil {
		return sdk.Result{}, err
	}
	if b.State == "queued" {
		return sdk.Result{}, fmt.Errorf("build %d is still queued and has no log yet", b.ID)
	}
	res, err := c.api.Send(ctx, http.MethodGet, "/downloadBuildLog.html", url.Values{"buildId": {strconv.FormatInt(b.ID, 10)}}, nil, http.Header{"Accept": {"text/plain"}})
	if err != nil {
		return sdk.Result{}, friendly(err, fmt.Sprintf("log of build %d", b.ID))
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return sdk.Result{}, fmt.Errorf("TeamCity answered %s for the log", res.Status)
	}
	if mt, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type")); mt == "text/html" {
		return sdk.Result{}, errors.New("TeamCity answered with a page instead of the log (is the token allowed to view this build?)")
	}
	lines, read, more, err := tail(io.LimitReader(res.Body, maxLogRead+1), n)
	if err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"build": b.ID, "buildType": b.BuildTypeID, "number": b.Number, "state": b.State, "status": b.Status, "lines": lines, "bytesRead": read}
	if more {
		out["note"] = fmt.Sprintf("the log is longer than %d MiB; these are the last lines of its first %d MiB", maxLogRead>>20, maxLogRead>>20)
	}
	return sdk.JSON(out)
}

// tail keeps the last n lines of r, each cut at maxLineLen, with terminal
// codes removed and anything that looks like a credential redacted.
func tail(r io.Reader, n int) (lines []string, read int64, more bool, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	ring := make([]string, 0, n)
	start := 0
	var cur []byte
	cut := false
	push := func(b []byte) {
		if cut {
			// The line was cut while it was read: drop what may be the first
			// part of a credential, which Redact wouldn't recognize.
			b = bytes.TrimRightFunc(b, tokenByte)
		}
		s := strings.TrimRight(strings.ToValidUTF8(string(b), "�"), "\r\n")
		s = ansiRe.ReplaceAllString(s, "")
		if i := strings.LastIndexByte(s, '\r'); i >= 0 {
			s = s[i+1:]
		}
		s = clip(rest.Redact(s), maxLineLen)
		if cut && !strings.HasSuffix(s, "…") {
			s += "…"
		}
		if len(ring) < n {
			ring = append(ring, s)
			return
		}
		ring[start] = s
		start = (start + 1) % n
	}
	for {
		chunk, e := br.ReadSlice('\n')
		read += int64(len(chunk))
		if len(cur) < maxLineLen*4 {
			cur = append(cur, chunk...)
		} else if len(chunk) > 0 {
			cut = true
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if len(chunk) > 0 && chunk[len(chunk)-1] == '\n' || (e == io.EOF && len(cur) > 0) {
			push(cur)
			cur, cut = cur[:0], false
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, read, false, e
		}
	}
	if read > maxLogRead {
		more, read = true, maxLogRead
	}
	return append(ring[start:], ring[:start]...), read, more, nil
}

// value turns a parameter value from the input into the string TeamCity
// takes, checking it against the parameter's type.
func value(d param, raw any) (string, error) {
	var v string
	fixed := false // a value the configuration defines (a choice, a checkbox's)
	switch x := raw.(type) {
	case string:
		v = x
	case bool:
		v = strconv.FormatBool(x)
		if d.kind() == "checkbox" {
			fixed = true
			a := d.attrs()
			on, off := "true", "false"
			if s, ok := a["checkedValue"]; ok {
				on = s
			}
			if s, ok := a["uncheckedValue"]; ok {
				off = s
			}
			if x {
				v = on
			} else {
				v = off
			}
		}
	case float64:
		v = strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return "", fmt.Errorf("parameter %s is a string, number or boolean", d.Name)
	}
	if len(v) > maxValueLen || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
		return "", fmt.Errorf("parameter %s is too long or not text", d.Name)
	}
	if ch := d.choices(); len(ch) > 0 && d.attrs()["multiple"] != "true" {
		ok := false
		for _, c := range ch {
			ok = ok || c == v
		}
		if !ok {
			return "", fmt.Errorf("parameter %s is one of %s", d.Name, strings.Join(ch, ", "))
		}
		fixed = true
	}
	// A reference would be resolved by TeamCity, so a value could pull in a
	// password parameter or a secret from a vault plugin and send it on.
	if !fixed && refRe.MatchString(strings.ReplaceAll(v, "%%", "")) {
		return "", fmt.Errorf("parameter %s refers to another parameter (%%name%%); Conduit doesn't pass references (write %%%% for a literal %%)", d.Name)
	}
	return v, nil
}

func (c *conn) trigger(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	id, err := validID(p.BuildType, "build configuration")
	if err != nil {
		return sdk.Result{}, err
	}
	branch := strings.TrimSpace(p.Branch)
	if branch != "" && !validBranch(branch) {
		return sdk.Result{}, errors.New("that isn't a branch name")
	}
	names := make([]string, 0, len(p.Parameters))
	for k := range p.Parameters {
		if !paramRe.MatchString(k) {
			return sdk.Result{}, fmt.Errorf("%q isn't a parameter name", k)
		}
		names = append(names, k)
	}
	sort.Strings(names)
	bt, err := c.buildType(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	defs := map[string]param{}
	for _, d := range bt.params() {
		defs[d.Name] = d
	}
	props := []map[string]string{}
	shown := map[string]any{}
	for _, k := range names {
		d, ok := defs[k]
		if !ok {
			return sdk.Result{}, fmt.Errorf("%s has no parameter %q (see build_configuration)", id, k)
		}
		if d.password() {
			return sdk.Result{}, fmt.Errorf("%s is a password parameter; Conduit doesn't pass those (its stored value is used)", k)
		}
		v, err := value(d, p.Parameters[k])
		if err != nil {
			return sdk.Result{}, err
		}
		props = append(props, map[string]string{"name": k, "value": v})
		if d.hidden() {
			shown[k] = "[hidden]"
		} else {
			shown[k] = clip(v, 300)
		}
	}
	target := "build configuration " + id
	if call.DryRun {
		sum := "Queue a build of " + bt.Name + " (" + id + ")"
		if branch != "" {
			sum += " on " + branch
		}
		if len(shown) > 0 {
			sum += " with parameters"
		}
		if bt.Paused {
			sum += "; the configuration is paused, so its triggers are off, but a queued build still runs"
		}
		ch := sdk.Change{Target: target, Op: "build"}
		after := map[string]any{}
		if branch != "" {
			after["branch"] = branch
		}
		if len(shown) > 0 {
			after["parameters"] = shown
		}
		if len(after) > 0 {
			ch.After, _ = json.Marshal(after)
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{ch}}}, nil
	}
	body := map[string]any{"buildType": map[string]string{"id": id}}
	if branch != "" {
		body["branchName"] = branch
	}
	if len(props) > 0 {
		body["properties"] = map[string]any{"property": props}
	}
	var b build
	if _, err := c.api.Do(ctx, http.MethodPost, "/app/rest/buildQueue", nil, body, &b); err != nil {
		return sdk.Result{}, friendly(err, target)
	}
	return sdk.JSON(map[string]any{"queued": true, "build": b.ID, "buildType": id, "state": b.State, "url": b.WebURL})
}
