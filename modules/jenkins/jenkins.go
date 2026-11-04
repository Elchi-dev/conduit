// Package jenkins works with a Jenkins controller through its REST API and
// a user's API token: jobs, builds with their results, causes and
// parameters, the tail of a build's console, the build queue, and starting
// and stopping builds (with CSRF crumbs where Jenkins asks for them).
package jenkins

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Jenkins controller.
type Config struct {
	URL                string `json:"url"`      // e.g. https://ci.example.com or https://example.com/jenkins
	Username           string `json:"username"` // the user the API token belongs to
	Token              string `json:"token"`    // secret:// API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	root  string
	http  *http.Client
	host  sdk.Host
	user  string
	token string

	mu    sync.Mutex
	crumb *crumb // nil until fetched; empty field when Jenkins has no crumb issuer
}

type crumb struct{ field, value string }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Jenkins module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// Jenkins refuses ?*/\%!@#$^&|<>[]:; in item names.
	segRe   = regexp.MustCompile(`^[^/\\?*%!@#$^&|<>\[\]:;"\x00-\x1f\x7f]{1,255}$`)
	paramRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	ansiRe  = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
	queueRe = regexp.MustCompile(`/queue/item/(\d+)/?$`)
)

const (
	maxConsoleRead = 32 << 20 // bytes of console read to find its tail
	maxLineLen     = 2000
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	job := `"job":{"type":"string","description":"Job name; jobs in folders as folder/job"}`
	num := `"number":{"type":"integer","minimum":1,"description":"Build number (the last build when left out)"}`
	return sdk.Manifest{
		ID: "jenkins", Name: "Jenkins", Version: "0.1.0", Category: "Development", Icon: "pipeline",
		Description: "Jenkins jobs and builds: status, recent builds, console tail, the queue, and starting builds with parameters or stopping them.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","token"],"properties":{
			"url":{"type":"string","description":"The Jenkins address, e.g. https://ci.example.com (with its context path if it has one, like /jenkins)"},
			"username":{"type":"string","description":"The Jenkins user the API token belongs to"},
			"token":{"type":"string","x-secret":true,"description":"An API token (user menu → Security → API Token); the user's permissions decide what works"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "jobs", Title: "Jobs", Description: "Jobs (and folders) with their status and last build.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"folder":{"type":"string","description":"Only the jobs in this folder"},"search":{"type":"string"},"problems":{"type":"boolean","description":"Only jobs whose last build failed or was unstable"}}}`)},
			{Name: "job", Title: "Job details", Description: "A job's status, health, last builds, parameters (with defaults, never for password parameters or ones whose name looks secret, like API_TOKEN) and whether it's queued.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["job"],"properties":{` + job + `}}`)},
			{Name: "builds", Title: "Recent builds", Description: "A job's last builds with result, start, duration and whether they're running.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["job"],"properties":{` + job + `,"limit":{"type":"integer","minimum":1,"maximum":50,"default":10}}}`)},
			{Name: "build", Title: "Build details", Description: "One build's result, causes, parameters (password values and ones whose name looks secret hidden), changes and artifacts.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["job"],"properties":{` + job + `,` + num + `}}`)},
			{Name: "console", Title: "Console tail", Description: "The last lines of a build's console output. Logs can hold secrets Jenkins didn't mask, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["job"],"properties":{` + job + `,` + num + `,"lines":{"type":"integer","minimum":1,"maximum":2000,"default":100}}}`)},
			{Name: "queue", Title: "Build queue", Description: "Waiting builds with why they wait and for how long.", Risk: sdk.RiskRead},
			{Name: "trigger_build", Title: "Start a build", Description: "Queues a build, with parameters for parameterized jobs. A build runs the job's code with its credentials, so this is destructive. Password and file parameters can't be passed.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["job"],"properties":{` + job + `,"parameters":{"type":"object","description":"Parameter values by name; the job's defaults fill the rest","additionalProperties":{"type":["string","number","boolean"]}}}}`)},
			{Name: "stop_build", Title: "Stop a build", Description: "Aborts a running build. Destructive: it interrupts work in flight (a deploy may be left half done).", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["job"],"properties":{` + job + `,` + num + `}}`)},
			{Name: "cancel_queued", Title: "Cancel a queued build", Description: "Removes a waiting build from the queue. Destructive: it never runs and has to be triggered again.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1,"description":"Queue item id (see queue)"}}}`)},
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
		return errors.New("the address is like https://ci.example.com")
	}
	user := strings.TrimSpace(c.Username)
	if user == "" || strings.ContainsAny(user, ":\r\n") {
		return errors.New("enter the Jenkins username the API token belongs to")
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
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 60 * time.Second, Transport: tr}
	}
	client = rest.SameHostOnly(client)
	// The crumb is bound to the session it was issued in.
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	m.set.Put(id, &conn{root: u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/"), http: client, host: h, user: user, token: c.Token})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// apiError is a Jenkins answer with a status of 300 or more.
type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func isStatus(err error, s int) bool {
	var e *apiError
	return errors.As(err, &e) && e.status == s
}

// send makes one request. POSTs carry the crumb when Jenkins issues one.
func (c *conn) send(ctx context.Context, method, path string, q url.Values, form url.Values) (*http.Response, error) {
	u := c.root + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	tok, err := c.host.Secret(ctx, c.token)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, strings.TrimSpace(tok))
	req.Header.Set("User-Agent", "Conduit")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if method == http.MethodPost {
		cr, err := c.getCrumb(ctx)
		if err != nil {
			return nil, err
		}
		if cr.field != "" {
			req.Header.Set(cr.field, cr.value)
		}
	}
	hc, ok := c.http, 300
	if method == http.MethodPost {
		// Jenkins answers a stop or cancel with a redirect to an HTML page;
		// a POST is done once it's answered, so redirects aren't followed.
		cp := *c.http
		cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		hc, ok = &cp, 400
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, rest.TransportError(err)
	}
	if res.StatusCode >= ok {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		res.Body.Close()
		return nil, statusError(res.StatusCode, raw)
	}
	return res, nil
}

func statusError(status int, raw []byte) error {
	switch status {
	case http.StatusUnauthorized:
		return &apiError{status, "Jenkins refused the username or API token"}
	case http.StatusForbidden:
		if bytes.Contains(raw, []byte("No valid crumb")) {
			return &apiError{status, "Jenkins refused the CSRF crumb"}
		}
		return &apiError{status, "Jenkins refused the request: the user lacks the permission for it"}
	case http.StatusNotFound:
		return &apiError{status, "not found"}
	case http.StatusMethodNotAllowed:
		return &apiError{status, "Jenkins doesn't allow this here"}
	}
	msg := strings.TrimSpace(string(raw))
	if strings.HasPrefix(msg, "<") {
		msg = ""
	}
	return &apiError{status, strings.TrimSpace(fmt.Sprintf("Jenkins answered %d %s", status, clip(msg, 200)))}
}

func (c *conn) getCrumb(ctx context.Context) (crumb, error) {
	c.mu.Lock()
	if c.crumb != nil {
		cr := *c.crumb
		c.mu.Unlock()
		return cr, nil
	}
	c.mu.Unlock()
	var out struct {
		Crumb             string `json:"crumb"`
		CrumbRequestField string `json:"crumbRequestField"`
	}
	err := c.getJSON(ctx, "/crumbIssuer/api/json", nil, &out)
	var cr crumb
	switch {
	case isStatus(err, http.StatusNotFound):
		// CSRF protection is off (or a plugin replaced the issuer).
	case err != nil:
		return cr, err
	default:
		if out.CrumbRequestField == "" || strings.ContainsAny(out.CrumbRequestField+out.Crumb, "\r\n:") {
			return cr, errors.New("unexpected crumb from Jenkins")
		}
		cr = crumb{field: out.CrumbRequestField, value: out.Crumb}
	}
	c.mu.Lock()
	c.crumb = &cr
	c.mu.Unlock()
	return cr, nil
}

// post sends a POST and retries once with a fresh crumb when Jenkins
// refuses the cached one (the session it belonged to expired).
func (c *conn) post(ctx context.Context, path string, q url.Values, form url.Values) (http.Header, error) {
	res, err := c.send(ctx, http.MethodPost, path, q, form)
	if err != nil && strings.Contains(err.Error(), "CSRF crumb") {
		c.mu.Lock()
		c.crumb = nil
		c.mu.Unlock()
		res, err = c.send(ctx, http.MethodPost, path, q, form)
	}
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	return res.Header, nil
}

func (c *conn) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	res, err := c.send(ctx, http.MethodGet, path, q, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errors.New("unexpected answer from Jenkins (is this the Jenkins address?)")
	}
	return nil
}

// jobPath turns "folder/job" into /job/folder/job/job, checking each part.
func jobPath(name string) (string, error) {
	name = strings.Trim(strings.TrimSpace(name), "/")
	if name == "" {
		return "", errors.New("enter the job's name (folder/job for jobs in folders)")
	}
	parts := strings.Split(name, "/")
	if len(parts) > 20 {
		return "", errors.New("the job is nested too deep")
	}
	// Accept paths copied from a URL: job/a/job/b.
	if len(parts)%2 == 0 {
		fromURL := true
		for i := 0; i < len(parts); i += 2 {
			fromURL = fromURL && parts[i] == "job"
		}
		if fromURL {
			var names []string
			for i := 1; i < len(parts); i += 2 {
				names = append(names, parts[i])
			}
			parts = names
		}
	}
	var b strings.Builder
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "." || p == ".." || !segRe.MatchString(p) {
			return "", fmt.Errorf("%q isn't a Jenkins job name", p)
		}
		b.WriteString("/job/" + url.PathEscape(p))
	}
	return b.String(), nil
}

func buildRef(number int64) (string, error) {
	if number < 0 {
		return "", errors.New("the build number is positive")
	}
	if number == 0 {
		return "/lastBuild", nil
	}
	return "/" + strconv.FormatInt(number, 10), nil
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func when(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	res, err := c.send(ctx, http.MethodGet, "/me/api/json", url.Values{"tree": {"id,fullName"}}, nil)
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Jenkins at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	ver := res.Header.Get("X-Jenkins")
	var me struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&me)
	res.Body.Close()
	if err != nil || ver == "" {
		return sdk.Health{Status: "down", Message: "no Jenkins at this address"}
	}
	msg := "signed in as " + me.ID + " · Jenkins " + ver
	var root struct {
		QuietingDown bool `json:"quietingDown"`
	}
	if c.getJSON(ctx, "/api/json", url.Values{"tree": {"quietingDown"}}, &root) == nil && root.QuietingDown {
		return sdk.Health{Status: "degraded", Message: msg + " · preparing for shutdown, no new builds start"}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type buildRefJSON struct {
	Number    int64  `json:"number"`
	Result    string `json:"result"`
	Building  bool   `json:"building"`
	Timestamp int64  `json:"timestamp"`
	Duration  int64  `json:"duration"`
}

func buildSummary(b *buildRefJSON) map[string]any {
	if b == nil {
		return nil
	}
	e := map[string]any{"number": b.Number, "started": when(b.Timestamp)}
	if b.Building {
		e["result"] = "RUNNING"
	} else {
		e["result"] = b.Result
		e["durationSeconds"] = b.Duration / 1000
	}
	return e
}

type jobJSON struct {
	Class       string        `json:"_class"`
	Name        string        `json:"name"`
	FullName    string        `json:"fullName"`
	URL         string        `json:"url"`
	Color       string        `json:"color"`
	Buildable   *bool         `json:"buildable"`
	InQueue     bool          `json:"inQueue"`
	Description string        `json:"description"`
	LastBuild   *buildRefJSON `json:"lastBuild"`
	LastOK      *buildRefJSON `json:"lastSuccessfulBuild"`
	LastFailed  *buildRefJSON `json:"lastFailedBuild"`
	NextBuild   int64         `json:"nextBuildNumber"`
	Health      []struct {
		Description string `json:"description"`
		Score       int    `json:"score"`
	} `json:"healthReport"`
	Property []struct {
		Defs []paramDef `json:"parameterDefinitions"`
	} `json:"property"`
	Builds []buildRefJSON `json:"builds"`
}

type paramDef struct {
	Class       string   `json:"_class"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Choices     []string `json:"choices"`
	Default     *struct {
		Value any `json:"value"`
	} `json:"defaultParameterValue"`
}

func (d paramDef) secret() bool {
	return strings.Contains(d.Class, "Password") || strings.Contains(d.Type, "Password") || strings.Contains(d.Class, "Credentials")
}

// secretNameRe matches parameter names that look like they hold a secret.
// Jobs often keep tokens in plain string parameters (API_TOKEN, AWS_KEY);
// their values are hidden just like password parameters.
var secretNameRe = regexp.MustCompile(`(?i)password|passwd|secret|token|key|credential`)

// secretName reports whether a parameter's name looks secret-ish.
func secretName(name string) bool { return secretNameRe.MatchString(name) }

// hidden reports whether the parameter's default value is kept out of
// answers and previews: password and credentials parameters, and any whose
// name looks like a secret.
func (d paramDef) hidden() bool { return d.secret() || secretName(d.Name) }

func (d paramDef) file() bool {
	return strings.Contains(d.Class, "File") || d.Type == "FileParameterDefinition"
}

func (j jobJSON) params() []paramDef {
	var out []paramDef
	for _, p := range j.Property {
		out = append(out, p.Defs...)
	}
	return out
}

func (j jobJSON) isFolder() bool {
	return strings.Contains(j.Class, "Folder") || strings.Contains(j.Class, "MultiBranchProject") || strings.Contains(j.Class, "OrganizationFolder")
}

// status reads a job's ball color.
func status(color string) string {
	base := strings.TrimSuffix(color, "_anime")
	s := map[string]string{"blue": "success", "green": "success", "red": "failed", "yellow": "unstable", "aborted": "aborted",
		"disabled": "disabled", "notbuilt": "not built", "grey": "not built", "nobuilt": "not built"}[base]
	if s == "" {
		s = base
	}
	if strings.HasSuffix(color, "_anime") {
		s += ", building"
	}
	return s
}

func jobOut(j jobJSON) map[string]any {
	name := j.FullName
	if name == "" {
		name = j.Name
	}
	e := map[string]any{"name": name}
	if j.isFolder() {
		e["type"] = "folder"
		return e
	}
	e["status"] = status(j.Color)
	if b := buildSummary(j.LastBuild); b != nil {
		e["lastBuild"] = b
	}
	return e
}

type input struct {
	Job        string         `json:"job"`
	Folder     string         `json:"folder"`
	Search     string         `json:"search"`
	Problems   bool           `json:"problems"`
	Number     int64          `json:"number"`
	Limit      int            `json:"limit"`
	Lines      int            `json:"lines"`
	Parameters map[string]any `json:"parameters"`
	ID         int64          `json:"id"`
}

const lastTree = `number,result,building,timestamp,duration`

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
	case "jobs":
		base := ""
		if strings.TrimSpace(p.Folder) != "" {
			if base, err = jobPath(p.Folder); err != nil {
				return sdk.Result{}, err
			}
		}
		var out struct {
			Jobs []jobJSON `json:"jobs"`
		}
		if err := c.getJSON(ctx, base+"/api/json", url.Values{"tree": {"jobs[_class,name,fullName,color,lastBuild[" + lastTree + "]]"}}, &out); err != nil {
			if isStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no folder %s", p.Folder)
			}
			return sdk.Result{}, err
		}
		s := strings.ToLower(strings.TrimSpace(p.Search))
		list := []map[string]any{}
		for _, j := range out.Jobs {
			if s != "" && !strings.Contains(strings.ToLower(j.FullName+" "+j.Name), s) {
				continue
			}
			if p.Problems {
				st := status(j.Color)
				if j.isFolder() || !(strings.HasPrefix(st, "failed") || strings.HasPrefix(st, "unstable")) {
					continue
				}
			}
			list = append(list, jobOut(j))
		}
		return sdk.JSON(list)

	case "job":
		j, err := c.job(ctx, p.Job, true)
		if err != nil {
			return sdk.Result{}, err
		}
		e := jobOut(j)
		if j.isFolder() {
			return sdk.JSON(e)
		}
		e["description"] = clip(j.Description, 500)
		e["inQueue"] = j.InQueue
		if j.Buildable != nil {
			e["buildable"] = *j.Buildable
		}
		e["nextBuildNumber"] = j.NextBuild
		if b := buildSummary(j.LastOK); b != nil {
			e["lastSuccessfulBuild"] = b
		}
		if b := buildSummary(j.LastFailed); b != nil {
			e["lastFailedBuild"] = b
		}
		if len(j.Health) > 0 {
			e["health"] = map[string]any{"score": j.Health[0].Score, "description": j.Health[0].Description}
		}
		params := []map[string]any{}
		for _, d := range j.params() {
			pe := map[string]any{"name": d.Name, "type": strings.TrimSuffix(d.Type, "ParameterDefinition")}
			if d.Description != "" {
				pe["description"] = clip(d.Description, 200)
			}
			if len(d.Choices) > 0 {
				pe["choices"] = d.Choices
			}
			if d.Default != nil && !d.hidden() {
				pe["default"] = d.Default.Value
			} else if d.Default != nil {
				pe["default"] = "[hidden]"
			}
			params = append(params, pe)
		}
		e["parameters"] = params
		recent := []map[string]any{}
		for i := range j.Builds {
			recent = append(recent, buildSummary(&j.Builds[i]))
		}
		e["recentBuilds"] = recent
		return sdk.JSON(e)

	case "builds":
		jp, err := jobPath(p.Job)
		if err != nil {
			return sdk.Result{}, err
		}
		n := p.Limit
		if n == 0 {
			n = 10
		}
		if n < 1 || n > 50 {
			return sdk.Result{}, errors.New("limit is between 1 and 50")
		}
		var out struct {
			Builds []buildRefJSON `json:"builds"`
		}
		if err := c.getJSON(ctx, jp+"/api/json", url.Values{"tree": {"builds[" + lastTree + "]{0," + strconv.Itoa(n) + "}"}}, &out); err != nil {
			return sdk.Result{}, notFound(err, "job "+p.Job)
		}
		list := []map[string]any{}
		for i := range out.Builds {
			list = append(list, buildSummary(&out.Builds[i]))
		}
		return sdk.JSON(list)

	case "build":
		return c.build(ctx, p)

	case "console":
		return c.console(ctx, p)

	case "queue":
		var out struct {
			Items []struct {
				ID           int64  `json:"id"`
				Why          string `json:"why"`
				Blocked      bool   `json:"blocked"`
				Stuck        bool   `json:"stuck"`
				InQueueSince int64  `json:"inQueueSince"`
				Task         struct {
					Name     string `json:"name"`
					FullName string `json:"fullName"`
				} `json:"task"`
			} `json:"items"`
		}
		if err := c.getJSON(ctx, "/queue/api/json", url.Values{"tree": {"items[id,why,blocked,stuck,inQueueSince,task[name,fullName]]"}}, &out); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, it := range out.Items {
			name := it.Task.FullName
			if name == "" {
				name = it.Task.Name
			}
			list = append(list, map[string]any{"id": it.ID, "job": name, "why": clip(it.Why, 300), "since": when(it.InQueueSince), "blocked": it.Blocked, "stuck": it.Stuck})
		}
		sort.SliceStable(list, func(i, j int) bool { return list[i]["since"].(string) < list[j]["since"].(string) })
		return sdk.JSON(list)

	case "trigger_build":
		return c.trigger(ctx, call, p)

	case "stop_build":
		jp, err := jobPath(p.Job)
		if err != nil {
			return sdk.Result{}, err
		}
		ref, err := buildRef(p.Number)
		if err != nil {
			return sdk.Result{}, err
		}
		var b buildRefJSON
		if err := c.getJSON(ctx, jp+ref+"/api/json", url.Values{"tree": {lastTree}}, &b); err != nil {
			return sdk.Result{}, notFound(err, "build")
		}
		if !b.Building {
			return sdk.Result{}, fmt.Errorf("build #%d of %s isn't running (%s)", b.Number, p.Job, b.Result)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Abort build #%d of %s, running since %s", b.Number, p.Job, when(b.Timestamp)),
				Changes: []sdk.Change{{Target: fmt.Sprintf("%s #%d", p.Job, b.Number), Op: "stop", Before: mustJSON("RUNNING"), After: mustJSON("ABORTED")}}}}, nil
		}
		if _, err := c.post(ctx, jp+"/"+strconv.FormatInt(b.Number, 10)+"/stop", nil, url.Values{}); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"job": p.Job, "number": b.Number, "stopped": true})

	case "cancel_queued":
		if p.ID < 1 {
			return sdk.Result{}, errors.New("enter the queue item's id (see queue)")
		}
		var it struct {
			ID   int64 `json:"id"`
			Task struct {
				FullName string `json:"fullName"`
				Name     string `json:"name"`
			} `json:"task"`
			Cancelled  bool `json:"cancelled"`
			Executable *struct {
				Number int64 `json:"number"`
			} `json:"executable"`
		}
		if err := c.getJSON(ctx, "/queue/item/"+strconv.FormatInt(p.ID, 10)+"/api/json", nil, &it); err != nil {
			return sdk.Result{}, notFound(err, "queue item")
		}
		name := it.Task.FullName
		if name == "" {
			name = it.Task.Name
		}
		if it.Cancelled || it.Executable != nil {
			return sdk.Result{}, fmt.Errorf("queue item %d (%s) isn't waiting anymore", p.ID, name)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Remove the waiting build of %s from the queue", name),
				Changes: []sdk.Change{{Target: fmt.Sprintf("queue item %d", p.ID), Op: "cancel"}}}}, nil
		}
		if _, err := c.post(ctx, "/queue/cancelItem", url.Values{"id": {strconv.FormatInt(p.ID, 10)}}, url.Values{}); err != nil && !isStatus(err, http.StatusNotFound) {
			// Older Jenkins answers the cancel with a redirect to a page that 404s.
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"id": p.ID, "job": name, "cancelled": true})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func notFound(err error, what string) error {
	if isStatus(err, http.StatusNotFound) {
		return fmt.Errorf("there's no %s like that", what)
	}
	return err
}

func (c *conn) job(ctx context.Context, name string, detail bool) (jobJSON, error) {
	var j jobJSON
	jp, err := jobPath(name)
	if err != nil {
		return j, err
	}
	tree := "_class,name,fullName,color,buildable,inQueue,nextBuildNumber,property[parameterDefinitions[_class,name,type,choices,defaultParameterValue[value]]],lastBuild[" + lastTree + "]"
	if detail {
		tree += ",description,healthReport[description,score],lastSuccessfulBuild[" + lastTree + "],lastFailedBuild[" + lastTree + "],builds[" + lastTree + "]{0,10}"
		tree = strings.Replace(tree, "parameterDefinitions[_class,name,type,", "parameterDefinitions[_class,name,type,description,", 1)
	}
	if err := c.getJSON(ctx, jp+"/api/json", url.Values{"tree": {tree}}, &j); err != nil {
		return j, notFound(err, "job "+name)
	}
	return j, nil
}

func (c *conn) build(ctx context.Context, p input) (sdk.Result, error) {
	jp, err := jobPath(p.Job)
	if err != nil {
		return sdk.Result{}, err
	}
	ref, err := buildRef(p.Number)
	if err != nil {
		return sdk.Result{}, err
	}
	var b struct {
		buildRefJSON
		DisplayName       string `json:"displayName"`
		Description       string `json:"description"`
		EstimatedDuration int64  `json:"estimatedDuration"`
		BuiltOn           string `json:"builtOn"`
		Actions           []struct {
			Causes []struct {
				ShortDescription string `json:"shortDescription"`
			} `json:"causes"`
			Parameters []struct {
				Class string `json:"_class"`
				Name  string `json:"name"`
				Value any    `json:"value"`
			} `json:"parameters"`
		} `json:"actions"`
		Artifacts []struct {
			RelativePath string `json:"relativePath"`
		} `json:"artifacts"`
		ChangeSets []struct {
			Items []struct {
				Msg      string `json:"msg"`
				CommitID string `json:"commitId"`
				Author   struct {
					FullName string `json:"fullName"`
				} `json:"author"`
			} `json:"items"`
		} `json:"changeSets"`
	}
	tree := lastTree + ",displayName,description,estimatedDuration,builtOn,actions[causes[shortDescription],parameters[_class,name,value]],artifacts[relativePath]{0,50},changeSets[items[msg,commitId,author[fullName]]{0,20}]"
	if err := c.getJSON(ctx, jp+ref+"/api/json", url.Values{"tree": {tree}}, &b); err != nil {
		return sdk.Result{}, notFound(err, "build")
	}
	e := buildSummary(&b.buildRefJSON)
	e["job"] = p.Job
	e["name"] = b.DisplayName
	if b.Description != "" {
		e["description"] = clip(b.Description, 500)
	}
	if b.Building && b.EstimatedDuration > 0 {
		e["estimatedSeconds"] = b.EstimatedDuration / 1000
	}
	if b.BuiltOn != "" {
		e["agent"] = b.BuiltOn
	}
	causes, params := []string{}, []map[string]any{}
	for _, a := range b.Actions {
		for _, c := range a.Causes {
			causes = append(causes, c.ShortDescription)
		}
		for _, pv := range a.Parameters {
			v := pv.Value
			if strings.Contains(pv.Class, "Password") || secretName(pv.Name) {
				v = "[hidden]"
			}
			if s, ok := v.(string); ok {
				v = clip(s, 300)
			}
			params = append(params, map[string]any{"name": pv.Name, "value": v})
		}
	}
	e["causes"], e["parameters"] = causes, params
	changes := []map[string]any{}
	for _, cs := range b.ChangeSets {
		for _, it := range cs.Items {
			id := it.CommitID
			if len(id) > 12 {
				id = id[:12]
			}
			changes = append(changes, map[string]any{"commit": id, "author": it.Author.FullName, "message": clip(rest.Redact(strings.SplitN(it.Msg, "\n", 2)[0]), 200)})
		}
	}
	e["changes"] = changes
	arts := []string{}
	for _, a := range b.Artifacts {
		arts = append(arts, a.RelativePath)
	}
	e["artifacts"] = arts
	return sdk.JSON(e)
}

// console reads a build's log and keeps its last lines. Jenkins can't serve
// a log from the end, so it streams through at most maxConsoleRead bytes.
func (c *conn) console(ctx context.Context, p input) (sdk.Result, error) {
	jp, err := jobPath(p.Job)
	if err != nil {
		return sdk.Result{}, err
	}
	ref, err := buildRef(p.Number)
	if err != nil {
		return sdk.Result{}, err
	}
	n := p.Lines
	if n == 0 {
		n = 100
	}
	if n < 1 || n > 2000 {
		return sdk.Result{}, errors.New("lines is between 1 and 2000")
	}
	var b buildRefJSON
	if err := c.getJSON(ctx, jp+ref+"/api/json", url.Values{"tree": {lastTree}}, &b); err != nil {
		return sdk.Result{}, notFound(err, "build")
	}
	res, err := c.send(ctx, http.MethodGet, jp+"/"+strconv.FormatInt(b.Number, 10)+"/consoleText", nil, nil)
	if err != nil {
		return sdk.Result{}, err
	}
	defer res.Body.Close()
	lines, read, more, err := tail(io.LimitReader(res.Body, maxConsoleRead+1), n)
	if err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"job": p.Job, "number": b.Number, "lines": lines, "bytesRead": read}
	if b.Building {
		out["result"] = "RUNNING"
	} else {
		out["result"] = b.Result
	}
	if more {
		out["note"] = fmt.Sprintf("the log is longer than %d MiB; these are the last lines of its first %d MiB", maxConsoleRead>>20, maxConsoleRead>>20)
	}
	return sdk.JSON(out)
}

// tail keeps the last n lines of r, each cut at maxLineLen and with
// terminal color codes removed.
func tail(r io.Reader, n int) (lines []string, read int64, more bool, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	ring := make([]string, 0, n)
	start := 0
	var cur []byte
	push := func(s string) {
		s = ansiRe.ReplaceAllString(strings.TrimRight(s, "\r"), "")
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
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if len(chunk) > 0 && chunk[len(chunk)-1] == '\n' || (e == io.EOF && len(cur) > 0) {
			push(clip(strings.ToValidUTF8(strings.TrimSuffix(string(cur), "\n"), "�"), maxLineLen))
			cur = cur[:0]
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, read, false, e
		}
	}
	if read > maxConsoleRead {
		more, read = true, maxConsoleRead
	}
	out := make([]string, 0, len(ring))
	out = append(out, ring[start:]...)
	out = append(out, ring[:start]...)
	return out, read, more, nil
}

func (c *conn) trigger(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	jp, err := jobPath(p.Job)
	if err != nil {
		return sdk.Result{}, err
	}
	j, err := c.job(ctx, p.Job, false)
	if err != nil {
		return sdk.Result{}, err
	}
	if j.isFolder() {
		return sdk.Result{}, fmt.Errorf("%s is a folder; name a job in it", p.Job)
	}
	if j.Buildable != nil && !*j.Buildable {
		return sdk.Result{}, fmt.Errorf("%s is disabled", p.Job)
	}
	defs := map[string]paramDef{}
	for _, d := range j.params() {
		defs[d.Name] = d
	}
	form := url.Values{}
	shown := map[string]any{}
	names := make([]string, 0, len(p.Parameters))
	for k := range p.Parameters {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		d, ok := defs[k]
		if !ok || !paramRe.MatchString(k) {
			if len(defs) == 0 {
				return sdk.Result{}, fmt.Errorf("%s takes no parameters", p.Job)
			}
			return sdk.Result{}, fmt.Errorf("%s has no parameter %q", p.Job, k)
		}
		if d.secret() || d.file() {
			return sdk.Result{}, fmt.Errorf("%s is a password, credentials or file parameter; Conduit doesn't pass those (the job's default is used)", k)
		}
		var v string
		switch x := p.Parameters[k].(type) {
		case string:
			v = x
		case bool:
			v = strconv.FormatBool(x)
		case float64:
			v = strconv.FormatFloat(x, 'f', -1, 64)
		default:
			return sdk.Result{}, fmt.Errorf("parameter %s is a string, number or boolean", k)
		}
		if len(v) > 10000 {
			return sdk.Result{}, fmt.Errorf("parameter %s is too long", k)
		}
		if strings.Contains(d.Class, "Boolean") && v != "true" && v != "false" {
			return sdk.Result{}, fmt.Errorf("parameter %s is true or false", k)
		}
		if len(d.Choices) > 0 {
			found := false
			for _, ch := range d.Choices {
				found = found || ch == v
			}
			if !found {
				return sdk.Result{}, fmt.Errorf("parameter %s is one of %s", k, strings.Join(d.Choices, ", "))
			}
		}
		form.Set(k, v)
		shown[k] = v
	}
	path := jp + "/build"
	if len(defs) > 0 {
		path = jp + "/buildWithParameters"
		for name, d := range defs {
			if _, set := shown[name]; !set && d.Default != nil {
				if d.hidden() {
					shown[name] = "(default, hidden)"
				} else {
					shown[name] = d.Default.Value
				}
			}
		}
	}
	if call.DryRun {
		sum := fmt.Sprintf("Start build #%d of %s", j.NextBuild, p.Job)
		if j.InQueue {
			sum += " (a build is already queued; Jenkins may merge them)"
		}
		ch := sdk.Change{Target: "job " + p.Job, Op: "build"}
		if len(shown) > 0 {
			ch.After = mustJSON(map[string]any{"parameters": shown})
			sum += " with parameters"
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{ch}}}, nil
	}
	hdr, err := c.post(ctx, path, nil, form)
	if err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"job": p.Job, "queued": true, "expectedNumber": j.NextBuild}
	if m := queueRe.FindStringSubmatch(hdr.Get("Location")); m != nil {
		id, _ := strconv.ParseInt(m[1], 10, 64)
		out["queueId"] = id
	}
	return sdk.JSON(out)
}
