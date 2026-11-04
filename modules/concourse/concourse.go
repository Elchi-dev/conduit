// Package concourse works with a Concourse CI server through its API, signed
// in the way fly is (a local user's password traded for a bearer token):
// teams, pipelines, jobs and builds, starting a job's build, and pausing or
// unpausing pipelines.
package concourse

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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Concourse server and team.
type Config struct {
	URL                string `json:"url"`      // e.g. https://ci.example.com
	Team               string `json:"team"`     // default team, "main" when empty
	Username           string `json:"username"` // a local user
	Password           string `json:"password"` // secret:// its password
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api   *rest.Client // the API, with the bearer token
	login *rest.Client // the token endpoint, without it
	host  sdk.Host
	user  string
	pass  string
	team  string

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Concourse module.
func New() *Module { return &Module{} }

// fly's public OAuth client, which Concourse's token endpoint accepts for
// password logins (fly:Zmx5).
const flyClient = "Basic Zmx5OlpteDU="

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// Concourse identifiers: letters (any script), digits, _ - and .
	nameRe = regexp.MustCompile(`^[\p{L}\p{N}_][\p{L}\p{N}_.-]{0,127}$`)
	userRe = regexp.MustCompile(`^[^\s:]{1,255}$`)
)

func validName(s, what string) (string, error) {
	v := strings.TrimSpace(s)
	if !nameRe.MatchString(v) || strings.Contains(v, "..") {
		return "", fmt.Errorf("the %s is its name, like build-and-test", what)
	}
	return v, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	team := `"team":{"type":"string","description":"Team name (the configured team when left out)"}`
	pipe := `"pipeline":{"type":"string","description":"Pipeline name (see pipelines)"}`
	job := `"job":{"type":"string","description":"Job name (see jobs)"}`
	onePipe := `{"type":"object","required":["pipeline"],"properties":{` + team + `,` + pipe + `}}`
	return sdk.Manifest{
		ID: "concourse", Name: "Concourse", Version: "0.1.0", Category: "Development", Icon: "pipeline",
		Description: "Concourse CI: teams, pipelines, jobs and builds, starting a job's build, and pausing or unpausing pipelines.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","username","password"],"properties":{
			"url":{"type":"string","description":"The Concourse address, e.g. https://ci.example.com"},
			"team":{"type":"string","default":"main","description":"The team actions use unless they name another"},
			"username":{"type":"string","description":"A local user (CONCOURSE_ADD_LOCAL_USER), signed in the way fly login is; its team roles decide what works"},
			"password":{"type":"string","x-secret":true,"description":"That user's password"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "teams", Title: "Teams", Description: "The teams on the server (their auth settings are left out).", Risk: sdk.RiskRead},
			{Name: "pipelines", Title: "Pipelines", Description: "A team's pipelines with whether they're paused (by whom, since when), archived or public.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + team + `}}`)},
			{Name: "jobs", Title: "Jobs", Description: "A pipeline's jobs with their groups, whether they're paused, and their last finished and next build.", Risk: sdk.RiskRead, Input: sdk.Schema(onePipe)},
			{Name: "builds", Title: "Builds", Description: "Recent builds, newest first, of a pipeline or one of its jobs: id, number, job, status, start, end and who started it.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["pipeline"],"properties":{` + team + `,` + pipe + `,` + job + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "trigger_job", Title: "Start a build", Description: "Starts a new build of a job. A build runs the job's tasks with the pipeline's credentials and can deploy, so this is destructive.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["pipeline","job"],"properties":{` + team + `,` + pipe + `,` + job + `}}`)},
			{Name: "pause_pipeline", Title: "Pause a pipeline", Description: "Pauses a pipeline: no new builds are scheduled and its resources stop being checked (running builds go on). Undo unpauses it.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(onePipe)},
			{Name: "unpause_pipeline", Title: "Unpause a pipeline", Description: "Unpauses a pipeline. Destructive: jobs can start at once on versions that arrived while it was paused. Undo pauses it again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(onePipe)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "pipeline", Title: "Pipelines", ListAction: "pipelines", ViewHint: "table"}},
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
	team := strings.TrimSpace(c.Team)
	if team == "" {
		team = "main"
	}
	if team, err = validName(team, "team"); err != nil {
		return err
	}
	user := strings.TrimSpace(c.Username)
	if !userRe.MatchString(user) {
		return errors.New("enter the local user's name")
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
	client = rest.SameHostOnly(client)
	root := u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
	cn := &conn{host: h, user: user, pass: c.Password, team: team}
	cn.login = rest.New(root, nil)
	cn.login.HTTP = client
	cn.api = rest.New(root+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := cn.bearer(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", t)
		return nil
	})
	cn.api.HTTP = client
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// bearer returns the cached token, signing in again when it's missing or
// about to expire.
func (c *conn) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	pw, err := c.host.Secret(ctx, c.pass)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"password"}, "username": {c.user}, "password": {strings.TrimRight(pw, "\r\n")}, "scope": {"openid profile email federated:id groups"}}
	res, err := c.login.Send(ctx, http.MethodPost, "/sky/issuer/token", nil, strings.NewReader(form.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}, "Authorization": {flyClient}})
	if err != nil {
		// The token endpoint's errors are not passed on: only what failed.
		switch {
		case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusBadRequest), rest.IsStatus(err, http.StatusForbidden):
			return "", errors.New("Concourse refused the username or password (is it a local user?)")
		case rest.IsStatus(err, http.StatusNotFound):
			return "", errors.New("no Concourse at this address")
		}
		var re *rest.Error
		if errors.As(err, &re) {
			return "", fmt.Errorf("Concourse's sign-in answered %d", re.Status)
		}
		return "", err
	}
	defer res.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if res.StatusCode >= 300 || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&tok) != nil || tok.AccessToken == "" || strings.ContainsAny(tok.AccessToken, " \r\n") {
		return "", errors.New("unexpected answer from Concourse's sign-in (is this the Concourse address?)")
	}
	if tok.TokenType != "" && !strings.EqualFold(tok.TokenType, "bearer") {
		return "", errors.New("Concourse's sign-in gave a token of an unknown type")
	}
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	if ttl <= 0 || ttl > 24*time.Hour {
		ttl = time.Hour
	}
	c.token, c.expires = "Bearer "+tok.AccessToken, time.Now().Add(ttl-time.Minute/2)
	return c.token, nil
}

func (c *conn) forget() {
	c.mu.Lock()
	c.token = ""
	c.mu.Unlock()
}

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Concourse refused the sign-in token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Concourse refused: the user's role in this team doesn't allow it")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s (or the user can't see it)", what)
	}
	return err
}

// do sends one API request; a token Concourse no longer accepts (it was
// revoked or the server restarted) is replaced once.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, out any, what string) error {
	_, err := c.api.Do(ctx, method, path, q, nil, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.forget()
		_, err = c.api.Do(ctx, method, path, q, nil, out)
	}
	return friendly(err, what)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var info struct {
		Version string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "/info", nil, &info, "Concourse at this address"); err != nil || info.Version == "" {
		if err == nil {
			err = errors.New("no Concourse at this address")
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var me struct {
		UserName string              `json:"user_name"`
		IsAdmin  bool                `json:"is_admin"`
		Teams    map[string][]string `json:"teams"`
	}
	if err := c.do(ctx, http.MethodGet, "/user", nil, &me, "user"); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + me.UserName + " · Concourse " + info.Version
	roles, ok := me.Teams[c.team]
	if !ok && !me.IsAdmin {
		return sdk.Health{Status: "degraded", Message: msg + " · not a member of team " + c.team}
	}
	if len(roles) > 0 {
		msg += " · " + c.team + ": " + strings.Join(roles, ", ")
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func unix(s int64) string {
	if s <= 0 {
		return ""
	}
	return time.Unix(s, 0).UTC().Format(time.RFC3339)
}

type pipeline struct {
	ID           int64          `json:"id"`
	Name         string         `json:"name"`
	InstanceVars map[string]any `json:"instance_vars"`
	Paused       bool           `json:"paused"`
	PausedBy     string         `json:"paused_by"`
	PausedAt     int64          `json:"paused_at"`
	Public       bool           `json:"public"`
	Archived     bool           `json:"archived"`
	LastUpdated  int64          `json:"last_updated"`
}

type build struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"` // the build number
	Status    string `json:"status"`
	JobName   string `json:"job_name"`
	Pipeline  string `json:"pipeline_name"`
	StartTime int64  `json:"start_time"`
	EndTime   int64  `json:"end_time"`
	CreatedBy string `json:"created_by"`
}

func buildOut(b *build) map[string]any {
	if b == nil {
		return nil
	}
	row := map[string]any{"id": b.ID, "number": b.Name, "status": b.Status}
	if b.JobName != "" {
		row["job"] = b.JobName
	}
	if s := unix(b.StartTime); s != "" {
		row["started"] = s
	}
	if s := unix(b.EndTime); s != "" {
		row["ended"] = s
		if b.StartTime > 0 && b.EndTime >= b.StartTime {
			row["duration"] = (time.Duration(b.EndTime-b.StartTime) * time.Second).String()
		}
	}
	if b.CreatedBy != "" {
		row["createdBy"] = b.CreatedBy
	}
	return row
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Team     string `json:"team"`
		Pipeline string `json:"pipeline"`
		Job      string `json:"job"`
		Limit    int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "teams":
		var ts []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		}
		if err := c.do(ctx, http.MethodGet, "/teams", nil, &ts, "teams"); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range ts {
			out = append(out, map[string]any{"id": t.ID, "name": t.Name, "configured": t.Name == c.team})
		}
		return sdk.JSON(out)
	case "pipelines", "jobs", "builds", "trigger_job", "pause_pipeline", "unpause_pipeline":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	team := c.team
	if strings.TrimSpace(p.Team) != "" {
		if team, err = validName(p.Team, "team"); err != nil {
			return sdk.Result{}, err
		}
	}
	tp := "/teams/" + url.PathEscape(team)
	if call.Action == "pipelines" {
		var ps []pipeline
		if err := c.do(ctx, http.MethodGet, tp+"/pipelines", nil, &ps, "team "+team); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ps {
			row := map[string]any{"name": x.Name, "paused": x.Paused, "public": x.Public, "lastUpdated": unix(x.LastUpdated)}
			if x.Paused {
				row["pausedBy"], row["pausedAt"] = x.PausedBy, unix(x.PausedAt)
			}
			if x.Archived {
				row["archived"] = true
			}
			if len(x.InstanceVars) > 0 {
				row["instanceVars"] = x.InstanceVars
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	}
	pname, err := validName(p.Pipeline, "pipeline")
	if err != nil {
		return sdk.Result{}, err
	}
	pp := tp + "/pipelines/" + url.PathEscape(pname)
	var jname string
	if call.Action == "trigger_job" || (call.Action == "builds" && strings.TrimSpace(p.Job) != "") {
		if jname, err = validName(p.Job, "job"); err != nil {
			return sdk.Result{}, err
		}
	}
	switch call.Action {
	case "jobs":
		var js []struct {
			Name          string   `json:"name"`
			Paused        bool     `json:"paused"`
			HasNewInputs  bool     `json:"has_new_inputs"`
			Groups        []string `json:"groups"`
			FinishedBuild *build   `json:"finished_build"`
			NextBuild     *build   `json:"next_build"`
		}
		if err := c.do(ctx, http.MethodGet, pp+"/jobs", nil, &js, "pipeline "+pname+" in team "+team); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, j := range js {
			row := map[string]any{"name": j.Name, "paused": j.Paused, "groups": j.Groups}
			if j.Groups == nil {
				row["groups"] = []string{}
			}
			if j.HasNewInputs {
				row["hasNewInputs"] = true
			}
			if b := buildOut(j.FinishedBuild); b != nil {
				row["lastBuild"] = b
			}
			if b := buildOut(j.NextBuild); b != nil {
				row["nextBuild"] = b
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "builds":
		n := p.Limit
		if n == 0 {
			n = 20
		}
		if n < 1 || n > 100 {
			return sdk.Result{}, errors.New("limit is between 1 and 100")
		}
		path, what := pp+"/builds", "pipeline "+pname+" in team "+team
		if jname != "" {
			path, what = pp+"/jobs/"+url.PathEscape(jname)+"/builds", "job "+pname+"/"+jname+" in team "+team
		}
		var bs []build
		if err := c.do(ctx, http.MethodGet, path, url.Values{"limit": {strconv.Itoa(n)}}, &bs, what); err != nil {
			return sdk.Result{}, err
		}
		sort.SliceStable(bs, func(i, j int) bool { return bs[i].ID > bs[j].ID })
		if len(bs) > n {
			bs = bs[:n]
		}
		out := []map[string]any{}
		for i := range bs {
			out = append(out, buildOut(&bs[i]))
		}
		return sdk.JSON(out)
	}

	var pl pipeline
	if err := c.do(ctx, http.MethodGet, pp, nil, &pl, "pipeline "+pname+" in team "+team); err != nil {
		return sdk.Result{}, err
	}
	if pl.Name != pname {
		return sdk.Result{}, fmt.Errorf("unexpected answer looking up pipeline %s", pname)
	}
	if len(pl.InstanceVars) > 0 {
		return sdk.Result{}, fmt.Errorf("%s is an instanced pipeline; Conduit acts only on pipelines without instance vars", pname)
	}
	target := team + "/" + pname

	if call.Action == "trigger_job" {
		if pl.Archived {
			return sdk.Result{}, fmt.Errorf("%s is archived", target)
		}
		if pl.Paused {
			return sdk.Result{}, fmt.Errorf("%s is paused, so a new build would wait; unpause it first", target)
		}
		var j struct {
			Name                 string `json:"name"`
			Paused               bool   `json:"paused"`
			DisableManualTrigger bool   `json:"disable_manual_trigger"`
			FinishedBuild        *build `json:"finished_build"`
		}
		if err := c.do(ctx, http.MethodGet, pp+"/jobs/"+url.PathEscape(jname), nil, &j, "job "+target+"/"+jname); err != nil {
			return sdk.Result{}, err
		}
		if j.Name != jname {
			return sdk.Result{}, fmt.Errorf("unexpected answer looking up job %s", jname)
		}
		if j.DisableManualTrigger {
			return sdk.Result{}, fmt.Errorf("%s/%s can't be started by hand (disable_manual_trigger)", target, jname)
		}
		if j.Paused {
			return sdk.Result{}, fmt.Errorf("%s/%s is paused; its new build would wait", target, jname)
		}
		if call.DryRun {
			sum := "Start a new build of " + target + "/" + jname
			if j.FinishedBuild != nil {
				sum += fmt.Sprintf(" (last: #%s, %s)", j.FinishedBuild.Name, j.FinishedBuild.Status)
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "job " + target + "/" + jname, Op: "build"}}}}, nil
		}
		var b build
		if err := c.do(ctx, http.MethodPost, pp+"/jobs/"+url.PathEscape(jname)+"/builds", nil, &b, "job "+target+"/"+jname); err != nil {
			return sdk.Result{}, err
		}
		out := buildOut(&b)
		out["pipeline"], out["team"] = pname, team
		return sdk.JSON(out)
	}

	// pause_pipeline, unpause_pipeline
	pause := call.Action == "pause_pipeline"
	if pl.Paused == pause {
		return sdk.JSON(map[string]any{"pipeline": pname, "team": team, "paused": pause, "note": "nothing to change"})
	}
	if pl.Archived && !pause {
		return sdk.Result{}, fmt.Errorf("%s is archived; set it again with fly to bring it back", target)
	}
	if call.DryRun {
		before, _ := json.Marshal(map[string]bool{"paused": pl.Paused})
		after, _ := json.Marshal(map[string]bool{"paused": pause})
		sum := "Pause " + target + "; no new builds are scheduled"
		if !pause {
			sum = "Unpause " + target + "; jobs can start at once on new versions"
			if pl.PausedBy != "" {
				sum += " (paused by " + pl.PausedBy + ")"
			}
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "pipeline " + target, Op: strings.TrimSuffix(call.Action, "_pipeline"), Before: before, After: after}}}}, nil
	}
	verb, back, undo := "unpause", "pause_pipeline", "Pause "+target+" again"
	if pause {
		verb, back, undo = "pause", "unpause_pipeline", "Unpause "+target+" again"
	}
	if err := c.do(ctx, http.MethodPut, pp+"/"+verb, nil, nil, "pipeline "+target); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"pipeline": pname, "team": team, "paused": pause})
	res.Undo = sdk.UndoWith(back, map[string]string{"team": team, "pipeline": pname}, undo)
	return res, err
}
