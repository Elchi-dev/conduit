// Package youtrack works with YouTrack (cloud or self-hosted) through its REST
// API and a permanent token: projects, issues found with YouTrack's query
// language, creating issues, commenting, and applying commands.
package youtrack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/mention"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one YouTrack instance.
type Config struct {
	URL                string `json:"url"`   // https://example.youtrack.cloud or a self-hosted address
	Token              string `json:"token"` // secret:// permanent token (perm:…)
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api  *rest.Client
	site string // for issue links
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the YouTrack module.
func New() *Module { return &Module{} }

const (
	maxSummary = 255
	maxText    = 50000
	maxQuery   = 2000
	maxCommand = 500
)

var (
	pathRe    = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	issueRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,49}-\d{1,9}$|^\d{1,9}-\d{1,12}$`) // PRJ-12, or a database id like 2-15
	projectRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,49}$`)
	commentRe = regexp.MustCompile(`^\d{1,9}-\d{1,12}$`)
)

const issueFields = "id,idReadable,summary,resolved,created,updated,project(shortName,name),customFields(name,value(name,fullName,presentation,text))"

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	issue := `"issue":{"type":"string","description":"Issue id, e.g. PRJ-12"}`
	return sdk.Manifest{
		ID: "youtrack", Name: "YouTrack", Version: "0.1.0", Category: "Development", Icon: "list",
		Description: "YouTrack (cloud or self-hosted): projects and issues by query; create issues, comment and apply commands.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Your YouTrack address, e.g. https://example.youtrack.cloud or https://youtrack.example.com"},
			"token":{"type":"string","x-secret":true,"description":"A permanent token, perm:… (Profile, Account security, Tokens) with YouTrack in its scope. It acts as you"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Projects you can see, with their short names.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"archived":{"type":"boolean","default":false,"description":"Include archived projects"}}}`)},
			{Name: "issues", Title: "Find issues", Description: "Issues matching a YouTrack query, e.g. 'for: me #Unresolved' or 'project: PRJ State: Open sort by: updated'.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","default":25,"maximum":100},"skip":{"type":"integer","default":0}}}`)},
			{Name: "issue", Title: "Issue details", Description: "Summary, description, fields (state, priority, assignee …) and recent comments.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["issue"],"properties":{` + issue + `}}`)},
			{Name: "create_issue", Title: "Create an issue", Description: "Creates an issue in a project. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","summary"],"properties":{"project":{"type":"string","description":"Project short name, e.g. PRJ"},"summary":{"type":"string","maxLength":255},"description":{"type":"string","x-multiline":true,"description":"Markdown"}}}`)},
			{Name: "comment", Title: "Comment on an issue", Description: "Adds a comment; people it @mentions are notified (the preview names them). Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["issue","text"],"properties":{` + issue + `,"text":{"type":"string","x-multiline":true,"description":"Markdown"}}}`)},
			{Name: "apply_command", Title: "Apply a command", Description: "Runs a YouTrack command on an issue, e.g. 'State In Progress', 'for me', 'Priority Critical', 'tag Backend'. A command can change anything, including deleting the issue; the preview shows what YouTrack will do.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["issue","command"],"properties":{` + issue + `,"command":{"type":"string"},"comment":{"type":"string","description":"A comment to add with the command"},"silent":{"type":"boolean","default":false,"description":"Don't send notifications for this change"}}}`)},
			{Name: "delete_comment", Title: "Delete a comment", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["issue","comment"],"properties":{` + issue + `,"comment":{"type":"string","description":"Comment id, e.g. 4-17"}}}`)},
			{Name: "delete_issue", Title: "Delete an issue", Description: "Deletes the issue for good, with its comments and history.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["issue"],"properties":{` + issue + `}}`)},
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
		return errors.New("the address is like https://example.youtrack.cloud")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the permanent token in the vault and enter its secret:// reference")
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
	site := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(site+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, site: site})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("YouTrack refused the token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("your YouTrack account isn't allowed to do this")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

type field struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

type issue struct {
	ID          string  `json:"id"`
	IDReadable  string  `json:"idReadable"`
	Summary     string  `json:"summary"`
	Description string  `json:"description"`
	Resolved    *int64  `json:"resolved"`
	Created     int64   `json:"created"`
	Updated     int64   `json:"updated"`
	Project     project `json:"project"`
	Fields      []field `json:"customFields"`
	Reporter    *struct {
		FullName string `json:"fullName"`
	} `json:"reporter"`
}

type project struct {
	ID          string `json:"id"`
	ShortName   string `json:"shortName"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Archived    bool   `json:"archived"`
}

// text renders a custom field's value: an enum, state or user by name, a
// list of them joined, a number or a text as it is.
func text(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var one struct {
		Name         string `json:"name"`
		FullName     string `json:"fullName"`
		Presentation string `json:"presentation"`
		Text         string `json:"text"`
	}
	if json.Unmarshal(raw, &one) == nil {
		for _, s := range []string{one.FullName, one.Name, one.Presentation, one.Text} {
			if s != "" {
				return s
			}
		}
		return ""
	}
	var many []json.RawMessage
	if json.Unmarshal(raw, &many) == nil {
		var out []string
		for _, v := range many {
			if s := text(v); s != "" {
				out = append(out, s)
			}
		}
		return strings.Join(out, ", ")
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.Trim(string(raw), `"`)
}

func when(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

func (c *conn) summary(i issue) map[string]any {
	fs := map[string]string{}
	for _, f := range i.Fields {
		if s := text(f.Value); s != "" {
			fs[f.Name] = s
		}
	}
	out := map[string]any{"id": i.IDReadable, "summary": i.Summary, "project": i.Project.ShortName, "resolved": i.Resolved != nil && *i.Resolved > 0,
		"fields": fs, "updated": when(i.Updated), "url": c.site + "/issue/" + url.PathEscape(i.IDReadable)}
	return out
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		FullName string `json:"fullName"`
		Login    string `json:"login"`
	}
	if err := c.do(ctx, http.MethodGet, "/users/me", url.Values{"fields": {"fullName,login"}}, nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no YouTrack API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	name := me.FullName
	if name == "" {
		name = me.Login
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + name}
}

type input struct {
	Archived    bool   `json:"archived"`
	Query       string `json:"query"`
	Limit       int    `json:"limit"`
	Skip        int    `json:"skip"`
	Issue       string `json:"issue"`
	Project     string `json:"project"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Text        string `json:"text"`
	Command     string `json:"command"`
	Comment     string `json:"comment"`
	Silent      bool   `json:"silent"`
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
	p.Issue, p.Project = strings.ToUpper(strings.TrimSpace(p.Issue)), strings.TrimSpace(p.Project)
	switch call.Action {
	case "issue", "comment", "apply_command", "delete_comment", "delete_issue":
		if !issueRe.MatchString(p.Issue) {
			return sdk.Result{}, errors.New("the issue is its id, like PRJ-12")
		}
	}
	switch call.Action {
	case "projects":
		var ps []project
		if err := c.do(ctx, http.MethodGet, "/admin/projects", url.Values{"fields": {"id,shortName,name,description,archived"}, "$top": {"500"}}, nil, &ps); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range ps {
			if x.Archived && !p.Archived {
				continue
			}
			r := map[string]any{"shortName": x.ShortName, "name": x.Name}
			if x.Description != "" {
				r["description"] = x.Description
			}
			if x.Archived {
				r["archived"] = true
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "issues":
		q := strings.TrimSpace(p.Query)
		if len(q) > maxQuery {
			return sdk.Result{}, errors.New("the query is too long")
		}
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 25
		}
		if p.Skip < 0 {
			return sdk.Result{}, errors.New("skip is 0 or more")
		}
		v := url.Values{"fields": {issueFields}, "$top": {strconv.Itoa(limit)}, "$skip": {strconv.Itoa(p.Skip)}}
		if q != "" {
			v.Set("query", q)
		}
		var is []issue
		if err := c.do(ctx, http.MethodGet, "/issues", v, nil, &is); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, i := range is {
			out = append(out, c.summary(i))
		}
		res := map[string]any{"count": len(out), "issues": out}
		if len(is) == limit {
			res["nextSkip"] = p.Skip + limit
		}
		return sdk.JSON(res)

	case "issue":
		i, err := c.issue(ctx, p.Issue, ",description,reporter(fullName)")
		if err != nil {
			return sdk.Result{}, err
		}
		out := c.summary(i)
		out["description"] = i.Description
		out["created"] = when(i.Created)
		if i.Reporter != nil {
			out["reporter"] = i.Reporter.FullName
		}
		var cs []struct {
			ID      string `json:"id"`
			Text    string `json:"text"`
			Created int64  `json:"created"`
			Author  *struct {
				FullName string `json:"fullName"`
			} `json:"author"`
		}
		comments := []map[string]any{}
		if c.do(ctx, http.MethodGet, "/issues/"+url.PathEscape(i.IDReadable)+"/comments", url.Values{"fields": {"id,text,created,author(fullName)"}, "$top": {"200"}}, nil, &cs) == nil {
			for _, x := range cs {
				r := map[string]any{"id": x.ID, "at": when(x.Created), "text": x.Text}
				if x.Author != nil {
					r["by"] = x.Author.FullName
				}
				comments = append(comments, r)
			}
		}
		if len(comments) > 20 {
			comments = comments[len(comments)-20:]
		}
		out["comments"] = comments
		return sdk.JSON(out)

	case "create_issue":
		return c.create(ctx, call, p)
	case "comment":
		return c.comment(ctx, call, p)
	case "apply_command":
		return c.command(ctx, call, p)

	case "delete_comment":
		if !commentRe.MatchString(strings.TrimSpace(p.Comment)) {
			return sdk.Result{}, errors.New("the comment is its id, like 4-17")
		}
		if err := c.do(ctx, http.MethodDelete, "/issues/"+url.PathEscape(p.Issue)+"/comments/"+url.PathEscape(strings.TrimSpace(p.Comment)), nil, nil, nil); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no comment %s on %s", p.Comment, p.Issue)
			}
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": strings.TrimSpace(p.Comment)})

	case "delete_issue":
		i, err := c.issue(ctx, p.Issue, "")
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete %s %q", i.IDReadable, i.Summary),
				Changes: []sdk.Change{{Target: fmt.Sprintf("issue %s %q", i.IDReadable, i.Summary), Op: "delete", Before: mustJSON(c.summary(i))}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/issues/"+url.PathEscape(i.IDReadable), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": i.IDReadable, "summary": i.Summary})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) issue(ctx context.Context, id, extra string) (issue, error) {
	var i issue
	if err := c.do(ctx, http.MethodGet, "/issues/"+url.PathEscape(id), url.Values{"fields": {issueFields + extra}}, nil, &i); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return i, fmt.Errorf("there's no issue %s", id)
		}
		return i, err
	}
	if !strings.EqualFold(i.IDReadable, id) && i.ID != id {
		// The id goes into the change's path and its undo.
		return i, fmt.Errorf("YouTrack answered with another issue for %s", id)
	}
	if !issueRe.MatchString(i.IDReadable) {
		return i, errors.New("unexpected answer from YouTrack")
	}
	return i, nil
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if !projectRe.MatchString(p.Project) {
		return sdk.Result{}, errors.New("the project is its short name, like PRJ")
	}
	sum := strings.TrimSpace(p.Summary)
	if sum == "" || len(sum) > maxSummary {
		return sdk.Result{}, fmt.Errorf("a summary is 1 to %d characters", maxSummary)
	}
	if len(p.Description) > maxText {
		return sdk.Result{}, errors.New("the description is too long")
	}
	// People @mentioned in a description are notified, as in a comment.
	found := mention.Find(p.Description)
	if found.Wildcard != "" {
		return sdk.Result{}, fmt.Errorf("%s would reach everyone; wildcard mentions aren't sent from Conduit", found.Wildcard)
	}
	var ps []project
	if err := c.do(ctx, http.MethodGet, "/admin/projects", url.Values{"fields": {"id,shortName,name,archived"}, "$top": {"500"}}, nil, &ps); err != nil {
		return sdk.Result{}, err
	}
	var pr *project
	for k := range ps {
		if strings.EqualFold(ps[k].ShortName, p.Project) {
			pr = &ps[k]
		}
	}
	if pr == nil {
		return sdk.Result{}, fmt.Errorf("there's no project %s (see projects)", strings.ToUpper(p.Project))
	}
	if pr.Archived {
		return sdk.Result{}, fmt.Errorf("project %s is archived", pr.ShortName)
	}
	body := map[string]any{"project": map[string]string{"id": pr.ID}, "summary": sum}
	if d := strings.TrimSpace(p.Description); d != "" {
		body["description"] = d
	}
	if call.DryRun {
		s := fmt.Sprintf("Create issue %q in %s", sum, pr.ShortName)
		if pv := found.Preview(); pv != "" {
			s += "; its description " + pv
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: s,
			Changes: []sdk.Change{{Target: "issue in " + pr.ShortName, Op: "create", After: mustJSON(map[string]string{"summary": sum, "description": strings.TrimSpace(p.Description)})}}}}, nil
	}
	var i issue
	if err := c.do(ctx, http.MethodPost, "/issues", url.Values{"fields": {"id,idReadable,summary"}}, body, &i); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]string{"id": i.IDReadable, "summary": i.Summary, "url": c.site + "/issue/" + url.PathEscape(i.IDReadable)})
	if issueRe.MatchString(i.IDReadable) {
		res.Undo = sdk.UndoWith("delete_issue", map[string]string{"issue": i.IDReadable}, "Delete "+i.IDReadable)
	}
	return res, err
}

func (c *conn) comment(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	t := strings.TrimSpace(p.Text)
	if t == "" || len(t) > maxText {
		return sdk.Result{}, fmt.Errorf("a comment is 1 to %d characters", maxText)
	}
	found := mention.Find(t)
	if found.Wildcard != "" {
		return sdk.Result{}, fmt.Errorf("%s would reach everyone; wildcard mentions aren't sent from Conduit", found.Wildcard)
	}
	i, err := c.issue(ctx, p.Issue, "")
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		s := "Comment on " + i.IDReadable
		if pv := found.Preview(); pv != "" {
			s += "; it " + pv
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: s,
			Changes: []sdk.Change{{Target: fmt.Sprintf("issue %s %q", i.IDReadable, i.Summary), Op: "create", After: mustJSON(map[string]string{"text": t})}}}}, nil
	}
	var r struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/issues/"+url.PathEscape(i.IDReadable)+"/comments", url.Values{"fields": {"id"}}, map[string]any{"text": t}, &r); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]string{"issue": i.IDReadable, "comment": r.ID})
	if commentRe.MatchString(r.ID) {
		res.Undo = sdk.UndoWith("delete_comment", map[string]string{"issue": i.IDReadable, "comment": r.ID}, "Delete the comment")
	}
	return res, err
}

func (c *conn) command(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	cmd := strings.TrimSpace(p.Command)
	if cmd == "" || len(cmd) > maxCommand || strings.ContainsAny(cmd, "\r\n") {
		return sdk.Result{}, fmt.Errorf("a command is one line of up to %d characters", maxCommand)
	}
	note := strings.TrimSpace(p.Comment)
	if len(note) > maxText {
		return sdk.Result{}, errors.New("the comment is too long")
	}
	found := mention.Find(note)
	if found.Wildcard != "" {
		return sdk.Result{}, fmt.Errorf("%s would reach everyone; wildcard mentions aren't sent from Conduit", found.Wildcard)
	}
	i, err := c.issue(ctx, p.Issue, "")
	if err != nil {
		return sdk.Result{}, err
	}
	issues := []map[string]string{{"idReadable": i.IDReadable}}
	// YouTrack parses the command first; anything it can't read stops here.
	var assist struct {
		Commands []struct {
			Description string `json:"description"`
			Error       bool   `json:"error"`
		} `json:"commands"`
	}
	if err := c.do(ctx, http.MethodPost, "/commands/assist", url.Values{"fields": {"commands(description,error)"}},
		map[string]any{"query": cmd, "caret": len(cmd), "issues": issues}, &assist); err != nil {
		return sdk.Result{}, err
	}
	var steps []string
	for _, x := range assist.Commands {
		if x.Error {
			return sdk.Result{}, fmt.Errorf("YouTrack can't apply %q to %s: %s", cmd, i.IDReadable, x.Description)
		}
		steps = append(steps, x.Description)
	}
	if len(steps) == 0 {
		return sdk.Result{}, fmt.Errorf("YouTrack doesn't read %q as a command", cmd)
	}
	if call.DryRun {
		after := map[string]any{"command": cmd, "does": steps, "silent": p.Silent}
		if note != "" {
			after["comment"] = note
		}
		sum := fmt.Sprintf("Apply %q to %s: %s", cmd, i.IDReadable, strings.Join(steps, "; "))
		if pv := found.Preview(); pv != "" {
			sum += "; the comment " + pv
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: sum,
			Changes: []sdk.Change{{Target: fmt.Sprintf("issue %s %q", i.IDReadable, i.Summary), Op: "command", After: mustJSON(after)}}}}, nil
	}
	body := map[string]any{"query": cmd, "issues": issues, "silent": p.Silent}
	if note != "" {
		body["comment"] = note
	}
	if err := c.do(ctx, http.MethodPost, "/commands", nil, body, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"issue": i.IDReadable, "command": cmd, "did": steps})
}
