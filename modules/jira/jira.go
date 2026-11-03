// Package jira searches, creates and moves Jira issues. It speaks the Jira
// Cloud REST API v3 with an email and API token, or the v2 API of Jira Data
// Center / Server with a personal access token.
package jira

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Jira site's settings.
type Config struct {
	Site  string `json:"site"`  // https://example.atlassian.net or a Data Center URL
	Email string `json:"email"` // Cloud: the account's email
	Token string `json:"token"` // Cloud: secret:// API token
	PAT   string `json:"pat"`   // Data Center / Server: secret:// personal access token
}

type conn struct {
	cfg Config
	api *rest.Client
	v   string // "3" (Cloud) or "2" (Data Center)
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Jira module.
func New() *Module { return &Module{} }

var (
	keyRe     = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,19}-\d{1,9}$`)
	projectRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,19}$`)
	idRe      = regexp.MustCompile(`^\d{1,12}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	key := `"key":{"type":"string","description":"Issue key, e.g. OPS-42"}`
	return sdk.Manifest{
		ID: "jira", Name: "Jira", Version: "0.1.0", Category: "Development", Icon: "list",
		Description: "Search, create, comment on and move Jira issues.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["site"],"properties":{
			"site":{"type":"string","format":"uri","description":"Your Jira address, e.g. https://example.atlassian.net"},
			"email":{"type":"string","description":"Jira Cloud: the email of the account the token belongs to"},
			"token":{"type":"string","x-secret":true,"description":"Jira Cloud: an API token (id.atlassian.com, Security, API tokens)"},
			"pat":{"type":"string","x-secret":true,"description":"Jira Data Center or Server: a personal access token, instead of email and token"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "search", Title: "Search issues", Description: "With JQL, e.g. assignee = currentUser() AND resolution = Unresolved.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["jql"],"properties":{"jql":{"type":"string"},"limit":{"type":"integer","default":25,"maximum":100}}}`)},
			{Name: "issue", Title: "Open an issue", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","required":["key"],"properties":{` + key + `}}`)},
			{Name: "create", Title: "Create an issue", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["project","summary"],"properties":{"project":{"type":"string","description":"Project key, e.g. OPS"},"type":{"type":"string","default":"Task"},"summary":{"type":"string","maxLength":255},"description":{"type":"string","format":"textarea"}}}`)},
			{Name: "delete_issue", Title: "Delete an issue", Risk: sdk.RiskDestructive, Input: sdk.Schema(`{"type":"object","required":["key"],"properties":{` + key + `}}`)},
			{Name: "comment", Title: "Comment", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["key","text"],"properties":{` + key + `,"text":{"type":"string","format":"textarea"}}}`)},
			{Name: "delete_comment", Title: "Delete a comment", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["key","id"],"properties":{` + key + `,"id":{"type":"string"}}}`)},
			{Name: "transitions", Title: "Possible moves", Description: "Where the issue can go from its current status.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["key"],"properties":{` + key + `}}`)},
			{Name: "transition", Title: "Move an issue", Description: "To a status by name, or by transition id.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["key"],"properties":{` + key + `,"to":{"type":"string","description":"Target status, e.g. In Progress"},"id":{"type":"string","description":"Transition id from Possible moves"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.Site = strings.TrimRight(strings.TrimSpace(c.Site), "/")
	if err := rest.ValidBase(c.Site); err != nil {
		return errors.New("the site is your Jira address, e.g. https://example.atlassian.net")
	}
	cn := &conn{cfg: c, v: "3"}
	var auth func(context.Context, *http.Request) error
	switch {
	case c.PAT != "":
		cn.v = "2"
		pat := c.PAT
		auth = func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, pat)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Bearer "+t)
			return nil
		}
	case c.Email != "" && c.Token != "":
		email, tok := c.Email, c.Token
		auth = func(ctx context.Context, r *http.Request) error {
			t, err := h.Secret(ctx, tok)
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(email+":"+t)))
			return nil
		}
	default:
		return errors.New("add an email and API token (Jira Cloud) or a personal access token (Data Center), stored in the vault")
	}
	cn.api = rest.New(c.Site+"/rest/api/"+cn.v, auth)
	if m.HTTP != nil {
		cn.api.HTTP = m.HTTP
	}
	m.set.Put(id, cn)
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
	var me struct {
		DisplayName string `json:"displayName"`
	}
	if _, err := c.api.Do(ctx, "GET", "/myself", nil, nil, &me); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "Signed in as " + me.DisplayName}
}

// doc wraps text in the Atlassian document format v3 expects; v2 takes a
// plain string.
func (c *conn) doc(text string) any {
	if c.v == "2" {
		return text
	}
	var paras []any
	for _, p := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n\n") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		paras = append(paras, map[string]any{"type": "paragraph", "content": []any{map[string]any{"type": "text", "text": p}}})
	}
	if paras == nil {
		paras = []any{}
	}
	return map[string]any{"type": "doc", "version": 1, "content": paras}
}

// plain turns a v3 document (or a v2 string) back into text.
func plain(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n struct {
		Type    string            `json:"type"`
		Text    string            `json:"text"`
		Content []json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &n) != nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(n.Text)
	for _, c := range n.Content {
		b.WriteString(plain(c))
	}
	if n.Type == "paragraph" || n.Type == "heading" || n.Type == "listItem" {
		b.WriteString("\n")
	}
	return b.String()
}

type issueFields struct {
	Summary  string                `json:"summary"`
	Status   struct{ Name string } `json:"status"`
	Assignee *struct {
		DisplayName string `json:"displayName"`
	} `json:"assignee"`
	Priority *struct{ Name string } `json:"priority"`
	Type     struct{ Name string }  `json:"issuetype"`
	Updated  string                 `json:"updated"`
	Created  string                 `json:"created"`
	Desc     json.RawMessage        `json:"description"`
}

type issueOut struct {
	Key         string `json:"key"`
	Summary     string `json:"summary"`
	Status      string `json:"status"`
	Type        string `json:"type,omitempty"`
	Assignee    string `json:"assignee,omitempty"`
	Priority    string `json:"priority,omitempty"`
	Updated     string `json:"updated,omitempty"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url"`
}

func (c *conn) out(key string, f issueFields) issueOut {
	o := issueOut{Key: key, Summary: f.Summary, Status: f.Status.Name, Type: f.Type.Name, Updated: f.Updated, URL: c.cfg.Site + "/browse/" + key}
	if f.Assignee != nil {
		o.Assignee = f.Assignee.DisplayName
	}
	if f.Priority != nil {
		o.Priority = f.Priority.Name
	}
	return o
}

type transition struct {
	ID string `json:"id"`
	To struct {
		Name string `json:"name"`
	} `json:"to"`
	Name string `json:"name"`
}

func (c *conn) transitions(ctx context.Context, key string) ([]transition, error) {
	var t struct {
		Transitions []transition `json:"transitions"`
	}
	_, err := c.api.Do(ctx, "GET", "/issue/"+key+"/transitions", nil, nil, &t)
	return t.Transitions, err
}

func (c *conn) status(ctx context.Context, key string) (string, error) {
	var is struct {
		Fields issueFields `json:"fields"`
	}
	_, err := c.api.Do(ctx, "GET", "/issue/"+key, url.Values{"fields": {"status"}}, nil, &is)
	return is.Fields.Status.Name, err
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		JQL         string `json:"jql"`
		Limit       int    `json:"limit"`
		Key         string `json:"key"`
		Project     string `json:"project"`
		Type        string `json:"type"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Text        string `json:"text"`
		ID          string `json:"id"`
		To          string `json:"to"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	p.Key = strings.ToUpper(strings.TrimSpace(p.Key))
	if call.Action != "search" && call.Action != "create" && !keyRe.MatchString(p.Key) {
		return sdk.Result{}, errors.New("give an issue key like OPS-42")
	}
	switch call.Action {
	case "search":
		if strings.TrimSpace(p.JQL) == "" {
			return sdk.Result{}, errors.New("a JQL query is required")
		}
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 25
		}
		q := url.Values{"jql": {p.JQL}, "maxResults": {strconv.Itoa(limit)}, "fields": {"summary,status,assignee,priority,issuetype,updated"}}
		path := "/search/jql" // Cloud's current search endpoint
		if c.v == "2" {
			path = "/search"
		}
		var res struct {
			Issues []struct {
				Key    string      `json:"key"`
				Fields issueFields `json:"fields"`
			} `json:"issues"`
		}
		if _, err := c.api.Do(ctx, "GET", path, q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		list := []issueOut{}
		for _, is := range res.Issues {
			list = append(list, c.out(is.Key, is.Fields))
		}
		return sdk.JSON(list)

	case "issue":
		var is struct {
			Key    string      `json:"key"`
			Fields issueFields `json:"fields"`
		}
		q := url.Values{"fields": {"summary,status,assignee,priority,issuetype,updated,created,description"}}
		if _, err := c.api.Do(ctx, "GET", "/issue/"+p.Key, q, nil, &is); err != nil {
			return sdk.Result{}, err
		}
		o := c.out(is.Key, is.Fields)
		o.Description = strings.TrimSpace(plain(is.Fields.Desc))
		return sdk.JSON(o)

	case "create":
		proj := strings.ToUpper(strings.TrimSpace(p.Project))
		if !projectRe.MatchString(proj) {
			return sdk.Result{}, errors.New("the project is its key, e.g. OPS")
		}
		sum := strings.TrimSpace(p.Summary)
		if sum == "" || len(sum) > 255 {
			return sdk.Result{}, errors.New("a summary is 1 to 255 characters")
		}
		typ := p.Type
		if typ == "" {
			typ = "Task"
		}
		fields := map[string]any{"project": map[string]string{"key": proj}, "issuetype": map[string]string{"name": typ}, "summary": sum}
		if strings.TrimSpace(p.Description) != "" {
			fields["description"] = c.doc(p.Description)
		}
		var out struct {
			Key string `json:"key"`
		}
		if _, err := c.api.Do(ctx, "POST", "/issue", nil, map[string]any{"fields": fields}, &out); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"key": out.Key, "url": c.cfg.Site + "/browse/" + out.Key})
		r.Undo = sdk.UndoWith("delete_issue", map[string]string{"key": out.Key}, "Delete "+out.Key)
		return r, nil

	case "delete_issue":
		if _, err := c.api.Do(ctx, "DELETE", "/issue/"+p.Key, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.Key})

	case "comment":
		if strings.TrimSpace(p.Text) == "" {
			return sdk.Result{}, errors.New("the comment is empty")
		}
		var out struct {
			ID string `json:"id"`
		}
		if _, err := c.api.Do(ctx, "POST", "/issue/"+p.Key+"/comment", nil, map[string]any{"body": c.doc(p.Text)}, &out); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"id": out.ID})
		r.Undo = sdk.UndoWith("delete_comment", map[string]string{"key": p.Key, "id": out.ID}, "Delete the comment")
		return r, nil

	case "delete_comment":
		if !idRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("comment id required")
		}
		if _, err := c.api.Do(ctx, "DELETE", "/issue/"+p.Key+"/comment/"+p.ID, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.ID})

	case "transitions":
		ts, err := c.transitions(ctx, p.Key)
		if err != nil {
			return sdk.Result{}, err
		}
		type t struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   string `json:"to"`
		}
		list := []t{}
		for _, x := range ts {
			list = append(list, t{x.ID, x.Name, x.To.Name})
		}
		return sdk.JSON(list)

	case "transition":
		before, err := c.status(ctx, p.Key)
		if err != nil {
			return sdk.Result{}, err
		}
		ts, err := c.transitions(ctx, p.Key)
		if err != nil {
			return sdk.Result{}, err
		}
		var pick *transition
		for i := range ts {
			if (p.ID != "" && ts[i].ID == p.ID) || (p.ID == "" && p.To != "" && (strings.EqualFold(ts[i].To.Name, p.To) || strings.EqualFold(ts[i].Name, p.To))) {
				pick = &ts[i]
				break
			}
		}
		if pick == nil {
			var names []string
			for _, x := range ts {
				names = append(names, x.To.Name)
			}
			return sdk.Result{}, fmt.Errorf("%s can't move to %q from %s; it can go to: %s", p.Key, p.To+p.ID, before, strings.Join(names, ", "))
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Move %s from %s to %s", p.Key, before, pick.To.Name)}}, nil
		}
		if _, err := c.api.Do(ctx, "POST", "/issue/"+p.Key+"/transitions", nil, map[string]any{"transition": map[string]string{"id": pick.ID}}, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"key": p.Key, "from": before, "to": pick.To.Name})
		// Undo only when the workflow allows going straight back.
		if back, err := c.transitions(ctx, p.Key); err == nil {
			for _, x := range back {
				if strings.EqualFold(x.To.Name, before) {
					r.Undo = sdk.UndoWith("transition", map[string]string{"key": p.Key, "id": x.ID}, "Move "+p.Key+" back to "+before)
					break
				}
			}
		}
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
