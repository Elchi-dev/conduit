// Package linear reads and changes Linear issues through its GraphQL API.
package linear

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Linear workspace connection.
type Config struct {
	APIKey string `json:"apiKey"` // secret:// personal API key
	API    string `json:"api"`    // default https://api.linear.app/graphql (tests)
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Linear module.
func New() *Module { return &Module{} }

var (
	idRe   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`) // ENG-123 or a uuid
	teamRe = regexp.MustCompile(`^[A-Za-z0-9]{1,10}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	issue := `"issue":{"type":"string","description":"e.g. ENG-123"}`
	return sdk.Manifest{
		ID: "linear", Name: "Linear", Version: "0.1.0", Category: "Development", Icon: "list",
		Description: "Your Linear issues: see what's assigned, search, create, comment and move issues.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"A personal API key (Settings, Security & access, Personal API keys)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "my_issues", Title: "My open issues", Risk: sdk.RiskRead},
			{Name: "search", Title: "Search issues", Risk: sdk.RiskRead, Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string"}}}`)},
			{Name: "issue", Title: "Issue details", Description: "Description, state, assignee and recent comments.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["issue"],"properties":{` + issue + `}}`)},
			{Name: "create", Title: "Create an issue", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["team","title"],"properties":{"team":{"type":"string","description":"Team key, e.g. ENG"},"title":{"type":"string","maxLength":255},"description":{"type":"string","x-multiline":true}}}`)},
			{Name: "archive", Title: "Archive an issue", Risk: sdk.RiskWrite, Input: sdk.Schema(`{"type":"object","required":["issue"],"properties":{` + issue + `}}`)},
			{Name: "comment", Title: "Comment on an issue", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["issue","body"],"properties":{` + issue + `,"body":{"type":"string","x-multiline":true}}}`)},
			{Name: "delete_comment", Title: "Delete a comment", Risk: sdk.RiskDestructive, Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}`)},
			{Name: "set_state", Title: "Move an issue", Description: "To another workflow state of its team, e.g. In Progress or Done.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["issue","state"],"properties":{` + issue + `,"state":{"type":"string","description":"State name, e.g. Done"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.APIKey == "" {
		return errors.New("add a Linear API key (stored in the vault)")
	}
	if c.API == "" {
		c.API = "https://api.linear.app/graphql"
	}
	key := c.APIKey
	api := rest.New(c.API, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, key)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", strings.TrimSpace(k))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// gql runs one GraphQL operation.
func (c *conn) gql(ctx context.Context, query string, vars map[string]any, out any) error {
	var res struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if _, err := c.api.Do(ctx, "POST", "", nil, map[string]any{"query": query, "variables": vars}, &res); err != nil {
		return err
	}
	if len(res.Errors) > 0 {
		return errors.New("Linear: " + res.Errors[0].Message)
	}
	if out != nil {
		return json.Unmarshal(res.Data, out)
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var d struct {
		Viewer struct {
			Name         string `json:"name"`
			Organization struct {
				Name string `json:"name"`
			} `json:"organization"`
		} `json:"viewer"`
	}
	if err := c.gql(ctx, `query { viewer { name organization { name } } }`, nil, &d); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: d.Viewer.Name + " in " + d.Viewer.Organization.Name}
}

type issue struct {
	ID         string `json:"id"`
	Identifier string `json:"identifier"`
	Title      string `json:"title"`
	URL        string `json:"url"`
	Priority   int    `json:"priority"`
	State      struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"state"`
}

const issueFields = `id identifier title url priority state { id name type }`

func summary(list []issue) []map[string]any {
	out := []map[string]any{}
	for _, i := range list {
		out = append(out, map[string]any{"issue": i.Identifier, "title": i.Title, "state": i.State.Name, "priority": i.Priority, "url": i.URL})
	}
	return out
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Query       string `json:"query"`
		Issue       string `json:"issue"`
		Team        string `json:"team"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Body        string `json:"body"`
		ID          string `json:"id"`
		State       string `json:"state"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	needIssue := func() error {
		if !idRe.MatchString(p.Issue) {
			return errors.New("an issue is its identifier, like ENG-123")
		}
		return nil
	}
	switch call.Action {
	case "my_issues":
		var d struct {
			Viewer struct {
				AssignedIssues struct {
					Nodes []issue `json:"nodes"`
				} `json:"assignedIssues"`
			} `json:"viewer"`
		}
		q := `query { viewer { assignedIssues(first: 50, filter: { state: { type: { nin: ["completed", "canceled"] } } }) { nodes { ` + issueFields + ` } } } }`
		if err := c.gql(ctx, q, nil, &d); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(summary(d.Viewer.AssignedIssues.Nodes))

	case "search":
		if strings.TrimSpace(p.Query) == "" {
			return sdk.Result{}, errors.New("enter something to search for")
		}
		var d struct {
			SearchIssues struct {
				Nodes []issue `json:"nodes"`
			} `json:"searchIssues"`
		}
		if err := c.gql(ctx, `query($q: String!) { searchIssues(term: $q, first: 25) { nodes { `+issueFields+` } } }`, map[string]any{"q": p.Query}, &d); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(summary(d.SearchIssues.Nodes))

	case "issue":
		if err := needIssue(); err != nil {
			return sdk.Result{}, err
		}
		var d struct {
			Issue struct {
				issue
				Description string `json:"description"`
				Assignee    *struct {
					Name string `json:"name"`
				} `json:"assignee"`
				Comments struct {
					Nodes []struct {
						Body      string `json:"body"`
						CreatedAt string `json:"createdAt"`
						User      *struct {
							Name string `json:"name"`
						} `json:"user"`
					} `json:"nodes"`
				} `json:"comments"`
			} `json:"issue"`
		}
		q := `query($id: String!) { issue(id: $id) { ` + issueFields + ` description assignee { name } comments(first: 20) { nodes { body createdAt user { name } } } } }`
		if err := c.gql(ctx, q, map[string]any{"id": p.Issue}, &d); err != nil {
			return sdk.Result{}, err
		}
		i := d.Issue
		out := map[string]any{"issue": i.Identifier, "title": i.Title, "state": i.State.Name, "url": i.URL, "description": i.Description}
		if i.Assignee != nil {
			out["assignee"] = i.Assignee.Name
		}
		comments := []map[string]string{}
		for _, cm := range i.Comments.Nodes {
			who := ""
			if cm.User != nil {
				who = cm.User.Name
			}
			comments = append(comments, map[string]string{"by": who, "at": cm.CreatedAt, "body": cm.Body})
		}
		out["comments"] = comments
		return sdk.JSON(out)

	case "create":
		if !teamRe.MatchString(p.Team) {
			return sdk.Result{}, errors.New("the team is its key, like ENG")
		}
		if strings.TrimSpace(p.Title) == "" {
			return sdk.Result{}, errors.New("an issue needs a title")
		}
		var t struct {
			Teams struct {
				Nodes []struct {
					ID string `json:"id"`
				} `json:"nodes"`
			} `json:"teams"`
		}
		if err := c.gql(ctx, `query($k: String!) { teams(filter: { key: { eq: $k } }) { nodes { id } } }`, map[string]any{"k": strings.ToUpper(p.Team)}, &t); err != nil {
			return sdk.Result{}, err
		}
		if len(t.Teams.Nodes) == 0 {
			return sdk.Result{}, fmt.Errorf("no team with the key %s", strings.ToUpper(p.Team))
		}
		var d struct {
			IssueCreate struct {
				Success bool  `json:"success"`
				Issue   issue `json:"issue"`
			} `json:"issueCreate"`
		}
		in := map[string]any{"teamId": t.Teams.Nodes[0].ID, "title": p.Title}
		if p.Description != "" {
			in["description"] = p.Description
		}
		if err := c.gql(ctx, `mutation($in: IssueCreateInput!) { issueCreate(input: $in) { success issue { `+issueFields+` } } }`, map[string]any{"in": in}, &d); err != nil {
			return sdk.Result{}, err
		}
		if !d.IssueCreate.Success {
			return sdk.Result{}, errors.New("Linear didn't create the issue")
		}
		r, _ := sdk.JSON(map[string]string{"issue": d.IssueCreate.Issue.Identifier, "url": d.IssueCreate.Issue.URL})
		r.Undo = sdk.UndoWith("archive", map[string]string{"issue": d.IssueCreate.Issue.Identifier}, "Archive the issue")
		return r, nil

	case "archive":
		if err := needIssue(); err != nil {
			return sdk.Result{}, err
		}
		var d struct {
			IssueArchive struct {
				Success bool `json:"success"`
			} `json:"issueArchive"`
		}
		if err := c.gql(ctx, `mutation($id: String!) { issueArchive(id: $id) { success } }`, map[string]any{"id": p.Issue}, &d); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"archived": p.Issue})

	case "comment":
		if err := needIssue(); err != nil {
			return sdk.Result{}, err
		}
		if strings.TrimSpace(p.Body) == "" {
			return sdk.Result{}, errors.New("a comment needs text")
		}
		var d struct {
			CommentCreate struct {
				Success bool `json:"success"`
				Comment struct {
					ID  string `json:"id"`
					URL string `json:"url"`
				} `json:"comment"`
			} `json:"commentCreate"`
		}
		if err := c.gql(ctx, `mutation($in: CommentCreateInput!) { commentCreate(input: $in) { success comment { id url } } }`,
			map[string]any{"in": map[string]any{"issueId": p.Issue, "body": p.Body}}, &d); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"comment": d.CommentCreate.Comment.ID, "url": d.CommentCreate.Comment.URL})
		r.Undo = sdk.UndoWith("delete_comment", map[string]string{"id": d.CommentCreate.Comment.ID}, "Delete the comment")
		return r, nil

	case "delete_comment":
		if !idRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("comment id required")
		}
		if err := c.gql(ctx, `mutation($id: String!) { commentDelete(id: $id) { success } }`, map[string]any{"id": p.ID}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.ID})

	case "set_state":
		if err := needIssue(); err != nil {
			return sdk.Result{}, err
		}
		var d struct {
			Issue struct {
				issue
				Team struct {
					States struct {
						Nodes []struct {
							ID   string `json:"id"`
							Name string `json:"name"`
						} `json:"nodes"`
					} `json:"states"`
				} `json:"team"`
			} `json:"issue"`
		}
		if err := c.gql(ctx, `query($id: String!) { issue(id: $id) { `+issueFields+` team { states { nodes { id name } } } } }`, map[string]any{"id": p.Issue}, &d); err != nil {
			return sdk.Result{}, err
		}
		target := ""
		names := []string{}
		for _, s := range d.Issue.Team.States.Nodes {
			names = append(names, s.Name)
			if strings.EqualFold(s.Name, strings.TrimSpace(p.State)) {
				target = s.ID
				p.State = s.Name
			}
		}
		if target == "" {
			return sdk.Result{}, fmt.Errorf("no state %q; this team has: %s", p.State, strings.Join(names, ", "))
		}
		before := d.Issue.State.Name
		if call.DryRun {
			b, _ := json.Marshal(before)
			a, _ := json.Marshal(p.State)
			return sdk.Result{Plan: &sdk.Plan{Summary: "Move " + p.Issue + " from " + before + " to " + p.State,
				Changes: []sdk.Change{{Target: p.Issue, Op: "update", Before: b, After: a}}}}, nil
		}
		if err := c.gql(ctx, `mutation($id: String!, $in: IssueUpdateInput!) { issueUpdate(id: $id, input: $in) { success } }`,
			map[string]any{"id": p.Issue, "in": map[string]any{"stateId": target}}, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"issue": p.Issue, "from": before, "to": p.State})
		if before != p.State {
			r.Undo = sdk.UndoWith("set_state", map[string]string{"issue": p.Issue, "state": before}, "Move it back to "+before)
		}
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
