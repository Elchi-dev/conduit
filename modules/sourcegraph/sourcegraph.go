// Package sourcegraph searches code on a Sourcegraph instance (self-hosted
// or sourcegraph.com) through its GraphQL API and an access token: code
// search with bounded, redacted results, and the instance's repositories.
// Queries travel as GraphQL variables only.
package sourcegraph

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
	"unicode"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Sourcegraph instance.
type Config struct {
	URL                string `json:"url"`   // default https://sourcegraph.com
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

// New returns the Sourcegraph module.
func New() *Module { return &Module{} }

var (
	pathRe  = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	repoRe  = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
	countRe = regexp.MustCompile(`(?i)(^|\s)-?count:`)
)

const (
	maxQuery     = 1000
	maxLine      = 200
	linesPerFile = 10
)

const (
	searchQuery = `query Search($query: String!) { search(query: $query, version: V2) { results { matchCount limitHit ` +
		`results { __typename ... on FileMatch { repository { name } file { path } lineMatches { preview lineNumber } } ... on Repository { name url } } } } }`
	reposQuery = `query Repositories($first: Int!) { repositories(first: $first) { nodes { name description url } } }`
	meQuery    = `query { currentUser { username } }`
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "sourcegraph", Name: "Sourcegraph", Version: "0.1.0", Category: "Development", Icon: "search",
		Description: "Sourcegraph: search code across repositories (bounded, with credentials masked) and list repositories. Read only.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"url":{"type":"string","default":"https://sourcegraph.com","description":"sourcegraph.com, or your instance's address, e.g. https://sourcegraph.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An access token (your user menu, Settings, Access tokens); it searches what its user can see"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "search", Title: "Search code", Description: "Runs a Sourcegraph search (its query language: repo:, file:, lang:, type: and so on) and returns matching files with up to 10 matching lines each, cut to 200 characters with anything that looks like a credential masked. At most 100 results.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string","maxLength":1000,"description":"A Sourcegraph search query, e.g. repo:^github.com/acme/ lang:go http.Client (the result count is set by limit, not count:)"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":30,"description":"Most results (files or repositories), and most matching lines in all"}}}`)},
			{Name: "repositories", Title: "Repositories", Description: "Repositories on the instance with name, description and address; with a name filter, those whose name matches.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"name":{"type":"string","description":"Only repositories whose name contains this, e.g. acme/ or github.com/acme"},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = "https://sourcegraph.com"
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) || strings.Contains(u.Path, "..") {
		return errors.New("the address is like https://sourcegraph.example.com")
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
	base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/.api/graphql"), "/.api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/.api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "token "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func clip(s string, n int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s))
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n]) + "…"
	}
	return s
}

// clean masks anything that looks like a credential, then cuts: a cut
// never leaves part of one behind.
func clean(s string, n int) string { return clip(rest.Redact(s), n) }

// gql sends one GraphQL request; the query is constant and every value
// travels in variables.
func (c *conn) gql(ctx context.Context, query string, vars map[string]any, out any) error {
	var res struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	body := map[string]any{"query": query}
	if vars != nil {
		body["variables"] = vars
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/graphql", nil, body, &res); err != nil {
		switch {
		case rest.IsStatus(err, http.StatusUnauthorized):
			return errors.New("Sourcegraph refused the access token")
		case rest.IsStatus(err, http.StatusForbidden):
			return errors.New("Sourcegraph refused: the token's user can't do this")
		case rest.IsStatus(err, http.StatusNotFound):
			return errors.New("no Sourcegraph API at this address")
		case rest.IsStatus(err, http.StatusTooManyRequests):
			return errors.New("Sourcegraph's rate limit was hit; try again in a minute")
		}
		return err
	}
	if len(res.Errors) > 0 {
		return errors.New("Sourcegraph: " + clean(res.Errors[0].Message, 300))
	}
	if len(res.Data) == 0 || string(res.Data) == "null" {
		return errors.New("Sourcegraph answered without data")
	}
	if err := json.Unmarshal(res.Data, out); err != nil {
		return fmt.Errorf("unexpected answer from Sourcegraph: %w", err)
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
		CurrentUser *struct {
			Username string `json:"username"`
		} `json:"currentUser"`
	}
	if err := c.gql(ctx, meQuery, nil, &d); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if d.CurrentUser == nil {
		return sdk.Health{Status: "down", Message: "Sourcegraph didn't accept the token as a user"}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + clip(d.CurrentUser.Username, 100)}
}

type result struct {
	Type       string `json:"__typename"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	Repository struct {
		Name string `json:"name"`
	} `json:"repository"`
	File struct {
		Path string `json:"path"`
	} `json:"file"`
	LineMatches []struct {
		Preview    string `json:"preview"`
		LineNumber int    `json:"lineNumber"`
	} `json:"lineMatches"`
}

func (c *conn) search(ctx context.Context, query string) ([]result, int, bool, error) {
	var d struct {
		Search *struct {
			Results struct {
				MatchCount int      `json:"matchCount"`
				LimitHit   bool     `json:"limitHit"`
				Results    []result `json:"results"`
			} `json:"results"`
		} `json:"search"`
	}
	if err := c.gql(ctx, searchQuery, map[string]any{"query": query}, &d); err != nil {
		return nil, 0, false, err
	}
	if d.Search == nil {
		return nil, 0, false, errors.New("Sourcegraph answered without search results")
	}
	r := d.Search.Results
	return r.Results, r.MatchCount, r.LimitHit, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Query string `json:"query"`
		Name  string `json:"name"`
		Limit int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" || utf8.RuneCountInString(q) > maxQuery || strings.IndexFunc(q, unicode.IsControl) >= 0 {
			return sdk.Result{}, errors.New("the query is one line of at most 1000 characters")
		}
		if countRe.MatchString(q) {
			return sdk.Result{}, errors.New("leave count: out of the query; limit sets how many results come back")
		}
		if p.Limit == 0 {
			p.Limit = 30
		}
		if p.Limit < 1 || p.Limit > 100 {
			return sdk.Result{}, errors.New("limit is between 1 and 100")
		}
		return c.code(ctx, q, p.Limit)
	case "repositories":
		if p.Limit == 0 {
			p.Limit = 50
		}
		if p.Limit < 1 || p.Limit > 200 {
			return sdk.Result{}, errors.New("limit is between 1 and 200")
		}
		name := strings.TrimSpace(p.Name)
		if name != "" && !repoRe.MatchString(name) {
			return sdk.Result{}, errors.New("the name filter is part of a repository name: letters, digits and . _ / -")
		}
		return c.repositories(ctx, name, p.Limit)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) code(ctx context.Context, q string, limit int) (sdk.Result, error) {
	rs, matches, limitHit, err := c.search(ctx, q+" count:"+strconv.Itoa(limit))
	if err != nil {
		return sdk.Result{}, err
	}
	files, repos := []map[string]any{}, []string{}
	lines, other, cut := 0, 0, false
	for _, r := range rs {
		if len(files)+len(repos) == limit {
			cut = true
			break
		}
		switch r.Type {
		case "FileMatch":
			ls := []map[string]any{}
			for _, l := range r.LineMatches {
				if len(ls) == linesPerFile || lines == limit {
					cut = true
					break
				}
				ls = append(ls, map[string]any{"line": l.LineNumber + 1, "text": clean(l.Preview, maxLine)})
				lines++
			}
			files = append(files, map[string]any{"repo": clip(r.Repository.Name, 200), "path": clip(r.File.Path, 300), "matches": ls})
		case "Repository":
			repos = append(repos, clip(r.Name, 200))
		default:
			other++
		}
	}
	out := map[string]any{"files": files, "matchCount": matches, "truncated": cut || limitHit || len(rs) > limit}
	if len(repos) > 0 {
		out["repositories"] = repos
	}
	if other > 0 {
		out["otherResults"] = other
		out["note"] = "commit, diff and symbol results are counted, not shown"
	}
	return sdk.JSON(out)
}

func (c *conn) repositories(ctx context.Context, name string, limit int) (sdk.Result, error) {
	rows := []map[string]any{}
	if name != "" {
		// A repository search: the filter is quoted, so it matches literally.
		rs, _, limitHit, err := c.search(ctx, "type:repo repo:"+regexp.QuoteMeta(name)+" count:"+strconv.Itoa(limit))
		if err != nil {
			return sdk.Result{}, err
		}
		for _, r := range rs {
			if r.Type != "Repository" || len(rows) == limit {
				continue
			}
			rows = append(rows, map[string]any{"name": clip(r.Name, 200), "url": clip(r.URL, 300)})
		}
		return sdk.JSON(map[string]any{"repositories": rows, "truncated": limitHit || len(rs) > limit})
	}
	var d struct {
		Repositories struct {
			Nodes []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				URL         string `json:"url"`
			} `json:"nodes"`
		} `json:"repositories"`
	}
	if err := c.gql(ctx, reposQuery, map[string]any{"first": limit}, &d); err != nil {
		return sdk.Result{}, err
	}
	for _, n := range d.Repositories.Nodes {
		if len(rows) == limit {
			break
		}
		row := map[string]any{"name": clip(n.Name, 200), "url": clip(n.URL, 300)}
		if n.Description != "" {
			row["description"] = clean(n.Description, 200)
		}
		rows = append(rows, row)
	}
	return sdk.JSON(map[string]any{"repositories": rows, "truncated": len(d.Repositories.Nodes) >= limit})
}
