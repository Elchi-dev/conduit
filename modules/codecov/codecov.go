// Package codecov reads code coverage from Codecov through its API v2 with
// an API access token: an owner's repositories with their coverage, the
// coverage of a branch or commit, and how a pull request (or any two
// commits) changes it. It never changes anything.
package codecov

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Codecov owner (a user or organization on a Git host).
type Config struct {
	Service string `json:"service"` // github, gitlab, bitbucket (or their self-hosted kinds)
	Owner   string `json:"owner"`   // user or organization name on that host
	Token   string `json:"token"`   // secret:// API access token
}

type conn struct {
	api   *rest.Client
	owner string // /{service}/{owner}
	name  string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.codecov.io/api/v2 (tests).
	Base string
}

// New returns the Codecov module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.codecov.io/api/v2"

var (
	services = map[string]bool{"github": true, "gitlab": true, "bitbucket": true, "github_enterprise": true, "gitlab_enterprise": true, "bitbucket_server": true}
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	shaRe    = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9_./+@#-]{1,255}$`)
)

func validName(s, what string) (string, error) {
	v := strings.TrimSpace(s)
	if !nameRe.MatchString(v) || strings.Trim(v, ".") == "" {
		return "", fmt.Errorf("the %s is its name, like conduit", what)
	}
	return v, nil
}

func validSHA(s, what string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if !shaRe.MatchString(v) {
		return "", fmt.Errorf("the %s is a commit SHA (7 to 64 hex characters)", what)
	}
	return v, nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	repo := `"repo":{"type":"string","description":"Repository name under the configured owner"}`
	return sdk.Manifest{
		ID: "codecov", Name: "Codecov", Version: "0.1.0", Category: "Development", Icon: "gauge",
		Description: "Codecov: coverage of your repositories, branches and commits, and the coverage change of a pull request. Read only.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["service","owner","token"],"properties":{
			"service":{"type":"string","enum":["github","gitlab","bitbucket","github_enterprise","gitlab_enterprise","bitbucket_server"],"default":"github","description":"Where the repositories are hosted"},
			"owner":{"type":"string","description":"User or organization name on that host"},
			"token":{"type":"string","x-secret":true,"description":"An API access token (Codecov Settings, Access)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "repos", Title: "Repositories", Description: "The owner's repositories active on Codecov with coverage, default branch, language and last update.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"includeInactive":{"type":"boolean","description":"Also repositories with no coverage uploads"}}}`)},
			{Name: "coverage", Title: "Coverage", Description: "Coverage totals of a repository's default branch, another branch, or one commit: percentage, lines, hits, misses, partials, files.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repo"],"properties":{` + repo + `,"branch":{"type":"string"},"sha":{"type":"string","description":"Commit SHA, instead of a branch"}}}`)},
			{Name: "commit", Title: "Commit coverage", Description: "One commit's coverage with its branch, author, CI status and processing state.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repo","sha"],"properties":{` + repo + `,"sha":{"type":"string"}}}`)},
			{Name: "compare", Title: "Compare coverage", Description: "How a pull request (or a head commit against a base commit) changes coverage: base, head, change, patch coverage, and the files whose coverage changed most.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["repo"],"properties":{` + repo + `,"pullRequest":{"type":"integer","minimum":1},"base":{"type":"string","description":"Base commit SHA (with head, instead of pullRequest)"},"head":{"type":"string","description":"Head commit SHA"},"files":{"type":"integer","minimum":0,"maximum":100,"default":20,"description":"How many changed files to list"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	svc := strings.TrimSpace(c.Service)
	if svc == "" {
		svc = "github"
	}
	if !services[svc] {
		return errors.New("the service is github, gitlab, bitbucket, github_enterprise, gitlab_enterprise or bitbucket_server")
	}
	owner, err := validName(c.Owner, "owner")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API access token in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, owner: "/" + svc + "/" + owner, name: owner})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Codecov refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Codecov refused: the token's user can't see this")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("no %s on Codecov (or the token can't see it)", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Codecov's rate limit was hit; try again in a minute")
	}
	return err
}

func (c *conn) get(ctx context.Context, path string, q url.Values, out any, what string) error {
	_, err := c.api.Do(ctx, http.MethodGet, c.owner+path, q, nil, out)
	return friendly(err, what)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var p struct {
		Count int `json:"count"`
	}
	if err := c.get(ctx, "/repos/", url.Values{"page_size": {"1"}, "active": {"true"}}, &p, "owner "+c.name); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s · %d active repositories", c.name, p.Count)}
}

// pct is a coverage percentage, which Codecov sends as a number, a string
// or null.
type pct struct {
	V   float64
	Set bool
}

func (p *pct) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" || s == "" {
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	p.V, p.Set = v, true
	return nil
}

func (p pct) out() any {
	if !p.Set {
		return nil
	}
	return math.Round(p.V*100) / 100
}

type totals struct {
	Files    int `json:"files"`
	Lines    int `json:"lines"`
	Hits     int `json:"hits"`
	Misses   int `json:"misses"`
	Partials int `json:"partials"`
	Coverage pct `json:"coverage"`
}

func (t *totals) row() map[string]any {
	if t == nil {
		return map[string]any{"coverage": nil}
	}
	return map[string]any{"coverage": t.Coverage.out(), "files": t.Files, "lines": t.Lines, "hits": t.Hits, "misses": t.Misses, "partials": t.Partials}
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

func short(sha string) string {
	if len(sha) > 10 {
		return sha[:10]
	}
	return sha
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Repo            string `json:"repo"`
		Branch          string `json:"branch"`
		SHA             string `json:"sha"`
		PullRequest     int64  `json:"pullRequest"`
		Base            string `json:"base"`
		Head            string `json:"head"`
		Files           *int   `json:"files"`
		IncludeInactive bool   `json:"includeInactive"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if call.Action == "repos" {
		type repo struct {
			Name     string  `json:"name"`
			Private  bool    `json:"private"`
			Updated  string  `json:"updatestamp"`
			Language string  `json:"language"`
			Branch   string  `json:"branch"`
			Active   bool    `json:"active"`
			Totals   *totals `json:"totals"`
		}
		out := []map[string]any{}
		q := url.Values{"page_size": {"100"}}
		if !p.IncludeInactive {
			q.Set("active", "true")
		}
		for page := 1; page <= 10; page++ {
			q.Set("page", strconv.Itoa(page))
			var res struct {
				Next    *string `json:"next"`
				Results []repo  `json:"results"`
			}
			if err := c.get(ctx, "/repos/", q, &res, "owner "+c.name); err != nil {
				return sdk.Result{}, err
			}
			for _, r := range res.Results {
				row := map[string]any{"repo": r.Name, "private": r.Private, "defaultBranch": r.Branch, "language": r.Language, "updated": r.Updated, "active": r.Active, "coverage": nil}
				if r.Totals != nil {
					row["coverage"] = r.Totals.Coverage.out()
				}
				out = append(out, row)
			}
			if res.Next == nil || *res.Next == "" {
				break
			}
		}
		return sdk.JSON(out)
	}
	switch call.Action {
	case "coverage", "commit", "compare":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	repo, err := validName(p.Repo, "repository")
	if err != nil {
		return sdk.Result{}, err
	}
	rp := "/repos/" + repo
	switch call.Action {
	case "coverage":
		q := url.Values{}
		b := strings.TrimSpace(p.Branch)
		switch {
		case b != "" && strings.TrimSpace(p.SHA) != "":
			return sdk.Result{}, errors.New("give a branch or a sha, not both")
		case b != "":
			if !branchRe.MatchString(b) || strings.Contains(b, "..") {
				return sdk.Result{}, errors.New("that isn't a branch name")
			}
			q.Set("branch", b)
		case strings.TrimSpace(p.SHA) != "":
			sha, err := validSHA(p.SHA, "sha")
			if err != nil {
				return sdk.Result{}, err
			}
			q.Set("sha", sha)
		}
		var t totals
		if err := c.get(ctx, rp+"/totals/", q, &t, "coverage report for "+repo); err != nil {
			return sdk.Result{}, err
		}
		out := t.row()
		out["repo"] = repo
		if b != "" {
			out["branch"] = b
		}
		if s := q.Get("sha"); s != "" {
			out["sha"] = s
		}
		return sdk.JSON(out)

	case "commit":
		sha, err := validSHA(p.SHA, "sha")
		if err != nil {
			return sdk.Result{}, err
		}
		var cm struct {
			CommitID  string  `json:"commitid"`
			Message   string  `json:"message"`
			Timestamp string  `json:"timestamp"`
			CIPassed  *bool   `json:"ci_passed"`
			Branch    string  `json:"branch"`
			State     string  `json:"state"`
			Parent    string  `json:"parent"`
			Totals    *totals `json:"totals"`
			Author    *struct {
				Username string `json:"username"`
			} `json:"author"`
		}
		if err := c.get(ctx, rp+"/commits/"+sha+"/", nil, &cm, "commit "+sha+" in "+repo); err != nil {
			return sdk.Result{}, err
		}
		out := cm.Totals.row()
		out["repo"], out["sha"], out["message"], out["timestamp"], out["branch"], out["state"], out["parent"] =
			repo, short(cm.CommitID), firstLine(cm.Message), cm.Timestamp, cm.Branch, cm.State, short(cm.Parent)
		if cm.CIPassed != nil {
			out["ciPassed"] = *cm.CIPassed
		}
		if cm.Author != nil {
			out["author"] = cm.Author.Username
		}
		return sdk.JSON(out)

	case "compare":
		q := url.Values{}
		base, head := strings.TrimSpace(p.Base), strings.TrimSpace(p.Head)
		switch {
		case p.PullRequest > 0 && (base != "" || head != ""):
			return sdk.Result{}, errors.New("give a pullRequest, or base and head, not both")
		case p.PullRequest > 0:
			q.Set("pullid", strconv.FormatInt(p.PullRequest, 10))
		case base != "" || head != "":
			b, err := validSHA(base, "base")
			if err != nil {
				return sdk.Result{}, err
			}
			h, err := validSHA(head, "head")
			if err != nil {
				return sdk.Result{}, err
			}
			q.Set("base", b)
			q.Set("head", h)
		default:
			return sdk.Result{}, errors.New("enter the pullRequest number, or base and head commits")
		}
		limit := 20
		if p.Files != nil {
			limit = *p.Files
		}
		if limit < 0 || limit > 100 {
			return sdk.Result{}, errors.New("files is between 0 and 100")
		}
		type side struct {
			Coverage pct `json:"coverage"`
		}
		var cmp struct {
			BaseCommit string `json:"base_commit"`
			HeadCommit string `json:"head_commit"`
			Totals     struct {
				Base  *side `json:"base"`
				Head  *side `json:"head"`
				Patch *side `json:"patch"`
			} `json:"totals"`
			Files []struct {
				Name struct {
					Base *string `json:"base"`
					Head *string `json:"head"`
				} `json:"name"`
				Totals struct {
					Base  *side `json:"base"`
					Head  *side `json:"head"`
					Patch *side `json:"patch"`
				} `json:"totals"`
				HasDiff bool `json:"has_diff"`
			} `json:"files"`
		}
		what := "comparison for " + repo
		if p.PullRequest > 0 {
			what = fmt.Sprintf("pull request #%d in %s (or it has no coverage yet)", p.PullRequest, repo)
		}
		if err := c.get(ctx, rp+"/compare/", q, &cmp, what); err != nil {
			return sdk.Result{}, err
		}
		cov := func(s *side) pct {
			if s == nil {
				return pct{}
			}
			return s.Coverage
		}
		change := func(b, h pct) any {
			if !b.Set || !h.Set {
				return nil
			}
			return math.Round((h.V-b.V)*100) / 100
		}
		type fileRow struct {
			row   map[string]any
			delta float64
		}
		var files []fileRow
		for _, f := range cmp.Files {
			b, h := cov(f.Totals.Base), cov(f.Totals.Head)
			d := change(b, h)
			if d == nil && !f.HasDiff {
				continue
			}
			if dv, ok := d.(float64); ok && dv == 0 && !f.HasDiff {
				continue
			}
			name := ""
			if f.Name.Head != nil {
				name = *f.Name.Head
			} else if f.Name.Base != nil {
				name = *f.Name.Base
			}
			dv, _ := d.(float64)
			files = append(files, fileRow{map[string]any{"file": name, "base": b.out(), "head": h.out(), "change": d, "patch": cov(f.Totals.Patch).out()}, math.Abs(dv)})
		}
		sort.SliceStable(files, func(i, j int) bool { return files[i].delta > files[j].delta })
		total := len(files)
		if len(files) > limit {
			files = files[:limit]
		}
		rows := []map[string]any{}
		for _, f := range files {
			rows = append(rows, f.row)
		}
		b, h := cov(cmp.Totals.Base), cov(cmp.Totals.Head)
		out := map[string]any{"repo": repo, "baseCommit": short(cmp.BaseCommit), "headCommit": short(cmp.HeadCommit),
			"base": b.out(), "head": h.out(), "change": change(b, h), "patch": cov(cmp.Totals.Patch).out(), "changedFiles": total, "files": rows}
		if p.PullRequest > 0 {
			out["pullRequest"] = p.PullRequest
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
