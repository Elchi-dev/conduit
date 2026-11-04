// Package harbor works with a Harbor container registry through its v2.0
// API: projects, repositories, artifacts with their tags and vulnerability
// scan summary, starting a scan, deleting an artifact or a tag (and adding
// a tag back), and robot accounts (never their secrets).
package harbor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Harbor instance and the account Conduit uses.
type Config struct {
	Address            string `json:"address"`  // e.g. https://harbor.example.com
	Username           string `json:"username"` // a user, or a robot account like robot$conduit
	Password           string `json:"password"` // secret:// password or robot secret
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Harbor module.
func New() *Module { return &Module{} }

var (
	projectRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)
	repoRe    = regexp.MustCompile(`^[a-z0-9]+([._-]+[a-z0-9]+)*(/[a-z0-9]+([._-]+[a-z0-9]+)*)*$`)
	tagRe     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	digestRe  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	filterRe  = regexp.MustCompile(`^[a-z0-9._-]{1,255}$`)
	userRe    = regexp.MustCompile(`^[A-Za-z0-9_.@$+-]{1,255}$`)
)

const vulnTypes = "application/vnd.security.vulnerability.report; version=1.1, application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	proj := `"project":{"type":"string","description":"Project name"}`
	repo := `"repository":{"type":"string","description":"Repository in the project, e.g. web/api"}`
	ref := `"reference":{"type":"string","description":"Tag or digest (sha256:…)"}`
	return sdk.Manifest{
		ID: "harbor", Name: "Harbor", Version: "0.1.0", Category: "Development", Icon: "container",
		Description: "Harbor registry: projects, repositories, artifacts with vulnerability summaries, starting scans, deleting artifacts and tags, robot accounts.",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["address","username","password"],"properties":{
			"address":{"type":"string","description":"Harbor's address, e.g. https://harbor.example.com"},
			"username":{"type":"string","description":"A user or robot account (robot$name); its role decides what works"},
			"password":{"type":"string","x-secret":true,"description":"The password, or the robot account's secret"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "projects", Title: "Projects", Description: "Projects with visibility, repository count, owner and whether they're a proxy cache.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"name":{"type":"string","description":"Only names containing this"}}}`)},
			{Name: "repositories", Title: "Repositories", Description: "Repositories of a project with artifact and pull counts and when they were last pushed.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project"],"properties":{` + proj + `}}`)},
			{Name: "artifacts", Title: "Artifacts", Description: "Artifacts of a repository, newest first: digest, tags, size, push and pull time and the vulnerability scan summary (status, highest severity, counts by severity, fixable).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["project","repository"],"properties":{` + proj + `,` + repo + `}}`)},
			{Name: "scan", Title: "Scan an artifact", Description: "Starts a vulnerability scan of one artifact with the project's scanner.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","repository","reference"],"properties":{` + proj + `,` + repo + `,` + ref + `}}`)},
			{Name: "delete_artifact", Title: "Delete an artifact", Description: "Deletes an artifact and every tag on it; its layers go at the next garbage collection. The preview lists the tags.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","repository","reference"],"properties":{` + proj + `,` + repo + `,` + ref + `}}`)},
			{Name: "delete_tag", Title: "Delete a tag", Description: "Removes one tag; the artifact stays (under its digest and any other tags). Undo adds the tag back to the same digest.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","repository","tag"],"properties":{` + proj + `,` + repo + `,"tag":{"type":"string"}}}`)},
			{Name: "add_tag", Title: "Add a tag", Description: "Adds a tag to an artifact (given by digest or another tag). Undo removes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["project","repository","reference","tag"],"properties":{` + proj + `,` + repo + `,` + ref + `,"tag":{"type":"string","description":"The new tag"}}}`)},
			{Name: "robots", Title: "Robot accounts", Description: "Robot accounts (system-wide, or of one project) with level, permissions, whether they're disabled and when they expire. Never their secrets.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + proj + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.Address))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return errors.New("the address is like https://harbor.example.com")
	}
	user := strings.TrimSpace(c.Username)
	if !userRe.MatchString(user) {
		return errors.New("enter the username (or robot account name)")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the password in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	ref := c.Password
	api := rest.New(u.Scheme+"://"+u.Host+"/api/v2.0", func(ctx context.Context, r *http.Request) error {
		pw, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.SetBasicAuth(user, strings.TrimSpace(pw))
		return nil
	})
	api.Header.Set("X-Accept-Vulnerabilities", vulnTypes)
	// Project names that are all digits would otherwise be taken as IDs.
	api.Header.Set("X-Is-Resource-Name", "true")
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Harbor refused the username or password")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Harbor refused: this account's role doesn't allow it")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusPreconditionFailed), rest.IsStatus(err, http.StatusConflict):
		return fmt.Errorf("Harbor refused (an immutability or retention rule, or it already exists): %w", err)
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) (http.Header, error) {
	return c.api.Do(ctx, method, path, q, body, out)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var hs struct {
		Status     string `json:"status"`
		Components []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"components"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/health", nil, nil, &hs); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var ps []json.RawMessage
	if _, err := c.do(ctx, http.MethodGet, "/projects", url.Values{"page_size": {"1"}}, nil, &ps); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "project").Error()}
	}
	if hs.Status != "healthy" {
		var bad []string
		for _, comp := range hs.Components {
			if comp.Status != "healthy" {
				bad = append(bad, comp.Name)
			}
		}
		return sdk.Health{Status: "degraded", Message: "unhealthy: " + strings.Join(bad, ", ")}
	}
	return sdk.Health{Status: "ok", Message: "healthy"}
}

type input struct {
	Name       string `json:"name"`
	Project    string `json:"project"`
	Repository string `json:"repository"`
	Reference  string `json:"reference"`
	Tag        string `json:"tag"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func project(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > 255 || !projectRe.MatchString(s) {
		return "", errors.New("the project is its name (lowercase, see projects)")
	}
	return s, nil
}

// repoPath checks a project and repository and returns the API path of the
// repository. Harbor wants slashes in repository names encoded twice.
func repoPath(p input) (string, string, string, error) {
	proj, err := project(p.Project)
	if err != nil {
		return "", "", "", err
	}
	repo := strings.Trim(strings.TrimSpace(p.Repository), "/")
	repo = strings.TrimPrefix(repo, proj+"/")
	if len(repo) > 255 || !repoRe.MatchString(repo) {
		return "", "", "", errors.New("the repository is its name in the project, like web/api")
	}
	return proj, repo, "/projects/" + url.PathEscape(proj) + "/repositories/" + url.PathEscape(url.PathEscape(repo)), nil
}

func reference(s string) (string, error) {
	s = strings.TrimSpace(s)
	if digestRe.MatchString(s) || tagRe.MatchString(s) {
		return s, nil
	}
	return "", errors.New("the reference is a tag or a sha256:… digest")
}

type scanReport struct {
	Status   string `json:"scan_status"`
	Severity string `json:"severity"`
	Start    string `json:"start_time"`
	End      string `json:"end_time"`
	Percent  int    `json:"complete_percent"`
	Summary  *struct {
		Total   int            `json:"total"`
		Fixable int            `json:"fixable"`
		By      map[string]int `json:"summary"`
	} `json:"summary"`
	Scanner *struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"scanner"`
}

type artifact struct {
	Digest   string `json:"digest"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	PushTime string `json:"push_time"`
	PullTime string `json:"pull_time"`
	Tags     []struct {
		Name      string `json:"name"`
		Immutable bool   `json:"immutable"`
	} `json:"tags"`
	ScanOverview map[string]scanReport `json:"scan_overview"`
}

func (a artifact) tags() []string {
	out := []string{}
	for _, t := range a.Tags {
		out = append(out, t.Name)
	}
	return out
}

func (a artifact) scan() map[string]any {
	keys := make([]string, 0, len(a.ScanOverview))
	for k := range a.ScanOverview {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return map[string]any{"status": "not scanned"}
	}
	sort.Strings(keys)
	r := a.ScanOverview[keys[0]]
	out := map[string]any{"status": r.Status, "severity": r.Severity, "completed": r.End}
	if r.Status == "Running" || r.Status == "Pending" {
		out["percent"] = r.Percent
	}
	if r.Summary != nil {
		out["total"], out["fixable"], out["bySeverity"] = r.Summary.Total, r.Summary.Fixable, r.Summary.By
	}
	if r.Scanner != nil {
		out["scanner"] = strings.TrimSpace(r.Scanner.Name + " " + r.Scanner.Version)
	}
	return out
}

func (a artifact) summary() map[string]any {
	return map[string]any{"digest": a.Digest, "tags": a.tags(), "type": a.Type, "size": a.Size, "pushed": a.PushTime, "pulled": a.PullTime, "scan": a.scan()}
}

func short(d string) string {
	if strings.HasPrefix(d, "sha256:") && len(d) > 19 {
		return d[:19]
	}
	return d
}

// getArtifact resolves a tag or digest to the artifact (and checks the digest).
func (c *conn) getArtifact(ctx context.Context, base, ref string) (artifact, error) {
	var a artifact
	q := url.Values{"with_tag": {"true"}, "with_scan_overview": {"true"}}
	if _, err := c.do(ctx, http.MethodGet, base+"/artifacts/"+url.PathEscape(ref), q, nil, &a); err != nil {
		return a, friendly(err, "artifact "+ref)
	}
	if !digestRe.MatchString(a.Digest) {
		return a, errors.New("unexpected artifact from Harbor")
	}
	return a, nil
}

func total(h http.Header, n int) int {
	if t, err := strconv.Atoi(h.Get("X-Total-Count")); err == nil {
		return t
	}
	return n
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
		q := url.Values{"page": {"1"}, "page_size": {"100"}}
		if n := strings.TrimSpace(p.Name); n != "" {
			if !filterRe.MatchString(n) {
				return sdk.Result{}, errors.New("the name filter is part of a project name")
			}
			q.Set("name", n)
		}
		var ps []struct {
			Name      string            `json:"name"`
			ID        int               `json:"project_id"`
			Owner     string            `json:"owner_name"`
			RepoCount int               `json:"repo_count"`
			Registry  int               `json:"registry_id"`
			Created   string            `json:"creation_time"`
			Metadata  map[string]string `json:"metadata"`
		}
		h, err := c.do(ctx, http.MethodGet, "/projects", q, nil, &ps)
		if err != nil {
			return sdk.Result{}, friendly(err, "project")
		}
		list := []map[string]any{}
		for _, pr := range ps {
			e := map[string]any{"name": pr.Name, "id": pr.ID, "public": pr.Metadata["public"] == "true", "repositories": pr.RepoCount, "owner": pr.Owner, "created": pr.Created}
			if pr.Registry != 0 {
				e["proxyCache"] = true
			}
			if pr.Metadata["auto_scan"] == "true" {
				e["autoScan"] = true
			}
			list = append(list, e)
		}
		return sdk.JSON(map[string]any{"total": total(h, len(ps)), "projects": list})

	case "repositories":
		proj, err := project(p.Project)
		if err != nil {
			return sdk.Result{}, err
		}
		var rs []struct {
			Name      string `json:"name"`
			Artifacts int    `json:"artifact_count"`
			Pulls     int    `json:"pull_count"`
			Updated   string `json:"update_time"`
			Desc      string `json:"description"`
		}
		h, err := c.do(ctx, http.MethodGet, "/projects/"+url.PathEscape(proj)+"/repositories", url.Values{"page": {"1"}, "page_size": {"100"}}, nil, &rs)
		if err != nil {
			return sdk.Result{}, friendly(err, "project "+proj)
		}
		list := []map[string]any{}
		for _, r := range rs {
			list = append(list, map[string]any{"name": strings.TrimPrefix(r.Name, proj+"/"), "artifacts": r.Artifacts, "pulls": r.Pulls, "updated": r.Updated, "description": r.Desc})
		}
		return sdk.JSON(map[string]any{"project": proj, "total": total(h, len(rs)), "repositories": list})

	case "artifacts":
		proj, repo, base, err := repoPath(p)
		if err != nil {
			return sdk.Result{}, err
		}
		var as []artifact
		q := url.Values{"page": {"1"}, "page_size": {"50"}, "with_tag": {"true"}, "with_scan_overview": {"true"}, "sort": {"-push_time"}}
		h, err := c.do(ctx, http.MethodGet, base+"/artifacts", q, nil, &as)
		if err != nil {
			return sdk.Result{}, friendly(err, "repository "+proj+"/"+repo)
		}
		list := []map[string]any{}
		for _, a := range as {
			list = append(list, a.summary())
		}
		return sdk.JSON(map[string]any{"repository": proj + "/" + repo, "total": total(h, len(as)), "artifacts": list})

	case "scan":
		proj, repo, base, err := repoPath(p)
		if err != nil {
			return sdk.Result{}, err
		}
		ref, err := reference(p.Reference)
		if err != nil {
			return sdk.Result{}, err
		}
		a, err := c.getArtifact(ctx, base, ref)
		if err != nil {
			return sdk.Result{}, err
		}
		name := proj + "/" + repo + "@" + short(a.Digest)
		if call.DryRun {
			last := a.scan()
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Scan %s (tags %s) for vulnerabilities; last scan: %v", name, strings.Join(a.tags(), ", "), last["status"]),
				Changes: []sdk.Change{{Target: "artifact " + name, Op: "scan", Before: mustJSON(last)}}}}, nil
		}
		if _, err := c.do(ctx, http.MethodPost, base+"/artifacts/"+url.PathEscape(a.Digest)+"/scan", nil, nil, nil); err != nil {
			return sdk.Result{}, friendly(err, "scanner for this project")
		}
		return sdk.JSON(map[string]any{"artifact": proj + "/" + repo, "digest": a.Digest, "scan": "started"})

	case "delete_artifact":
		proj, repo, base, err := repoPath(p)
		if err != nil {
			return sdk.Result{}, err
		}
		ref, err := reference(p.Reference)
		if err != nil {
			return sdk.Result{}, err
		}
		a, err := c.getArtifact(ctx, base, ref)
		if err != nil {
			return sdk.Result{}, err
		}
		name := proj + "/" + repo + "@" + short(a.Digest)
		if call.DryRun {
			sum := fmt.Sprintf("Delete %s (%d MiB) and its %d tag(s): %s. This can't be undone; anything pulling these tags fails", name, a.Size>>20, len(a.Tags), strings.Join(a.tags(), ", "))
			for _, t := range a.Tags {
				if t.Immutable {
					sum += "; tag " + t.Name + " is immutable, so Harbor will refuse"
				}
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "artifact " + name, Op: "delete", Before: mustJSON(map[string]any{"digest": a.Digest, "tags": a.tags(), "size": a.Size, "pushed": a.PushTime})}}}}, nil
		}
		// Delete by digest, so a tag moved in between doesn't take another artifact.
		if _, err := c.do(ctx, http.MethodDelete, base+"/artifacts/"+url.PathEscape(a.Digest), nil, nil, nil); err != nil {
			return sdk.Result{}, friendly(err, "artifact")
		}
		return sdk.JSON(map[string]any{"artifact": proj + "/" + repo, "digest": a.Digest, "deleted": true, "tags": a.tags()})

	case "delete_tag", "add_tag":
		proj, repo, base, err := repoPath(p)
		if err != nil {
			return sdk.Result{}, err
		}
		tag := strings.TrimSpace(p.Tag)
		if !tagRe.MatchString(tag) {
			return sdk.Result{}, errors.New("the tag is like v1.2.3 or latest")
		}
		if call.Action == "delete_tag" {
			return c.deleteTag(ctx, call, proj, repo, base, tag)
		}
		ref, err := reference(p.Reference)
		if err != nil {
			return sdk.Result{}, err
		}
		a, err := c.getArtifact(ctx, base, ref)
		if err != nil {
			return sdk.Result{}, err
		}
		name := proj + "/" + repo + "@" + short(a.Digest)
		for _, t := range a.tags() {
			if t == tag {
				return sdk.JSON(map[string]any{"artifact": proj + "/" + repo, "tag": tag, "note": "it already has this tag"})
			}
		}
		if call.DryRun {
			sum := fmt.Sprintf("Tag %s as %s:%s", name, proj+"/"+repo, tag)
			if _, err := c.getArtifact(ctx, base, tag); err == nil {
				sum += "; the tag is on another artifact now, so Harbor will refuse until it's removed there"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "artifact " + name, Op: "tag", Before: mustJSON(map[string]any{"tags": a.tags()}), After: mustJSON(map[string]any{"tags": append(a.tags(), tag)})}}}}, nil
		}
		if _, err := c.do(ctx, http.MethodPost, base+"/artifacts/"+url.PathEscape(a.Digest)+"/tags", nil, map[string]any{"name": tag}, nil); err != nil {
			return sdk.Result{}, friendly(err, "artifact")
		}
		res, err := sdk.JSON(map[string]any{"artifact": proj + "/" + repo, "digest": a.Digest, "tag": tag})
		res.Undo = sdk.UndoWith("delete_tag", map[string]any{"project": proj, "repository": repo, "tag": tag}, "Remove tag "+tag+" again")
		return res, err

	case "robots":
		q := url.Values{"page": {"1"}, "page_size": {"100"}}
		scope := "system"
		if strings.TrimSpace(p.Project) != "" {
			proj, err := project(p.Project)
			if err != nil {
				return sdk.Result{}, err
			}
			var pr struct {
				ID int `json:"project_id"`
			}
			if _, err := c.do(ctx, http.MethodGet, "/projects/"+url.PathEscape(proj), nil, nil, &pr); err != nil {
				return sdk.Result{}, friendly(err, "project "+proj)
			}
			if pr.ID <= 0 {
				return sdk.Result{}, errors.New("unexpected project from Harbor")
			}
			q.Set("q", fmt.Sprintf("Level=project,ProjectID=%d", pr.ID))
			scope = proj
		}
		var rs []struct {
			ID          int    `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Level       string `json:"level"`
			Disable     bool   `json:"disable"`
			ExpiresAt   int64  `json:"expires_at"`
			Duration    int    `json:"duration"`
			Created     string `json:"creation_time"`
			Permissions []struct {
				Kind      string `json:"kind"`
				Namespace string `json:"namespace"`
				Access    []struct {
					Resource string `json:"resource"`
					Action   string `json:"action"`
					Effect   string `json:"effect"`
				} `json:"access"`
			} `json:"permissions"`
		}
		h, err := c.do(ctx, http.MethodGet, "/robots", q, nil, &rs)
		if err != nil {
			return sdk.Result{}, friendly(err, "robot account")
		}
		list := []map[string]any{}
		for _, r := range rs {
			perms := []map[string]any{}
			for _, pm := range r.Permissions {
				var acc []string
				for _, a := range pm.Access {
					s := a.Resource + ":" + a.Action
					if a.Effect == "deny" {
						s = "!" + s
					}
					acc = append(acc, s)
				}
				perms = append(perms, map[string]any{"kind": pm.Kind, "namespace": pm.Namespace, "access": acc})
			}
			e := map[string]any{"id": r.ID, "name": r.Name, "description": r.Description, "level": r.Level, "disabled": r.Disable, "created": r.Created, "permissions": perms}
			if r.ExpiresAt > 0 {
				e["expires"] = time.Unix(r.ExpiresAt, 0).UTC().Format(time.RFC3339)
				if time.Unix(r.ExpiresAt, 0).Before(time.Now()) {
					e["expired"] = true
				}
			} else {
				e["expires"] = "never"
			}
			list = append(list, e)
		}
		return sdk.JSON(map[string]any{"scope": scope, "total": total(h, len(rs)), "robots": list})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) deleteTag(ctx context.Context, call sdk.Call, proj, repo, base, tag string) (sdk.Result, error) {
	a, err := c.getArtifact(ctx, base, tag)
	if err != nil {
		return sdk.Result{}, err
	}
	name := proj + "/" + repo + ":" + tag
	if call.DryRun {
		others := []string{}
		for _, t := range a.Tags {
			if t.Name != tag {
				others = append(others, t.Name)
			}
		}
		sum := fmt.Sprintf("Remove tag %s from %s; the artifact stays", name, short(a.Digest))
		if len(others) == 0 {
			sum += " with no tags (a retention rule for untagged artifacts may delete it)"
		} else {
			sum += " with tags " + strings.Join(others, ", ")
		}
		sum += "; undo adds the tag back to this digest"
		return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "tag " + name, Op: "delete", Before: mustJSON(map[string]any{"digest": a.Digest})}}}}, nil
	}
	if _, err := c.do(ctx, http.MethodDelete, base+"/artifacts/"+url.PathEscape(a.Digest)+"/tags/"+url.PathEscape(tag), nil, nil, nil); err != nil {
		return sdk.Result{}, friendly(err, "tag")
	}
	res, err := sdk.JSON(map[string]any{"artifact": proj + "/" + repo, "digest": a.Digest, "tag": tag, "deleted": true})
	res.Undo = sdk.UndoWith("add_tag", map[string]any{"project": proj, "repository": repo, "reference": a.Digest, "tag": tag}, "Add tag "+tag+" back")
	return res, err
}
