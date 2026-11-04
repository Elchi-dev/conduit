package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Actions, secrets and variables, webhooks, access, deploy keys,
// environments, organizations, search, notifications and gists.

var secretNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,199}$`)

// scope is where Actions secrets and variables live: a repository, one of
// its environments, or an organization.
func scope(p args) (base, label string, err error) {
	switch {
	case p.Org != "":
		if _, err := needName("org", p.Org); err != nil {
			return "", "", err
		}
		return "/orgs/" + p.Org + "/actions", "organization " + p.Org, nil
	case p.Environment != "":
		r, err := needRepo(p.Repo)
		if err != nil {
			return "", "", err
		}
		return "/repos/" + r + "/environments/" + seg(p.Environment), r + " environment " + p.Environment, nil
	}
	r, err := needRepo(p.Repo)
	if err != nil {
		return "", "", errors.New("name a repo (with an environment) or an org")
	}
	return "/repos/" + r + "/actions", r, nil
}

func secretName(n string) error {
	if !secretNameRe.MatchString(n) || strings.HasPrefix(strings.ToUpper(n), "GITHUB_") {
		return fmt.Errorf("%q isn't a valid name (letters, digits and _, not starting with GITHUB_)", n)
	}
	return nil
}

// hooksBase is a repository's or an organization's webhooks.
func hooksBase(p args) (string, error) {
	if p.Org != "" && p.Repo == "" {
		if _, err := needName("org", p.Org); err != nil {
			return "", err
		}
		return "/orgs/" + p.Org + "/hooks", nil
	}
	r, err := needRepo(p.Repo)
	if err != nil {
		return "", err
	}
	return "/repos/" + r + "/hooks", nil
}

var scopeProps = []string{pRepo, pEnv, pStr("org", "Organization (instead of repo)")}

func withScope(props ...string) []string { return append(append([]string{}, scopeProps...), props...) }

func init() {
	// --- Actions ---
	def(read("run", "Workflow run", "A run with its jobs and their steps.", schema("repo,runId", pRepo, pInt("runId", ""))),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil || p.RunID == 0 {
				return sdk.Result{}, errors.New("repo and runId are required")
			}
			var run map[string]any
			if err := a.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d", r, p.RunID), nil, &run); err != nil {
				return sdk.Result{}, err
			}
			jobs, err := a.list(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/jobs", r, p.RunID), nil, "jobs", 100)
			if err != nil {
				return sdk.Result{}, err
			}
			out := slim(pick(run, "id", "name", "display_title", "head_branch", "head_sha", "event", "status", "conclusion", "run_attempt", "run_started_at", "updated_at", "html_url", "actor")).(map[string]any)
			out["jobs"] = slimAll(jobs)
			return sdk.JSON(out)
		})
	def(read("jobs", "Jobs of a run", "", schema("repo,runId", pRepo, pInt("runId", ""), pEnum("filter", "", "latest", "all"))),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil || p.RunID == 0 {
				return sdk.Result{}, errors.New("repo and runId are required")
			}
			return a.listSlim(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/jobs", r, p.RunID), nil, "jobs", 100)
		})
	def(read("job_logs", "Job log", "The end of a job's log (at most 2000 lines and 256 KB).", schema("repo,jobId", pRepo, pInt("jobId", ""), pInt("tailLines", "Lines from the end (default 200)"))),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil || p.JobID == 0 {
				return sdk.Result{}, errors.New("repo and jobId are required")
			}
			n := p.TailLines
			if n <= 0 {
				n = 200
			}
			if n > 2000 {
				n = 2000
			}
			res, err := a.raw(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/actions/jobs/%d/logs", r, p.JobID), nil, nil, nil, 256<<10, true)
			if err != nil {
				return sdk.Result{}, err
			}
			if res.Status >= 300 {
				return sdk.Result{}, fmt.Errorf("GitHub answered %d (logs expire after the retention period)", res.Status)
			}
			lines := strings.Split(strings.TrimRight(string(res.Body), "\n"), "\n")
			cut := res.Truncated
			if res.Truncated && len(lines) > 0 {
				lines = lines[1:] // the first line is partial
			}
			if len(lines) > n {
				lines, cut = lines[len(lines)-n:], true
			}
			return sdk.JSON(map[string]any{"jobId": p.JobID, "lines": len(lines), "truncated": cut, "log": strings.Join(lines, "\n")})
		})
	def(write("rerun_run", "Re-run a workflow run", "Re-runs every job (rerun re-runs only the failed ones).", schema("repo,runId", pRepo, pInt("runId", "")), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			return a.post(ctx, c, p.Repo, fmt.Sprintf("/actions/runs/%d/rerun", p.RunID), p.RunID != 0, fmt.Sprintf("Re-run run %d", p.RunID))
		})
	def(write("rerun_job", "Re-run a job", "", schema("repo,jobId", pRepo, pInt("jobId", "")), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			return a.post(ctx, c, p.Repo, fmt.Sprintf("/actions/jobs/%d/rerun", p.JobID), p.JobID != 0, fmt.Sprintf("Re-run job %d", p.JobID))
		})
	def(write("cancel_run", "Cancel a workflow run", "", schema("repo,runId", pRepo, pInt("runId", "")), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			return a.post(ctx, c, p.Repo, fmt.Sprintf("/actions/runs/%d/cancel", p.RunID), p.RunID != 0, fmt.Sprintf("Cancel run %d", p.RunID))
		})
	def(read("workflows", "Workflows", "", schema("repo", pRepo)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, "/repos/"+r+"/actions/workflows", nil, "workflows", 100)
		})
	def(write("dispatch_workflow", "Run a workflow", "Starts a workflow that has a workflow_dispatch trigger.", schema("repo,workflow,ref", pRepo, pStr("workflow", "Workflow file name (ci.yml) or id"),
		pStr("ref", "Branch or tag"), pObj("inputs", "The workflow's inputs")), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if needText("workflow", p.Workflow) != nil || needText("ref", p.Ref) != nil {
				return sdk.Result{}, errors.New("workflow and ref are required")
			}
			body := map[string]any{"ref": p.Ref}
			if len(p.Inputs) > 0 {
				body["inputs"] = p.Inputs
			}
			if c.DryRun {
				return plan("Run "+p.Workflow+" on "+p.Ref, r+":"+p.Workflow, "dispatch", nil, body)
			}
			if err := a.send(ctx, http.MethodPost, "/repos/"+r+"/actions/workflows/"+seg(p.Workflow)+"/dispatches", body, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"dispatched": p.Workflow, "ref": p.Ref})
		})
	for _, enable := range []bool{true, false} {
		name, title, verb, undo := "enable_workflow", "Enable a workflow", "enable", "disable_workflow"
		if !enable {
			name, title, verb, undo = "disable_workflow", "Disable a workflow", "disable", "enable_workflow"
		}
		def(write(name, title, "", schema("repo,workflow", pRepo, pStr("workflow", "File name or id")), true),
			func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
				r, err := needRepo(p.Repo)
				if err != nil {
					return sdk.Result{}, err
				}
				if err := needText("workflow", p.Workflow); err != nil {
					return sdk.Result{}, err
				}
				if c.DryRun {
					return plan(title+" "+p.Workflow, r+":"+p.Workflow, verb, nil, nil)
				}
				if err := a.send(ctx, http.MethodPut, "/repos/"+r+"/actions/workflows/"+seg(p.Workflow)+"/"+verb, nil, nil); err != nil {
					return sdk.Result{}, err
				}
				res, err := sdk.JSON(map[string]any{"workflow": p.Workflow, "enabled": enable})
				return withUndo(res, err, undo, map[string]string{"repo": r, "workflow": p.Workflow}, "Undo")
			})
	}
	def(read("artifacts", "Artifacts", "Build artifacts of a repository or one run.", schema("repo", pRepo, pInt("runId", ""), pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			path := "/repos/" + r + "/actions/artifacts"
			if p.RunID != 0 {
				path = fmt.Sprintf("/repos/%s/actions/runs/%d/artifacts", r, p.RunID)
			}
			return a.listSlim(ctx, path, nil, "artifacts", p.limit())
		})

	// --- secrets (names only; values are write-only) ---
	def(read("secrets", "Actions secrets", "Names of a repository's, environment's or organization's secrets (values can't be read).", schema("", withScope(pLimit)...)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			base, _, err := scope(p)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, base+"/secrets", nil, "secrets", p.limit())
		})
	def(sdk.ActionSpec{Name: "set_secret", Title: "Set an Actions secret", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true,
		Description: "Creates or replaces a secret. The value is encrypted for GitHub (sealed box) before it leaves Conduit and never logged.",
		Input: schema("name,value", withScope(pStr("name", "Secret name"), `"value":{"type":"string","x-secret":true,"description":"The secret value"}`,
			pEnum("visibility", "Organization secrets: which repositories get it (default private)", "all", "private", "selected"),
			`"selectedRepositoryIds":{"type":"array","items":{"type":"integer"},"description":"With visibility selected"}`)...)},
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			base, label, err := scope(p)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := secretName(p.Name); err != nil {
				return sdk.Result{}, err
			}
			if p.Value == "" {
				return sdk.Result{}, errors.New("value is required")
			}
			exists := a.get(ctx, base+"/secrets/"+seg(p.Name), nil, nil) == nil
			op := "create"
			if exists {
				op = "update"
			}
			if c.DryRun {
				return plan(fmt.Sprintf("%s secret %s in %s", capital(op), p.Name, label), label+": "+p.Name, op, nil, map[string]string{"value": "(hidden)"})
			}
			var pk struct {
				KeyID string `json:"key_id"`
				Key   string `json:"key"`
			}
			if err := a.get(ctx, base+"/secrets/public-key", nil, &pk); err != nil {
				return sdk.Result{}, fmt.Errorf("public key: %w", err)
			}
			enc, err := sealSecret(pk.Key, p.Value)
			if err != nil {
				return sdk.Result{}, err
			}
			body := map[string]any{"encrypted_value": enc, "key_id": pk.KeyID}
			if p.Org != "" {
				vis := p.Visibility
				if vis == "" {
					vis = "private"
				}
				body["visibility"] = vis
				if vis == "selected" {
					body["selected_repository_ids"] = p.Repos
				}
			}
			if err := a.send(ctx, http.MethodPut, base+"/secrets/"+seg(p.Name), body, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"name": p.Name, "scope": label, op + "d": true})
		})
	def(destructive("delete_secret", "Delete an Actions secret", "Workflows using it fail until it's set again. Can't be undone (values can't be read back).", schema("name", withScope(pStr("name", ""))...), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			base, label, err := scope(p)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := secretName(p.Name); err != nil {
				return sdk.Result{}, err
			}
			var cur map[string]any
			if err := a.get(ctx, base+"/secrets/"+seg(p.Name), nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Delete secret "+p.Name+" in "+label, label+": "+p.Name, "delete", pick(cur, "name", "updated_at"), nil)
			}
			if err := a.send(ctx, http.MethodDelete, base+"/secrets/"+seg(p.Name), nil, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]string{"deleted": p.Name, "scope": label})
		})

	// --- variables ---
	def(read("variables", "Actions variables", "", schema("", withScope(pLimit)...)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			base, _, err := scope(p)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, base+"/variables", nil, "variables", p.limit())
		})
	def(write("set_variable", "Set an Actions variable", "Creates or changes a variable. Undo restores the previous value.", schema("name,value", withScope(pStr("name", ""), pStr("value", ""),
		pEnum("visibility", "Organization variables (default private)", "all", "private", "selected"))...), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			base, label, err := scope(p)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := secretName(p.Name); err != nil {
				return sdk.Result{}, err
			}
			var cur struct {
				Value string `json:"value"`
			}
			gerr := a.get(ctx, base+"/variables/"+seg(p.Name), nil, &cur)
			if gerr != nil && !isNotFound(gerr) {
				return sdk.Result{}, gerr
			}
			exists := gerr == nil
			if c.DryRun {
				var before any
				if exists {
					before = cur.Value
				}
				return plan("Set variable "+p.Name+" in "+label, label+": "+p.Name, map[bool]string{true: "update", false: "create"}[exists], before, p.Value)
			}
			body := map[string]any{"name": p.Name, "value": p.Value}
			if p.Org != "" {
				vis := p.Visibility
				if vis == "" {
					vis = "private"
				}
				body["visibility"] = vis
			}
			if exists {
				err = a.send(ctx, http.MethodPatch, base+"/variables/"+seg(p.Name), body, nil)
			} else {
				err = a.send(ctx, http.MethodPost, base+"/variables", body, nil)
			}
			if err != nil {
				return sdk.Result{}, err
			}
			res, err := sdk.JSON(map[string]string{"name": p.Name, "scope": label})
			if err != nil {
				return res, err
			}
			sc := map[string]any{"repo": p.Repo, "org": p.Org, "environment": p.Environment, "name": p.Name}
			if !exists {
				return withUndo(res, nil, "delete_variable", sc, "Delete variable "+p.Name)
			}
			sc["value"] = cur.Value
			return withUndo(res, nil, "set_variable", sc, "Restore the previous value")
		})
	def(destructive("delete_variable", "Delete an Actions variable", "Undo recreates it with the same value.", schema("name", withScope(pStr("name", ""))...), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			base, label, err := scope(p)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := secretName(p.Name); err != nil {
				return sdk.Result{}, err
			}
			var cur struct {
				Value string `json:"value"`
			}
			if err := a.get(ctx, base+"/variables/"+seg(p.Name), nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Delete variable "+p.Name+" in "+label, label+": "+p.Name, "delete", cur.Value, nil)
			}
			if err := a.send(ctx, http.MethodDelete, base+"/variables/"+seg(p.Name), nil, nil); err != nil {
				return sdk.Result{}, err
			}
			res, err := sdk.JSON(map[string]string{"deleted": p.Name, "scope": label})
			return withUndo(res, err, "set_variable", map[string]any{"repo": p.Repo, "org": p.Org, "environment": p.Environment, "name": p.Name, "value": cur.Value}, "Recreate "+p.Name)
		})

	// --- webhooks ---
	hookProps := []string{pRepo, pStr("org", "Organization (instead of repo)")}
	def(read("hooks", "Webhooks", "", schema("", hookProps...)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			base, err := hooksBase(p)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, base, nil, "", 100)
		})
	def(sdk.ActionSpec{Name: "create_hook", Title: "Create a webhook", Risk: sdk.RiskWrite, DryRun: true, Sensitive: true,
		Description: "Sends events to a URL. The optional secret signs deliveries; it's never logged.",
		Input: schema("url", append(hookProps, pStr("url", "Payload URL"), pStrs("events", "Default [push]"), pEnum("contentType", "", "json", "form"),
			`"secret":{"type":"string","x-secret":true}`, pBool("active", "Default true"))...)},
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			base, err := hooksBase(p)
			if err != nil {
				return sdk.Result{}, err
			}
			u, err := url.Parse(p.URL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return sdk.Result{}, errors.New("url must be an http(s) URL")
			}
			events := p.Events
			if len(events) == 0 {
				events = []string{"push"}
			}
			ct := p.ContentType
			if ct == "" {
				ct = "json"
			}
			cfg := map[string]any{"url": p.URL, "content_type": ct}
			if p.Secret != "" {
				cfg["secret"] = p.Secret
			}
			body := map[string]any{"name": "web", "active": p.Active == nil || *p.Active, "events": events, "config": cfg}
			if c.DryRun {
				return plan("Send "+strings.Join(events, ", ")+" events to "+u.Host, base, "create", nil, map[string]any{"url": p.URL, "events": events})
			}
			res, _, err := a.sendSlim(ctx, http.MethodPost, base, body)
			return res, err
		})
	def(write("update_hook", "Change a webhook", "URL, events or active state. Undo restores them.", schema("id", append(hookProps, pInt("id", "Hook id"), pStr("url", ""), pStrs("events", ""), pBool("active", ""))...), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			base, err := hooksBase(p)
			if err != nil || p.ID == 0 {
				return sdk.Result{}, errors.New("repo or org, and id, are required")
			}
			path := fmt.Sprintf("%s/%d", base, p.ID)
			var cur struct {
				Active bool           `json:"active"`
				Events []string       `json:"events"`
				Config map[string]any `json:"config"`
			}
			if err := a.get(ctx, path, nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			body := map[string]any{}
			if p.URL != "" {
				body["config"] = map[string]any{"url": p.URL, "content_type": cur.Config["content_type"]}
			}
			if len(p.Events) > 0 {
				body["events"] = p.Events
			}
			if p.Active != nil {
				body["active"] = *p.Active
			}
			if len(body) == 0 {
				return sdk.Result{}, errors.New("nothing to change")
			}
			before := map[string]any{"url": cur.Config["url"], "events": cur.Events, "active": cur.Active}
			if c.DryRun {
				return plan(fmt.Sprintf("Change webhook %d", p.ID), path, "update", before, body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPatch, path, body)
			return withUndo(res, err, "update_hook", map[string]any{"repo": p.Repo, "org": p.Org, "id": p.ID, "url": cur.Config["url"], "events": cur.Events, "active": cur.Active}, "Restore the webhook")
		})
	def(destructive("delete_hook", "Delete a webhook", "", schema("id", append(hookProps, pInt("id", "Hook id"))...), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			base, err := hooksBase(p)
			if err != nil || p.ID == 0 {
				return sdk.Result{}, errors.New("repo or org, and id, are required")
			}
			path := fmt.Sprintf("%s/%d", base, p.ID)
			var cur map[string]any
			if err := a.get(ctx, path, nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				cfg, _ := cur["config"].(map[string]any)
				return plan(fmt.Sprintf("Delete webhook %d", p.ID), path, "delete", map[string]any{"url": cfg["url"], "events": cur["events"]}, nil)
			}
			if err := a.send(ctx, http.MethodDelete, path, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"deleted": p.ID})
		})
	def(write("ping_hook", "Ping a webhook", "Sends a test delivery.", schema("id", append(hookProps, pInt("id", "Hook id"))...), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			base, err := hooksBase(p)
			if err != nil || p.ID == 0 {
				return sdk.Result{}, errors.New("repo or org, and id, are required")
			}
			path := fmt.Sprintf("%s/%d/pings", base, p.ID)
			if c.DryRun {
				return plan(fmt.Sprintf("Ping webhook %d", p.ID), path, "ping", nil, nil)
			}
			if err := a.send(ctx, http.MethodPost, path, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"pinged": p.ID})
		})
	def(read("hook_deliveries", "Webhook deliveries", "Recent deliveries and their answers.", schema("id", append(hookProps, pInt("id", "Hook id"), pLimit)...)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			base, err := hooksBase(p)
			if err != nil || p.ID == 0 {
				return sdk.Result{}, errors.New("repo or org, and id, are required")
			}
			q := url.Values{"per_page": {fmt.Sprint(min(p.limit(), 100))}}
			var items []any
			if err := a.get(ctx, fmt.Sprintf("%s/%d/deliveries", base, p.ID), q, &items); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(slim(items))
		})

	// --- collaborators and teams ---
	def(read("collaborators", "Collaborators", "People with access and their permission.", schema("repo", pRepo, pEnum("affiliation", "", "outside", "direct", "all"), pLimit)),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			var f struct {
				Affiliation string `json:"affiliation"`
			}
			_ = sdk.Decode(c, &f)
			q := url.Values{}
			if f.Affiliation != "" {
				q.Set("affiliation", f.Affiliation)
			}
			items, err := a.list(ctx, "/repos/"+r+"/collaborators", q, "", p.limit())
			if err != nil {
				return sdk.Result{}, err
			}
			out := []map[string]any{}
			for _, raw := range items {
				m := toMap(raw)
				out = append(out, map[string]any{"login": m["login"], "role": m["role_name"], "permissions": m["permissions"]})
			}
			return sdk.JSON(out)
		})
	def(write("add_collaborator", "Add a collaborator", "Invites a person (or changes their permission). Undo removes them or restores the old permission.",
		schema("repo,username", pRepo, pStr("username", "GitHub login"), pEnum("permission", "Default push", "pull", "triage", "push", "maintain", "admin")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if _, err := needName("username", p.Username); err != nil {
				return sdk.Result{}, err
			}
			perm := p.Permission
			if perm == "" {
				perm = "push"
			}
			prev := a.collaboratorRole(ctx, r, p.Username)
			if c.DryRun {
				return plan(fmt.Sprintf("Give %s %s access to %s", p.Username, perm, r), r+": "+p.Username, "update", prev, perm)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPut, "/repos/"+r+"/collaborators/"+p.Username, map[string]string{"permission": perm})
			if prev == "" {
				return withUndo(res, err, "remove_collaborator", map[string]string{"repo": r, "username": p.Username}, "Remove "+p.Username)
			}
			return withUndo(res, err, "add_collaborator", map[string]string{"repo": r, "username": p.Username, "permission": prev}, "Restore "+p.Username+"'s permission")
		})
	def(destructive("remove_collaborator", "Remove a collaborator", "Undo invites them again with the same permission.", schema("repo,username", pRepo, pStr("username", "")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if _, err := needName("username", p.Username); err != nil {
				return sdk.Result{}, err
			}
			prev := a.collaboratorRole(ctx, r, p.Username)
			if c.DryRun {
				return plan("Remove "+p.Username+" from "+r, r+": "+p.Username, "delete", prev, nil)
			}
			if err := a.send(ctx, http.MethodDelete, "/repos/"+r+"/collaborators/"+p.Username, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			res, err := sdk.JSON(map[string]string{"removed": p.Username})
			if prev == "" {
				return res, err
			}
			return withUndo(res, err, "add_collaborator", map[string]string{"repo": r, "username": p.Username, "permission": prev}, "Add "+p.Username+" again")
		})
	def(read("repo_teams", "Teams with access", "", schema("repo", pRepo)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, "/repos/"+r+"/teams", nil, "", 100)
		})
	def(read("org_teams", "Teams", "An organization's teams.", schema("org", pOrg, pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			o, err := needName("org", p.Org)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, "/orgs/"+o+"/teams", nil, "", p.limit())
		})
	def(write("set_team_access", "Give a team access", "Adds a team to a repository or changes its permission. Undo restores it.",
		schema("repo,team,permission", pRepo, pStr("team", "Team slug"), pEnum("permission", "", "pull", "triage", "push", "maintain", "admin")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if _, err := needName("team", p.Team); err != nil || p.Permission == "" {
				return sdk.Result{}, errors.New("team and permission are required")
			}
			prev, err := a.teamPermission(ctx, r, p.Team)
			if err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan(fmt.Sprintf("Give team %s %s access to %s", p.Team, p.Permission, r), r+": team "+p.Team, "update", prev, p.Permission)
			}
			org := strings.Split(r, "/")[0]
			if err := a.send(ctx, http.MethodPut, "/orgs/"+org+"/teams/"+p.Team+"/repos/"+r, map[string]string{"permission": p.Permission}, nil); err != nil {
				return sdk.Result{}, err
			}
			res, err := sdk.JSON(map[string]string{"team": p.Team, "permission": p.Permission})
			if prev == "" {
				return withUndo(res, err, "remove_team_access", map[string]string{"repo": r, "team": p.Team}, "Remove team "+p.Team)
			}
			return withUndo(res, err, "set_team_access", map[string]string{"repo": r, "team": p.Team, "permission": prev}, "Restore team "+p.Team+"'s permission")
		})
	def(destructive("remove_team_access", "Remove a team's access", "Undo gives the team its permission back.", schema("repo,team", pRepo, pStr("team", "Team slug")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if _, err := needName("team", p.Team); err != nil {
				return sdk.Result{}, err
			}
			prev, err := a.teamPermission(ctx, r, p.Team)
			if err != nil {
				return sdk.Result{}, err
			}
			if prev == "" {
				return sdk.Result{}, fmt.Errorf("team %s has no access to %s", p.Team, r)
			}
			if c.DryRun {
				return plan("Remove team "+p.Team+" from "+r, r+": team "+p.Team, "delete", prev, nil)
			}
			org := strings.Split(r, "/")[0]
			if err := a.send(ctx, http.MethodDelete, "/orgs/"+org+"/teams/"+p.Team+"/repos/"+r, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			res, err := sdk.JSON(map[string]string{"removed": p.Team})
			return withUndo(res, err, "set_team_access", map[string]string{"repo": r, "team": p.Team, "permission": prev}, "Give team "+p.Team+" access again")
		})

	// --- deploy keys ---
	def(read("deploy_keys", "Deploy keys", "", schema("repo", pRepo)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, "/repos/"+r+"/keys", nil, "", 100)
		})
	def(write("add_deploy_key", "Add a deploy key", "An SSH public key with access to one repository.", schema("repo,title,key", pRepo, pTitle, pText("key", "The public key (ssh-ed25519 …)"), pBool("readOnly", "Default true")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if needText("title", p.Title) != nil || !strings.HasPrefix(strings.TrimSpace(p.Key), "ssh-") && !strings.HasPrefix(strings.TrimSpace(p.Key), "ecdsa-") && !strings.HasPrefix(strings.TrimSpace(p.Key), "sk-") {
				return sdk.Result{}, errors.New("title and an SSH public key are required")
			}
			ro := p.ReadOnly == nil || *p.ReadOnly
			body := map[string]any{"title": p.Title, "key": strings.TrimSpace(p.Key), "read_only": ro}
			if c.DryRun {
				return plan(fmt.Sprintf("Add deploy key %q (%s)", p.Title, map[bool]string{true: "read-only", false: "read and write"}[ro]), r, "create", nil, body)
			}
			res, raw, err := a.sendSlim(ctx, http.MethodPost, "/repos/"+r+"/keys", body)
			return withUndo(res, err, "delete_deploy_key", map[string]any{"repo": r, "id": int64(num(toMap(raw)["id"]))}, "Remove the deploy key")
		})
	def(destructive("delete_deploy_key", "Remove a deploy key", "Undo adds the same public key again.", schema("repo,id", pRepo, pInt("id", "Key id")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil || p.ID == 0 {
				return sdk.Result{}, errors.New("repo and id are required")
			}
			path := fmt.Sprintf("/repos/%s/keys/%d", r, p.ID)
			var cur map[string]any
			if err := a.get(ctx, path, nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Remove deploy key "+str(cur, "title"), path, "delete", pick(cur, "title", "read_only", "created_at"), nil)
			}
			if err := a.send(ctx, http.MethodDelete, path, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			res, err := sdk.JSON(map[string]any{"deleted": p.ID})
			ro, _ := cur["read_only"].(bool)
			return withUndo(res, err, "add_deploy_key", map[string]any{"repo": r, "title": cur["title"], "key": cur["key"], "readOnly": ro}, "Add the key again")
		})

	// --- environments ---
	def(read("environments", "Environments", "Deployment environments and their protection rules.", schema("repo", pRepo)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, "/repos/"+r+"/environments", nil, "environments", 100)
		})
	def(write("set_environment", "Create or change an environment", "Wait timer, required reviewers and which branches may deploy. Undo restores the previous rules (or deletes a new environment).",
		schema("repo,name", pRepo, pStr("name", "Environment name"), pObj("settings", `GitHub's fields: wait_timer (minutes), prevent_self_review, reviewers [{type: User|Team, id}], deployment_branch_policy {protected_branches, custom_branch_policies} or null`)), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("name", p.Name); err != nil {
				return sdk.Result{}, err
			}
			path := "/repos/" + r + "/environments/" + seg(p.Name)
			body := pick(p.Settings, "wait_timer", "prevent_self_review", "reviewers", "deployment_branch_policy")
			var cur map[string]any
			gerr := a.get(ctx, path, nil, &cur)
			if gerr != nil && !isNotFound(gerr) {
				return sdk.Result{}, gerr
			}
			var before map[string]any
			if gerr == nil {
				before = environmentInput(cur)
			}
			if c.DryRun {
				op := "create"
				if before != nil {
					op = "update"
				}
				return plan(capital(op)+" environment "+p.Name, r+": "+p.Name, op, before, body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPut, path, body)
			if before == nil {
				return withUndo(res, err, "delete_environment", map[string]string{"repo": r, "name": p.Name}, "Delete environment "+p.Name)
			}
			return withUndo(res, err, "set_environment", map[string]any{"repo": r, "name": p.Name, "settings": before}, "Restore environment "+p.Name)
		})
	def(destructive("delete_environment", "Delete an environment", "Its secrets and variables go with it.", schema("repo,name", pRepo, pStr("name", "")), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			path := "/repos/" + r + "/environments/" + seg(p.Name)
			var cur map[string]any
			if err := a.get(ctx, path, nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Delete environment "+p.Name, r+": "+p.Name, "delete", environmentInput(cur), nil)
			}
			if err := a.send(ctx, http.MethodDelete, path, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]string{"deleted": p.Name})
		})

	// --- organizations ---
	def(read("orgs", "Organizations", "Organizations you belong to.", nil),
		func(ctx context.Context, a *account, _ args, _ sdk.Call) (sdk.Result, error) {
			return a.listSlim(ctx, "/user/orgs", nil, "", 100)
		})
	def(read("org_members", "Organization members", "", schema("org", pOrg, pEnum("role", "", "all", "admin", "member"), pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			o, err := needName("org", p.Org)
			if err != nil {
				return sdk.Result{}, err
			}
			q := url.Values{}
			if p.Role != "" {
				q.Set("role", p.Role)
			}
			return a.listSlim(ctx, "/orgs/"+o+"/members", q, "", p.limit())
		})
	def(write("set_org_membership", "Invite or change an organization member", "Invites a person, or changes a member's role. Undo restores it.",
		schema("org,username", pOrg, pStr("username", ""), pEnum("role", "Default member", "member", "admin")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			o, err := needName("org", p.Org)
			if err != nil {
				return sdk.Result{}, err
			}
			if _, err := needName("username", p.Username); err != nil {
				return sdk.Result{}, err
			}
			role := p.Role
			if role == "" {
				role = "member"
			}
			var cur struct {
				Role  string `json:"role"`
				State string `json:"state"`
			}
			gerr := a.get(ctx, "/orgs/"+o+"/memberships/"+p.Username, nil, &cur)
			if gerr != nil && !isNotFound(gerr) {
				return sdk.Result{}, gerr
			}
			if c.DryRun {
				return plan(fmt.Sprintf("Make %s %s of %s", p.Username, role, o), o+": "+p.Username, "update", cur.Role, role)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPut, "/orgs/"+o+"/memberships/"+p.Username, map[string]string{"role": role})
			if gerr != nil {
				return withUndo(res, err, "remove_org_member", map[string]string{"org": o, "username": p.Username}, "Remove "+p.Username)
			}
			return withUndo(res, err, "set_org_membership", map[string]string{"org": o, "username": p.Username, "role": cur.Role}, "Restore "+p.Username+"'s role")
		})
	def(destructive("remove_org_member", "Remove an organization member", "They lose access to the organization's repositories. Undo invites them again.", schema("org,username", pOrg, pStr("username", "")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			o, err := needName("org", p.Org)
			if err != nil {
				return sdk.Result{}, err
			}
			if _, err := needName("username", p.Username); err != nil {
				return sdk.Result{}, err
			}
			var cur struct {
				Role string `json:"role"`
			}
			if err := a.get(ctx, "/orgs/"+o+"/memberships/"+p.Username, nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Remove "+p.Username+" from "+o, o+": "+p.Username, "delete", cur.Role, nil)
			}
			if err := a.send(ctx, http.MethodDelete, "/orgs/"+o+"/memberships/"+p.Username, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			res, err := sdk.JSON(map[string]string{"removed": p.Username})
			return withUndo(res, err, "set_org_membership", map[string]string{"org": o, "username": p.Username, "role": cur.Role}, "Invite "+p.Username+" again")
		})

	// --- search and notifications ---
	def(read("search", "Search GitHub", "Code, issues and pull requests, repositories, commits or users, with GitHub's search syntax.",
		schema("type,query", pEnum("type", "", "code", "issues", "repositories", "commits", "users"), pStr("query", "e.g. \"repo:owner/name TODO\" or \"is:pr is:open author:@me\""), pStr("sort", ""), pEnum("order", "", "desc", "asc"), pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			switch p.Type {
			case "code", "issues", "repositories", "commits", "users":
			default:
				return sdk.Result{}, errors.New("type is code, issues, repositories, commits or users")
			}
			if err := needText("query", p.Query); err != nil {
				return sdk.Result{}, err
			}
			q := url.Values{"q": {p.Query}}
			if p.Sort != "" {
				q.Set("sort", p.Sort)
			}
			if p.Order != "" {
				q.Set("order", p.Order)
			}
			lim := p.limit()
			if lim > 100 {
				lim = 100 // search pages are expensive and rate limited
			}
			items, err := a.list(ctx, "/search/"+p.Type, q, "items", lim)
			if err != nil {
				return sdk.Result{}, err
			}
			out := slimAll(items)
			for _, x := range out {
				if m, ok := x.(map[string]any); ok {
					delete(m, "score")
					if r, ok := m["repository"].(map[string]any); ok {
						m["repository"] = r["full_name"]
					}
				}
			}
			return sdk.JSON(out)
		})
	def(read("notifications", "Notifications", "Your unread notifications (or all).", schema("", pBool("all", "Include read ones"), pBool("participating", "Only where you're involved"), pLimit)),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			var f struct {
				Participating bool `json:"participating"`
			}
			_ = sdk.Decode(c, &f)
			q := url.Values{}
			if p.All {
				q.Set("all", "true")
			}
			if f.Participating {
				q.Set("participating", "true")
			}
			items, err := a.list(ctx, "/notifications", q, "", p.limit())
			if err != nil {
				return sdk.Result{}, err
			}
			out := []map[string]any{}
			for _, raw := range items {
				m := toMap(raw)
				sub, _ := m["subject"].(map[string]any)
				repo, _ := m["repository"].(map[string]any)
				out = append(out, map[string]any{"threadId": m["id"], "repo": repo["full_name"], "reason": m["reason"], "unread": m["unread"], "updated": m["updated_at"],
					"title": sub["title"], "type": sub["type"]})
			}
			return sdk.JSON(out)
		})
	def(write("mark_notifications_read", "Mark notifications read", "One thread, or everything up to now.", schema("", pStr("threadId", "Leave empty for all")), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			if c.DryRun {
				what := "all notifications"
				if p.ThreadID != "" {
					what = "thread " + p.ThreadID
				}
				return plan("Mark "+what+" read", "notifications", "update", nil, nil)
			}
			var err error
			if p.ThreadID != "" {
				if _, e := needName("threadId", p.ThreadID); e != nil {
					return sdk.Result{}, e
				}
				err = a.send(ctx, http.MethodPatch, "/notifications/threads/"+p.ThreadID, nil, nil)
			} else {
				err = a.send(ctx, http.MethodPut, "/notifications", map[string]any{"last_read_at": time.Now().UTC().Format(time.RFC3339), "read": true}, nil)
			}
			if err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]bool{"ok": true})
		})

	// --- gists ---
	def(read("gists", "Gists", "Your gists.", schema("", pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			items, err := a.list(ctx, "/gists", nil, "", p.limit())
			if err != nil {
				return sdk.Result{}, err
			}
			out := []map[string]any{}
			for _, raw := range items {
				m := toMap(raw)
				files, _ := m["files"].(map[string]any)
				out = append(out, map[string]any{"gistId": m["id"], "description": m["description"], "public": m["public"], "files": keys(files), "updated": m["updated_at"], "url": m["html_url"]})
			}
			return sdk.JSON(out)
		})
	def(read("gist", "Gist", "A gist with its files (each cut to 64 KB).", schema("gistId", pStr("gistId", ""))),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			g, err := a.gist(ctx, p.GistID)
			if err != nil {
				return sdk.Result{}, err
			}
			files := map[string]string{}
			for name, f := range g.Files {
				c := f.Content
				if len(c) > 64<<10 {
					c = c[:64<<10] + "\n… (cut)"
				}
				files[name] = c
			}
			return sdk.JSON(map[string]any{"gistId": g.ID, "description": g.Description, "public": g.Public, "files": files, "url": g.HTMLURL})
		})
	def(write("create_gist", "Create a gist", "", schema("files", pStr("description", ""), pBool("public", "Default secret (unlisted)"), `"files":{"type":"object","additionalProperties":{"type":"string"},"description":"File name to content"}`), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			if len(p.Files) == 0 {
				return sdk.Result{}, errors.New("add at least one file")
			}
			files := map[string]any{}
			for n, content := range p.Files {
				files[n] = map[string]string{"content": content}
			}
			pub := p.Public != nil && *p.Public
			if c.DryRun {
				return plan(fmt.Sprintf("Create a %s gist with %d file(s)", map[bool]string{true: "public", false: "secret"}[pub], len(files)), "gists", "create", nil, keys(files))
			}
			res, raw, err := a.sendSlim(ctx, http.MethodPost, "/gists", map[string]any{"description": p.Description, "public": pub, "files": files})
			id := str(toMap(raw), "id")
			return withUndo(res, err, "delete_gist", map[string]string{"gistId": id}, "Delete the gist")
		})
	def(write("update_gist", "Change a gist", "Description and files (a file set to an empty string is deleted). Undo restores the previous files.",
		schema("gistId", pStr("gistId", ""), pStr("description", ""), `"files":{"type":"object","additionalProperties":{"type":"string"}}`), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			g, err := a.gist(ctx, p.GistID)
			if err != nil {
				return sdk.Result{}, err
			}
			files := map[string]any{}
			undoFiles := map[string]string{}
			for n, content := range p.Files {
				if old, ok := g.Files[n]; ok {
					undoFiles[n] = old.Content
				} else {
					undoFiles[n] = ""
				}
				if content == "" {
					files[n] = nil
				} else {
					files[n] = map[string]string{"content": content}
				}
			}
			body := map[string]any{"files": files}
			var raw map[string]any
			_ = sdk.Decode(c, &raw)
			if _, ok := raw["description"]; ok {
				body["description"] = p.Description
			}
			if c.DryRun {
				return plan("Change gist "+g.ID, "gist "+g.ID, "update", map[string]any{"description": g.Description, "files": undoFiles}, body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPatch, "/gists/"+g.ID, body)
			return withUndo(res, err, "update_gist", map[string]any{"gistId": g.ID, "description": g.Description, "files": undoFiles}, "Restore the gist")
		})
	def(destructive("delete_gist", "Delete a gist", "", schema("gistId", pStr("gistId", "")), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			g, err := a.gist(ctx, p.GistID)
			if err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				names := []string{}
				for n := range g.Files {
					names = append(names, n)
				}
				return plan("Delete gist "+g.ID, "gist "+g.ID, "delete", map[string]any{"description": g.Description, "files": names}, nil)
			}
			if err := a.send(ctx, http.MethodDelete, "/gists/"+g.ID, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]string{"deleted": g.ID})
		})
}

func capital(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// post sends a bodyless POST under a repository (re-runs, cancels).
func (a *account) post(ctx context.Context, c sdk.Call, repo, sub string, ok bool, summary string) (sdk.Result, error) {
	r, err := needRepo(repo)
	if err != nil || !ok {
		return sdk.Result{}, errors.New("repo and an id are required")
	}
	if c.DryRun {
		return plan(summary+" in "+r, r, "update", nil, nil)
	}
	if err := a.send(ctx, http.MethodPost, "/repos/"+r+sub, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]bool{"ok": true})
}

// collaboratorRole is a person's direct role on a repository ("" when they
// have none).
func (a *account) collaboratorRole(ctx context.Context, repo, user string) string {
	if a.get(ctx, "/repos/"+repo+"/collaborators/"+user, nil, nil) != nil {
		return ""
	}
	var p struct {
		Permission string `json:"permission"`
		RoleName   string `json:"role_name"`
	}
	if a.get(ctx, "/repos/"+repo+"/collaborators/"+user+"/permission", nil, &p) != nil {
		return ""
	}
	// role_name uses the UI names; the API takes pull/push for read/write.
	switch r := p.RoleName; r {
	case "read":
		return "pull"
	case "write":
		return "push"
	case "":
		return map[string]string{"read": "pull", "write": "push", "admin": "admin"}[p.Permission]
	default:
		return r
	}
}

// teamPermission is a team's permission on a repository ("" for none).
func (a *account) teamPermission(ctx context.Context, repo, team string) (string, error) {
	items, err := a.list(ctx, "/repos/"+repo+"/teams", nil, "", 300)
	if err != nil {
		return "", err
	}
	for _, raw := range items {
		m := toMap(raw)
		if str(m, "slug") == team {
			return str(m, "permission"), nil
		}
	}
	return "", nil
}

// environmentInput converts an environment into the body that recreates its
// protection rules.
func environmentInput(e map[string]any) map[string]any {
	out := map[string]any{"wait_timer": 0, "reviewers": []any{}, "deployment_branch_policy": e["deployment_branch_policy"]}
	rules, _ := e["protection_rules"].([]any)
	for _, x := range rules {
		r, _ := x.(map[string]any)
		switch r["type"] {
		case "wait_timer":
			out["wait_timer"] = r["wait_timer"]
		case "required_reviewers":
			if v, ok := r["prevent_self_review"]; ok {
				out["prevent_self_review"] = v
			}
			revs := []any{}
			list, _ := r["reviewers"].([]any)
			for _, y := range list {
				rv, _ := y.(map[string]any)
				who, _ := rv["reviewer"].(map[string]any)
				revs = append(revs, map[string]any{"type": rv["type"], "id": who["id"]})
			}
			out["reviewers"] = revs
		}
	}
	return out
}

type gistFile struct {
	Content string `json:"content"`
}

type gistData struct {
	ID          string              `json:"id"`
	Description string              `json:"description"`
	Public      bool                `json:"public"`
	HTMLURL     string              `json:"html_url"`
	Files       map[string]gistFile `json:"files"`
}

func (a *account) gist(ctx context.Context, id string) (gistData, error) {
	if _, err := needName("gistId", id); err != nil {
		return gistData{}, err
	}
	var g gistData
	err := a.get(ctx, "/gists/"+id, nil, &g)
	return g, err
}
