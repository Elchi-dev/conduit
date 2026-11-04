package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Repository settings update_repo may change.
var repoSettings = []string{"name", "description", "homepage", "private", "visibility", "default_branch", "has_issues", "has_projects", "has_wiki",
	"has_discussions", "is_template", "allow_squash_merge", "allow_merge_commit", "allow_rebase_merge", "allow_auto_merge", "delete_branch_on_merge",
	"allow_update_branch", "web_commit_signoff_required", "squash_merge_commit_title", "squash_merge_commit_message", "merge_commit_title", "merge_commit_message"}

func init() {
	// --- repositories ---
	def(read("repo", "Repository", "A repository's settings and counts.", schema("repo", pRepo)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.getSlim(ctx, "/repos/"+r, nil)
		})
	def(write("create_repo", "Create a repository", "Creates a repository for you or in an organization.", schema("name",
		pStr("name", "Repository name"), pOrg, pStr("description", ""), pEnum("visibility", "Default private", "private", "public", "internal"),
		pBool("autoInit", "Start with a README"), pStr("gitignore", "gitignore template, e.g. Go"), pStr("license", "License template, e.g. mit")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			if _, err := needName("name", p.Name); err != nil {
				return sdk.Result{}, err
			}
			path := "/user/repos"
			if p.Org != "" {
				if _, err := needName("org", p.Org); err != nil {
					return sdk.Result{}, err
				}
				path = "/orgs/" + p.Org + "/repos"
			}
			vis := p.Visibility
			if vis == "" {
				vis = "private"
			}
			var extra struct {
				Gitignore string `json:"gitignore"`
				License   string `json:"license"`
			}
			_ = sdk.Decode(c, &extra)
			body := map[string]any{"name": p.Name, "description": p.Description, "private": vis != "public", "auto_init": p.AutoInit}
			if vis == "internal" {
				body["visibility"] = "internal"
			}
			if extra.Gitignore != "" {
				body["gitignore_template"] = extra.Gitignore
			}
			if extra.License != "" {
				body["license_template"] = extra.License
			}
			owner := p.Org
			if owner == "" {
				owner = "you"
			}
			if c.DryRun {
				return plan(fmt.Sprintf("Create the %s repository %s/%s", vis, owner, p.Name), owner+"/"+p.Name, "create", nil, body)
			}
			res, raw, err := a.sendSlim(ctx, http.MethodPost, path, body)
			full := str(toMap(raw), "full_name")
			return withUndo(res, err, "delete_repo", map[string]string{"repo": full}, "Delete "+full)
		})
	def(destructive("update_repo", "Change repository settings", "Description, homepage, visibility (private/public/internal), default branch, features (issues, wiki, projects, discussions), merge options, or a new name. Making a repository public or renaming it can't be contained, so this is destructive. Undo restores the previous settings.",
		schema("repo,settings", pRepo, pObj("settings", "Settings to change, by GitHub's names: description, homepage, visibility, private, default_branch, has_issues, has_wiki, has_projects, has_discussions, allow_squash_merge, allow_merge_commit, allow_rebase_merge, allow_auto_merge, delete_branch_on_merge, name ...")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			want := pick(p.Settings, repoSettings...)
			if len(want) == 0 {
				return sdk.Result{}, errors.New("settings names nothing that can be changed: " + strings.Join(repoSettings, ", "))
			}
			var cur map[string]any
			if err := a.get(ctx, "/repos/"+r, nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			before := pick(cur, keys(want)...)
			if c.DryRun {
				return plan("Change the settings of "+r, r, "update", before, want)
			}
			res, raw, err := a.sendSlim(ctx, http.MethodPatch, "/repos/"+r, want)
			full := str(toMap(raw), "full_name")
			if full == "" {
				full = r
			}
			if _, renamed := want["name"]; renamed {
				before["name"] = cur["name"]
			}
			return withUndo(res, err, "update_repo", map[string]any{"repo": full, "settings": before}, "Restore the previous settings of "+r)
		})
	def(write("set_topics", "Set repository topics", "Replaces the repository's topics.", schema("repo,topics", pRepo, pStrs("topics", "Lowercase topics")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			var cur struct {
				Names []string `json:"names"`
			}
			if err := a.get(ctx, "/repos/"+r+"/topics", nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			if cur.Names == nil {
				cur.Names = []string{}
			}
			topics := p.Topics
			if topics == nil {
				topics = []string{}
			}
			if c.DryRun {
				return plan("Set the topics of "+r, r, "update", cur.Names, topics)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPut, "/repos/"+r+"/topics", map[string]any{"names": topics})
			return withUndo(res, err, "set_topics", map[string]any{"repo": r, "topics": cur.Names}, "Restore the previous topics")
		})
	for _, arch := range []bool{true, false} {
		name, title, verb, undo := "archive_repo", "Archive a repository", "Archive", "unarchive_repo"
		if !arch {
			name, title, verb, undo = "unarchive_repo", "Unarchive a repository", "Unarchive", "archive_repo"
		}
		spec := write(name, title, "Archived repositories are read-only.", schema("repo", pRepo), true)
		if arch {
			// Archiving stops every push, issue and pull request, so it's
			// destructive (unarchiving gives that back, so it stays write).
			spec = destructive(name, title, "Makes the repository read-only: no pushes, issues or pull requests until it's unarchived, so this is destructive. Undo unarchives it.", schema("repo", pRepo), true)
		}
		def(spec,
			func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
				r, err := needRepo(p.Repo)
				if err != nil {
					return sdk.Result{}, err
				}
				if c.DryRun {
					return plan(verb+" "+r, r, "update", map[string]bool{"archived": !arch}, map[string]bool{"archived": arch})
				}
				res, _, err := a.sendSlim(ctx, http.MethodPatch, "/repos/"+r, map[string]bool{"archived": arch})
				return withUndo(res, err, undo, map[string]string{"repo": r}, strings.TrimSuffix(undo, "_repo")+" "+r)
			})
	}
	def(destructive("delete_repo", "Delete a repository", "Deletes a repository with its issues, pull requests, wiki and releases. Can't be undone. The token needs Administration write.", schema("repo", pRepo), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			var cur map[string]any
			if err := a.get(ctx, "/repos/"+r, nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Permanently delete "+r, r, "delete", pick(cur, "full_name", "private", "stargazers_count", "forks_count", "open_issues_count", "pushed_at"), nil)
			}
			if err := a.send(ctx, http.MethodDelete, "/repos/"+r, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]string{"deleted": r})
		})
	def(destructive("transfer_repo", "Transfer a repository", "Moves a repository to another user or organization. The new owner must accept when it's a user.",
		schema("repo,newOwner", pRepo, pStr("newOwner", "User or organization to move it to"), pStr("newName", "Optional new name")), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if _, err := needName("newOwner", p.NewOwner); err != nil {
				return sdk.Result{}, err
			}
			body := map[string]any{"new_owner": p.NewOwner}
			if p.NewName != "" {
				if _, err := needName("newName", p.NewName); err != nil {
					return sdk.Result{}, err
				}
				body["new_name"] = p.NewName
			}
			if c.DryRun {
				return plan("Transfer "+r+" to "+p.NewOwner, r, "transfer", map[string]string{"owner": strings.Split(r, "/")[0]}, body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPost, "/repos/"+r+"/transfer", body)
			return res, err
		})
	def(write("fork_repo", "Fork a repository", "", schema("repo", pRepo, pOrg, pStr("name", "Name of the fork")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			body := map[string]any{}
			if p.Org != "" {
				body["organization"] = p.Org
			}
			if p.Name != "" {
				body["name"] = p.Name
			}
			if c.DryRun {
				return plan("Fork "+r, r, "fork", nil, body)
			}
			res, raw, err := a.sendSlim(ctx, http.MethodPost, "/repos/"+r+"/forks", body)
			full := str(toMap(raw), "full_name")
			return withUndo(res, err, "delete_repo", map[string]string{"repo": full}, "Delete the fork "+full)
		})

	// --- branches and protection ---
	def(read("branches", "Branches", "", schema("repo", pRepo, pBool("protected", "Only protected branches"), pLimit)),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			var f struct {
				Protected bool `json:"protected"`
			}
			_ = sdk.Decode(c, &f)
			q := url.Values{}
			if f.Protected {
				q.Set("protected", "true")
			}
			return a.listSlim(ctx, "/repos/"+r+"/branches", q, "", p.limit())
		})
	def(read("branch", "Branch", "A branch with its head commit and protection.", schema("repo,branch", pRepo, pStr("branch", ""))),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("branch", p.Branch); err != nil {
				return sdk.Result{}, err
			}
			return a.getSlim(ctx, "/repos/"+r+"/branches/"+seg(p.Branch), nil)
		})
	def(write("create_branch", "Create a branch", "From another branch, a tag or a commit (default: the default branch).",
		schema("repo,branch", pRepo, pStr("branch", "New branch name"), pStr("from", "Branch, tag or commit SHA to start from")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("branch", p.Branch); err != nil {
				return sdk.Result{}, err
			}
			sha, err := a.resolveRef(ctx, r, p.From)
			if err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Create branch "+p.Branch+" at "+short(sha), r+"@"+p.Branch, "create", nil, map[string]string{"sha": sha})
			}
			res, _, err := a.sendSlim(ctx, http.MethodPost, "/repos/"+r+"/git/refs", map[string]string{"ref": "refs/heads/" + p.Branch, "sha": sha})
			return withUndo(res, err, "delete_branch", map[string]string{"repo": r, "branch": p.Branch}, "Delete branch "+p.Branch)
		})
	def(destructive("delete_branch", "Delete a branch", "Undo recreates it at the same commit.", schema("repo,branch", pRepo, pStr("branch", "")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("branch", p.Branch); err != nil {
				return sdk.Result{}, err
			}
			var ref struct {
				Object struct {
					SHA string `json:"sha"`
				} `json:"object"`
			}
			if err := a.get(ctx, "/repos/"+r+"/git/ref/heads/"+seg(p.Branch), nil, &ref); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Delete branch "+p.Branch+" (at "+short(ref.Object.SHA)+")", r+"@"+p.Branch, "delete", map[string]string{"sha": ref.Object.SHA}, nil)
			}
			if err := a.send(ctx, http.MethodDelete, "/repos/"+r+"/git/refs/heads/"+seg(p.Branch), nil, nil); err != nil {
				return sdk.Result{}, err
			}
			res, err := sdk.JSON(map[string]string{"deleted": p.Branch, "sha": ref.Object.SHA})
			return withUndo(res, err, "create_branch", map[string]string{"repo": r, "branch": p.Branch, "from": ref.Object.SHA}, "Recreate branch "+p.Branch)
		})
	def(write("rename_branch", "Rename a branch", "Open pull requests and protection follow the new name.", schema("repo,branch,newName", pRepo, pStr("branch", ""), pStr("newName", "")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if needText("branch", p.Branch) != nil || needText("newName", p.NewName) != nil {
				return sdk.Result{}, errors.New("branch and newName are required")
			}
			if c.DryRun {
				return plan("Rename branch "+p.Branch+" to "+p.NewName, r+"@"+p.Branch, "rename", p.Branch, p.NewName)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPost, "/repos/"+r+"/branches/"+seg(p.Branch)+"/rename", map[string]string{"new_name": p.NewName})
			return withUndo(res, err, "rename_branch", map[string]string{"repo": r, "branch": p.NewName, "newName": p.Branch}, "Rename back to "+p.Branch)
		})
	def(read("branch_protection", "Branch protection", "The protection rules of a branch.", schema("repo,branch", pRepo, pStr("branch", ""))),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			res, err := a.getSlim(ctx, "/repos/"+r+"/branches/"+seg(p.Branch)+"/protection", nil)
			if isNotFound(err) {
				return sdk.JSON(map[string]any{"protected": false})
			}
			return res, err
		})
	def(destructive("set_branch_protection", "Protect a branch", "Sets a branch's protection rules (replacing the current ones): looser rules let changes in without review or checks, so this is destructive. Undo restores the previous rules.",
		schema("repo,branch,protection", pRepo, pStr("branch", ""), pObj("protection", `GitHub's protection object: required_status_checks {strict, contexts}, enforce_admins, required_pull_request_reviews {required_approving_review_count, dismiss_stale_reviews, require_code_owner_reviews}, restrictions {users, teams, apps} or null, required_linear_history, allow_force_pushes, allow_deletions, required_conversation_resolution. Missing required keys default to null.`)), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("branch", p.Branch); err != nil {
				return sdk.Result{}, err
			}
			body := map[string]any{"required_status_checks": nil, "enforce_admins": nil, "required_pull_request_reviews": nil, "restrictions": nil}
			for k, v := range p.Protection {
				body[k] = v
			}
			prev, had, err := a.protection(ctx, r, p.Branch)
			if err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				var before any
				if had {
					before = prev
				}
				return plan("Set the protection of "+p.Branch, r+"@"+p.Branch, "update", before, body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPut, "/repos/"+r+"/branches/"+seg(p.Branch)+"/protection", body)
			if !had {
				return withUndo(res, err, "delete_branch_protection", map[string]string{"repo": r, "branch": p.Branch}, "Remove the protection again")
			}
			return withUndo(res, err, "set_branch_protection", map[string]any{"repo": r, "branch": p.Branch, "protection": prev}, "Restore the previous protection")
		})
	def(destructive("delete_branch_protection", "Remove branch protection", "Undo restores the rules.", schema("repo,branch", pRepo, pStr("branch", "")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			prev, had, err := a.protection(ctx, r, p.Branch)
			if err != nil {
				return sdk.Result{}, err
			}
			if !had {
				return sdk.Result{}, fmt.Errorf("%s isn't protected", p.Branch)
			}
			if c.DryRun {
				return plan("Remove the protection of "+p.Branch, r+"@"+p.Branch, "delete", prev, nil)
			}
			if err := a.send(ctx, http.MethodDelete, "/repos/"+r+"/branches/"+seg(p.Branch)+"/protection", nil, nil); err != nil {
				return sdk.Result{}, err
			}
			res, err := sdk.JSON(map[string]string{"unprotected": p.Branch})
			return withUndo(res, err, "set_branch_protection", map[string]any{"repo": r, "branch": p.Branch, "protection": prev}, "Protect "+p.Branch+" again")
		})

	// --- files, trees, commits ---
	def(read("file", "Read a file", "A file's text (or base64 for binary files, up to 1 MB) and its SHA, or a directory listing.",
		schema("repo,path", pRepo, pStr("path", "File or directory path"), pStr("ref", "Branch, tag or commit (default branch when empty)"))),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			f, raw, err := a.contents(ctx, r, p.Path, p.Ref)
			if err != nil {
				return sdk.Result{}, err
			}
			if f == nil {
				return sdk.JSON(slimRaw(raw))
			}
			out := map[string]any{"path": f.Path, "sha": f.SHA, "size": f.Size, "url": f.HTMLURL}
			if b, err := f.bytes(); err == nil {
				if utf8.Valid(b) {
					out["content"], out["encoding"] = string(b), "utf-8"
				} else {
					out["content"], out["encoding"] = base64.StdEncoding.EncodeToString(b), "base64"
				}
			} else {
				out["note"] = "too large to show here; use the download URL"
				out["downloadUrl"] = f.DownloadURL
			}
			return sdk.JSON(out)
		})
	def(read("tree", "File tree", "Paths in a repository at a ref (bounded).", schema("repo", pRepo, pStr("ref", "Branch, tag or commit"), pStr("path", "Only paths under this directory"), pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			ref := p.Ref
			if ref == "" {
				ref = "HEAD"
			}
			var t struct {
				Tree []struct {
					Path string `json:"path"`
					Type string `json:"type"`
					Size int    `json:"size"`
				} `json:"tree"`
				Truncated bool `json:"truncated"`
			}
			if err := a.get(ctx, "/repos/"+r+"/git/trees/"+seg(ref), url.Values{"recursive": {"1"}}, &t); err != nil {
				return sdk.Result{}, err
			}
			lim := p.Limit
			if lim <= 0 || lim > 2000 {
				lim = 500
			}
			prefix := strings.Trim(p.Path, "/")
			out := []map[string]any{}
			more := t.Truncated
			for _, e := range t.Tree {
				if prefix != "" && e.Path != prefix && !strings.HasPrefix(e.Path, prefix+"/") {
					continue
				}
				if len(out) >= lim {
					more = true
					break
				}
				out = append(out, map[string]any{"path": e.Path, "type": e.Type, "size": e.Size})
			}
			return sdk.JSON(map[string]any{"entries": out, "truncated": more})
		})
	def(write("put_file", "Create or update a file", "Commits a file. Undo commits the previous content back (or deletes a new file).",
		schema("repo,path,content,message", pRepo, pStr("path", ""), pText("content", "The new content"), pEnum("encoding", "How content is given (default utf-8)", "utf-8", "base64"),
			pStr("message", "Commit message"), pStr("branch", "Branch (default branch when empty)"), pStr("sha", "The SHA of the file being replaced; looked up when empty")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			fp, err := filePath(p.Path)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("message", p.Message); err != nil {
				return sdk.Result{}, err
			}
			content := p.Content
			if p.Encoding != "base64" {
				content = base64.StdEncoding.EncodeToString([]byte(p.Content))
			} else if _, err := base64.StdEncoding.DecodeString(content); err != nil {
				return sdk.Result{}, errors.New("content isn't valid base64")
			}
			cur, _, err := a.contents(ctx, r, p.Path, p.Branch)
			if err != nil && !isNotFound(err) {
				return sdk.Result{}, err
			}
			if cur == nil && err == nil {
				return sdk.Result{}, fmt.Errorf("%s is a directory", p.Path)
			}
			body := map[string]any{"message": p.Message, "content": content}
			if p.Branch != "" {
				body["branch"] = p.Branch
			}
			if cur != nil {
				if p.SHA != "" && p.SHA != cur.SHA {
					return sdk.Result{}, fmt.Errorf("%s changed since %s (now %s)", p.Path, short(p.SHA), short(cur.SHA))
				}
				body["sha"] = cur.SHA
			}
			if c.DryRun {
				var before any
				op := "create"
				if cur != nil {
					op = "update"
					if b, err := cur.bytes(); err == nil && utf8.Valid(b) {
						before = string(b)
					} else {
						before = map[string]any{"sha": cur.SHA, "size": cur.Size}
					}
				}
				after := any(p.Content)
				if p.Encoding == "base64" {
					after = map[string]any{"base64Bytes": len(p.Content)}
				}
				return plan(fmt.Sprintf("Commit %s: %s", p.Path, p.Message), r+":"+p.Path, op, before, after)
			}
			var res struct {
				Content struct {
					SHA string `json:"sha"`
				} `json:"content"`
				Commit struct {
					SHA     string `json:"sha"`
					HTMLURL string `json:"html_url"`
				} `json:"commit"`
			}
			if err := a.send(ctx, http.MethodPut, "/repos/"+r+"/contents/"+fp, body, &res); err != nil {
				return sdk.Result{}, err
			}
			out, err := sdk.JSON(map[string]string{"path": p.Path, "sha": res.Content.SHA, "commit": res.Commit.SHA, "url": res.Commit.HTMLURL})
			if cur == nil {
				return withUndo(out, err, "delete_file", map[string]string{"repo": r, "path": p.Path, "branch": p.Branch, "sha": res.Content.SHA, "message": "Revert: " + p.Message}, "Delete "+p.Path+" again")
			}
			prev, berr := cur.bytes()
			if berr != nil {
				return out, err // too large to keep for undo
			}
			return withUndo(out, err, "put_file", map[string]string{"repo": r, "path": p.Path, "branch": p.Branch, "sha": res.Content.SHA, "content": base64.StdEncoding.EncodeToString(prev), "encoding": "base64", "message": "Revert: " + p.Message}, "Restore the previous "+p.Path)
		})
	def(destructive("delete_file", "Delete a file", "Commits the file's removal. Undo commits it back.",
		schema("repo,path,message", pRepo, pStr("path", ""), pStr("message", "Commit message"), pStr("branch", ""), pStr("sha", "The SHA of the file; looked up when empty")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			fp, err := filePath(p.Path)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("message", p.Message); err != nil {
				return sdk.Result{}, err
			}
			cur, _, err := a.contents(ctx, r, p.Path, p.Branch)
			if err != nil {
				return sdk.Result{}, err
			}
			if cur == nil {
				return sdk.Result{}, fmt.Errorf("%s is a directory", p.Path)
			}
			if p.SHA != "" && p.SHA != cur.SHA {
				return sdk.Result{}, fmt.Errorf("%s changed since %s (now %s)", p.Path, short(p.SHA), short(cur.SHA))
			}
			if c.DryRun {
				return plan(fmt.Sprintf("Delete %s: %s", p.Path, p.Message), r+":"+p.Path, "delete", map[string]any{"sha": cur.SHA, "size": cur.Size}, nil)
			}
			prev, berr := cur.bytes()
			body := map[string]any{"message": p.Message, "sha": cur.SHA}
			if p.Branch != "" {
				body["branch"] = p.Branch
			}
			var res struct {
				Commit struct {
					SHA     string `json:"sha"`
					HTMLURL string `json:"html_url"`
				} `json:"commit"`
			}
			if err := a.send(ctx, http.MethodDelete, "/repos/"+r+"/contents/"+fp, body, &res); err != nil {
				return sdk.Result{}, err
			}
			out, err := sdk.JSON(map[string]string{"deleted": p.Path, "commit": res.Commit.SHA, "url": res.Commit.HTMLURL})
			if berr != nil {
				return out, err
			}
			return withUndo(out, err, "put_file", map[string]string{"repo": r, "path": p.Path, "branch": p.Branch, "content": base64.StdEncoding.EncodeToString(prev), "encoding": "base64", "message": "Revert: " + p.Message}, "Restore "+p.Path)
		})
	def(read("commits", "Commits", "Recent commits, newest first.", schema("repo", pRepo, pStr("ref", "Branch, tag or SHA to start from"), pStr("path", "Only commits touching this path"),
		pStr("author", "GitHub login or email"), pStr("since", "ISO 8601 time"), pStr("until", "ISO 8601 time"), pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			q := url.Values{}
			for k, v := range map[string]string{"sha": p.Ref, "path": p.Path, "author": p.Author, "since": p.Since, "until": p.Until} {
				if v != "" {
					q.Set(k, v)
				}
			}
			items, err := a.list(ctx, "/repos/"+r+"/commits", q, "", p.limit())
			if err != nil {
				return sdk.Result{}, err
			}
			out := []map[string]any{}
			for _, raw := range items {
				var cm ghCommit
				_ = json.Unmarshal(raw, &cm)
				out = append(out, cm.row())
			}
			return sdk.JSON(out)
		})
	def(read("commit", "Commit", "One commit with its changed files (patches cut to 4 KB each, 100 files).", schema("repo,ref", pRepo, pStr("ref", "SHA, branch or tag"))),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("ref", p.Ref); err != nil {
				return sdk.Result{}, err
			}
			var cm ghCommit
			if err := a.get(ctx, "/repos/"+r+"/commits/"+seg(p.Ref), nil, &cm); err != nil {
				return sdk.Result{}, err
			}
			out := cm.row()
			out["stats"] = cm.Stats
			out["files"] = boundFiles(cm.Files, 100)
			return sdk.JSON(out)
		})
	def(read("compare", "Compare", "How head differs from base: commits ahead and behind, and the changed files.", schema("repo,base,head", pRepo, pStr("base", ""), pStr("head", ""))),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if needText("base", p.Base) != nil || needText("head", p.Head) != nil {
				return sdk.Result{}, errors.New("base and head are required")
			}
			var cmp struct {
				Status    string     `json:"status"`
				Ahead     int        `json:"ahead_by"`
				Behind    int        `json:"behind_by"`
				Total     int        `json:"total_commits"`
				HTMLURL   string     `json:"html_url"`
				Commits   []ghCommit `json:"commits"`
				Files     []ghFile   `json:"files"`
				MergeBase ghCommit   `json:"merge_base_commit"`
			}
			if err := a.get(ctx, "/repos/"+r+"/compare/"+seg(p.Base)+"..."+seg(p.Head), url.Values{"per_page": {"100"}}, &cmp); err != nil {
				return sdk.Result{}, err
			}
			commits := []map[string]any{}
			for i, cm := range cmp.Commits {
				if i >= 100 {
					break
				}
				commits = append(commits, cm.row())
			}
			return sdk.JSON(map[string]any{"status": cmp.Status, "aheadBy": cmp.Ahead, "behindBy": cmp.Behind, "totalCommits": cmp.Total, "mergeBase": cmp.MergeBase.SHA,
				"url": cmp.HTMLURL, "commits": commits, "files": boundFiles(cmp.Files, 100)})
		})
	def(read("checks", "Checks", "Check runs and commit statuses for a ref.", schema("repo,ref", pRepo, pStr("ref", "SHA, branch or tag"))),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("ref", p.Ref); err != nil {
				return sdk.Result{}, err
			}
			runs, err := a.list(ctx, "/repos/"+r+"/commits/"+seg(p.Ref)+"/check-runs", nil, "check_runs", 100)
			if err != nil {
				return sdk.Result{}, err
			}
			var st struct {
				State    string            `json:"state"`
				Statuses []json.RawMessage `json:"statuses"`
			}
			_ = a.get(ctx, "/repos/"+r+"/commits/"+seg(p.Ref)+"/status", nil, &st)
			checks := []map[string]any{}
			for _, raw := range runs {
				m := toMap(raw)
				checks = append(checks, map[string]any{"name": m["name"], "status": m["status"], "conclusion": m["conclusion"], "url": m["html_url"], "started": m["started_at"], "completed": m["completed_at"]})
			}
			// A status's description is free text from the CI server.
			statuses := slimAll(st.Statuses)
			for _, x := range statuses {
				if m, ok := x.(map[string]any); ok {
					if d, ok := m["description"].(string); ok {
						m["description"] = rest.Redact(d)
					}
				}
			}
			return sdk.JSON(map[string]any{"checkRuns": checks, "combinedState": st.State, "statuses": statuses})
		})
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// resolveRef turns a branch, tag or SHA (or "" for the default branch) into
// a commit SHA.
func (a *account) resolveRef(ctx context.Context, repo, ref string) (string, error) {
	if ref == "" {
		var r struct {
			DefaultBranch string `json:"default_branch"`
		}
		if err := a.get(ctx, "/repos/"+repo, nil, &r); err != nil {
			return "", err
		}
		ref = r.DefaultBranch
	}
	var cm struct {
		SHA string `json:"sha"`
	}
	if err := a.get(ctx, "/repos/"+repo+"/commits/"+seg(ref), nil, &cm); err != nil {
		return "", fmt.Errorf("%s: %w", ref, err)
	}
	return cm.SHA, nil
}

type ghContent struct {
	Type        string `json:"type"`
	Path        string `json:"path"`
	SHA         string `json:"sha"`
	Size        int    `json:"size"`
	Content     string `json:"content"`
	Encoding    string `json:"encoding"`
	HTMLURL     string `json:"html_url"`
	DownloadURL string `json:"download_url"`
}

func (f *ghContent) bytes() ([]byte, error) {
	if f.Encoding != "base64" {
		return nil, errors.New("content not included")
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
}

// contents reads a path: a file (f set) or a directory (f nil, raw listing).
func (a *account) contents(ctx context.Context, repo, path, ref string) (*ghContent, json.RawMessage, error) {
	fp, err := filePath(path)
	if err != nil {
		return nil, nil, err
	}
	q := url.Values{}
	if ref != "" {
		q.Set("ref", ref)
	}
	var raw json.RawMessage
	if err := a.get(ctx, "/repos/"+repo+"/contents/"+fp, q, &raw); err != nil {
		return nil, nil, err
	}
	if len(raw) > 0 && raw[0] == '[' {
		return nil, raw, nil
	}
	var f ghContent
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, err
	}
	if f.Type != "file" {
		return nil, raw, nil
	}
	return &f, raw, nil
}

// protection reads a branch's protection in the shape PUT accepts.
func (a *account) protection(ctx context.Context, repo, branch string) (map[string]any, bool, error) {
	var g map[string]any
	err := a.get(ctx, "/repos/"+repo+"/branches/"+seg(branch)+"/protection", nil, &g)
	if isNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return protectionInput(g), true, nil
}

// protectionInput converts GitHub's protection answer into the request body
// that sets the same rules.
func protectionInput(g map[string]any) map[string]any {
	enabled := func(k string) any {
		if m, ok := g[k].(map[string]any); ok {
			return m["enabled"]
		}
		return nil
	}
	out := map[string]any{"required_status_checks": nil, "enforce_admins": enabled("enforce_admins"), "required_pull_request_reviews": nil, "restrictions": nil}
	if out["enforce_admins"] == nil {
		out["enforce_admins"] = false
	}
	if sc, ok := g["required_status_checks"].(map[string]any); ok {
		out["required_status_checks"] = map[string]any{"strict": sc["strict"], "contexts": orEmpty(sc["contexts"])}
	}
	if rv, ok := g["required_pull_request_reviews"].(map[string]any); ok {
		out["required_pull_request_reviews"] = pick(rv, "dismiss_stale_reviews", "require_code_owner_reviews", "required_approving_review_count", "require_last_push_approval")
	}
	if rs, ok := g["restrictions"].(map[string]any); ok {
		out["restrictions"] = map[string]any{"users": names(rs["users"], "login"), "teams": names(rs["teams"], "slug"), "apps": names(rs["apps"], "slug")}
	}
	for _, k := range []string{"required_linear_history", "allow_force_pushes", "allow_deletions", "block_creations", "required_conversation_resolution", "lock_branch", "allow_fork_syncing"} {
		if v := enabled(k); v != nil {
			out[k] = v
		}
	}
	return out
}

func orEmpty(v any) any {
	if v == nil {
		return []any{}
	}
	return v
}

func names(v any, key string) []string {
	out := []string{}
	list, _ := v.([]any)
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			if s, ok := m[key].(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

type ghCommit struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Commit  struct {
		Message string `json:"message"`
		Author  struct {
			Name string `json:"name"`
			Date string `json:"date"`
		} `json:"author"`
	} `json:"commit"`
	Author *struct {
		Login string `json:"login"`
	} `json:"author"`
	Stats map[string]int `json:"stats,omitempty"`
	Files []ghFile       `json:"files"`
}

func (c ghCommit) row() map[string]any {
	who := c.Commit.Author.Name
	if c.Author != nil && c.Author.Login != "" {
		who = c.Author.Login
	}
	return map[string]any{"sha": c.SHA, "message": rest.Redact(c.Commit.Message), "author": who, "date": c.Commit.Author.Date, "url": c.HTMLURL}
}

type ghFile struct {
	Filename  string `json:"filename"`
	Status    string `json:"status"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	Patch     string `json:"patch,omitempty"`
	Previous  string `json:"previous_filename,omitempty"`
}

func boundFiles(fs []ghFile, n int) []ghFile {
	if len(fs) > n {
		fs = fs[:n]
	}
	out := make([]ghFile, len(fs))
	for i, f := range fs {
		if len(f.Patch) > 4096 {
			f.Patch = f.Patch[:4096] + "\n… (cut)"
		}
		out[i] = f
	}
	return out
}
