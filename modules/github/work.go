package github

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Issues, pull requests, labels, milestones, releases and tags.

var (
	pTitle = pStr("title", "")
	pBody  = pText("body", "Markdown")
	pRelID = pInt("releaseId", "Release id (see releases)")
)

func issuePath(r string, n int) string { return fmt.Sprintf("/repos/%s/issues/%d", r, n) }
func pullPath(r string, n int) string  { return fmt.Sprintf("/repos/%s/pulls/%d", r, n) }

func repoNum(p args) (string, error) {
	r, err := needRepo(p.Repo)
	if err != nil {
		return "", err
	}
	if p.Number <= 0 {
		return "", errors.New("number is required")
	}
	return r, nil
}

func init() {
	// --- issues ---
	def(read("issue", "Issue", "An issue or pull request with its comments (up to 100).", schema("repo,number", pRepo, pNumber)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := repoNum(p)
			if err != nil {
				return sdk.Result{}, err
			}
			var is map[string]any
			if err := a.get(ctx, issuePath(r, p.Number), nil, &is); err != nil {
				return sdk.Result{}, err
			}
			cs, err := a.list(ctx, issuePath(r, p.Number)+"/comments", nil, "", 100)
			if err != nil {
				return sdk.Result{}, err
			}
			out := slim(is).(map[string]any)
			out["comments_list"] = slimAll(cs)
			return sdk.JSON(out)
		})
	def(read("search_issues_in_repo", "Find issues", "Issues and pull requests in one repository matching a GitHub search (e.g. \"is:open label:bug\").", schema("repo,query", pRepo, pStr("query", "Search qualifiers"), pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, "/search/issues", url.Values{"q": {"repo:" + r + " " + p.Query}}, "items", p.limit())
		})
	def(write("update_issue", "Edit an issue", "Title, body, state, labels, assignees or milestone of an issue (or a pull request's shared fields). Undo restores them.",
		schema("repo,number", pRepo, pNumber, pTitle, pBody, pEnum("state", "", "open", "closed"), pEnum("stateReason", "Why it was closed", "completed", "not_planned", "reopened"),
			pStrs("labels", "Replaces the labels"), pStrs("assignees", "Replaces the assignees"), pInt("milestone", "Milestone number, 0 to clear")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := repoNum(p)
			if err != nil {
				return sdk.Result{}, err
			}
			var raw map[string]any
			_ = sdk.Decode(c, &raw)
			body := map[string]any{}
			for _, k := range []string{"title", "body", "state", "labels", "assignees"} {
				if v, ok := raw[k]; ok {
					body[k] = v
				}
			}
			if v, ok := raw["stateReason"]; ok {
				body["state_reason"] = v
			}
			if p.Milestone != nil {
				if *p.Milestone == 0 {
					body["milestone"] = nil
				} else {
					body["milestone"] = *p.Milestone
				}
			}
			if len(body) == 0 {
				return sdk.Result{}, errors.New("nothing to change")
			}
			var cur ghIssueFull
			if err := a.get(ctx, issuePath(r, p.Number), nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			before := cur.fields(body)
			if c.DryRun {
				return plan(fmt.Sprintf("Edit #%d", p.Number), fmt.Sprintf("%s#%d", r, p.Number), "update", before, body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPatch, issuePath(r, p.Number), body)
			undo := map[string]any{"repo": r, "number": p.Number}
			for k, v := range before {
				switch k {
				case "state_reason":
					continue
				case "milestone":
					if v == nil {
						undo["milestone"] = 0
					} else {
						undo["milestone"] = v
					}
				default:
					undo[k] = v
				}
			}
			return withUndo(res, err, "update_issue", undo, fmt.Sprintf("Restore #%d", p.Number))
		})
	def(read("comments", "Comments", "Comments on an issue or pull request.", schema("repo,number", pRepo, pNumber, pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := repoNum(p)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, issuePath(r, p.Number)+"/comments", nil, "", p.limit())
		})
	def(write("edit_comment", "Edit a comment", "", schema("repo,commentId,body", pRepo, pInt("commentId", ""), pBody), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if p.CommentID == 0 || needText("body", p.Body) != nil {
				return sdk.Result{}, errors.New("commentId and body are required")
			}
			path := fmt.Sprintf("/repos/%s/issues/comments/%d", r, p.CommentID)
			var cur struct {
				Body string `json:"body"`
			}
			if err := a.get(ctx, path, nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Edit the comment", path, "update", cur.Body, p.Body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPatch, path, map[string]string{"body": p.Body})
			return withUndo(res, err, "edit_comment", map[string]any{"repo": r, "commentId": p.CommentID, "body": cur.Body}, "Restore the comment")
		})
	for _, add := range []bool{true, false} {
		name, title, undo := "add_labels", "Add labels", "remove_labels"
		if !add {
			name, title, undo = "remove_labels", "Remove labels", "add_labels"
		}
		def(write(name, title, "On an issue or pull request.", schema("repo,number,labels", pRepo, pNumber, pStrs("labels", "")), true),
			func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
				r, err := repoNum(p)
				if err != nil {
					return sdk.Result{}, err
				}
				if len(p.Labels) == 0 {
					return sdk.Result{}, errors.New("labels are required")
				}
				var cur ghIssueFull
				if err := a.get(ctx, issuePath(r, p.Number), nil, &cur); err != nil {
					return sdk.Result{}, err
				}
				have := map[string]bool{}
				for _, l := range cur.Labels {
					have[l.Name] = true
				}
				// Only the labels that actually change are undone.
				var changed []string
				for _, l := range p.Labels {
					if have[l] != add {
						changed = append(changed, l)
					}
				}
				if c.DryRun {
					return plan(fmt.Sprintf("%s on #%d: %s", title, p.Number, strings.Join(changed, ", ")), fmt.Sprintf("%s#%d", r, p.Number), "update", cur.labelNames(), changed)
				}
				var res sdk.Result
				if add {
					res, _, err = a.sendSlim(ctx, http.MethodPost, issuePath(r, p.Number)+"/labels", map[string]any{"labels": p.Labels})
				} else {
					for _, l := range changed {
						if err = a.send(ctx, http.MethodDelete, issuePath(r, p.Number)+"/labels/"+seg(l), nil, nil); err != nil {
							break
						}
					}
					if err == nil {
						res, err = sdk.JSON(map[string]any{"removed": changed})
					}
				}
				if len(changed) == 0 {
					return res, err
				}
				return withUndo(res, err, undo, map[string]any{"repo": r, "number": p.Number, "labels": changed}, "Undo the label change")
			})
	}
	for _, add := range []bool{true, false} {
		name, title, undo, method := "assign", "Assign", "unassign", http.MethodPost
		if !add {
			name, title, undo, method = "unassign", "Unassign", "assign", http.MethodDelete
		}
		def(write(name, title, "People on an issue or pull request.", schema("repo,number,assignees", pRepo, pNumber, pStrs("assignees", "Logins")), true),
			func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
				r, err := repoNum(p)
				if err != nil {
					return sdk.Result{}, err
				}
				if len(p.Assignees) == 0 {
					return sdk.Result{}, errors.New("assignees are required")
				}
				if c.DryRun {
					return plan(fmt.Sprintf("%s %s on #%d", title, strings.Join(p.Assignees, ", "), p.Number), fmt.Sprintf("%s#%d", r, p.Number), "update", nil, p.Assignees)
				}
				res, _, err := a.sendSlim(ctx, method, issuePath(r, p.Number)+"/assignees", map[string]any{"assignees": p.Assignees})
				return withUndo(res, err, undo, map[string]any{"repo": r, "number": p.Number, "assignees": p.Assignees}, "Undo")
			})
	}
	for _, lock := range []bool{true, false} {
		name, title, undo, method := "lock_issue", "Lock a conversation", "unlock_issue", http.MethodPut
		if !lock {
			name, title, undo, method = "unlock_issue", "Unlock a conversation", "lock_issue", http.MethodDelete
		}
		def(write(name, title, "", schema("repo,number", pRepo, pNumber, pEnum("reason", "", "off-topic", "too heated", "resolved", "spam")), true),
			func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
				r, err := repoNum(p)
				if err != nil {
					return sdk.Result{}, err
				}
				if c.DryRun {
					return plan(fmt.Sprintf("%s #%d", title, p.Number), fmt.Sprintf("%s#%d", r, p.Number), "update", nil, nil)
				}
				var body any
				var reason struct {
					Reason string `json:"reason"`
				}
				_ = sdk.Decode(c, &reason)
				if lock && reason.Reason != "" {
					body = map[string]string{"lock_reason": reason.Reason}
				}
				if err := a.send(ctx, method, issuePath(r, p.Number)+"/lock", body, nil); err != nil {
					return sdk.Result{}, err
				}
				res, err := sdk.JSON(map[string]any{"number": p.Number, "locked": lock})
				return withUndo(res, err, undo, map[string]any{"repo": r, "number": p.Number}, "Undo")
			})
	}

	// --- pull requests ---
	def(read("pull_request", "Pull request", "A pull request with its changed files (up to 100, patches cut to 4 KB), reviews and checks state.", schema("repo,number", pRepo, pNumber)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := repoNum(p)
			if err != nil {
				return sdk.Result{}, err
			}
			var pr map[string]any
			if err := a.get(ctx, pullPath(r, p.Number), nil, &pr); err != nil {
				return sdk.Result{}, err
			}
			var files []ghFile
			_ = a.get(ctx, pullPath(r, p.Number)+"/files", url.Values{"per_page": {"100"}}, &files)
			revs, _ := a.list(ctx, pullPath(r, p.Number)+"/reviews", nil, "", 100)
			out := slim(pr).(map[string]any)
			out["files"] = boundFiles(files, 100)
			out["reviews"] = slimAll(revs)
			return sdk.JSON(out)
		})
	def(write("create_pr", "Open a pull request", "", schema("repo,title,head,base", pRepo, pTitle, pStr("head", "Branch with the changes (owner:branch for a fork)"),
		pStr("base", "Branch to merge into"), pBody, pBool("draft", "")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if needText("title", p.Title) != nil || needText("head", p.Head) != nil || needText("base", p.Base) != nil {
				return sdk.Result{}, errors.New("title, head and base are required")
			}
			body := map[string]any{"title": p.Title, "head": p.Head, "base": p.Base, "body": p.Body, "draft": p.Draft != nil && *p.Draft}
			if c.DryRun {
				return plan(fmt.Sprintf("Open \"%s\" (%s into %s)", p.Title, p.Head, p.Base), r, "create", nil, body)
			}
			res, raw, err := a.sendSlim(ctx, http.MethodPost, "/repos/"+r+"/pulls", body)
			n := int(num(toMap(raw)["number"]))
			return withUndo(res, err, "close_pr", map[string]any{"repo": r, "number": n}, fmt.Sprintf("Close #%d", n))
		})
	def(write("update_pr", "Edit a pull request", "Title, body, base branch or state. Undo restores them.", schema("repo,number", pRepo, pNumber, pTitle, pBody, pStr("base", ""), pEnum("state", "", "open", "closed")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := repoNum(p)
			if err != nil {
				return sdk.Result{}, err
			}
			var raw map[string]any
			_ = sdk.Decode(c, &raw)
			body := pick(raw, "title", "body", "base", "state")
			if len(body) == 0 {
				return sdk.Result{}, errors.New("nothing to change")
			}
			var cur map[string]any
			if err := a.get(ctx, pullPath(r, p.Number), nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			before := pick(cur, "title", "body", "state")
			if b, ok := cur["base"].(map[string]any); ok {
				before["base"] = b["ref"]
			}
			before = pick(before, keys(body)...)
			if c.DryRun {
				return plan(fmt.Sprintf("Edit #%d", p.Number), fmt.Sprintf("%s#%d", r, p.Number), "update", before, body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPatch, pullPath(r, p.Number), body)
			before["repo"], before["number"] = r, p.Number
			return withUndo(res, err, "update_pr", before, fmt.Sprintf("Restore #%d", p.Number))
		})
	for _, closeIt := range []bool{true, false} {
		name, title, state, undo := "close_pr", "Close a pull request", "closed", "reopen_pr"
		if !closeIt {
			name, title, state, undo = "reopen_pr", "Reopen a pull request", "open", "close_pr"
		}
		def(write(name, title, "", schema("repo,number", pRepo, pNumber), true),
			func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
				r, err := repoNum(p)
				if err != nil {
					return sdk.Result{}, err
				}
				if c.DryRun {
					return plan(fmt.Sprintf("%s #%d", title, p.Number), fmt.Sprintf("%s#%d", r, p.Number), "update", nil, map[string]string{"state": state})
				}
				res, _, err := a.sendSlim(ctx, http.MethodPatch, pullPath(r, p.Number), map[string]string{"state": state})
				return withUndo(res, err, undo, map[string]any{"repo": r, "number": p.Number}, "Undo")
			})
	}
	def(destructive("review_pr", "Review a pull request", "Approve, request changes or comment, optionally with line comments. An approval counts toward required reviews, so this is destructive; a plain line comment is review_comment.",
		schema("repo,number,event", pRepo, pNumber, pEnum("event", "", "APPROVE", "REQUEST_CHANGES", "COMMENT"), pBody,
			`"comments":{"type":"array","items":{"type":"object","properties":{"path":{"type":"string"},"line":{"type":"integer"},"side":{"type":"string","enum":["LEFT","RIGHT"]},"body":{"type":"string"}}},"description":"Line comments"}`), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := repoNum(p)
			if err != nil {
				return sdk.Result{}, err
			}
			switch p.Event {
			case "APPROVE", "COMMENT", "REQUEST_CHANGES":
			default:
				return sdk.Result{}, errors.New("event is APPROVE, REQUEST_CHANGES or COMMENT")
			}
			if p.Event != "APPROVE" && strings.TrimSpace(p.Body) == "" && len(p.Comments) == 0 {
				return sdk.Result{}, errors.New("say something: a body or line comments")
			}
			var pr struct {
				Head struct {
					SHA string `json:"sha"`
				} `json:"head"`
			}
			if err := a.get(ctx, pullPath(r, p.Number), nil, &pr); err != nil {
				return sdk.Result{}, err
			}
			body := map[string]any{"event": p.Event, "body": p.Body, "commit_id": pr.Head.SHA}
			if len(p.Comments) > 0 {
				body["comments"] = p.Comments
			}
			if c.DryRun {
				return plan(fmt.Sprintf("%s #%d at %s", strings.ToLower(strings.ReplaceAll(p.Event, "_", " ")), p.Number, short(pr.Head.SHA)), fmt.Sprintf("%s#%d", r, p.Number), "review", nil, body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPost, pullPath(r, p.Number)+"/reviews", body)
			return res, err
		})
	def(write("review_comment", "Comment on a line", "A comment on one line of a pull request's diff.", schema("repo,number,path,line,body", pRepo, pNumber, pStr("path", ""), pInt("line", "Line in the new file (or old with side LEFT)"),
		pEnum("side", "", "RIGHT", "LEFT"), pBody), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := repoNum(p)
			if err != nil {
				return sdk.Result{}, err
			}
			if needText("path", p.Path) != nil || p.Line <= 0 || needText("body", p.Body) != nil {
				return sdk.Result{}, errors.New("path, line and body are required")
			}
			var pr struct {
				Head struct {
					SHA string `json:"sha"`
				} `json:"head"`
			}
			if err := a.get(ctx, pullPath(r, p.Number), nil, &pr); err != nil {
				return sdk.Result{}, err
			}
			side := p.Side
			if side == "" {
				side = "RIGHT"
			}
			body := map[string]any{"body": p.Body, "path": p.Path, "line": p.Line, "side": side, "commit_id": pr.Head.SHA}
			if c.DryRun {
				return plan(fmt.Sprintf("Comment on %s:%d in #%d", p.Path, p.Line, p.Number), fmt.Sprintf("%s#%d", r, p.Number), "create", nil, body)
			}
			res, raw, err := a.sendSlim(ctx, http.MethodPost, pullPath(r, p.Number)+"/comments", body)
			id := int64(num(toMap(raw)["id"]))
			return withUndo(res, err, "delete_review_comment", map[string]any{"repo": r, "commentId": id}, "Delete the comment")
		})
	def(destructive("delete_review_comment", "Delete a line comment", "", schema("repo,commentId", pRepo, pInt("commentId", "")), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil || p.CommentID == 0 {
				return sdk.Result{}, errors.New("repo and commentId are required")
			}
			path := fmt.Sprintf("/repos/%s/pulls/comments/%d", r, p.CommentID)
			if c.DryRun {
				return plan("Delete line comment", path, "delete", nil, nil)
			}
			if err := a.send(ctx, http.MethodDelete, path, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"deleted": p.CommentID})
		})
	for _, add := range []bool{true, false} {
		name, title, undo, method := "request_reviewers", "Request reviewers", "remove_reviewers", http.MethodPost
		if !add {
			name, title, undo, method = "remove_reviewers", "Remove review requests", "request_reviewers", http.MethodDelete
		}
		def(write(name, title, "", schema("repo,number", pRepo, pNumber, pStrs("reviewers", "Logins"), pStrs("teamReviewers", "Team slugs")), true),
			func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
				r, err := repoNum(p)
				if err != nil {
					return sdk.Result{}, err
				}
				if len(p.Reviewers)+len(p.TeamRevs) == 0 {
					return sdk.Result{}, errors.New("name reviewers or teamReviewers")
				}
				body := map[string]any{"reviewers": orStrings(p.Reviewers), "team_reviewers": orStrings(p.TeamRevs)}
				if c.DryRun {
					return plan(fmt.Sprintf("%s on #%d", title, p.Number), fmt.Sprintf("%s#%d", r, p.Number), "update", nil, body)
				}
				res, _, err := a.sendSlim(ctx, method, pullPath(r, p.Number)+"/requested_reviewers", body)
				return withUndo(res, err, undo, map[string]any{"repo": r, "number": p.Number, "reviewers": p.Reviewers, "teamReviewers": p.TeamRevs}, "Undo")
			})
	}
	def(write("update_pr_branch", "Update a pull request's branch", "Merges the base branch into the head branch.", schema("repo,number", pRepo, pNumber), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := repoNum(p)
			if err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan(fmt.Sprintf("Merge the base branch into #%d", p.Number), fmt.Sprintf("%s#%d", r, p.Number), "update", nil, nil)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPut, pullPath(r, p.Number)+"/update-branch", map[string]any{})
			return res, err
		})

	// --- labels ---
	def(read("labels", "Labels", "", schema("repo", pRepo, pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, "/repos/"+r+"/labels", nil, "", p.limit())
		})
	def(write("create_label", "Create a label", "", schema("repo,name", pRepo, pStr("name", ""), pStr("color", "Hex without #, e.g. d73a4a"), pStr("description", "")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("name", p.Name); err != nil {
				return sdk.Result{}, err
			}
			color := strings.TrimPrefix(p.Color, "#")
			if color == "" {
				color = "ededed"
			}
			body := map[string]string{"name": p.Name, "color": color, "description": p.Description}
			if c.DryRun {
				return plan("Create label "+p.Name, r, "create", nil, body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPost, "/repos/"+r+"/labels", body)
			return withUndo(res, err, "delete_label", map[string]string{"repo": r, "name": p.Name}, "Delete label "+p.Name)
		})
	def(write("update_label", "Change a label", "Rename it or change its color or description.", schema("repo,name", pRepo, pStr("name", "Current name"), pStr("newName", ""), pStr("color", ""), pStr("description", "")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			var cur map[string]any
			if err := a.get(ctx, "/repos/"+r+"/labels/"+seg(p.Name), nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			body := map[string]string{}
			if p.NewName != "" {
				body["new_name"] = p.NewName
			}
			if p.Color != "" {
				body["color"] = strings.TrimPrefix(p.Color, "#")
			}
			var raw map[string]any
			_ = sdk.Decode(c, &raw)
			if _, ok := raw["description"]; ok {
				body["description"] = p.Description
			}
			if len(body) == 0 {
				return sdk.Result{}, errors.New("nothing to change")
			}
			if c.DryRun {
				return plan("Change label "+p.Name, r, "update", pick(cur, "name", "color", "description"), body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPatch, "/repos/"+r+"/labels/"+seg(p.Name), body)
			newName := p.Name
			if p.NewName != "" {
				newName = p.NewName
			}
			return withUndo(res, err, "update_label", map[string]any{"repo": r, "name": newName, "newName": cur["name"], "color": cur["color"], "description": str(cur, "description")}, "Restore label "+p.Name)
		})
	def(destructive("delete_label", "Delete a label", "Removes it from every issue too; undo recreates the label but not those assignments.", schema("repo,name", pRepo, pStr("name", "")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			var cur map[string]any
			if err := a.get(ctx, "/repos/"+r+"/labels/"+seg(p.Name), nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Delete label "+p.Name, r, "delete", pick(cur, "name", "color", "description"), nil)
			}
			if err := a.send(ctx, http.MethodDelete, "/repos/"+r+"/labels/"+seg(p.Name), nil, nil); err != nil {
				return sdk.Result{}, err
			}
			res, err := sdk.JSON(map[string]string{"deleted": p.Name})
			return withUndo(res, err, "create_label", map[string]any{"repo": r, "name": p.Name, "color": cur["color"], "description": str(cur, "description")}, "Recreate label "+p.Name)
		})

	// --- milestones ---
	def(read("milestones", "Milestones", "", schema("repo", pRepo, pEnum("state", "", "open", "closed", "all"), pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			q := url.Values{}
			if p.State != "" {
				q.Set("state", p.State)
			}
			return a.listSlim(ctx, "/repos/"+r+"/milestones", q, "", p.limit())
		})
	def(write("create_milestone", "Create a milestone", "", schema("repo,title", pRepo, pTitle, pStr("description", ""), pStr("dueOn", "ISO 8601 date")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("title", p.Title); err != nil {
				return sdk.Result{}, err
			}
			body := map[string]any{"title": p.Title, "description": p.Description}
			if p.DueOn != "" {
				body["due_on"] = p.DueOn
			}
			if c.DryRun {
				return plan("Create milestone "+p.Title, r, "create", nil, body)
			}
			res, raw, err := a.sendSlim(ctx, http.MethodPost, "/repos/"+r+"/milestones", body)
			n := int(num(toMap(raw)["number"]))
			return withUndo(res, err, "delete_milestone", map[string]any{"repo": r, "number": n}, "Delete milestone "+p.Title)
		})
	def(write("update_milestone", "Change a milestone", "Title, description, due date or state.", schema("repo,number", pRepo, pInt("number", "Milestone number"), pTitle, pStr("description", ""), pStr("dueOn", ""), pEnum("state", "", "open", "closed")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := repoNum(p)
			if err != nil {
				return sdk.Result{}, err
			}
			var raw map[string]any
			_ = sdk.Decode(c, &raw)
			body := pick(raw, "title", "description", "state")
			if v, ok := raw["dueOn"]; ok {
				body["due_on"] = v
			}
			if len(body) == 0 {
				return sdk.Result{}, errors.New("nothing to change")
			}
			path := fmt.Sprintf("/repos/%s/milestones/%d", r, p.Number)
			var cur map[string]any
			if err := a.get(ctx, path, nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			before := pick(cur, "title", "description", "state", "due_on")
			if c.DryRun {
				return plan("Change milestone "+str(cur, "title"), path, "update", before, body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPatch, path, body)
			undo := map[string]any{"repo": r, "number": p.Number, "title": before["title"], "description": str(before, "description"), "state": before["state"]}
			if before["due_on"] != nil {
				undo["dueOn"] = before["due_on"]
			}
			return withUndo(res, err, "update_milestone", undo, "Restore the milestone")
		})
	def(destructive("delete_milestone", "Delete a milestone", "Issues in it stay, without the milestone.", schema("repo,number", pRepo, pInt("number", "Milestone number")), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := repoNum(p)
			if err != nil {
				return sdk.Result{}, err
			}
			path := fmt.Sprintf("/repos/%s/milestones/%d", r, p.Number)
			var cur map[string]any
			if err := a.get(ctx, path, nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Delete milestone "+str(cur, "title"), path, "delete", pick(cur, "title", "open_issues", "closed_issues"), nil)
			}
			if err := a.send(ctx, http.MethodDelete, path, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"deleted": p.Number})
		})

	// --- releases and tags ---
	def(read("releases", "Releases", "", schema("repo", pRepo, pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, "/repos/"+r+"/releases", nil, "", p.limit())
		})
	def(read("release", "Release", "One release by id or tag, or the latest.", schema("repo", pRepo, pRelID, pStr("tag", "Tag name; empty with no id for the latest release"))),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			switch {
			case p.ReleaseID > 0:
				return a.getSlim(ctx, fmt.Sprintf("/repos/%s/releases/%d", r, p.ReleaseID), nil)
			case p.Tag != "":
				return a.getSlim(ctx, "/repos/"+r+"/releases/tags/"+seg(p.Tag), nil)
			}
			return a.getSlim(ctx, "/repos/"+r+"/releases/latest", nil)
		})
	def(write("create_release", "Create a release", "Creates the tag too when it doesn't exist (from target).",
		schema("repo,tag", pRepo, pStr("tag", ""), pStr("name", ""), pBody, pStr("target", "Branch or SHA for a new tag (default branch)"), pBool("draft", ""), pBool("prerelease", ""), pBool("generateNotes", "Let GitHub write the notes")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("tag", p.Tag); err != nil {
				return sdk.Result{}, err
			}
			var t struct {
				Target string `json:"target"`
			}
			_ = sdk.Decode(c, &t)
			body := map[string]any{"tag_name": p.Tag, "name": p.Name, "body": p.Body, "draft": p.Draft != nil && *p.Draft, "prerelease": p.Prerelease != nil && *p.Prerelease, "generate_release_notes": p.Generate}
			if t.Target != "" {
				body["target_commitish"] = t.Target
			}
			if c.DryRun {
				return plan("Create release "+p.Tag, r, "create", nil, body)
			}
			res, raw, err := a.sendSlim(ctx, http.MethodPost, "/repos/"+r+"/releases", body)
			id := int64(num(toMap(raw)["id"]))
			return withUndo(res, err, "delete_release", map[string]any{"repo": r, "releaseId": id}, "Delete release "+p.Tag)
		})
	def(write("update_release", "Edit a release", "Name, notes, draft or prerelease. Undo restores them.", schema("repo,releaseId", pRepo, pRelID, pStr("name", ""), pBody, pBool("draft", ""), pBool("prerelease", ""), pStr("tag", "Rename the tag")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil || p.ReleaseID == 0 {
				return sdk.Result{}, errors.New("repo and releaseId are required")
			}
			var raw map[string]any
			_ = sdk.Decode(c, &raw)
			body := pick(raw, "name", "body", "draft", "prerelease")
			if p.Tag != "" {
				body["tag_name"] = p.Tag
			}
			if len(body) == 0 {
				return sdk.Result{}, errors.New("nothing to change")
			}
			path := fmt.Sprintf("/repos/%s/releases/%d", r, p.ReleaseID)
			var cur map[string]any
			if err := a.get(ctx, path, nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			before := pick(cur, "name", "body", "draft", "prerelease", "tag_name")
			if c.DryRun {
				return plan("Edit release "+str(cur, "tag_name"), path, "update", pick(before, keys(body)...), body)
			}
			res, _, err := a.sendSlim(ctx, http.MethodPatch, path, body)
			undo := map[string]any{"repo": r, "releaseId": p.ReleaseID, "name": str(before, "name"), "body": str(before, "body"), "draft": before["draft"], "prerelease": before["prerelease"], "tag": before["tag_name"]}
			return withUndo(res, err, "update_release", undo, "Restore the release")
		})
	def(destructive("delete_release", "Delete a release", "The tag stays.", schema("repo,releaseId", pRepo, pRelID), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil || p.ReleaseID == 0 {
				return sdk.Result{}, errors.New("repo and releaseId are required")
			}
			path := fmt.Sprintf("/repos/%s/releases/%d", r, p.ReleaseID)
			var cur map[string]any
			if err := a.get(ctx, path, nil, &cur); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				assets, _ := cur["assets"].([]any)
				return plan("Delete release "+str(cur, "tag_name"), path, "delete", map[string]any{"tag": cur["tag_name"], "name": cur["name"], "assets": len(assets)}, nil)
			}
			if err := a.send(ctx, http.MethodDelete, path, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"deleted": p.ReleaseID})
		})
	def(write("upload_release_asset", "Upload a release asset", "Attaches a file (up to 25 MB) to a release.", schema("repo,releaseId,name,content", pRepo, pRelID, pStr("name", "File name"),
		pText("content", "File content"), pEnum("encoding", "How content is given (default utf-8)", "utf-8", "base64"), pStr("contentType", "Default application/octet-stream")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil || p.ReleaseID == 0 {
				return sdk.Result{}, errors.New("repo and releaseId are required")
			}
			if err := needText("name", p.Name); err != nil {
				return sdk.Result{}, err
			}
			data := []byte(p.Content)
			if p.Encoding == "base64" {
				if data, err = base64.StdEncoding.DecodeString(p.Content); err != nil {
					return sdk.Result{}, errors.New("content isn't valid base64")
				}
			}
			if len(data) > 25<<20 {
				return sdk.Result{}, errors.New("assets uploaded here are limited to 25 MB")
			}
			var rel struct {
				UploadURL string `json:"upload_url"`
				Tag       string `json:"tag_name"`
			}
			if err := a.get(ctx, fmt.Sprintf("/repos/%s/releases/%d", r, p.ReleaseID), nil, &rel); err != nil {
				return sdk.Result{}, err
			}
			up, err := a.uploadURL(rel.UploadURL)
			if err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan(fmt.Sprintf("Upload %s (%d bytes) to %s", p.Name, len(data), rel.Tag), r+"@"+rel.Tag, "create", nil, map[string]any{"name": p.Name, "bytes": len(data)})
			}
			ct := p.ContentType
			if ct == "" {
				ct = "application/octet-stream"
			}
			res, err := a.raw(ctx, http.MethodPost, up, url.Values{"name": {p.Name}}, readerOf(data), map[string]string{"Content-Type": ct, "Content-Length": strconv.Itoa(len(data))}, 1<<20, false)
			if err != nil {
				return sdk.Result{}, err
			}
			if res.Status >= 300 {
				return sdk.Result{}, fmt.Errorf("upload failed: %d %s", res.Status, strings.TrimSpace(string(res.Body)))
			}
			m := toMap(res.Body)
			out, err := sdk.JSON(slim(m))
			return withUndo(out, err, "delete_release_asset", map[string]any{"repo": r, "id": int64(num(m["id"]))}, "Delete "+p.Name)
		})
	def(destructive("delete_release_asset", "Delete a release asset", "", schema("repo,id", pRepo, pInt("id", "Asset id")), false),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil || p.ID == 0 {
				return sdk.Result{}, errors.New("repo and id are required")
			}
			path := fmt.Sprintf("/repos/%s/releases/assets/%d", r, p.ID)
			if c.DryRun {
				var cur map[string]any
				if err := a.get(ctx, path, nil, &cur); err != nil {
					return sdk.Result{}, err
				}
				return plan("Delete asset "+str(cur, "name"), path, "delete", pick(cur, "name", "size", "download_count"), nil)
			}
			if err := a.send(ctx, http.MethodDelete, path, nil, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]any{"deleted": p.ID})
		})
	def(read("tags", "Tags", "", schema("repo", pRepo, pLimit)),
		func(ctx context.Context, a *account, p args, _ sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			return a.listSlim(ctx, "/repos/"+r+"/tags", nil, "", p.limit())
		})
	def(write("create_tag", "Create a tag", "A lightweight tag, or an annotated one with a message.", schema("repo,tag", pRepo, pStr("tag", ""), pStr("from", "Branch, tag or SHA (default branch)"), pStr("message", "Makes an annotated tag")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("tag", p.Tag); err != nil {
				return sdk.Result{}, err
			}
			sha, err := a.resolveRef(ctx, r, p.From)
			if err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Tag "+short(sha)+" as "+p.Tag, r+"@"+p.Tag, "create", nil, map[string]string{"sha": sha, "message": p.Message})
			}
			target := sha
			if p.Message != "" {
				var tg struct {
					SHA string `json:"sha"`
				}
				if err := a.send(ctx, http.MethodPost, "/repos/"+r+"/git/tags", map[string]string{"tag": p.Tag, "message": p.Message, "object": sha, "type": "commit"}, &tg); err != nil {
					return sdk.Result{}, err
				}
				target = tg.SHA
			}
			res, _, err := a.sendSlim(ctx, http.MethodPost, "/repos/"+r+"/git/refs", map[string]string{"ref": "refs/tags/" + p.Tag, "sha": target})
			return withUndo(res, err, "delete_tag", map[string]string{"repo": r, "tag": p.Tag}, "Delete tag "+p.Tag)
		})
	def(destructive("delete_tag", "Delete a tag", "Undo recreates it at the same commit (as a lightweight tag).", schema("repo,tag", pRepo, pStr("tag", "")), true),
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			r, err := needRepo(p.Repo)
			if err != nil {
				return sdk.Result{}, err
			}
			if err := needText("tag", p.Tag); err != nil {
				return sdk.Result{}, err
			}
			sha, err := a.resolveRef(ctx, r, "refs/tags/"+p.Tag)
			if err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Delete tag "+p.Tag+" (at "+short(sha)+")", r+"@"+p.Tag, "delete", map[string]string{"sha": sha}, nil)
			}
			if err := a.send(ctx, http.MethodDelete, "/repos/"+r+"/git/refs/tags/"+seg(p.Tag), nil, nil); err != nil {
				return sdk.Result{}, err
			}
			res, err := sdk.JSON(map[string]string{"deleted": p.Tag, "sha": sha})
			return withUndo(res, err, "create_tag", map[string]string{"repo": r, "tag": p.Tag, "from": sha}, "Recreate tag "+p.Tag)
		})
}

type ghIssueFull struct {
	Title  string `json:"title"`
	Body   string `json:"body"`
	State  string `json:"state"`
	Reason string `json:"state_reason"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
	Assignees []struct {
		Login string `json:"login"`
	} `json:"assignees"`
	Milestone *struct {
		Number int `json:"number"`
	} `json:"milestone"`
}

func (i ghIssueFull) labelNames() []string {
	out := []string{}
	for _, l := range i.Labels {
		out = append(out, l.Name)
	}
	return out
}

// fields returns the current values of the fields a change touches.
func (i ghIssueFull) fields(change map[string]any) map[string]any {
	all := map[string]any{"title": i.Title, "body": i.Body, "state": i.State, "labels": i.labelNames()}
	as := []string{}
	for _, x := range i.Assignees {
		as = append(as, x.Login)
	}
	all["assignees"] = as
	if i.Milestone != nil {
		all["milestone"] = i.Milestone.Number
	} else {
		all["milestone"] = nil
	}
	out := map[string]any{}
	for k := range change {
		if v, ok := all[k]; ok {
			out[k] = v
		}
	}
	return out
}

func num(v any) float64 {
	f, _ := v.(float64)
	return f
}

func orStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// uploadURL checks a release's upload URL before the token is sent there:
// it must be GitHub's upload host (for github.com) or the Enterprise
// server's own host.
func (a *account) uploadURL(tmpl string) (string, error) {
	raw, _, _ := strings.Cut(tmpl, "{")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" && !strings.HasPrefix(a.api.Base, "http://") {
		return "", fmt.Errorf("unexpected upload URL %q", tmpl)
	}
	base, _ := url.Parse(a.api.Base)
	ok := strings.EqualFold(u.Host, base.Host) || (strings.EqualFold(base.Host, "api.github.com") && strings.EqualFold(u.Host, "uploads.github.com"))
	if !ok {
		return "", fmt.Errorf("refusing to send the token to %s for an upload", u.Host)
	}
	return u.String(), nil
}
