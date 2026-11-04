package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// --- schema helpers ------------------------------------------------------------

// schema builds an object schema: req is a comma-separated list of required
// properties; props are snippets made by the helpers below.
func schema(req string, props ...string) json.RawMessage {
	var r []string
	for _, x := range strings.Split(req, ",") {
		if x = strings.TrimSpace(x); x != "" {
			r = append(r, strconv.Quote(x))
		}
	}
	s := `{"type":"object"`
	if len(r) > 0 {
		s += `,"required":[` + strings.Join(r, ",") + `]`
	}
	return json.RawMessage(s + `,"properties":{` + strings.Join(props, ",") + `}}`)
}

func prop(name, typ, desc string) string {
	if desc == "" {
		return fmt.Sprintf(`%q:{"type":%q}`, name, typ)
	}
	return fmt.Sprintf(`%q:{"type":%q,"description":%q}`, name, typ, desc)
}
func pStr(name, desc string) string  { return prop(name, "string", desc) }
func pInt(name, desc string) string  { return prop(name, "integer", desc) }
func pBool(name, desc string) string { return prop(name, "boolean", desc) }
func pObj(name, desc string) string  { return prop(name, "object", desc) }
func pText(name, desc string) string {
	return fmt.Sprintf(`%q:{"type":"string","format":"textarea","description":%q}`, name, desc)
}
func pStrs(name, desc string) string {
	return fmt.Sprintf(`%q:{"type":"array","items":{"type":"string"},"description":%q}`, name, desc)
}
func pEnum(name, desc string, vals ...string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = strconv.Quote(v)
	}
	return fmt.Sprintf(`%q:{"type":"string","enum":[%s],"description":%q}`, name, strings.Join(q, ","), desc)
}

var (
	pRepo   = pStr("repo", "owner/name")
	pNumber = pInt("number", "Issue or pull request number")
	pLimit  = pInt("limit", "At most this many results (default 30, at most 300)")
	pOrg    = pStr("org", "Organization login")
	pEnv    = pStr("environment", "Deployment environment name (for environment secrets and variables)")
)

// --- arguments -------------------------------------------------------------------

// args holds every field the new actions take. Each action reads the ones it
// declares in its schema.
type args struct {
	Repo        string            `json:"repo"`
	Number      int               `json:"number"`
	Org         string            `json:"org"`
	Owner       string            `json:"owner"`
	Name        string            `json:"name"`
	NewName     string            `json:"newName"`
	NewOwner    string            `json:"newOwner"`
	Username    string            `json:"username"`
	Team        string            `json:"team"`
	Branch      string            `json:"branch"`
	From        string            `json:"from"`
	Ref         string            `json:"ref"`
	Base        string            `json:"base"`
	Head        string            `json:"head"`
	Path        string            `json:"path"`
	SHA         string            `json:"sha"`
	Tag         string            `json:"tag"`
	Title       string            `json:"title"`
	Body        string            `json:"body"`
	Message     string            `json:"message"`
	Content     string            `json:"content"`
	Encoding    string            `json:"encoding"`
	Description string            `json:"description"`
	Color       string            `json:"color"`
	State       string            `json:"state"`
	Event       string            `json:"event"`
	Method      string            `json:"method"`
	Query       string            `json:"query"`
	Type        string            `json:"type"`
	Sort        string            `json:"sort"`
	Order       string            `json:"order"`
	Permission  string            `json:"permission"`
	Role        string            `json:"role"`
	Visibility  string            `json:"visibility"`
	Environment string            `json:"environment"`
	Workflow    string            `json:"workflow"`
	Value       string            `json:"value"`
	Key         string            `json:"key"`
	URL         string            `json:"url"`
	Secret      string            `json:"secret"`
	ContentType string            `json:"contentType"`
	Since       string            `json:"since"`
	Until       string            `json:"until"`
	Author      string            `json:"author"`
	DueOn       string            `json:"dueOn"`
	Limit       int               `json:"limit"`
	ID          int64             `json:"id"`
	RunID       int64             `json:"runId"`
	JobID       int64             `json:"jobId"`
	ReleaseID   int64             `json:"releaseId"`
	CommentID   int64             `json:"commentId"`
	TailLines   int               `json:"tailLines"`
	Private     *bool             `json:"private"`
	ReadOnly    *bool             `json:"readOnly"`
	Draft       *bool             `json:"draft"`
	Prerelease  *bool             `json:"prerelease"`
	Active      *bool             `json:"active"`
	Recursive   bool              `json:"recursive"`
	All         bool              `json:"all"`
	AutoInit    bool              `json:"autoInit"`
	Generate    bool              `json:"generateNotes"`
	Labels      []string          `json:"labels"`
	Assignees   []string          `json:"assignees"`
	Reviewers   []string          `json:"reviewers"`
	TeamRevs    []string          `json:"teamReviewers"`
	Topics      []string          `json:"topics"`
	Events      []string          `json:"events"`
	Files       map[string]string `json:"files"`
	Inputs      map[string]any    `json:"inputs"`
	Params      map[string]string `json:"params"`
	Variables   map[string]any    `json:"variables"`
	Settings    map[string]any    `json:"settings"`
	Protection  map[string]any    `json:"protection"`
	Comments    []map[string]any  `json:"comments"`
	Milestone   *int              `json:"milestone"`
	Data        json.RawMessage   `json:"data"`
	Previous    json.RawMessage   `json:"previous"`
	Line        int               `json:"line"`
	Side        string            `json:"side"`
	CommitID    string            `json:"commitId"`
	Repos       []int64           `json:"selectedRepositoryIds"`
	GistID      string            `json:"gistId"`
	ThreadID    string            `json:"threadId"`
	Public      *bool             `json:"public"`
}

func (p args) limit() int {
	switch {
	case p.Limit <= 0:
		return 30
	case p.Limit > 300:
		return 300
	}
	return p.Limit
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

func needRepo(r string) (string, error) {
	if !repoRe.MatchString(r) {
		return "", fmt.Errorf("repo must be owner/name, got %q", r)
	}
	return r, nil
}

func needName(what, s string) (string, error) {
	if !nameRe.MatchString(s) {
		return "", fmt.Errorf("%s %q is missing or invalid", what, s)
	}
	return s, nil
}

func needText(what, s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("%s is required", what)
	}
	return nil
}

// seg escapes one path segment (a branch, a tag, a label name ...).
func seg(s string) string { return url.PathEscape(s) }

// filePath escapes a repository file path segment by segment.
func filePath(p string) (string, error) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", errors.New("path is required")
	}
	parts := strings.Split(p, "/")
	for i, x := range parts {
		if x == "" || x == "." || x == ".." {
			return "", fmt.Errorf("invalid path %q", p)
		}
		parts[i] = url.PathEscape(x)
	}
	return strings.Join(parts, "/"), nil
}

// --- requests --------------------------------------------------------------------

func (a *account) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := a.api.Do(ctx, http.MethodGet, path, q, nil, out)
	return err
}

func (a *account) send(ctx context.Context, method, path string, body, out any) error {
	_, err := a.api.Do(ctx, method, path, nil, body, out)
	return err
}

// rawResp is a response read without decoding.
type rawResp struct {
	Status int
	Header http.Header
	Body   []byte
	// Truncated is set when the body was longer than the limit; Body then
	// holds its last limit bytes when tail was asked for, else its first.
	Truncated bool
}

// raw sends any request to the API and reads at most limit bytes of the
// answer (the tail of it with tail). target is a path under the API base or,
// for uploads, an absolute URL the caller has checked.
func (a *account) raw(ctx context.Context, method, target string, q url.Values, body io.Reader, hdr map[string]string, limit int64, tail bool) (rawResp, error) {
	u := target
	if strings.HasPrefix(target, "/") {
		u = a.api.Base + target
	}
	if len(q) > 0 {
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		u += sep + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return rawResp{}, err
	}
	for k, v := range a.api.Header {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", "Conduit")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if a.api.Auth != nil {
		if err := a.api.Auth(ctx, req); err != nil {
			return rawResp{}, err
		}
	}
	res, err := a.api.HTTP.Do(req)
	if err != nil {
		return rawResp{}, err
	}
	defer res.Body.Close()
	out := rawResp{Status: res.StatusCode, Header: res.Header}
	if tail {
		out.Body, out.Truncated, err = readTail(res.Body, limit)
	} else {
		out.Body, err = io.ReadAll(io.LimitReader(res.Body, limit+1))
		if int64(len(out.Body)) > limit {
			out.Body, out.Truncated = out.Body[:limit], true
		}
	}
	return out, err
}

// readTail keeps the last limit bytes of r (reading at most 64 MiB).
func readTail(r io.Reader, limit int64) ([]byte, bool, error) {
	buf := make([]byte, 0, limit)
	chunk := make([]byte, 32<<10)
	cut := false
	var total int64
	for {
		n, err := r.Read(chunk)
		total += int64(n)
		buf = append(buf, chunk[:n]...)
		if int64(len(buf)) > limit {
			buf = append(buf[:0], buf[int64(len(buf))-limit:]...)
			cut = true
		}
		if err == io.EOF || total > 64<<20 {
			return buf, cut || total > 64<<20, nil
		}
		if err != nil {
			return buf, cut, err
		}
	}
}

// list reads up to limit items of a paginated list. key names the array in
// wrapped answers ({"total_count":…, "workflow_runs":[…]}); "" for plain
// arrays. At most 10 pages are read.
func (a *account) list(ctx context.Context, path string, q url.Values, key string, limit int) ([]json.RawMessage, error) {
	if q == nil {
		q = url.Values{}
	}
	per := limit
	if per > 100 {
		per = 100
	}
	q.Set("per_page", strconv.Itoa(per))
	out := []json.RawMessage{}
	for page := 1; page <= 10 && len(out) < limit; page++ {
		q.Set("page", strconv.Itoa(page))
		var items []json.RawMessage
		if key == "" {
			if err := a.get(ctx, path, q, &items); err != nil {
				return nil, err
			}
		} else {
			var w map[string]json.RawMessage
			if err := a.get(ctx, path, q, &w); err != nil {
				return nil, err
			}
			_ = json.Unmarshal(w[key], &items)
		}
		out = append(out, items...)
		if len(items) < per {
			break
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// --- results ---------------------------------------------------------------------

// slim makes GitHub's answers smaller for people and agents: API link
// fields (*_url, except html_url and download links), node ids and avatar
// noise go, and user objects become their login.
func slim(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if login, ok := t["login"].(string); ok {
			if _, isUser := t["avatar_url"]; isUser {
				return login
			}
		}
		out := make(map[string]any, len(t))
		for k, x := range t {
			switch {
			case k == "node_id", k == "gravatar_id", k == "_links":
				continue
			case strings.HasSuffix(k, "_url") && k != "html_url" && k != "download_url" && k != "browser_download_url":
				continue
			case k == "url":
				if _, ok := t["html_url"]; ok {
					continue
				}
			}
			out[k] = slim(x)
		}
		return out
	case []any:
		for i := range t {
			t[i] = slim(t[i])
		}
		return t
	}
	return v
}

func slimRaw(raw json.RawMessage) any {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	return slim(v)
}

func slimAll(items []json.RawMessage) []any {
	out := make([]any, 0, len(items))
	for _, x := range items {
		out = append(out, slimRaw(x))
	}
	return out
}

// getSlim fetches one object and slims it.
func (a *account) getSlim(ctx context.Context, path string, q url.Values) (sdk.Result, error) {
	var raw json.RawMessage
	if err := a.get(ctx, path, q, &raw); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(slimRaw(raw))
}

// listSlim fetches a list and slims it.
func (a *account) listSlim(ctx context.Context, path string, q url.Values, key string, limit int) (sdk.Result, error) {
	items, err := a.list(ctx, path, q, key, limit)
	if err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(slimAll(items))
}

// sendSlim sends a request and returns the slimmed answer.
func (a *account) sendSlim(ctx context.Context, method, path string, body any) (sdk.Result, json.RawMessage, error) {
	var raw json.RawMessage
	if err := a.send(ctx, method, path, body, &raw); err != nil {
		return sdk.Result{}, nil, err
	}
	if len(raw) == 0 {
		raw = json.RawMessage(`{"ok":true}`)
	}
	r, err := sdk.JSON(slimRaw(raw))
	return r, raw, err
}

func js(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// plan builds a dry-run result with one change.
func plan(summary, target, op string, before, after any) (sdk.Result, error) {
	ch := sdk.Change{Target: target, Op: op}
	if before != nil {
		ch.Before = js(before)
	}
	if after != nil {
		ch.After = js(after)
	}
	return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{ch}}}, nil
}

// withUndo attaches an undo token to a result.
func withUndo(r sdk.Result, err error, action string, input any, desc string) (sdk.Result, error) {
	if err != nil {
		return r, err
	}
	r.Undo = sdk.UndoWith(action, input, desc)
	return r, nil
}

func isNotFound(err error) bool { return rest.IsStatus(err, http.StatusNotFound) }

// pick copies the given keys of m (when present) into a new map.
func pick(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

func toMap(raw json.RawMessage) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(raw, &m)
	return m
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func readerOf(b []byte) io.Reader { return bytes.NewReader(b) }
