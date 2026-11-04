package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// The generic REST and GraphQL actions reach anything the token allows that
// the dedicated actions don't cover. Their risk follows what the call can
// do: GET is read, POST/PATCH/PUT are write and DELETE is destructive, each
// a separate action so the policy engine (and approvals) see the real risk.
// GraphQL queries are read; anything with a mutation must go through
// graphql_mutate (write).

// apiPath checks a path relative to the API base: it must start with "/",
// stay on the API (no scheme, no host, no "//", no ".." segments) and may
// carry a query string, which is merged into query.
func apiPath(p string, query map[string]string) (string, url.Values, error) {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.Contains(p, "://") || strings.ContainsAny(p, "\\#\r\n\t ") {
		return "", nil, errors.New(`path must be an API path starting with "/", like /repos/owner/name; absolute URLs aren't allowed`)
	}
	path, rawq, _ := strings.Cut(p, "?")
	for _, s := range strings.Split(path, "/") {
		if dec, err := url.PathUnescape(s); err != nil || dec == ".." || dec == "." {
			return "", nil, fmt.Errorf("invalid path segment %q", s)
		}
	}
	q, err := url.ParseQuery(rawq)
	if err != nil {
		return "", nil, fmt.Errorf("invalid query string: %w", err)
	}
	for k, v := range query {
		q.Set(k, v)
	}
	return path, q, nil
}

type apiIn struct {
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Query  map[string]string `json:"query"`
	Body   json.RawMessage   `json:"body"`
}

var apiSchema = func(methods ...string) json.RawMessage {
	props := []string{pStr("path", `API path, e.g. /repos/owner/name/rulesets (no host)`), `"query":{"type":"object","additionalProperties":{"type":"string"}}`}
	if len(methods) > 1 {
		props = append(props, pEnum("method", "", methods...))
	}
	if len(methods) > 0 {
		props = append(props, `"body":{"description":"JSON request body"}`)
	}
	req := "path"
	if len(methods) > 1 {
		req = "method,path"
	}
	return schema(req, props...)
}

func init() {
	def(sdk.ActionSpec{Name: "api_read", Title: "GitHub API (read)", Risk: sdk.RiskRead, Input: apiSchema(),
		Description: "Any GET request to the GitHub REST API, for what the other actions don't cover. Answers over 1 MB are cut."},
		func(ctx context.Context, a *account, _ args, c sdk.Call) (sdk.Result, error) {
			return a.apiCall(ctx, c, http.MethodGet)
		})
	def(sdk.ActionSpec{Name: "api_write", Title: "GitHub API (write)", Risk: sdk.RiskWrite, DryRun: true, Input: apiSchema(http.MethodPost, http.MethodPatch, http.MethodPut),
		Description: "Any POST, PATCH or PUT request to the GitHub REST API."},
		func(ctx context.Context, a *account, _ args, c sdk.Call) (sdk.Result, error) {
			var in apiIn
			if err := sdk.Decode(c, &in); err != nil {
				return sdk.Result{}, err
			}
			m := strings.ToUpper(in.Method)
			if m != http.MethodPost && m != http.MethodPatch && m != http.MethodPut {
				return sdk.Result{}, errors.New("api_write takes POST, PATCH or PUT; use api_read for GET and api_delete for DELETE")
			}
			return a.apiCall(ctx, c, m)
		})
	def(sdk.ActionSpec{Name: "api_delete", Title: "GitHub API (delete)", Risk: sdk.RiskDestructive, DryRun: true, Input: apiSchema(http.MethodDelete),
		Description: "Any DELETE request to the GitHub REST API."},
		func(ctx context.Context, a *account, _ args, c sdk.Call) (sdk.Result, error) {
			return a.apiCall(ctx, c, http.MethodDelete)
		})
	def(sdk.ActionSpec{Name: "graphql_read", Title: "GitHub GraphQL (query)", Risk: sdk.RiskRead,
		Description: "A GraphQL query. Mutations are refused here; use graphql_mutate.",
		Input:       schema("query", pText("query", "GraphQL query"), pObj("variables", ""))},
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			if isMutation(p.Query) {
				return sdk.Result{}, errors.New("this GraphQL document contains a mutation or subscription; use graphql_mutate")
			}
			return a.graphql(ctx, p.Query, p.Variables)
		})
	def(sdk.ActionSpec{Name: "graphql_mutate", Title: "GitHub GraphQL (mutation)", Risk: sdk.RiskWrite, DryRun: true,
		Description: "A GraphQL document that changes something.",
		Input:       schema("query", pText("query", "GraphQL mutation"), pObj("variables", ""))},
		func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error) {
			if err := needText("query", p.Query); err != nil {
				return sdk.Result{}, err
			}
			if c.DryRun {
				return plan("Run a GraphQL mutation", a.graphqlURL(), "mutate", nil, map[string]any{"query": p.Query, "variables": p.Variables})
			}
			return a.graphql(ctx, p.Query, p.Variables)
		})
}

// mutationRe finds a mutation or subscription operation. It looks at the
// document with comments and strings removed, so a word inside a string
// doesn't count, while any real operation of those kinds does.
var (
	mutationRe   = regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_])(mutation|subscription)([^A-Za-z0-9_]|$)`)
	gqlStringRe  = regexp.MustCompile(`"""(?s:.*?)"""|"(?:[^"\\\n]|\\.)*"`)
	gqlCommentRe = regexp.MustCompile(`#[^\n]*`)
)

func isMutation(q string) bool {
	s := gqlStringRe.ReplaceAllString(q, `""`)
	s = gqlCommentRe.ReplaceAllString(s, "")
	// A field or alias named "mutation" is refused too; being conservative
	// only costs a switch to graphql_mutate.
	return mutationRe.MatchString(s)
}

func (a *account) graphqlURL() string {
	if b, ok := strings.CutSuffix(a.api.Base, "/api/v3"); ok {
		return b + "/api/graphql"
	}
	return a.api.Base + "/graphql"
}

func (a *account) graphql(ctx context.Context, query string, vars map[string]any) (sdk.Result, error) {
	if err := needText("query", query); err != nil {
		return sdk.Result{}, err
	}
	body, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	res, err := a.raw(ctx, http.MethodPost, a.graphqlURL(), nil, bytes.NewReader(body), map[string]string{"Content-Type": "application/json"}, 1<<20, false)
	if err != nil {
		return sdk.Result{}, err
	}
	if res.Status >= 300 {
		return sdk.Result{}, fmt.Errorf("GraphQL: %d %s", res.Status, strings.TrimSpace(string(res.Body)))
	}
	if res.Truncated {
		return sdk.Result{}, errors.New("the GraphQL answer is larger than 1 MB; ask for fewer fields or nodes")
	}
	var out struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(res.Body, &out); err != nil {
		return sdk.Result{}, err
	}
	if len(out.Errors) > 0 && len(out.Data) == 0 || string(out.Data) == "null" && len(out.Errors) > 0 {
		return sdk.Result{}, errors.New("GraphQL: " + out.Errors[0].Message)
	}
	return sdk.JSON(map[string]any{"data": out.Data, "errors": out.Errors})
}

func (a *account) apiCall(ctx context.Context, c sdk.Call, method string) (sdk.Result, error) {
	var in apiIn
	if err := sdk.Decode(c, &in); err != nil {
		return sdk.Result{}, err
	}
	path, q, err := apiPath(in.Path, in.Query)
	if err != nil {
		return sdk.Result{}, err
	}
	hasBody := len(in.Body) > 0 && string(in.Body) != "null"
	if method == http.MethodGet && hasBody {
		return sdk.Result{}, errors.New("a GET request has no body")
	}
	if c.DryRun {
		var after any
		if hasBody {
			after = in.Body
		}
		target := path
		if len(q) > 0 {
			target += "?" + q.Encode()
		}
		op := map[string]string{http.MethodDelete: "delete", http.MethodPost: "create", http.MethodPut: "update", http.MethodPatch: "update"}[method]
		return plan(method+" "+target, target, op, nil, after)
	}
	var body *bytes.Reader
	hdr := map[string]string{}
	if hasBody {
		body = bytes.NewReader(in.Body)
		hdr["Content-Type"] = "application/json"
	}
	var res rawResp
	if body != nil {
		res, err = a.raw(ctx, method, path, q, body, hdr, 1<<20, false)
	} else {
		res, err = a.raw(ctx, method, path, q, nil, hdr, 1<<20, false)
	}
	if err != nil {
		return sdk.Result{}, err
	}
	out := map[string]any{"status": res.Status}
	if l := res.Header.Get("Link"); l != "" {
		out["link"] = l
	}
	if res.Truncated {
		out["truncated"] = true
	}
	var v any
	if !res.Truncated && json.Unmarshal(res.Body, &v) == nil {
		out["body"] = v
	} else if len(res.Body) > 0 {
		out["body"] = string(res.Body)
	}
	if res.Status >= 400 {
		msg := fmt.Sprintf("GitHub answered %d", res.Status)
		if m, ok := v.(map[string]any); ok && str(m, "message") != "" {
			msg += ": " + str(m, "message")
		}
		return sdk.Result{}, errors.New(msg)
	}
	return sdk.JSON(out)
}
