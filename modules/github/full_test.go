package github

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// repoFake is a small in-memory GitHub: one repository with files, branches,
// secrets and variables, enough to exercise the table-driven actions.
type repoFake struct {
	t       *testing.T
	mu      sync.Mutex
	pub     *[32]byte
	priv    *[32]byte
	secrets map[string]string // name -> decrypted value
	vars    map[string]string
	files   map[string]string // path -> content
	sha     map[string]string // path -> blob sha
	refs    map[string]string // refs/heads/x -> commit sha
	calls   []string
	pages   int
}

func newRepoFake(t *testing.T) *repoFake {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &repoFake{t: t, pub: pub, priv: priv, secrets: map[string]string{}, vars: map[string]string{},
		files: map[string]string{"README.md": "hello\n"}, sha: map[string]string{"README.md": "s1"}, refs: map[string]string{"refs/heads/main": "c1", "refs/heads/old": "c0"}}
}

func (f *repoFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/v3")
	f.calls = append(f.calls, r.Method+" "+path)
	if r.Header.Get("Authorization") != "Bearer ghp_test" {
		w.WriteHeader(401)
		return
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	const repo = "/repos/acme/app"
	switch {
	case r.Method == "GET" && path == repo+"/actions/secrets/public-key":
		io.WriteString(w, `{"key_id":"k1","key":"`+base64.StdEncoding.EncodeToString(f.pub[:])+`"}`)
	case r.Method == "GET" && strings.HasPrefix(path, repo+"/actions/secrets/"):
		name := strings.TrimPrefix(path, repo+"/actions/secrets/")
		if _, ok := f.secrets[name]; !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		io.WriteString(w, `{"name":"`+name+`"}`)
	case r.Method == "PUT" && strings.HasPrefix(path, repo+"/actions/secrets/"):
		name := strings.TrimPrefix(path, repo+"/actions/secrets/")
		if body["key_id"] != "k1" {
			w.WriteHeader(422)
			return
		}
		sealed, _ := base64.StdEncoding.DecodeString(body["encrypted_value"].(string))
		plain, ok := box.OpenAnonymous(nil, sealed, f.pub, f.priv)
		if !ok {
			w.WriteHeader(422)
			io.WriteString(w, `{"message":"bad box"}`)
			return
		}
		f.secrets[name] = string(plain)
		w.WriteHeader(201)
	case r.Method == "GET" && strings.HasPrefix(path, repo+"/actions/variables/"):
		name := strings.TrimPrefix(path, repo+"/actions/variables/")
		v, ok := f.vars[name]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"name": name, "value": v})
	case r.Method == "POST" && path == repo+"/actions/variables":
		f.vars[body["name"].(string)] = body["value"].(string)
		w.WriteHeader(201)
	case r.Method == "PATCH" && strings.HasPrefix(path, repo+"/actions/variables/"):
		f.vars[strings.TrimPrefix(path, repo+"/actions/variables/")] = body["value"].(string)
		w.WriteHeader(204)
	case r.Method == "DELETE" && strings.HasPrefix(path, repo+"/actions/variables/"):
		delete(f.vars, strings.TrimPrefix(path, repo+"/actions/variables/"))
		w.WriteHeader(204)
	case strings.HasPrefix(path, repo+"/contents/"):
		fp := strings.TrimPrefix(path, repo+"/contents/")
		switch r.Method {
		case "GET":
			c, ok := f.files[fp]
			if !ok {
				w.WriteHeader(404)
				io.WriteString(w, `{"message":"Not Found"}`)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"type": "file", "path": fp, "sha": f.sha[fp], "size": len(c), "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(c))})
		case "PUT":
			if old, ok := f.sha[fp]; ok && body["sha"] != old {
				w.WriteHeader(409)
				io.WriteString(w, `{"message":"sha mismatch"}`)
				return
			}
			b, _ := base64.StdEncoding.DecodeString(body["content"].(string))
			f.files[fp] = string(b)
			f.sha[fp] = "s" + strconv.Itoa(len(f.calls))
			json.NewEncoder(w).Encode(map[string]any{"content": map[string]string{"sha": f.sha[fp]}, "commit": map[string]string{"sha": "c" + strconv.Itoa(len(f.calls))}})
		case "DELETE":
			if body["sha"] != f.sha[fp] {
				w.WriteHeader(409)
				return
			}
			delete(f.files, fp)
			delete(f.sha, fp)
			json.NewEncoder(w).Encode(map[string]any{"commit": map[string]string{"sha": "cd"}})
		}
	case r.Method == "GET" && strings.HasPrefix(path, repo+"/git/ref/heads/"):
		ref := "refs/heads/" + strings.TrimPrefix(path, repo+"/git/ref/heads/")
		sha, ok := f.refs[ref]
		if !ok {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"ref":"`+ref+`","object":{"sha":"`+sha+`"}}`)
	case r.Method == "DELETE" && strings.HasPrefix(path, repo+"/git/refs/heads/"):
		delete(f.refs, "refs/heads/"+strings.TrimPrefix(path, repo+"/git/refs/heads/"))
		w.WriteHeader(204)
	case r.Method == "POST" && path == repo+"/git/refs":
		f.refs[body["ref"].(string)] = body["sha"].(string)
		w.WriteHeader(201)
		io.WriteString(w, `{"ref":"`+body["ref"].(string)+`"}`)
	case r.Method == "GET" && strings.HasPrefix(path, repo+"/commits/"):
		ref := strings.TrimPrefix(path, repo+"/commits/")
		if sha, ok := f.refs["refs/heads/"+ref]; ok {
			ref = sha
		}
		io.WriteString(w, `{"sha":"`+ref+`"}`)
	case r.Method == "GET" && path == repo+"/branches":
		// An endless list: pagination must stop by itself.
		f.pages++
		n, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		items := make([]map[string]any, n)
		for i := range items {
			items[i] = map[string]any{"name": "b" + strconv.Itoa(i), "commit": map[string]string{"sha": "x", "url": "https://api/..."}}
		}
		json.NewEncoder(w).Encode(items)
	case r.Method == "GET" && path == repo:
		io.WriteString(w, `{"full_name":"acme/app","default_branch":"main","owner":{"login":"acme","avatar_url":"a"},"node_id":"N","hooks_url":"x","html_url":"https://github.com/acme/app"}`)
	case path == "/api/graphql" || path == "/graphql":
		io.WriteString(w, `{"data":{"viewer":{"login":"octo"}}}`)
	case path == repo+"/rulesets":
		w.Header().Set("Link", `<x>; rel="next"`)
		io.WriteString(w, `[{"id":1,"name":"main"}]`)
	case r.Method == "DELETE" && path == repo+"/rulesets/1":
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found: `+r.Method+" "+path+`"}`)
	}
}

func setupFake(t *testing.T, enterprise bool) (*Module, *repoFake) {
	t.Helper()
	f := newRepoFake(t)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	base := srv.URL
	if enterprise {
		base += "/api/v3"
	}
	m := New()
	m.HTTP = srv.Client()
	cfg, _ := json.Marshal(map[string]any{"token": "secret://gh", "api": base})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://gh": "ghp_test"}), "gh", cfg); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(t *testing.T, m *Module, action string, in any, dry bool) (sdk.Result, error) {
	t.Helper()
	b, _ := json.Marshal(in)
	return m.Invoke(context.Background(), sdk.Call{Instance: "gh", Action: action, Input: b, DryRun: dry})
}

func mustT(t *testing.T) func(sdk.Result, error) sdk.Result {
	return func(r sdk.Result, err error) sdk.Result {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
}

func TestSealSecretRoundTrip(t *testing.T) {
	pub, priv, _ := box.GenerateKey(rand.Reader)
	enc, err := sealSecret(base64.StdEncoding.EncodeToString(pub[:]), "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(enc)
	if got, ok := box.OpenAnonymous(nil, raw, pub, priv); !ok || string(got) != "hunter2" {
		t.Fatalf("round trip: %q %v", got, ok)
	}
	if _, err := sealSecret("short", "x"); err == nil {
		t.Fatal("a bad key must be refused")
	}
}

func TestSetSecretEncryptsForGitHub(t *testing.T) {
	m, f := setupFake(t, false)
	must := mustT(t)
	spec, _ := findSpec(m, "set_secret")
	if !spec.Sensitive || spec.Risk != sdk.RiskDestructive {
		t.Fatalf("set_secret must be sensitive and destructive (it can replace deploy credentials): %+v", spec)
	}
	// Running a workflow on any ref, cancelling a run and deleting a file
	// are destructive too.
	for _, n := range []string{"dispatch_workflow", "cancel_run", "delete_file"} {
		if s, _ := findSpec(m, n); s.Risk != sdk.RiskDestructive {
			t.Fatalf("%s must be destructive: %+v", n, s)
		}
	}
	if d, _ := findSpec(m, "delete_secret"); d.Risk != sdk.RiskDestructive {
		t.Fatal("delete_secret must be destructive")
	}
	// The dry run never carries the value.
	r := must(invoke(t, m, "set_secret", map[string]string{"repo": "acme/app", "name": "DEPLOY_KEY", "value": "s3cr3t"}, true))
	if b, _ := json.Marshal(r.Plan); strings.Contains(string(b), "s3cr3t") || r.Plan == nil {
		t.Fatalf("plan %s", b)
	}
	must(invoke(t, m, "set_secret", map[string]string{"repo": "acme/app", "name": "DEPLOY_KEY", "value": "s3cr3t"}, false))
	if f.secrets["DEPLOY_KEY"] != "s3cr3t" {
		t.Fatalf("GitHub decrypted %q", f.secrets["DEPLOY_KEY"])
	}
	if _, err := invoke(t, m, "set_secret", map[string]string{"repo": "acme/app", "name": "GITHUB_TOKEN", "value": "x"}, false); err == nil {
		t.Fatal("GITHUB_ names are reserved")
	}
}

func TestVariablesUndo(t *testing.T) {
	m, f := setupFake(t, false)
	must := mustT(t)
	r := must(invoke(t, m, "set_variable", map[string]string{"repo": "acme/app", "name": "REGION", "value": "eu"}, false))
	if f.vars["REGION"] != "eu" || r.Undo == nil || r.Undo.Action != "delete_variable" {
		t.Fatalf("create: %v %+v", f.vars, r.Undo)
	}
	r = must(invoke(t, m, "set_variable", map[string]string{"repo": "acme/app", "name": "REGION", "value": "us"}, false))
	if f.vars["REGION"] != "us" || r.Undo.Action != "set_variable" {
		t.Fatalf("update: %v %+v", f.vars, r.Undo)
	}
	must(m.Invoke(context.Background(), sdk.Call{Instance: "gh", Action: r.Undo.Action, Input: r.Undo.Input}))
	if f.vars["REGION"] != "eu" {
		t.Fatalf("undo: %v", f.vars)
	}
}

func TestPutFileAndUndo(t *testing.T) {
	m, f := setupFake(t, false)
	must := mustT(t)
	// Dry run shows the old and new text.
	r := must(invoke(t, m, "put_file", map[string]string{"repo": "acme/app", "path": "README.md", "content": "bye\n", "message": "Update"}, true))
	if ch := r.Plan.Changes[0]; ch.Op != "update" || string(ch.Before) != `"hello\n"` || string(ch.After) != `"bye\n"` {
		t.Fatalf("plan %+v", r.Plan)
	}
	if f.files["README.md"] != "hello\n" {
		t.Fatal("a dry run changed the file")
	}
	r = must(invoke(t, m, "put_file", map[string]string{"repo": "acme/app", "path": "README.md", "content": "bye\n", "message": "Update"}, false))
	if f.files["README.md"] != "bye\n" || r.Undo == nil {
		t.Fatalf("update: %q %+v", f.files["README.md"], r.Undo)
	}
	must(m.Invoke(context.Background(), sdk.Call{Instance: "gh", Action: r.Undo.Action, Input: r.Undo.Input}))
	if f.files["README.md"] != "hello\n" {
		t.Fatalf("undo restored %q", f.files["README.md"])
	}
	// A new file's undo deletes it.
	r = must(invoke(t, m, "put_file", map[string]string{"repo": "acme/app", "path": "docs/new file.md", "content": "x", "message": "Add"}, false))
	if _, ok := f.files["docs/new file.md"]; !ok || r.Undo.Action != "delete_file" {
		t.Fatalf("create %v %+v", f.files, r.Undo)
	}
	must(m.Invoke(context.Background(), sdk.Call{Instance: "gh", Action: r.Undo.Action, Input: r.Undo.Input}))
	if _, ok := f.files["docs/new file.md"]; ok {
		t.Fatal("undo should delete the new file")
	}
	// Stale SHAs and odd paths are refused.
	if _, err := invoke(t, m, "put_file", map[string]string{"repo": "acme/app", "path": "README.md", "content": "y", "message": "m", "sha": "stale"}, false); err == nil {
		t.Fatal("stale sha accepted")
	}
	if _, err := invoke(t, m, "file", map[string]string{"repo": "acme/app", "path": "../../user"}, false); err == nil {
		t.Fatal("path traversal accepted")
	}
	r = must(invoke(t, m, "file", map[string]string{"repo": "acme/app", "path": "README.md"}, false))
	if !strings.Contains(string(r.Output), `"content":"hello\n"`) {
		t.Fatalf("file %s", r.Output)
	}
}

func TestDeleteBranchUndo(t *testing.T) {
	m, f := setupFake(t, false)
	must := mustT(t)
	r := must(invoke(t, m, "delete_branch", map[string]string{"repo": "acme/app", "branch": "old"}, false))
	if _, ok := f.refs["refs/heads/old"]; ok || r.Undo == nil || r.Undo.Action != "create_branch" {
		t.Fatalf("delete: %v %+v", f.refs, r.Undo)
	}
	must(m.Invoke(context.Background(), sdk.Call{Instance: "gh", Action: r.Undo.Action, Input: r.Undo.Input}))
	if f.refs["refs/heads/old"] != "c0" {
		t.Fatalf("undo: %v", f.refs)
	}
}

func TestPaginationBounded(t *testing.T) {
	m, f := setupFake(t, false)
	must := mustT(t)
	r := must(invoke(t, m, "branches", map[string]any{"repo": "acme/app", "limit": 250}, false))
	var out []map[string]any
	_ = json.Unmarshal(r.Output, &out)
	if len(out) != 250 || f.pages != 3 {
		t.Fatalf("got %d items over %d pages", len(out), f.pages)
	}
	if _, ok := out[0]["commit"].(map[string]any)["url"]; !ok {
		// "url" stays when there's no html_url to replace it.
		t.Fatalf("slim dropped too much: %v", out[0])
	}
	f.pages = 0
	must(invoke(t, m, "branches", map[string]any{"repo": "acme/app", "limit": 100000}, false))
	if f.pages != 3 {
		t.Fatalf("limit not capped: %d pages", f.pages)
	}
	// Answers are slimmed: user objects become logins, API links go.
	r = must(invoke(t, m, "repo", map[string]string{"repo": "acme/app"}, false))
	if s := string(r.Output); !strings.Contains(s, `"owner":"acme"`) || strings.Contains(s, "hooks_url") || strings.Contains(s, "node_id") {
		t.Fatalf("repo %s", s)
	}
}

func TestAPIRiskSplit(t *testing.T) {
	m, f := setupFake(t, false)
	must := mustT(t)
	want := map[string]sdk.Risk{"api_read": sdk.RiskRead, "api_write": sdk.RiskDestructive, "api_delete": sdk.RiskDestructive, "graphql_read": sdk.RiskRead, "graphql_mutate": sdk.RiskDestructive}
	for name, risk := range want {
		s, ok := findSpec(m, name)
		if !ok || s.Risk != risk {
			t.Errorf("%s: %+v", name, s)
		}
	}
	r := must(invoke(t, m, "api_read", map[string]any{"path": "/repos/acme/app/rulesets", "query": map[string]string{"includes_parents": "true"}}, false))
	if !strings.Contains(string(r.Output), `"name":"main"`) || !strings.Contains(string(r.Output), `rel=\"next\"`) {
		t.Fatalf("api_read %s", r.Output)
	}
	// Methods can't cross risk levels.
	if _, err := invoke(t, m, "api_write", map[string]any{"method": "DELETE", "path": "/repos/acme/app/rulesets/1"}, false); err == nil {
		t.Fatal("api_write accepted DELETE")
	}
	if _, err := invoke(t, m, "api_write", map[string]any{"method": "GET", "path": "/user"}, false); err == nil {
		t.Fatal("api_write accepted GET")
	}
	if _, err := invoke(t, m, "api_read", map[string]any{"path": "/user", "body": map[string]int{"a": 1}}, false); err == nil {
		t.Fatal("api_read accepted a body")
	}
	// Only API paths.
	for _, p := range []string{"https://evil.example/x", "//evil.example/x", "repos/acme/app", "/repos/../../admin", "/repos/%2e%2e/x", "/a b"} {
		if _, err := invoke(t, m, "api_read", map[string]any{"path": p}, false); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	// Dry runs of writes send nothing.
	n := len(f.calls)
	r = must(invoke(t, m, "api_delete", map[string]any{"path": "/repos/acme/app/rulesets/1"}, true))
	if r.Plan == nil || len(f.calls) != n || r.Plan.Changes[0].Op != "delete" {
		t.Fatalf("dry run %+v, calls %v", r.Plan, f.calls[n:])
	}
	must(invoke(t, m, "api_delete", map[string]any{"path": "/repos/acme/app/rulesets/1"}, false))

	// GraphQL: queries read, mutations refused there.
	if _, err := invoke(t, m, "graphql_read", map[string]any{"query": "mutation { addStar(input:{starrableId:\"x\"}) { clientMutationId } }"}, false); err == nil {
		t.Fatal("graphql_read ran a mutation")
	}
	if _, err := invoke(t, m, "graphql_read", map[string]any{"query": "query Q {\n  viewer { login }\n} mutation M { x }"}, false); err == nil {
		t.Fatal("a second mutation operation slipped through")
	}
	r = must(invoke(t, m, "graphql_read", map[string]any{"query": "{ viewer { login } } # no mutation here\n", "variables": map[string]any{"q": "mutation"}}, false))
	if !strings.Contains(string(r.Output), "octo") {
		t.Fatalf("graphql %s", r.Output)
	}
	must(invoke(t, m, "graphql_read", map[string]any{"query": `{ search(query: "mutation", type: REPOSITORY, first: 1) { repositoryCount } }`}, false))
	must(invoke(t, m, "graphql_mutate", map[string]any{"query": "mutation { x }"}, false))
}

func TestEnterpriseGraphQLAndUploads(t *testing.T) {
	m, f := setupFake(t, true)
	must := mustT(t)
	must(invoke(t, m, "graphql_read", map[string]any{"query": "{ viewer { login } }"}, false))
	if last := f.calls[len(f.calls)-1]; last != "POST /api/graphql" {
		t.Fatalf("Enterprise GraphQL went to %s", last)
	}
	a, _ := m.set.Get("gh")
	host := strings.TrimPrefix(a.api.Base, "http://")
	host = strings.TrimSuffix(host, "/api/v3")
	if _, err := a.uploadURL("http://" + host + "/api/uploads/repos/acme/app/releases/1/assets{?name,label}"); err != nil {
		t.Fatalf("own host refused: %v", err)
	}
	if _, err := a.uploadURL("https://evil.example/upload{?name}"); err == nil {
		t.Fatal("token would go to another host")
	}
}

func TestManifestShape(t *testing.T) {
	man := New().Manifest()
	seen := map[string]bool{}
	legacy := map[string]bool{"rerun": true, "create_issue": true, "close_issue": true, "reopen_issue": true, "comment": true, "delete_comment": true}
	for _, a := range man.Actions {
		if seen[a.Name] {
			t.Errorf("duplicate %s", a.Name)
		}
		seen[a.Name] = true
		if a.Risk != sdk.RiskRead && a.Risk != sdk.RiskWrite && a.Risk != sdk.RiskDestructive {
			t.Errorf("%s has no risk", a.Name)
		}
		if a.Risk != sdk.RiskRead && !a.DryRun && !legacy[a.Name] {
			t.Errorf("%s changes things but has no dry run", a.Name)
		}
		if len(a.Input) > 0 && !json.Valid(a.Input) {
			t.Errorf("%s: invalid schema %s", a.Name, a.Input)
		}
	}
	for _, n := range []string{"delete_repo", "transfer_repo", "delete_secret", "delete_branch", "api_delete"} {
		if s, _ := findSpec(New(), n); s.Risk != sdk.RiskDestructive {
			t.Errorf("%s must be destructive", n)
		}
	}
	if len(man.Actions) < 100 {
		t.Errorf("only %d actions", len(man.Actions))
	}
}

func findSpec(m *Module, name string) (sdk.ActionSpec, bool) {
	for _, a := range m.Manifest().Actions {
		if a.Name == name {
			return a, true
		}
	}
	return sdk.ActionSpec{}, false
}
