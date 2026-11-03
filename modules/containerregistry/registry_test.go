package containerregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	dIndex = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dAmd   = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dArm   = "sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// fakeRegistry speaks the distribution API behind a Bearer token service.
type fakeRegistry struct {
	mu         sync.Mutex
	tokenCalls int
	private    bool // the token service wants basic auth
	srvURL     string
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		f.mu.Lock()
		f.tokenCalls++
		f.mu.Unlock()
		if u, p, ok := r.BasicAuth(); f.private && (!ok || u != "me" || p != "regpass") {
			w.WriteHeader(401)
			return
		}
		if r.URL.Query().Get("service") != "fake" || !strings.HasPrefix(r.URL.Query().Get("scope"), "repository:team/app:pull") && r.URL.Query().Get("scope") != "registry:catalog:*" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"token":"tok-123","expires_in":300}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok-123" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="fake",scope="repository:team/app:pull"`, f.srvURL))
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`)
		return
	}
	switch r.URL.Path {
	case "/v2/team/app/tags/list":
		if r.URL.Query().Get("last") == "" {
			w.Header().Set("Link", `</v2/team/app/tags/list?last=1.2.3&n=1000>; rel="next"`)
			io.WriteString(w, `{"name":"team/app","tags":["latest","1.2.2","1.2.3","1.2.3-alpine"]}`)
			return
		}
		io.WriteString(w, `{"name":"team/app","tags":["1.2.10","1.3.0","2.0.0","1.3","v1.4.0","2.0.0-rc1","1.3.0-alpine"]}`)
	case "/v2/team/app/manifests/latest":
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		w.Header().Set("Docker-Content-Digest", dIndex)
		fmt.Fprintf(w, `{"manifests":[{"digest":%q,"platform":{"os":"linux","architecture":"amd64"}},{"digest":%q,"platform":{"os":"linux","architecture":"arm64","variant":"v8"}},{"digest":"sha256:dd","platform":{"os":"unknown","architecture":"unknown"}}]}`, dAmd, dArm)
	case "/v2/team/app/manifests/" + dAmd, "/v2/team/app/manifests/" + dArm, "/v2/team/app/manifests/1.2.3":
		if !strings.Contains(r.Header.Get("Accept"), "application/vnd.oci.image.manifest.v1+json") {
			w.WriteHeader(406)
			return
		}
		w.Header().Set("Docker-Content-Digest", dAmd)
		io.WriteString(w, `{"config":{"size":1000},"layers":[{"size":20000},{"size":30000}]}`)
	case "/v2/":
		w.WriteHeader(200)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry"}]}`)
	}
}

func setup(t *testing.T, private bool, cfg Config) (*Module, *fakeRegistry) {
	f := &fakeRegistry{private: private}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.srvURL = srv.URL
	m := New()
	cfg.Registry = srv.URL
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://reg": "regpass", "secret://bad": "nope"}), "r", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (map[string]any, error) {
	r, err := m.Invoke(context.Background(), sdk.Call{Instance: "r", Action: action, Input: json.RawMessage(in)})
	var out map[string]any
	if err == nil {
		json.Unmarshal(r.Output, &out)
	}
	return out, err
}

func TestRegistry(t *testing.T) {
	m, f := setup(t, false, Config{})
	if h := m.Health(context.Background(), "r"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	out, err := invoke(m, "tags", `{"repository":"team/app"}`)
	if err != nil || out["count"].(float64) != 11 {
		t.Fatalf("%v %v", out, err)
	}
	out, err = invoke(m, "manifest", `{"repository":"team/app"}`)
	if err != nil || out["digest"] != dIndex {
		t.Fatalf("%v %v", out, err)
	}
	pl := out["platforms"].([]any)
	if len(pl) != 2 || pl[1].(map[string]any)["platform"] != "linux/arm64/v8" || pl[0].(map[string]any)["size"].(float64) != 51000 {
		t.Fatalf("platforms %v", pl)
	}
	out, err = invoke(m, "manifest", `{"repository":"team/app","tag":"1.2.3"}`)
	if err != nil || out["size"].(float64) != 51000 || out["layers"].(float64) != 2 {
		t.Fatalf("%v %v", out, err)
	}
	out, err = invoke(m, "newer", `{"repository":"team/app","tag":"1.2.3"}`)
	if err != nil || out["latest"] != "2.0.0" || out["majorUpdate"] != true {
		t.Fatalf("%v %v", out, err)
	}
	if got := fmt.Sprint(out["newer"]); got != "[2.0.0 1.3.0 1.2.10]" {
		t.Fatal(got)
	}
	if f.tokenCalls != 1 {
		t.Fatalf("token fetched %d times, want it reused", f.tokenCalls)
	}
	if _, err := invoke(m, "tags", `{"repository":"team/missing"}`); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatal(err)
	}
}

func TestRegistryPrivate(t *testing.T) {
	m, _ := setup(t, true, Config{Username: "me", Password: "secret://reg"})
	if _, err := invoke(m, "tags", `{"repository":"team/app"}`); err != nil {
		t.Fatal(err)
	}
	bad, _ := setup(t, true, Config{Username: "me", Password: "secret://bad"})
	if _, err := invoke(bad, "tags", `{"repository":"team/app"}`); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
	anon, _ := setup(t, true, Config{})
	if _, err := invoke(anon, "tags", `{"repository":"team/app"}`); err == nil {
		t.Fatal("anonymous access to a private image")
	}
}

func TestNewer(t *testing.T) {
	tags := []string{"1.2.3", "1.2.4", "1.10.0", "1.9.9", "1.3", "v1.5.0", "1.2.4-alpine", "1.11.0-alpine", "latest", "2.0.0-rc1"}
	cases := map[string][]string{
		"1.2.3":        {"1.10.0", "1.9.9", "1.2.4"},
		"1.2":          {"1.3"},
		"v1.4.0":       {"v1.5.0"},
		"1.2.3-alpine": {"1.11.0-alpine", "1.2.4-alpine"},
		"1.10.0":       {},
	}
	for cur, want := range cases {
		got, err := Newer(cur, tags)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v %v, want %v", cur, got, err, want)
		}
	}
	if _, err := Newer("latest", tags); err == nil {
		t.Error("latest is not a version")
	}
}

func TestRegistryValidation(t *testing.T) {
	m, f := setup(t, false, Config{})
	for _, in := range []string{
		`{"repository":"../etc"}`, `{"repository":"Team/App"}`, `{"repository":"team/app?x"}`, `{"repository":"team//app"}`,
		`{"repository":"team/app","tag":"../x"}`, `{"repository":"team/app","tag":"a/b"}`, `{"repository":"team/app","tag":"-x"}`,
	} {
		if _, err := invoke(m, "manifest", in); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if f.tokenCalls != 0 {
		t.Fatal("invalid input reached the registry")
	}
	for _, c := range []Config{
		{Registry: "http://registry.example.com"},
		{Registry: "ghcr.io/path"},
		{Registry: "ghcr.io", Username: "me", Password: "plain"},
		{Registry: "ghcr.io", Password: "secret://reg"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	hub := New()
	raw, _ := json.Marshal(Config{Registry: "docker.io"})
	hub.Configure(context.Background(), fakehost.New(nil), "h", raw)
	c, _ := hub.set.Get("h")
	if r, err := c.repo("nginx"); err != nil || r != "library/nginx" || c.base != "https://registry-1.docker.io" {
		t.Fatal(r, err, c.base)
	}
}

func TestChallenge(t *testing.T) {
	s, p := challenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`)
	if s != "bearer" || p["realm"] != "https://auth.docker.io/token" || p["service"] != "registry.docker.io" || p["scope"] != "repository:library/nginx:pull" {
		t.Fatal(s, p)
	}
	if next := nextLink(`<https://evil.example/v2/x/tags/list?last=a>; rel="next"`, "x"); next != "" {
		t.Fatal("followed a link off the registry")
	}
}
