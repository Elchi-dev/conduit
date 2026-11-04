package gcp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		testKey = k
	})
	return testKey
}

func keyJSON(t *testing.T, tokenURI string) string {
	der, _ := x509.MarshalPKCS8PrivateKey(rsaKey(t))
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	b, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "demo-project", "private_key_id": "kid123",
		"private_key": pemKey, "client_email": "conduit@demo-project.iam.gserviceaccount.com", "token_uri": tokenURI})
	return string(b)
}

type fakeGCP struct {
	mu      sync.Mutex
	t       *testing.T
	srv     *httptest.Server
	seen    []string
	tokens  int
	status  map[string]string
	traffic string
	patched map[string]any
}

// checkJWT verifies the assertion as Google would: RS256 over the header
// and claims with the key's public half, and the expected claims.
func (f *fakeGCP) checkJWT(jwt string) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return fmt.Errorf("not a JWT")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&rsaKey(f.t).PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		return err
	}
	var h map[string]string
	var c map[string]any
	hb, _ := b64.DecodeString(parts[0])
	cb, _ := b64.DecodeString(parts[1])
	json.Unmarshal(hb, &h)
	json.Unmarshal(cb, &c)
	if h["alg"] != "RS256" || h["typ"] != "JWT" || h["kid"] != "kid123" {
		return fmt.Errorf("header %v", h)
	}
	iat, _ := c["iat"].(float64)
	exp, _ := c["exp"].(float64)
	if c["iss"] != "conduit@demo-project.iam.gserviceaccount.com" || c["aud"] != f.srv.URL+"/token" || c["scope"] != scope || exp-iat != 3600 {
		return fmt.Errorf("claims %v", c)
	}
	return nil
}

func (f *fakeGCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/token" {
		r.ParseForm()
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			w.WriteHeader(400)
			return
		}
		if err := f.checkJWT(r.PostForm.Get("assertion")); err != nil {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`)
			return
		}
		f.tokens++
		io.WriteString(w, `{"access_token":"ya29.fake-token","expires_in":3599,"token_type":"Bearer"}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer ya29.fake-token" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":401,"message":"Request had invalid authentication credentials."}}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	ip := "/compute/v1/projects/demo-project/zones/europe-west1-b/instances/"
	sp := "/v2/projects/demo-project/locations/europe-west1/services/hello"
	inst := func(name string) string {
		return fmt.Sprintf(`{"id":"123","name":%q,"zone":"https://compute.googleapis.com/compute/v1/projects/demo-project/zones/europe-west1-b","status":%q,
			"machineType":"https://x/machineTypes/e2-small","metadata":{"items":[{"key":"ssh-keys","value":"LEAKME"},{"key":"startup-script","value":"LEAKME"}]},
			"serviceAccounts":[{"email":"LEAKME"}],"networkInterfaces":[{"networkIP":"10.0.0.2","accessConfigs":[{"natIP":"34.1.2.3"}]}],"scheduling":{"provisioningModel":"SPOT"}}`, name, f.status[name])
	}
	svc := func() string {
		return `{"name":"projects/demo-project/locations/europe-west1/services/hello","uri":"https://hello-abc.a.run.app","ingress":"INGRESS_TRAFFIC_ALL",
			"latestReadyRevision":"projects/demo-project/locations/europe-west1/services/hello/revisions/hello-00002-xyz","terminalCondition":{"state":"CONDITION_SUCCEEDED"},
			"template":{"containers":[{"image":"gcr.io/x/hello","env":[{"name":"DB_PASSWORD","value":"LEAKME"}]}],"serviceAccount":"LEAKME"},
			"traffic":` + f.traffic + `,"trafficStatuses":` + f.traffic + `,"etag":"\"abc\""}`
	}
	switch {
	case r.URL.Path == "/v1/projects/demo-project":
		io.WriteString(w, `{"projectId":"demo-project","name":"Demo","projectNumber":"42","lifecycleState":"ACTIVE"}`)
	case r.URL.Path == "/v1/projects" && r.URL.Query().Get("pageToken") == "":
		io.WriteString(w, `{"projects":[{"projectId":"demo-project","name":"Demo","projectNumber":"42","lifecycleState":"ACTIVE","labels":{"x":"LEAKME"}}],"nextPageToken":"p2"}`)
	case r.URL.Path == "/v1/projects":
		io.WriteString(w, `{"projects":[{"projectId":"other-project","name":"Other","lifecycleState":"DELETE_REQUESTED"}]}`)
	case r.URL.Path == "/compute/v1/projects/demo-project/aggregated/instances":
		fmt.Fprintf(w, `{"items":{"zones/europe-west1-b":{"instances":[%s]},"zones/us-east1-a":{"warning":{"code":"NO_RESULTS_ON_PAGE"}}}}`, inst("web-1"))
	case r.URL.Path == "/compute/v1/projects/demo-project/zones/europe-west1-b/instances":
		fmt.Fprintf(w, `{"items":[%s]}`, inst("web-1"))
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, ip):
		name := strings.TrimPrefix(r.URL.Path, ip)
		if _, ok := f.status[name]; !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":{"code":404,"message":"The resource was not found"}}`)
			return
		}
		io.WriteString(w, inst(name))
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, ip):
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, ip), "/")
		f.status[parts[0]] = map[string]string{"start": "RUNNING", "stop": "TERMINATED", "reset": "RUNNING"}[parts[1]]
		io.WriteString(w, `{"kind":"compute#operation","status":"RUNNING"}`)
	case r.URL.Path == "/v2/projects/demo-project/locations/-/services":
		fmt.Fprintf(w, `{"services":[%s]}`, svc())
	case r.Method == "GET" && r.URL.Path == sp:
		io.WriteString(w, svc())
	case r.Method == "GET" && r.URL.Path == sp+"/revisions":
		io.WriteString(w, `{"revisions":[{"name":"projects/demo-project/locations/europe-west1/services/hello/revisions/hello-00002-xyz","createTime":"2026-11-01T00:00:00Z",
			"containers":[{"image":"gcr.io/x/hello:2","env":[{"name":"K","value":"LEAKME"}]}],"scaling":{"maxInstanceCount":3},"conditions":[{"type":"Ready","state":"CONDITION_SUCCEEDED"}]},
			{"name":"projects/demo-project/locations/europe-west1/services/hello/revisions/hello-00001-abc","containers":[{"image":"gcr.io/x/hello:1"}]}]}`)
	case r.Method == "PATCH" && r.URL.Path == sp:
		var b map[string]any
		json.Unmarshal(body, &b)
		f.patched = b
		if r.URL.Query().Get("validateOnly") != "true" {
			t, _ := json.Marshal(b["traffic"])
			f.traffic = string(t)
		}
		io.WriteString(w, `{"name":"op"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"code":404,"message":"no route"}}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeGCP) {
	f := &fakeGCP{t: t, status: map[string]string{"web-1": "TERMINATED"}, traffic: `[{"type":"TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST","percent":100}]`}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Errorf("the key's token_uri was used") }))
	t.Cleanup(evil.Close)
	m := New()
	m.Base, m.TokenURL = f.srv.URL, f.srv.URL+"/token"
	raw, _ := json.Marshal(Config{Key: ref})
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(other)
	var w map[string]string
	json.Unmarshal([]byte(keyJSON(t, evil.URL)), &w)
	w["private_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	wb, _ := json.Marshal(w)
	secrets := map[string]string{"secret://gcp": keyJSON(t, evil.URL), "secret://wrong": string(wb), "secret://junk": "not json"}
	if err := m.Configure(context.Background(), fakehost.New(secrets), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func clean(t *testing.T, out string) {
	t.Helper()
	for _, s := range []string{"LEAKME", "PRIVATE KEY", "ya29", "kid123"} {
		if strings.Contains(out, s) {
			t.Fatalf("output has %s: %s", s, out)
		}
	}
}

func TestGCP(t *testing.T) {
	m, f := setup(t, "secret://gcp")
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || h.Message != "project Demo (demo-project)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"projectId":"other-project"`},
		{"instances", `{}`, `"externalIps":["34.1.2.3"]`},
		{"instances", `{"zone":"europe-west1-b"}`, `"machineType":"e2-small"`},
		{"run_services", `{}`, `"latestReadyRevision":"hello-00002-xyz"`},
		{"run_revisions", `{"region":"europe-west1","service":"hello"}`, `"trafficPercent":100`},
		{"run_revisions", `{"region":"europe-west1","service":"hello"}`, `"images":["gcr.io/x/hello:1"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
		clean(t, out)
	}
	if f.tokens != 1 {
		t.Fatalf("token not cached: %d", f.tokens)
	}

	in := `{"zone":"europe-west1-b","instance":"web-1"}`
	r, err := invoke(m, "start_instance", in, true)
	if err != nil || r.Plan == nil || f.status["web-1"] != "TERMINATED" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "start_instance", in, false)
	if err != nil || f.status["web-1"] != "RUNNING" || r.Undo == nil || r.Undo.Action != "stop_instance" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, _ := invoke(m, "start_instance", in, false); !strings.Contains(string(r.Output), "nothing to change") || r.Undo != nil {
		t.Fatal(string(r.Output))
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.status["web-1"] != "TERMINATED" {
		t.Fatal(err)
	}
	if _, err := invoke(m, "reset_instance", in, false); err == nil || !strings.Contains(err.Error(), "only a running") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "stop_instance", `{"zone":"europe-west1-b","instance":"gone"}`, false); err == nil || !strings.Contains(err.Error(), "there's no instance gone") {
		t.Fatal(err)
	}

	// Traffic: preview validates with Google and changes nothing.
	tin := `{"region":"europe-west1","service":"hello","traffic":[{"revision":"hello-00001-abc","percent":10},{"latest":true,"percent":90}]}`
	r, err = invoke(m, "set_traffic", tin, true)
	if err != nil || r.Plan == nil || !strings.Contains(f.seen[len(f.seen)-1], "validateOnly=true") || strings.Contains(f.traffic, "hello-00001") {
		t.Fatalf("%+v %v %v", r.Plan, err, f.seen)
	}
	r, err = invoke(m, "set_traffic", tin, false)
	if err != nil || !strings.Contains(f.traffic, `"percent":10,"revision":"hello-00001-abc"`) || r.Undo == nil {
		t.Fatalf("%s %v %s", r.Output, err, f.traffic)
	}
	// The rest of the service went back unchanged.
	if tpl, _ := json.Marshal(f.patched["template"]); !strings.Contains(string(tpl), "DB_PASSWORD") || f.patched["etag"] != `"abc"` {
		t.Fatal(string(tpl))
	}
	clean(t, string(r.Output))
	if r, _ := invoke(m, "set_traffic", tin, false); !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(string(r.Output))
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.traffic != `[{"percent":100,"type":"TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"}]` {
		t.Fatal(err, f.traffic)
	}

	for _, a := range m.Manifest().Actions {
		destructive := a.Name == "stop_instance" || a.Name == "reset_instance" || a.Name == "set_traffic"
		if destructive != (a.Risk == sdk.RiskDestructive) {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestGCPValidation(t *testing.T) {
	m, f := setup(t, "secret://gcp")
	for _, c := range []struct{ action, in string }{
		{"start_instance", `{"instance":"web-1"}`},
		{"start_instance", `{"zone":"europe-west1-b","instance":"../x"}`},
		{"stop_instance", `{"zone":"europe/west1","instance":"web-1"}`},
		{"instances", `{"project":"Bad Project"}`},
		{"instances", `{"zone":"x?y"}`},
		{"run_services", `{"region":"../../x"}`},
		{"run_revisions", `{"region":"europe-west1","service":"a/b"}`},
		{"set_traffic", `{"region":"europe-west1","service":"hello"}`},
		{"set_traffic", `{"region":"europe-west1","service":"hello","traffic":[{"revision":"a","percent":50}]}`},
		{"set_traffic", `{"region":"europe-west1","service":"hello","traffic":[{"revision":"a","latest":true,"percent":100}]}`},
		{"set_traffic", `{"region":"europe-west1","service":"hello","revision":"x/../y"}`},
		{"set_traffic", `{"region":"europe-west1","service":"hello","revision":"a","traffic":[{"latest":true,"percent":100}]}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 || f.tokens != 0 {
		t.Fatalf("invalid input reached Google: %v %d", f.seen, f.tokens)
	}
	for _, c := range []Config{{Key: `{"type":"service_account"}`}, {Key: "secret://gcp", Project: "UPPER"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	// A key Google doesn't know is refused, and the error says nothing of it.
	wrong, _ := setup(t, "secret://wrong")
	if h := wrong.Health(context.Background(), "g"); h.Status != "down" || !strings.Contains(h.Message, "refused the service-account key") {
		t.Fatalf("%+v", h)
	}
	junk, _ := setup(t, "secret://junk")
	if h := junk.Health(context.Background(), "g"); h.Status != "down" || strings.Contains(h.Message, "not json") {
		t.Fatalf("%+v", h)
	}
}

func TestGCPRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		leaked = r.Header.Get("Authorization") + r.PostForm.Get("assertion")
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base, m.TokenURL = srv.URL, srv.URL+"/token"
	raw, _ := json.Marshal(Config{Key: "secret://gcp", Project: "demo-project"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://gcp": keyJSON(t, "")}), "g", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "g"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

func TestParseKeyPKCS1(t *testing.T) {
	k := rsaKey(t)
	pk := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	b, _ := json.Marshal(map[string]string{"type": "service_account", "private_key": pk, "client_email": "a@b"})
	if _, got, err := parseKey(string(b)); err != nil || !got.Equal(k) {
		t.Fatal(err)
	}
}
