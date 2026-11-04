package incus

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// clientPEM makes a self-signed client certificate and key, PEM, in one value.
func clientPEM(t *testing.T) (string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "conduit"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})), hex.EncodeToString(sum[:])
}

type fakeIncus struct {
	mu      sync.Mutex
	trusted map[string]bool
	token   string
	seen    []string
	status  map[string]string
	snaps   map[string][]string
}

func (f *fakeIncus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	fp := hex.EncodeToString(sum[:])
	b, _ := io.ReadAll(r.Body)
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(b))
	sync := func(v any) {
		json.NewEncoder(w).Encode(map[string]any{"type": "sync", "status": "Success", "status_code": 200, "metadata": v})
	}
	async := func() {
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]any{"type": "async", "status": "Operation created", "status_code": 100, "operation": "/1.0/operations/66e83638-9dd7-4a26-aef2-5462814869a1",
			"metadata": map[string]any{"id": "66e83638-9dd7-4a26-aef2-5462814869a1", "status": "Running"}})
	}
	fail := func(code int, msg string) {
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": msg, "error_code": code})
	}
	if r.URL.Path == "/1.0" && r.Method == "GET" {
		auth := "untrusted"
		if f.trusted[fp] {
			auth = "trusted"
		}
		sync(map[string]any{"auth": auth, "api_version": "1.0", "environment": map[string]any{"server": "incus", "server_version": "6.6", "server_name": "node1",
			"certificate": "-----BEGIN CERTIFICATE-----LEAKSERVER", "certificate_fingerprint": "LEAKFP"}})
		return
	}
	if r.URL.Path == "/1.0/certificates" && r.Method == "POST" {
		var req map[string]any
		json.Unmarshal(b, &req)
		if req["trust_token"] != f.token || f.token == "" {
			fail(403, "not authorized")
			return
		}
		f.trusted[fp] = true
		f.token = "" // single use
		sync(nil)
		return
	}
	if !f.trusted[fp] {
		fail(403, "not authorized")
		return
	}
	if r.URL.Query().Get("project") != "default" {
		fail(404, "project not found")
		return
	}
	inst := func(name string) map[string]any {
		return map[string]any{"name": name, "status": f.status[name], "type": map[string]string{"web": "container", "win": "virtual-machine"}[name], "architecture": "x86_64",
			"location": "none", "profiles": []string{"default"}, "created_at": "2026-10-01T10:00:00.123456789Z", "last_used_at": "1970-01-01T00:00:00Z",
			"config": map[string]string{"cloud-init.user-data": "#cloud-config\npassword: LEAKME"}, "devices": map[string]any{"root": map[string]string{"pool": "LEAKDEV"}}}
	}
	p := r.URL.Path
	switch {
	case r.Method == "GET" && p == "/1.0/instances":
		if r.URL.Query().Get("recursion") == "1" {
			sync([]any{inst("win"), inst("web")})
		} else {
			sync([]string{"/1.0/instances/web", "/1.0/instances/win"})
		}
	case r.Method == "GET" && (p == "/1.0/instances/web" || p == "/1.0/instances/win"):
		sync(inst(strings.TrimPrefix(p, "/1.0/instances/")))
	case r.Method == "GET" && p == "/1.0/instances/other":
		sync(inst("web"))
	case r.Method == "PUT" && p == "/1.0/instances/web/state":
		var req struct {
			Action string `json:"action"`
		}
		json.Unmarshal(b, &req)
		f.status["web"] = map[string]string{"start": "Running", "stop": "Stopped", "restart": "Running"}[req.Action]
		async()
	case r.Method == "GET" && p == "/1.0/instances/web/snapshots":
		out := []any{}
		for k, s := range f.snaps["web"] {
			out = append(out, map[string]any{"name": s, "created_at": fmt.Sprintf("2026-11-0%dT10:00:00Z", k+1), "expires_at": "0001-01-01T00:00:00Z", "size": 4096,
				"config": map[string]string{"cloud-init.user-data": "LEAKME"}})
		}
		sync(out)
	case r.Method == "POST" && p == "/1.0/instances/web/snapshots":
		var req struct {
			Name string `json:"name"`
		}
		json.Unmarshal(b, &req)
		f.snaps["web"] = append(f.snaps["web"], req.Name)
		async()
	case r.Method == "DELETE" && strings.HasPrefix(p, "/1.0/instances/web/snapshots/"):
		name := strings.TrimPrefix(p, "/1.0/instances/web/snapshots/")
		kept := []string{}
		for _, s := range f.snaps["web"] {
			if s != name {
				kept = append(kept, s)
			}
		}
		f.snaps["web"] = kept
		async()
	case r.Method == "GET" && p == "/1.0/operations/66e83638-9dd7-4a26-aef2-5462814869a1/wait":
		sync(map[string]any{"status": "Success", "status_code": 200})
	default:
		fail(404, "not found")
	}
}

type world struct {
	srv  *httptest.Server
	fake *fakeIncus
	fp   string // server certificate fingerprint
	host *fakehost.Host
	cfp  string // client certificate fingerprint
}

func newWorld(t *testing.T) *world {
	cert, cfp := clientPEM(t)
	other, _ := clientPEM(t)
	f := &fakeIncus{trusted: map[string]bool{cfp: true}, status: map[string]string{"web": "Running", "win": "Stopped"}, snaps: map[string][]string{"web": {"daily-1"}}}
	srv := httptest.NewUnstartedServer(f)
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	h := fakehost.New(map[string]string{"secret://incus": cert, "secret://other": other, "secret://junk": "not a pem", "secret://token": "eyJ0b2tlbiI6InRydXN0LW1lIn0="})
	return &world{srv: srv, fake: f, fp: hex.EncodeToString(sum[:]), host: h, cfp: cfp}
}

func (w *world) module(t *testing.T, c Config) *Module {
	t.Helper()
	if c.URL == "" {
		c.URL = w.srv.URL
	}
	if c.Fingerprint == "" && !c.InsecureSkipVerify {
		c.Fingerprint = w.fp
	}
	m := New()
	raw, _ := json.Marshal(c)
	if err := m.Configure(context.Background(), w.host, "i", raw); err != nil {
		t.Fatal(err)
	}
	return m
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "i", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func noLeak(t *testing.T, s string) {
	t.Helper()
	for _, bad := range []string{"LEAK", "PRIVATE KEY", "BEGIN CERTIFICATE", "eyJ0b2tlbiI6"} {
		if strings.Contains(s, bad) {
			t.Fatalf("leaked %s: %s", bad, s)
		}
	}
}

func TestIncus(t *testing.T) {
	opWait = 6
	w := newWorld(t)
	m := w.module(t, Config{ClientCert: "secret://incus"})
	h := m.Health(context.Background(), "i")
	if h.Status != "ok" || h.Message != "Incus 6.6 on node1, 2 instances in project default" {
		t.Fatalf("%+v", h)
	}
	noLeak(t, h.Message)
	for _, c := range []struct{ action, in, want string }{
		{"instances", `{}`, `"type":"virtual-machine"`},
		{"instances", `{}`, `"created":"2026-10-01T10:00:00Z"`},
		{"instances", `{"state":"Stopped"}`, `"name":"win"`},
		{"snapshots", `{"instance":"web"}`, `"name":"daily-1"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		noLeak(t, out)
	}
	if r, _ := invoke(m, "instances", `{"state":"Stopped"}`, false); strings.Contains(string(r.Output), `"web"`) || strings.Contains(string(r.Output), "lastUsed") {
		t.Fatal(string(r.Output))
	}

	// Stop: preview, real with read-back, undo, nothing to change.
	r, err := invoke(m, "stop", `{"instance":"web"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Stop container web" || w.fake.status["web"] != "Running" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "stop", `{"instance":"web","force":true}`, false)
	if err != nil || w.fake.status["web"] != "Stopped" || !strings.Contains(string(r.Output), `"status":"Stopped"`) || r.Undo == nil || r.Undo.Action != "start" {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if last := w.fake.seen[len(w.fake.seen)-3]; !strings.Contains(last, `PUT /1.0/instances/web/state?project=default {"action":"stop","force":true,"timeout":1}`) {
		t.Fatal(last)
	}
	if r, err := invoke(m, "stop", `{"instance":"web"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "restart", `{"instance":"web"}`, false); err == nil || !strings.Contains(err.Error(), "isn't running") {
		t.Fatal(err)
	}
	if r, err := invoke(m, "start", `{"instance":"web"}`, false); err != nil || w.fake.status["web"] != "Running" || r.Undo.Action != "stop" {
		t.Fatal(err)
	}
	if r, err := invoke(m, "restart", `{"instance":"web"}`, false); err != nil || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Snapshot: preview, take with read-back, undo deletes it.
	if r, err := invoke(m, "snapshot", `{"instance":"web","name":"before-upgrade"}`, true); err != nil || r.Plan.Summary != "Take snapshot before-upgrade of container web in project default" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "snapshot", `{"instance":"web","name":"before-upgrade"}`, false)
	if err != nil || len(w.fake.snaps["web"]) != 2 || r.Undo == nil || r.Undo.Action != "delete_snapshot" || string(r.Undo.Input) != `{"instance":"web","name":"before-upgrade"}` {
		t.Fatalf("%s %+v %v", r.Output, r.Undo, err)
	}
	if _, err := invoke(m, "snapshot", `{"instance":"web","name":"before-upgrade"}`, false); err == nil || !strings.Contains(err.Error(), "already has") {
		t.Fatal(err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(w.fake.snaps["web"]) != 1 {
		t.Fatal(err, w.fake.snaps)
	}
	if r, err := invoke(m, "delete_snapshot", `{"instance":"web","name":"before-upgrade"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "start", `{"instance":"other"}`, false); err == nil || !strings.Contains(err.Error(), "another instance") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "start", `{"instance":"gone"}`, false); err == nil || !strings.Contains(err.Error(), "no instance gone") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if (a.Name == "stop" || a.Name == "restart" || a.Name == "delete_snapshot") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
		for _, no := range []string{"exec", "console", "file", "delete_instance"} {
			if strings.Contains(a.Name, no) {
				t.Fatalf("%s offered", a.Name)
			}
		}
	}
}

func TestIncusTrust(t *testing.T) {
	w := newWorld(t)
	// An untrusted certificate, no token.
	m := w.module(t, Config{ClientCert: "secret://other"})
	if h := m.Health(context.Background(), "i"); h.Status != "down" || !strings.Contains(h.Message, "doesn't trust") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(m, "instances", `{}`, false); err == nil {
		t.Fatal("listed with an untrusted certificate")
	}
	// A wrong token.
	w.fake.token = "something-else"
	m = w.module(t, Config{ClientCert: "secret://other", TrustToken: "secret://token"})
	if h := m.Health(context.Background(), "i"); h.Status != "down" || !strings.Contains(h.Message, "refused the trust token") {
		t.Fatalf("%+v", h)
	}
	// A token Incus has answered isn't sent again.
	posts := func() int {
		n := 0
		for _, x := range w.fake.seen {
			if strings.HasPrefix(x, "POST /1.0/certificates") {
				n++
			}
		}
		return n
	}
	before := posts()
	if h := m.Health(context.Background(), "i"); h.Status != "down" || !strings.Contains(h.Message, "already used") || posts() != before {
		t.Fatalf("%+v, %d posts", h, posts()-before)
	}
	if _, err := invoke(m, "instances", `{}`, false); err == nil || posts() != before {
		t.Fatal("sent the trust token again")
	}
	// The right token adds the certificate once.
	w.fake.token = "eyJ0b2tlbiI6InRydXN0LW1lIn0="
	m = w.module(t, Config{ClientCert: "secret://other", TrustToken: "secret://token"})
	r, err := invoke(m, "instances", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"web"`) || w.fake.token != "" {
		t.Fatalf("%s %v", r.Output, err)
	}
	noLeak(t, string(r.Output))
	if h := m.Health(context.Background(), "i"); h.Status != "ok" {
		t.Fatalf("%+v", h)
	}
	// A secret that isn't a certificate and key.
	m = w.module(t, Config{ClientCert: "secret://junk"})
	if h := m.Health(context.Background(), "i"); h.Status != "down" {
		t.Fatalf("%+v", h)
	} else {
		noLeak(t, h.Message)
	}
	// A wrong server pin.
	m = w.module(t, Config{ClientCert: "secret://incus", Fingerprint: strings.Repeat("ab", 32)})
	if h := m.Health(context.Background(), "i"); h.Status != "down" || !strings.Contains(h.Message, "fingerprint") {
		t.Fatalf("%+v", h)
	}
	// No pin: Incus's self-signed certificate is refused.
	m = New()
	raw, _ := json.Marshal(Config{URL: w.srv.URL, ClientCert: "secret://incus"})
	m.Configure(context.Background(), w.host, "i", raw)
	if h := m.Health(context.Background(), "i"); h.Status != "down" {
		t.Fatalf("%+v", h)
	}
}

func TestIncusValidation(t *testing.T) {
	w := newWorld(t)
	m := w.module(t, Config{ClientCert: "secret://incus"})
	for _, c := range []struct{ action, in string }{
		{"start", `{}`},
		{"start", `{"instance":"../certificates"}`},
		{"stop", `{"instance":"web/state"}`},
		{"restart", `{"instance":"9web"}`},
		{"snapshots", `{"instance":"web?project=x"}`},
		{"snapshot", `{"instance":"web","name":""}`},
		{"snapshot", `{"instance":"web","name":"../x"}`},
		{"delete_snapshot", `{"instance":"web","name":"a/b"}`},
		{"exec", `{"instance":"web"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(w.fake.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", w.fake.seen)
	}
	for _, c := range []Config{
		{URL: "https://incus.lan:8443", ClientCert: "-----BEGIN CERTIFICATE-----"},
		{URL: "https://incus.lan:8443", ClientCert: "secret://incus", TrustToken: "plain-token"},
		{URL: "http://incus.lan:8443", ClientCert: "secret://incus"},
		{URL: "https://u:p@incus.lan:8443", ClientCert: "secret://incus"},
		{URL: "https://incus.lan:8443/?x=1", ClientCert: "secret://incus"},
		{URL: "https://incus.lan:8443/#x", ClientCert: "secret://incus"},
		{URL: "https://incus.lan:8443/1.0", ClientCert: "secret://incus"},
		{URL: "https://incus.lan:8443", ClientCert: "secret://incus", Project: "a/b"},
		{URL: "https://incus.lan:8443", ClientCert: "secret://incus", Fingerprint: "zz"},
		// The trust token never goes to an unverified server.
		{URL: "https://incus.lan:8443", ClientCert: "secret://incus", TrustToken: "secret://token", InsecureSkipVerify: true},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

func TestIncusKeyPair(t *testing.T) {
	good, _ := clientPEM(t)
	other, _ := clientPEM(t)
	certOf := func(s string) string { return s[:strings.Index(s, "-----BEGIN EC PRIVATE KEY")] }
	keyOf := func(s string) string { return s[strings.Index(s, "-----BEGIN EC PRIVATE KEY"):] }
	kb, _ := pem.Decode([]byte(keyOf(good)))
	//nolint:staticcheck // an old-style encrypted key, as openssl writes without -nodes
	enc, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", kb.Bytes, []byte("pw"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	encPEM := string(pem.EncodeToMemory(enc))
	// A PKCS #8 encrypted key: its DER holds ciphertext, not a key.
	junk := make([]byte, 96)
	rand.Read(junk)
	pkcs8Enc := string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: junk}))
	for name, v := range map[string]string{
		"key first":          keyOf(good) + certOf(good),
		"chain after":        good + certOf(other),
		"text around blocks": "conduit client\n" + good + "\nend\n",
	} {
		if c, err := keyPair(v); err != nil || len(c.Certificate) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, v := range map[string]string{
		"empty":          "",
		"cert only":      certOf(good),
		"key only":       keyOf(good),
		"other's key":    certOf(good) + keyOf(other),
		"other cert 1st": certOf(other) + good,
		"encrypted":      certOf(good) + encPEM,
		"pkcs8 enc":      certOf(good) + pkcs8Enc,
		"public key":     certOf(good) + string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: kb.Bytes})),
	} {
		_, err := keyPair(v)
		if err == nil {
			t.Fatalf("%s accepted", name)
		}
		noLeak(t, err.Error())
	}
}

func TestIncusRefusesCrossHostRedirect(t *testing.T) {
	w := newWorld(t)
	var reached bool
	evil := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { reached = true }))
	defer evil.Close()
	redir := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer redir.Close()
	m := w.module(t, Config{URL: redir.URL, ClientCert: "secret://incus", InsecureSkipVerify: true})
	if h := m.Health(context.Background(), "i"); h.Status != "down" || reached || !strings.Contains(h.Message, "another host") {
		t.Fatalf("followed the redirect: %+v %v", h, reached)
	}
}
