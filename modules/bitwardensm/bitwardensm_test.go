package bitwardensm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Known answers from the Bitwarden SDK's own tests (bitwarden-crypto,
// derive_shareable_key), so the derivation matches the real clients.
func TestShareableKeyKnownAnswers(t *testing.T) {
	for _, c := range []struct{ secret, info, want string }{
		{"&/$%F1a895g67HlX", "", "4PV6+PcmF2w7YHRatvyMcVQtI7zvCyssv/wFWmzjiH6Iv9altjmDkuBD1aagLVaLezbthbSe+ktR+U6qswxNnQ=="},
		{"67t9b5g67$%Dh89n", "test", "F9jVQmrACGx9VUPjuzfMYDjr726JtL300Y3Yg+VYUnVQtQ1s8oImJ5xtp1KALC9h2nav04++1LDW4iFD+infng=="},
	} {
		k, err := shareableKey([]byte(c.secret), "test_key", c.info)
		if got := base64.StdEncoding.EncodeToString(append(append([]byte{}, k.enc...), k.mac...)); err != nil || got != c.want {
			t.Fatalf("%s: %s %v", c.secret, got, err)
		}
	}
	at, err := parseAccessToken("0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==")
	if err != nil || at.id != "ec2c1d46-6a4b-4751-a310-af9601317f2d" || at.secret != "C2IgxjjLF7qSshsbwe8JGcbM075YXw" || len(at.key) != 16 {
		t.Fatalf("%+v %v", at, err)
	}
	for _, bad := range []string{"", "0.x.y:z", "1.ec2c1d46-6a4b-4751-a310-af9601317f2d.s:X8vbvA0bduihIDe/qrzIQQ==", "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.s", "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.s:AAAA"} {
		if _, err := parseAccessToken(bad); err == nil || (bad != "" && strings.Contains(err.Error(), bad)) {
			t.Fatalf("accepted %q: %v", bad, err)
		}
	}
}

func encrypt(t *testing.T, k symKey, plain []byte) string {
	t.Helper()
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	n := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(n)}, n)...)
	block, _ := aes.NewCipher(k.enc)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	h := hmac.New(sha256.New, k.mac)
	h.Write(iv)
	h.Write(ct)
	b := base64.StdEncoding.EncodeToString
	return "2." + b(iv) + "|" + b(ct) + "|" + b(h.Sum(nil))
}

const (
	orgID   = "11111111-2222-3333-4444-555555555555"
	tokenID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	projA   = "a0000000-0000-0000-0000-000000000001"
	secDB   = "50000000-0000-0000-0000-000000000001"
	secAPI  = "50000000-0000-0000-0000-000000000002"
	secDup1 = "50000000-0000-0000-0000-000000000003"
	secDup2 = "50000000-0000-0000-0000-000000000004"
)

type fake struct {
	t      *testing.T
	mu     sync.Mutex
	logins int
	seen   []string
	org    symKey
	tokKey []byte
}

func (f *fake) enc(s string) string { return encrypt(f.t, f.org, []byte(s)) }

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	f.seen = append(f.seen, r.Method+" "+r.URL.Path)
	if r.URL.Path == "/identity/connect/token" {
		q, _ := url.ParseQuery(string(body))
		if q.Get("client_id") != tokenID || q.Get("client_secret") != "client-s3cret" || q.Get("scope") != "api.secrets" || q.Get("grant_type") != "client_credentials" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"invalid_client"}`)
			return
		}
		f.logins++
		at := accessToken{key: f.tokKey}
		pk, _ := at.payloadKey()
		orgRaw := base64.StdEncoding.EncodeToString(append(append([]byte{}, f.org.enc...), f.org.mac...))
		payload := encrypt(f.t, pk, []byte(`{"encryptionKey":"`+orgRaw+`"}`))
		claims := base64.RawURLEncoding.EncodeToString([]byte(`{"organization":"` + orgID + `","sub":"x"}`))
		json.NewEncoder(w).Encode(map[string]any{"access_token": "eyJhbGciOiJSUzI1NiJ9." + claims + ".sig", "expires_in": 3600, "token_type": "Bearer", "encrypted_payload": payload})
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer eyJ") {
		w.WriteHeader(401)
		return
	}
	enc := json.NewEncoder(w)
	ident := func(id, key string) map[string]any {
		return map[string]any{"id": id, "organizationId": orgID, "key": f.enc(key), "creationDate": "2026-01-01T00:00:00Z", "revisionDate": "2026-02-01T00:00:00Z",
			"projects": []map[string]any{{"id": projA, "name": f.enc("Backend")}}}
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/organizations/" + orgID + "/projects":
		enc.Encode(map[string]any{"data": []map[string]any{{"id": projA, "organizationId": orgID, "name": f.enc("Backend"), "creationDate": "2026-01-01T00:00:00Z"}}})
	case "GET /api/organizations/" + orgID + "/secrets", "GET /api/projects/" + projA + "/secrets":
		enc.Encode(map[string]any{"secrets": []map[string]any{ident(secDB, "DB_PASSWORD"), ident(secAPI, "API_KEY"), ident(secDup1, "DUP"), ident(secDup2, "DUP")}})
	case "POST /api/secrets/get-by-ids":
		var b struct{ IDs []string }
		json.Unmarshal(body, &b)
		vals := map[string][2]string{secDB: {"DB_PASSWORD", "hunter2"}, secAPI: {"API_KEY", "sk-live-xyz"}}
		data := []map[string]any{}
		for _, id := range b.IDs {
			if v, ok := vals[id]; ok {
				e := ident(id, v[0])
				e["value"] = f.enc(v[1])
				e["note"] = f.enc("note: root pw is n0te-secret")
				data = append(data, e)
			}
		}
		enc.Encode(map[string]any{"data": data})
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T) (*Module, *fake) {
	tokKey := make([]byte, 16)
	rand.Read(tokKey)
	org := make([]byte, 64)
	rand.Read(org)
	f := &fake{t: t, org: symKey{enc: org[:32], mac: org[32:]}, tokKey: tokKey}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{AccessToken: "secret://bw", Region: "self-hosted", ServerURL: srv.URL})
	tok := "0." + tokenID + ".client-s3cret:" + base64.StdEncoding.EncodeToString(tokKey)
	wrong := make([]byte, 16)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bw": tok, "secret://wrongkey": "0." + tokenID + ".client-s3cret:" + base64.StdEncoding.EncodeToString(wrong)}), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in)})
}

func TestBitwardenListsDecryptedNames(t *testing.T) {
	m, f := setup(t)
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || !strings.Contains(h.Message, "1 project") {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"projects", `{}`, `"name":"Backend"`},
		{"secrets", `{}`, `"key":"API_KEY","projects":["Backend"]`},
		{"secrets", `{"project":"Backend"}`, `"project":"Backend"`},
		{"secrets", `{"project":"` + projA + `"}`, `"key":"DB_PASSWORD"`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "hunter2") || strings.Contains(out, "2.") && strings.Contains(out, "|") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	// The session is reused.
	if f.logins != 1 {
		t.Fatalf("logged in %d times", f.logins)
	}
}

func TestBitwardenReveal(t *testing.T) {
	m, f := setup(t)
	r, err := invoke(m, "reveal_secret", `{"keys":["DB_PASSWORD","NOPE"]}`)
	out := string(r.Output)
	if err != nil || !strings.Contains(out, `"key":"DB_PASSWORD","value":"hunter2"`) || strings.Contains(out, "sk-live-xyz") || strings.Contains(out, "n0te-secret") || !strings.Contains(out, `"missing":["NOPE"]`) {
		t.Fatalf("%s %v", out, err)
	}
	r, err = invoke(m, "reveal_secret", `{"ids":["`+secAPI+`"]}`)
	if err != nil || !strings.Contains(string(r.Output), "sk-live-xyz") || strings.Contains(string(r.Output), "hunter2") || strings.Contains(string(r.Output), "note") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "reveal_secret", `{"keys":["DUP"]}`); err == nil || !strings.Contains(err.Error(), secDup2) {
		t.Fatal(err)
	}
	before := len(f.seen)
	for _, in := range []string{`{}`, `{"ids":["../x"]}`, `{"keys":["a\nb"]}`, `{"keys":["1","2","3","4","5","6"],"ids":["` + secDB + `","` + secDB + `","` + secDB + `","` + secDB + `","` + secDB + `"]}`} {
		if _, err := invoke(m, "reveal_secret", in); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.seen) != before {
		t.Fatalf("invalid input reached the server: %v", f.seen[before:])
	}
	for _, a := range m.Manifest().Actions {
		switch {
		case a.Name == "reveal_secret":
			if a.Risk != sdk.RiskDestructive || !a.Sensitive {
				t.Fatal("reveal_secret must be sensitive and destructive")
			}
		case a.Risk != sdk.RiskRead:
			t.Fatalf("%s must be a read", a.Name)
		}
	}
}

func TestBitwardenWrongKeyAndConfig(t *testing.T) {
	m, _ := setup(t)
	c, _ := m.set.Get("b")
	c.tokenRef = "secret://wrongkey"
	if h := m.Health(context.Background(), "b"); h.Status != "down" || !strings.Contains(h.Message, "couldn't decrypt the organization key") || strings.Contains(h.Message, "client-s3cret") {
		t.Fatalf("%+v", h)
	}
	k := symKey{enc: make([]byte, 32), mac: make([]byte, 32)}
	ct := encrypt(t, k, []byte("x"))
	if _, err := (symKey{enc: make([]byte, 32), mac: bytes.Repeat([]byte{1}, 32)}).decrypt(ct); err == nil {
		t.Fatal("a bad MAC decrypted")
	}
	if _, err := k.decrypt("0." + strings.TrimPrefix(ct, "2.")); err == nil {
		t.Fatal("decrypted an unsupported type")
	}
	for _, c := range []Config{{AccessToken: "0.x.y:z"}, {AccessToken: "secret://bw", Region: "mars"}, {AccessToken: "secret://bw", Region: "self-hosted"}, {AccessToken: "secret://bw", Region: "self-hosted", ServerURL: "ftp://x"}, {AccessToken: "secret://bw", Region: "self-hosted", ServerURL: "https://u:p@x"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for _, region := range []string{"", "us", "eu"} {
		raw, _ := json.Marshal(Config{AccessToken: "secret://bw", Region: region})
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
			t.Fatal(region, err)
		}
	}
}

func TestBitwardenRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		leaked = r.Header.Get("Authorization") + string(b) + "!"
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{AccessToken: "secret://bw", Region: "self-hosted", ServerURL: srv.URL})
	tok := "0." + tokenID + ".client-s3cret:" + base64.StdEncoding.EncodeToString(make([]byte, 16))
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bw": tok}), "b", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(m, "projects", `{}`); err == nil || leaked != "" {
		t.Fatalf("followed the redirect: %v %q", err, leaked)
	}
}
