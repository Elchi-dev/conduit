package daemon

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/core"
)

// softKey is a minimal software authenticator: one ES256 passkey that
// verifies its user (the UV flag is set).
type softKey struct {
	t      *testing.T
	priv   *ecdsa.PrivateKey
	credID []byte
	user   []byte // user handle given at registration
	count  uint32
	rpID   string
}

func newSoftKey(t *testing.T, rpID string) *softKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softKey{t: t, priv: k, credID: id, rpID: rpID}
}

var pkb64 = base64.RawURLEncoding

func (k *softKey) authData(flags byte, attested bool) []byte {
	h := sha256.Sum256([]byte(k.rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, k.count)
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(k.credID)))
		out = append(out, k.credID...)
		x := k.priv.PublicKey.X.FillBytes(make([]byte, 32))
		y := k.priv.PublicKey.Y.FillBytes(make([]byte, 32))
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		out = append(out, cose...)
	}
	return out
}

func pkClientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

// pkChallenge digs the challenge and user id out of begin options.
func pkChallenge(opts map[string]any) (string, []byte) {
	pk := opts["options"].(map[string]any)["publicKey"].(map[string]any)
	var user []byte
	if u, ok := pk["user"].(map[string]any); ok {
		user, _ = pkb64.DecodeString(u["id"].(string))
	}
	return pk["challenge"].(string), user
}

func (k *softKey) create(opts map[string]any, origin string) map[string]any {
	ch, user := pkChallenge(opts)
	k.user = user
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(0x45, true)})
	return map[string]any{
		"id": pkb64.EncodeToString(k.credID), "rawId": pkb64.EncodeToString(k.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": pkb64.EncodeToString(pkClientData("webauthn.create", ch, origin)), "attestationObject": pkb64.EncodeToString(att), "transports": []string{"internal"}},
	}
}

func (k *softKey) get(opts map[string]any, origin string) map[string]any {
	ch, _ := pkChallenge(opts)
	k.count++
	ad := k.authData(0x05, false)
	cd := pkClientData("webauthn.get", ch, origin)
	h := sha256.Sum256(cd)
	msg := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, msg[:])
	if err != nil {
		k.t.Fatal(err)
	}
	return map[string]any{
		"id": pkb64.EncodeToString(k.credID), "rawId": pkb64.EncodeToString(k.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": pkb64.EncodeToString(cd), "authenticatorData": pkb64.EncodeToString(ad),
			"signature": pkb64.EncodeToString(sig), "userHandle": pkb64.EncodeToString(k.user)},
	}
}

// hostClient talks to the test server under another host name, the way a
// browser at that address would (Host and Origin headers).
type hostClient struct {
	t     *testing.T
	base  string // the real listener
	host  string // e.g. localhost:1234
	token string
}

func (c hostClient) origin() string { return "http://" + c.host }

func (c hostClient) do(method, path string, body any, want int) map[string]any {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, c.base+path, &buf)
	req.Host = c.host
	req.Header.Set("Origin", c.origin())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	raw := new(bytes.Buffer)
	_, _ = raw.ReadFrom(res.Body)
	_ = json.Unmarshal(raw.Bytes(), &out)
	if res.StatusCode != want {
		c.t.Fatalf("%s %s = %d, want %d: %s", method, path, res.StatusCode, want, raw.String())
	}
	return out
}

func (c hostClient) list(path string) []any {
	c.t.Helper()
	req, _ := http.NewRequest("GET", c.base+path, nil)
	req.Host = c.host
	req.Header.Set("Authorization", "Bearer "+c.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out []any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return out
}

func localhostClient(t *testing.T, c client) hostClient {
	// Failed sign-ins from other tests count against the same source.
	loginFailsBySource.Reset("127.0.0.1")
	u, _ := url.Parse(c.base)
	return hostClient{t: t, base: c.base, host: "localhost:" + u.Port(), token: c.token}
}

const ownerPassword = "correct horse"

func (c hostClient) register(k *softKey, name string) map[string]any {
	c.t.Helper()
	begin := c.do("POST", "/api/v1/me/passkeys/register/begin", map[string]string{"password": ownerPassword}, 200)
	return c.do("POST", "/api/v1/me/passkeys/register/finish", map[string]any{"ceremony": begin["ceremony"], "name": name, "response": k.create(begin, c.origin())}, 201)
}

func (c hostClient) signIn(k *softKey, origin string, want int) string {
	c.t.Helper()
	anon := c
	anon.token = ""
	lb := anon.do("POST", "/api/v1/auth/passkeys/login/begin", nil, 200)
	res := anon.do("POST", "/api/v1/auth/passkeys/login/finish", map[string]any{"ceremony": lb["ceremony"], "device": "test", "response": k.get(lb, origin)}, want)
	tok, _ := res["token"].(string)
	return tok
}

func TestPasskeys(t *testing.T) {
	app, c, _, _ := setup(t)
	lc := localhostClient(t, c)
	key := newSoftKey(t, "localhost")

	if av := lc.do("GET", "/api/v1/auth/passkeys/available", nil, 200); av["available"] != true || av["rpId"] != "localhost" {
		t.Fatalf("available on localhost: %v", av)
	}

	// Registering needs the password again.
	lc.do("POST", "/api/v1/me/passkeys/register/begin", nil, 403)
	lc.do("POST", "/api/v1/me/passkeys/register/begin", map[string]string{"password": "wrong password"}, 403)
	begin := lc.do("POST", "/api/v1/me/passkeys/register/begin", map[string]string{"password": ownerPassword}, 200)
	// An answer made for another origin is refused.
	lc.do("POST", "/api/v1/me/passkeys/register/finish", map[string]any{"ceremony": begin["ceremony"], "name": "Evil", "response": key.create(begin, "http://evil.test")}, 400)
	// And that used up the ceremony.
	lc.do("POST", "/api/v1/me/passkeys/register/finish", map[string]any{"ceremony": begin["ceremony"], "name": "Again", "response": key.create(begin, lc.origin())}, 400)
	created := lc.register(key, "  Laptop  ")
	if created["name"] != "Laptop" || created["rpId"] != "localhost" {
		t.Fatalf("created %v", created)
	}
	list := lc.list("/api/v1/me/passkeys")
	if len(list) != 1 {
		t.Fatalf("list %v", list)
	}
	id := list[0].(map[string]any)["id"].(string)

	// Rename.
	if r := lc.do("PATCH", "/api/v1/me/passkeys/"+id, map[string]string{"name": "Work laptop"}, 200); r["name"] != "Work laptop" {
		t.Fatalf("rename %v", r)
	}

	// Sign in without an email address; a passkey is both factors.
	tok := lc.signIn(key, lc.origin(), 200)
	me := hostClient{t: t, base: c.base, host: lc.host, token: tok}.do("GET", "/api/v1/me", nil, 200)
	if me["user"].(map[string]any)["email"] != "owner@example.com" {
		t.Fatalf("me %v", me)
	}
	if l := lc.list("/api/v1/me/passkeys"); l[0].(map[string]any)["lastUsedAt"] == nil {
		t.Fatalf("last used not recorded: %v", l)
	}

	// The same answer replayed against the same ceremony fails.
	anon := lc
	anon.token = ""
	lb := anon.do("POST", "/api/v1/auth/passkeys/login/begin", nil, 200)
	ans := key.get(lb, lc.origin())
	anon.do("POST", "/api/v1/auth/passkeys/login/finish", map[string]any{"ceremony": lb["ceremony"], "response": ans}, 200)
	anon.do("POST", "/api/v1/auth/passkeys/login/finish", map[string]any{"ceremony": lb["ceremony"], "response": ans}, 400)
	// An answer to an old challenge on a new ceremony fails.
	old := anon.do("POST", "/api/v1/auth/passkeys/login/begin", nil, 200)
	lb = anon.do("POST", "/api/v1/auth/passkeys/login/begin", nil, 200)
	anon.do("POST", "/api/v1/auth/passkeys/login/finish", map[string]any{"ceremony": lb["ceremony"], "response": key.get(old, lc.origin())}, 401)
	// A registration ceremony can't finish a sign-in.
	rb := lc.do("POST", "/api/v1/me/passkeys/register/begin", map[string]string{"password": ownerPassword}, 200)
	anon.do("POST", "/api/v1/auth/passkeys/login/finish", map[string]any{"ceremony": rb["ceremony"], "response": key.get(rb, lc.origin())}, 400)

	loginFailsBySource.Reset("127.0.0.1")
	// Wrong origin.
	lc.signIn(key, "http://evil.test", 401)
	// Same port, other host name: a ceremony started at one name can't be
	// finished at another.
	other := lc
	other.host = strings.Replace(lc.host, "localhost", "conduit.localhost", 1)
	lb = anon.do("POST", "/api/v1/auth/passkeys/login/begin", nil, 200)
	other.token = ""
	other.do("POST", "/api/v1/auth/passkeys/login/finish", map[string]any{"ceremony": lb["ceremony"], "response": key.get(lb, other.origin())}, 400)

	// A counter that goes backwards is refused.
	saved := key.count
	key.count = 0
	lc.signIn(key, lc.origin(), 401)
	key.count = saved + 10

	// The audit log has the passkey events.
	entries, _ := app.Engine.Audit.List(t.Context(), core.Query{Limit: 200})
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Action] = true
	}
	for _, a := range []string{"passkey_added", "passkey_login"} {
		if !seen[a] {
			t.Errorf("no %s in the audit log", a)
		}
	}

	// Someone else can't touch it; the owner can remove it, and then it stops working.
	var member auth.User
	c.do("POST", "/api/v1/users", map[string]string{"email": "kim@example.com", "password": "kim's long password", "role": "member"}, &member)
	var ks sessionResp
	c.do("POST", "/api/v1/auth/login", map[string]string{"email": "kim@example.com", "password": "kim's long password"}, &ks)
	kim := hostClient{t: t, base: c.base, host: lc.host, token: ks.Token}
	kim.do("DELETE", "/api/v1/me/passkeys/"+id, nil, 404)
	kim.do("PATCH", "/api/v1/me/passkeys/"+id, map[string]string{"name": "mine"}, 404)
	lc.do("DELETE", "/api/v1/me/passkeys/"+id, nil, 204)
	lc.signIn(key, lc.origin(), 401)
	entries, _ = app.Engine.Audit.List(t.Context(), core.Query{Limit: 200})
	found := false
	for _, e := range entries {
		found = found || e.Action == "passkey_removed"
	}
	if !found {
		t.Error("no passkey_removed in the audit log")
	}
}

func TestPasskeyIPHostRefused(t *testing.T) {
	_, c, _, _ := setup(t)
	u, _ := url.Parse(c.base) // 127.0.0.1:port
	ip := hostClient{t: t, base: c.base, host: u.Host, token: c.token}
	if av := ip.do("GET", "/api/v1/auth/passkeys/available", nil, 200); av["available"] != false || av["reason"] == nil {
		t.Fatalf("available on an IP: %v", av)
	}
	ip.do("POST", "/api/v1/me/passkeys/register/begin", map[string]string{"password": ownerPassword}, 400)
	ip.do("POST", "/api/v1/auth/passkeys/login/begin", nil, 400)

	// A ceremony started at localhost can't be finished at the IP address.
	lc := localhostClient(t, c)
	begin := lc.do("POST", "/api/v1/me/passkeys/register/begin", map[string]string{"password": ownerPassword}, 200)
	ip.do("POST", "/api/v1/me/passkeys/register/finish", map[string]any{"ceremony": begin["ceremony"], "response": newSoftKey(t, u.Hostname()).create(begin, ip.origin())}, 400)
}

func TestPasskeyNotForKeysOrAgents(t *testing.T) {
	_, c, _, _ := setup(t)
	lc := localhostClient(t, c)
	for _, kind := range []string{"live", "agent"} {
		var k keyResp
		scopes := []string{"admin:*:*"}
		if kind == "agent" {
			scopes = []string{"modules:*:read"}
		}
		if code := c.do("POST", "/api/v1/keys", map[string]any{"name": kind, "kind": kind, "scopes": scopes}, &k); code != 201 {
			t.Fatalf("create %s key = %d", kind, code)
		}
		kc := lc
		kc.token = k.Secret
		kc.do("POST", "/api/v1/me/passkeys/register/begin", map[string]string{"password": ownerPassword}, 403)
		kc.do("POST", "/api/v1/me/passkeys/register/finish", map[string]any{"ceremony": "x"}, 403)
		kc.do("GET", "/api/v1/me/passkeys", nil, 403)
		kc.do("DELETE", "/api/v1/me/passkeys/pk_x", nil, 403)
	}
}

func TestPasskeyDisabledAndPasswordReset(t *testing.T) {
	app, c, _, _ := setup(t)
	ctx := t.Context()
	var member auth.User
	c.do("POST", "/api/v1/users", map[string]string{"email": "kim@example.com", "password": "kim's long password", "role": "member"}, &member)
	login := func() string {
		var s sessionResp
		if code := c.do("POST", "/api/v1/auth/login", map[string]string{"email": "kim@example.com", "password": "kim's long password"}, &s); code != 200 {
			t.Fatalf("kim login = %d", code)
		}
		return s.Token
	}
	lc := localhostClient(t, c)
	kim := lc
	kim.token = login()
	key := newSoftKey(t, "localhost")
	begin := kim.do("POST", "/api/v1/me/passkeys/register/begin", map[string]string{"password": "kim's long password"}, 200)
	kim.do("POST", "/api/v1/me/passkeys/register/finish", map[string]any{"ceremony": begin["ceremony"], "name": "Phone", "response": key.create(begin, kim.origin())}, 201)
	kim.signIn(key, kim.origin(), 200)

	// Switched off: the passkey stops working.
	if code := c.do("PATCH", "/api/v1/users/"+member.ID, map[string]any{"disabled": true}, nil); code != 200 {
		t.Fatalf("disable = %d", code)
	}
	kim.signIn(key, kim.origin(), 401)
	c.do("PATCH", "/api/v1/users/"+member.ID, map[string]any{"disabled": false}, nil)
	kim.signIn(key, kim.origin(), 200)

	// An admin's password reset removes the passkeys.
	if code := c.do("POST", "/api/v1/users/"+member.ID+"/password", map[string]string{"password": "a brand new password"}, nil); code != 204 {
		t.Fatalf("reset = %d", code)
	}
	if n := app.Auth.PasskeyCount(ctx, member.ID); n != 0 {
		t.Fatalf("%d passkeys left after a reset", n)
	}
	kim.signIn(key, kim.origin(), 401)

	// So does changing your own password.
	lc.register(newSoftKey(t, "localhost"), "Owner key")
	var me struct{ User auth.User }
	c.do("GET", "/api/v1/me", nil, &me)
	if app.Auth.PasskeyCount(ctx, me.User.ID) != 1 {
		t.Fatal("owner passkey not stored")
	}
	if code := c.do("POST", "/api/v1/me/password", map[string]string{"current": ownerPassword, "new": "another long password"}, nil); code != 204 {
		t.Fatalf("change password = %d", code)
	}
	if n := app.Auth.PasskeyCount(ctx, me.User.ID); n != 0 {
		t.Fatalf("%d passkeys left after a password change", n)
	}
	entries, _ := app.Engine.Audit.List(ctx, core.Query{Limit: 200})
	n := 0
	for _, e := range entries {
		if e.Action == "passkeys_removed" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("passkeys_removed audited %d times, want 2", n)
	}
}
