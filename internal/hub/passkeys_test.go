package hub

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// softKey is a minimal software authenticator: one ES256 passkey.
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

var b64 = base64.RawURLEncoding

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

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

// challenge digs the challenge and user id out of begin options.
func challenge(opts map[string]any) (string, []byte) {
	pk := opts["options"].(map[string]any)["publicKey"].(map[string]any)
	var user []byte
	if u, ok := pk["user"].(map[string]any); ok {
		user, _ = b64.DecodeString(u["id"].(string))
	}
	return pk["challenge"].(string), user
}

func (k *softKey) create(opts map[string]any, origin string) map[string]any {
	ch, user := challenge(opts)
	k.user = user
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(0x45, true)})
	return map[string]any{
		"id": b64.EncodeToString(k.credID), "rawId": b64.EncodeToString(k.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(clientData("webauthn.create", ch, origin)), "attestationObject": b64.EncodeToString(att)},
	}
}

func (k *softKey) get(opts map[string]any, origin string) map[string]any {
	ch, _ := challenge(opts)
	k.count++
	ad := k.authData(0x05, false)
	cd := clientData("webauthn.get", ch, origin)
	h := sha256.Sum256(cd)
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, sha256Sum(append(append([]byte{}, ad...), h[:]...)))
	if err != nil {
		k.t.Fatal(err)
	}
	return map[string]any{
		"id": b64.EncodeToString(k.credID), "rawId": b64.EncodeToString(k.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(k.user)},
	}
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func TestPasskeys(t *testing.T) {
	h := newHarness(t, nil)
	const origin = "https://hub.test"
	alice := h.signup("alice@example.com")
	key := newSoftKey(t, "hub.test")

	// Register: a session alone isn't enough, the password is needed too.
	h.do("POST", "/v1/passkeys/register/begin", alice, nil, 403)
	h.do("POST", "/v1/passkeys/register/begin", alice, map[string]string{"password": "wrong password"}, 403)
	begin := h.do("POST", "/v1/passkeys/register/begin", alice, map[string]string{"password": "correct horse battery"}, 200)
	created := h.do("POST", "/v1/passkeys/register/finish", alice, map[string]any{"ceremony": begin["ceremony"], "name": "Laptop", "response": key.create(begin, origin)}, 201)
	if created["name"] != "Laptop" {
		t.Fatalf("created %v", created)
	}
	// The ceremony is single use.
	h.do("POST", "/v1/passkeys/register/finish", alice, map[string]any{"ceremony": begin["ceremony"], "name": "Again", "response": key.create(begin, origin)}, 400)
	list := h.do("GET", "/v1/passkeys", alice, nil, 200)["items"].([]any)
	if len(list) != 1 {
		t.Fatalf("list %v", list)
	}

	// Sign in without an email address.
	lb := h.do("POST", "/v1/sessions/passkey/begin", "", nil, 200)
	res := h.do("POST", "/v1/sessions/passkey/finish", "", map[string]any{"ceremony": lb["ceremony"], "response": key.get(lb, origin)}, 200)
	tok, _ := res["token"].(string)
	me := h.do("GET", "/v1/me", tok, nil, 200)
	if me["account"].(map[string]any)["email"] != "alice@example.com" {
		t.Fatalf("me %v", me)
	}
	// Replaying the same answer against the same ceremony fails.
	h.do("POST", "/v1/sessions/passkey/finish", "", map[string]any{"ceremony": lb["ceremony"], "response": key.get(lb, origin)}, 400)

	// Wrong origin.
	lb = h.do("POST", "/v1/sessions/passkey/begin", "", nil, 200)
	h.do("POST", "/v1/sessions/passkey/finish", "", map[string]any{"ceremony": lb["ceremony"], "response": key.get(lb, "https://evil.test")}, 401)

	// An answer to an old challenge on a new ceremony fails.
	old := h.do("POST", "/v1/sessions/passkey/begin", "", nil, 200)
	lb = h.do("POST", "/v1/sessions/passkey/begin", "", nil, 200)
	h.do("POST", "/v1/sessions/passkey/finish", "", map[string]any{"ceremony": lb["ceremony"], "response": key.get(old, origin)}, 401)

	// A counter that goes backwards is refused.
	key.count = 0
	lb = h.do("POST", "/v1/sessions/passkey/begin", "", nil, 200)
	h.do("POST", "/v1/sessions/passkey/finish", "", map[string]any{"ceremony": lb["ceremony"], "response": key.get(lb, origin)}, 401)
	key.count = 100

	// Someone else can't remove it; the owner can, and then it stops working.
	bob := h.signup("bob@example.com")
	id := list[0].(map[string]any)["id"].(string)
	h.do("DELETE", "/v1/passkeys/"+id, bob, nil, 404)
	h.do("DELETE", "/v1/passkeys/"+id, alice, nil, 204)
	lb = h.do("POST", "/v1/sessions/passkey/begin", "", nil, 200)
	h.do("POST", "/v1/sessions/passkey/finish", "", map[string]any{"ceremony": lb["ceremony"], "response": key.get(lb, origin)}, 401)

	// A password reset removes passkeys, so it takes the account back.
	key2 := newSoftKey(t, "hub.test")
	b2 := h.do("POST", "/v1/passkeys/register/begin", alice, map[string]string{"password": "correct horse battery"}, 200)
	h.do("POST", "/v1/passkeys/register/finish", alice, map[string]any{"ceremony": b2["ceremony"], "name": "Planted", "response": key2.create(b2, origin)}, 201)
	h.do("POST", "/v1/accounts/password-reset", "", map[string]string{"email": "alice@example.com"}, 202)
	h.do("POST", "/v1/accounts/password-reset/confirm", "", map[string]string{"token": h.mail.lastToken(t, "alice@example.com"), "password": "a brand new password"}, 200)
	lb = h.do("POST", "/v1/sessions/passkey/begin", "", nil, 200)
	h.do("POST", "/v1/sessions/passkey/finish", "", map[string]any{"ceremony": lb["ceremony"], "response": key2.get(lb, origin)}, 401)
}

func TestPasskeyNeedsConfirmedPerson(t *testing.T) {
	h := newHarness(t, nil)
	h.do("POST", "/v1/accounts", "", map[string]string{"email": "new@example.com", "password": "correct horse battery"}, 202)
	tok := h.do("POST", "/v1/sessions", "", map[string]string{"email": "new@example.com", "password": "correct horse battery"}, 200)["token"].(string)
	h.do("POST", "/v1/passkeys/register/begin", tok, map[string]string{"password": "correct horse battery"}, 403)
	h.do("POST", "/v1/passkeys/register/begin", "", nil, 401)
}
