package hub

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/totp"
)

func TestHubTwoFactor(t *testing.T) {
	h := newHarness(t, nil)
	const pw = "correct horse battery"
	alice := h.signup("alice@example.com")

	h.do("POST", "/v1/me/2fa/setup", alice, map[string]string{"password": "wrong password"}, 403)
	st := h.do("POST", "/v1/me/2fa/setup", alice, map[string]string{"password": pw}, 200)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(st["secret"].(string))
	if err != nil {
		t.Fatal(err)
	}
	step := func() int64 { return totp.Step(time.Now()) }
	h.do("POST", "/v1/me/2fa/enable", alice, map[string]string{"code": "000000"}, 400)
	used := step()
	en := h.do("POST", "/v1/me/2fa/enable", alice, map[string]string{"code": totp.Code(secret, used)}, 200)
	codes := en["recoveryCodes"].([]any)
	if len(codes) != 10 {
		t.Fatalf("codes %v", codes)
	}

	// A password alone no longer signs in.
	login := func() string {
		t.Helper()
		res := h.do("POST", "/v1/sessions", "", map[string]string{"email": "alice@example.com", "password": pw}, 200)
		if res["twoFactor"] != true || res["token"] != nil {
			t.Fatalf("login %v", res)
		}
		return res["challenge"].(string)
	}
	ch := login()
	h.do("POST", "/v1/sessions/2fa", "", map[string]string{"challenge": ch, "code": "111111"}, 401)
	h.do("POST", "/v1/sessions/2fa", "", map[string]string{"challenge": ch, "code": totp.Code(secret, used)}, 401) // replay
	next := step() + 1
	ok := h.do("POST", "/v1/sessions/2fa", "", map[string]string{"challenge": ch, "code": totp.Code(secret, next)}, 200)
	if ok["token"] == nil {
		t.Fatal("no token")
	}
	h.do("POST", "/v1/sessions/2fa", "", map[string]string{"challenge": login(), "code": totp.Code(secret, next)}, 401)

	// Recovery codes work once.
	h.do("POST", "/v1/sessions/2fa", "", map[string]string{"challenge": login(), "code": codes[0].(string)}, 200)
	h.do("POST", "/v1/sessions/2fa", "", map[string]string{"challenge": login(), "code": codes[0].(string)}, 401)
	if st := h.do("GET", "/v1/me/2fa", alice, nil, 200); st["recoveryCodesLeft"] != 9.0 {
		t.Fatalf("status %v", st)
	}

	// Turning it off needs the password and a code.
	h.do("POST", "/v1/me/2fa/disable", alice, map[string]string{"password": pw, "code": "000000"}, 403)
	h.do("POST", "/v1/me/2fa/disable", alice, map[string]string{"password": "wrong password", "code": codes[1].(string)}, 403)
	h.do("POST", "/v1/me/2fa/disable", alice, map[string]string{"password": pw, "code": codes[2].(string)}, 204)
	if res := h.do("POST", "/v1/sessions", "", map[string]string{"email": "alice@example.com", "password": pw}, 200); res["token"] == nil {
		t.Fatal("password sign-in after turning it off")
	}

	// Hub API keys can't manage it.
	key := h.do("POST", "/v1/keys", alice, map[string]any{"name": "ci", "scopes": []string{"sync"}}, 201)["secret"].(string)
	h.do("POST", "/v1/me/2fa/setup", key, map[string]string{"password": pw}, 403)
	h.do("GET", "/v1/me/2fa", key, nil, 403)
}
