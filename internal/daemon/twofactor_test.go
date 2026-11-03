package daemon

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/totp"
)

func TestTwoFactor(t *testing.T) {
	_, c, _, _ := setup(t)
	const pw = "correct horse" // the owner's password from setup()

	// Setup needs the password.
	if code := c.do("POST", "/api/v1/me/2fa/setup", map[string]string{"password": "wrong"}, nil); code != 403 {
		t.Fatalf("setup with a wrong password = %d", code)
	}
	var st struct{ Secret, URI string }
	if code := c.do("POST", "/api/v1/me/2fa/setup", map[string]string{"password": pw}, &st); code != 200 || st.Secret == "" {
		t.Fatalf("setup = %d", code)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(st.Secret)
	if err != nil {
		t.Fatal(err)
	}
	now := func() int64 { return totp.Step(time.Now()) }

	// Enabling needs a correct code and answers ten recovery codes.
	if code := c.do("POST", "/api/v1/me/2fa/enable", map[string]string{"code": "000000"}, nil); code != 400 {
		t.Fatalf("enable with a wrong code = %d", code)
	}
	used := now()
	var rc struct{ RecoveryCodes []string }
	if code := c.do("POST", "/api/v1/me/2fa/enable", map[string]string{"code": totp.Code(secret, used)}, &rc); code != 200 || len(rc.RecoveryCodes) != 10 {
		t.Fatalf("enable = %d %v", code, rc)
	}
	var me struct{ User auth.User }
	c.do("GET", "/api/v1/me", nil, &me)
	if !me.User.TwoFactor {
		t.Fatal("user doesn't show two-factor")
	}

	// Signing in now takes two steps.
	login := func() string {
		t.Helper()
		var res map[string]any
		anon := client{t: t, base: c.base}
		if code := anon.do("POST", "/api/v1/auth/login", map[string]string{"email": "owner@example.com", "password": pw}, &res); code != 200 || res["twoFactor"] != true || res["token"] != nil {
			t.Fatalf("login = %d %v", code, res)
		}
		return res["challenge"].(string)
	}
	finish := func(ch, code string) (int, string) {
		t.Helper()
		var res sessionResp
		n := client{t: t, base: c.base}.do("POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch, "code": code}, &res)
		return n, res.Token
	}
	ch := login()
	if n, _ := finish(ch, "123456"); n != 401 {
		t.Fatalf("wrong code = %d", n)
	}
	// The code that turned 2FA on can't be used again.
	if n, _ := finish(ch, totp.Code(secret, used)); n != 401 {
		t.Fatalf("replayed code = %d", n)
	}
	next := now() + 1
	n, tok := finish(ch, totp.Code(secret, next))
	if n != 200 || tok == "" {
		t.Fatalf("good code = %d", n)
	}
	if code := (client{t: t, base: c.base, token: tok}).do("GET", "/api/v1/me", nil, nil); code != 200 {
		t.Fatalf("new session = %d", code)
	}
	// A finished challenge is gone, and the same code doesn't work twice.
	if n, _ := finish(ch, totp.Code(secret, next)); n != 401 {
		t.Fatalf("challenge reused = %d", n)
	}
	if n, _ := finish(login(), totp.Code(secret, next)); n != 401 {
		t.Fatalf("code reused = %d", n)
	}

	// Recovery codes work once.
	if n, _ := finish(login(), rc.RecoveryCodes[0]); n != 200 {
		t.Fatalf("recovery code = %d", n)
	}
	if n, _ := finish(login(), rc.RecoveryCodes[0]); n != 401 {
		t.Fatalf("recovery code reused = %d", n)
	}
	var state struct {
		Enabled           bool
		RecoveryCodesLeft int
	}
	c.do("GET", "/api/v1/me/2fa", nil, &state)
	if !state.Enabled || state.RecoveryCodesLeft != 9 {
		t.Fatalf("state %+v", state)
	}

	// API keys can't touch any of it.
	var k keyResp
	c.do("POST", "/api/v1/keys", map[string]any{"name": "ci", "kind": "live", "scopes": []string{"admin:*:*"}}, &k)
	key := client{t: t, base: c.base, token: k.Secret}
	for _, p := range []string{"/api/v1/me/2fa/setup", "/api/v1/me/2fa/disable", "/api/v1/me/2fa/recovery-codes"} {
		if code := key.do("POST", p, map[string]string{"password": pw}, nil); code != 403 {
			t.Fatalf("key %s = %d", p, code)
		}
	}

	// Turning it off needs the password and a code.
	if code := c.do("POST", "/api/v1/me/2fa/disable", map[string]string{"password": pw, "code": "000000"}, nil); code != 403 {
		t.Fatalf("disable with a wrong code = %d", code)
	}
	if code := c.do("POST", "/api/v1/me/2fa/disable", map[string]string{"password": "nope", "code": rc.RecoveryCodes[1]}, nil); code != 403 {
		t.Fatalf("disable with a wrong password = %d", code)
	}
	if code := c.do("POST", "/api/v1/me/2fa/disable", map[string]string{"password": pw, "code": rc.RecoveryCodes[2]}, nil); code != 204 {
		t.Fatalf("disable = %d", code)
	}
	var res map[string]any
	if (client{t: t, base: c.base}).do("POST", "/api/v1/auth/login", map[string]string{"email": "owner@example.com", "password": pw}, &res); res["token"] == nil {
		t.Fatalf("login after disable: %v", res)
	}
}

func TestTwoFactorReset(t *testing.T) {
	app, c, _, _ := setup(t)
	ctx := t.Context()
	var member auth.User
	c.do("POST", "/api/v1/users", map[string]string{"email": "kim@example.com", "password": "kim's long password", "role": "member"}, &member)
	sec, _, err := app.Auth.BeginTwoFactor(ctx, member.ID, member.Email)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(sec)
	if _, err := app.Auth.EnableTwoFactor(ctx, member.ID, totp.Code(raw, totp.Step(time.Now()))); err != nil {
		t.Fatal(err)
	}
	var ch map[string]any
	c.do("POST", "/api/v1/auth/login", map[string]string{"email": "kim@example.com", "password": "kim's long password"}, &ch)
	var sess sessionResp
	c.do("POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch["challenge"].(string), "code": totp.Code(raw, totp.Step(time.Now())+1)}, &sess)
	kim := client{t: t, base: c.base, token: sess.Token}
	if code := kim.do("GET", "/api/v1/me", nil, nil); code != 200 {
		t.Fatalf("member two-step sign-in = %d", code)
	}
	// A member can't reset anyone; nobody resets the owner or themselves.
	if code := kim.do("POST", "/api/v1/users/"+member.ID+"/2fa/reset", nil, nil); code != 403 {
		t.Fatalf("member reset = %d", code)
	}
	var me struct{ User auth.User }
	c.do("GET", "/api/v1/me", nil, &me)
	if code := c.do("POST", "/api/v1/users/"+me.User.ID+"/2fa/reset", nil, nil); code != 400 {
		t.Fatalf("own reset = %d", code)
	}
	if code := c.do("POST", "/api/v1/users/"+member.ID+"/2fa/reset", nil, nil); code != 204 {
		t.Fatalf("owner resets member = %d", code)
	}
	if app.Auth.TwoFactorEnabled(ctx, member.ID) {
		t.Fatal("still on")
	}
	if code := kim.do("GET", "/api/v1/me", nil, nil); code != 401 {
		t.Fatalf("member still signed in after reset = %d", code)
	}
}
