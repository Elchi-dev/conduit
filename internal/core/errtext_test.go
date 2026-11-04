package core

// Regression tests: a failed call's error text reaching the audit log and
// events with what a sensitive action carries, or a URL's query.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/modules/lemonsqueezy"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type httpStatusErr struct{ code int }

func (e httpStatusErr) Error() string {
	return fmt.Sprintf("no order for victim@example.org (%d)", e.code)
}
func (e httpStatusErr) HTTPStatus() int { return e.code }

type timeoutErr struct{}

func (timeoutErr) Error() string { return "deadline for victim@example.org" }
func (timeoutErr) Timeout() bool { return true }

// failMod fails every call with the error set for its action.
type failMod struct{ errs map[string]error }

func (failMod) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "failmod", Name: "f", Actions: []sdk.ActionSpec{
		{Name: "orders", Risk: sdk.RiskRead, Sensitive: true},
		{Name: "orders_http", Risk: sdk.RiskRead, Sensitive: true},
		{Name: "orders_timeout", Risk: sdk.RiskRead, Sensitive: true},
		{Name: "orders_plain", Risk: sdk.RiskRead, Sensitive: true},
		{Name: "list", Risk: sdk.RiskRead},
	}}
}
func (failMod) Configure(context.Context, sdk.Host, string, json.RawMessage) error { return nil }
func (failMod) Close(string) error                                                 { return nil }
func (failMod) Health(context.Context, string) sdk.Health                          { return sdk.Health{Status: "ok"} }
func (m failMod) Invoke(_ context.Context, c sdk.Call) (sdk.Result, error) {
	return sdk.Result{}, m.errs[c.Action]
}

func TestSensitiveErrorKeepsOnlyClass(t *testing.T) {
	ctx := context.Background()
	e, _, _ := newTestEngine(t)
	full := `https://api.example.com/v1/orders?filter%5Buser_email%5D=victim%40example.org`
	m := failMod{errs: map[string]error{
		"orders":         &url.Error{Op: "Get", URL: full, Err: errors.New("EOF")},
		"orders_http":    fmt.Errorf("wrapped: %w", httpStatusErr{404}),
		"orders_timeout": timeoutErr{},
		"orders_plain":   errors.New("no customer victim@example.org"),
		"list":           &url.Error{Op: "Get", URL: "https://user:pw@api.example.com/v1/list?api_key=k3y#frag", Err: errors.New("EOF")},
	}}
	if err := e.Register(m); err != nil {
		t.Fatal(err)
	}
	id := saveInst(t, e, "failmod", `{}`)
	events, stop := e.Bus.Subscribe("action.", 16)
	defer stop()
	for action, want := range map[string]string{
		"orders":         "failed (connection error)",
		"orders_http":    "failed (HTTP 404)",
		"orders_timeout": "failed (timeout)",
		"orders_plain":   "failed",
		"list":           `Get "https://api.example.com/v1/list": EOF`,
	} {
		in := `{"email":"victim@example.org"}`
		if action == "list" { // not sensitive: its input is logged as it is
			in = `{}`
		}
		out, err := e.Invoke(ctx, Actor{ID: "a", Kind: ActorAgent}, sdk.Call{Instance: id, Action: action, Input: json.RawMessage(in)}, InvokeOptions{})
		if err == nil || err.Error() != m.errs[action].Error() {
			t.Fatalf("%s: the caller must get the full error, got %v", action, err)
		}
		if out.Audit.Error != want {
			t.Errorf("%s: audit error %q, want %q", action, out.Audit.Error, want)
		}
		noLeak(t, e, out.Audit.Seq, "victim", "k3y", "pw@", "frag")
		select {
		case ev := <-events:
			if s := string(ev.Data); strings.Contains(s, "victim") || strings.Contains(s, "k3y") {
				t.Errorf("%s: event holds the error text: %s", action, s)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s: no event", action)
		}
	}
}

func TestSanitizeErrorText(t *testing.T) {
	for in, want := range map[string]string{
		`Get "https://h.example/a?email=x%40y.org": EOF`:   `Get "https://h.example/a": EOF`,
		`dial https://u:p@h.example:8443/x failed`:         `dial https://h.example:8443/x failed`,
		`see http://h/x#tok and ftp://a:b@c/d?e`:           `see http://h/x and ftp://c/d`,
		`no URL here, key=value`:                           `no URL here, key=value`,
		`Post "http://[::1]:80/x?k=v": connection refused`: `Post "http://[::1]:80/x": connection refused`,
	} {
		if got := SanitizeErrorText(in); got != want {
			t.Errorf("SanitizeErrorText(%q) = %q, want %q", in, got, want)
		}
	}
}

// The PoC: Lemon Squeezy's sensitive orders listing filters on an email
// address in the query; a dropped connection quoted it in the audit log.
func TestLemonSqueezyOrdersErrorNotLogged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close()
	}))
	defer srv.Close()
	e := leakEngine(t)
	e.SetSecrets(leakSecrets{"secret://ls": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiI5NGQ1OSIsImp0aSI6IjEyMyJ9.c2lnbmF0dXJlc2lnbmF0dXJl"})
	if err := e.Register(&lemonsqueezy.Module{Base: srv.URL, HTTP: srv.Client()}); err != nil {
		t.Fatal(err)
	}
	id := saveInst(t, e, "lemonsqueezy", `{"key":"secret://ls"}`)
	out, err := e.Invoke(context.Background(), Actor{ID: "a", Kind: ActorAgent}, sdk.Call{Instance: id, Action: "orders", Input: json.RawMessage(`{"email":"victim@example.org"}`)}, InvokeOptions{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "victim") {
		t.Errorf("the module's error quotes the query: %v", err)
	}
	if out.Audit.Error != "failed (connection error)" {
		t.Errorf("audit error %q", out.Audit.Error)
	}
	noLeak(t, e, out.Audit.Seq, "victim")
}
