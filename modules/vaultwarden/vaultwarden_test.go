package vaultwarden

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func fakeVW(adminOn bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /alive":
			io.WriteString(w, `"2026-11-03T12:00:00Z"`)
		case "GET /api/config":
			io.WriteString(w, `{"version":"2025.10.0","server":{"name":"Vaultwarden"},"environment":{"vault":"https://vault.example.com"}}`)
		case "POST /admin":
			if !adminOn {
				w.WriteHeader(404)
				return
			}
			r.ParseForm()
			if r.Form.Get("token") != "adm1n" {
				w.WriteHeader(401)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "VW_ADMIN", Value: "sess"})
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		case "GET /admin/users":
			if ck, err := r.Cookie("VW_ADMIN"); err != nil || ck.Value != "sess" {
				w.WriteHeader(401)
				return
			}
			old := time.Now().AddDate(0, 0, -200).UTC().Format("2006-01-02 15:04:05 UTC")
			now := time.Now().UTC().Format(time.RFC3339)
			io.WriteString(w, `[{"email":"a@x","_enabled":true,"twoFactorEnabled":true,"lastActive":"`+now+`"},
				{"email":"b@x","_enabled":true,"twoFactorEnabled":false,"lastActive":"`+old+`"},
				{"email":"c@x","_enabled":false,"twoFactorEnabled":false}]`)
		default:
			w.WriteHeader(404)
		}
	})
}

func setup(t *testing.T, adminOn bool, admin string) *Module {
	srv := httptest.NewServer(fakeVW(adminOn))
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, AdminToken: admin})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://vw": "adm1n", "secret://bad": "no"}), "v", raw); err != nil {
		t.Fatal(err)
	}
	return m
}

func invoke(m *Module, action string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "v", Action: action, Input: json.RawMessage(`{}`)})
}

func TestVaultwarden(t *testing.T) {
	m := setup(t, true, "secret://vw")
	if h := m.Health(context.Background(), "v"); h.Status != "ok" || h.Message != "Vaultwarden 2025.10.0" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "status")
	if err != nil || !strings.Contains(string(r.Output), `"up":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "accounts")
	if err != nil || string(r.Output) != `{"disabled":1,"idle90Days":1,"total":3,"withoutTwoFactor":1}` {
		t.Fatalf("%s %v", r.Output, err)
	}
	if strings.Contains(string(r.Output), "@") {
		t.Fatal("emails leaked")
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s is not read-only", a.Name)
		}
	}
}

func TestVaultwardenAdmin(t *testing.T) {
	if _, err := invoke(setup(t, true, ""), "accounts"); err == nil || !strings.Contains(err.Error(), "admin token") {
		t.Fatal(err)
	}
	if _, err := invoke(setup(t, true, "secret://bad"), "accounts"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatal(err)
	}
	if _, err := invoke(setup(t, false, "secret://vw"), "accounts"); err == nil || !strings.Contains(err.Error(), "turned off") {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(Config{URL: "https://v", AdminToken: "plain"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
		t.Fatal("accepted a plain admin token")
	}
}

func TestVaultwardenDown(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL})
	m.Configure(context.Background(), fakehost.New(nil), "v", raw)
	if h := m.Health(context.Background(), "v"); h.Status != "down" {
		t.Fatalf("%+v", h)
	}
	if r, err := invoke(m, "status"); err != nil || string(r.Output) != `{"up":false,"latencyMs":0}` {
		t.Fatalf("%s %v", r.Output, err)
	}
}
