package gumroad

import (
	"context"
	"encoding/json"
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

const goodToken = "gumroadTOKEN0123456789abcdefXYZ"

var secrets = map[string]string{"secret://g": goodToken, "secret://bad": "gumroadBAD0123456789abcdefXYZ00", "secret://junk": "hunter2"}

type fakeGumroad struct {
	mu        sync.Mutex
	seen      []string
	published bool
	ignore    bool
}

func (f *fakeGumroad) product() string {
	return fmt.Sprintf(`{"id":"A-m3CDDC5dlrSdKZp0RFhA==","name":"Pattern pack","published":%t,"deleted":false,"price":1250,"currency":"usd","sales_count":"14","sales_usd_cents":"17500","short_url":"https://gum.co/pp","is_tiered_membership":true,"subscription_duration":"monthly"}`, f.published)
}

func (f *fakeGumroad) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("access_token") != "" {
		w.WriteHeader(400)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+goodToken {
		w.WriteHeader(401)
		io.WriteString(w, `{"success":false,"message":"The access token you provided is not valid."}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	switch r.Method + " " + r.URL.EscapedPath() {
	case "GET /v2/user":
		io.WriteString(w, `{"success":true,"user":{"name":"Ada's Patterns","email":"seller@LEAKME.example","user_id":"u1"}}`)
	case "GET /v2/products":
		fmt.Fprintf(w, `{"success":true,"products":[%s,{"id":"old","name":"Gone","deleted":true,"price":100,"currency":"usd"}]}`, f.product())
	case "GET /v2/products/A-m3CDDC5dlrSdKZp0RFhA==":
		fmt.Fprintf(w, `{"success":true,"product":%s}`, f.product())
	case "GET /v2/products/other":
		fmt.Fprintf(w, `{"success":true,"product":%s}`, f.product())
	case "PUT /v2/products/A-m3CDDC5dlrSdKZp0RFhA==/enable", "PUT /v2/products/A-m3CDDC5dlrSdKZp0RFhA==/disable":
		if !f.ignore {
			f.published = strings.HasSuffix(r.URL.Path, "/enable")
		}
		fmt.Fprintf(w, `{"success":true,"product":%s}`, f.product())
	case "GET /v2/products/A-m3CDDC5dlrSdKZp0RFhA==/subscribers":
		if r.URL.Query().Get("page_key") == "" {
			io.WriteString(w, `{"success":true,"next_page_key":"k2","subscribers":[{"id":"s1","status":"alive","user_email":"LEAKME@example.org"},{"id":"s2","status":"pending_cancellation"}]}`)
			return
		}
		io.WriteString(w, `{"success":true,"subscribers":[{"id":"s3","status":"cancelled","user_email":"LEAKME@example.org"}]}`)
	case "GET /v2/sales":
		if q := r.URL.Query(); q.Get("after") != "" && q.Get("after") != "2026-11-01" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"success":true,"next_page_key":"p2","sales":[{"id":"sale1","email":"LEAKME@example.org","full_name":"LEAKME","product_id":"A-m3CDDC5dlrSdKZp0RFhA==","product_name":"Pattern pack","price":1250,"currency":"usd","created_at":"2026-11-02T10:00:00Z","refunded":false,"partially_refunded":true,"ip_country":"LEAKME","custom_fields":{"x":"LEAKME"}}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"success":false,"message":"The product was not found."}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeGumroad) {
	t.Helper()
	f := &fakeGumroad{published: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

const pid = "A-m3CDDC5dlrSdKZp0RFhA=="

func TestGumroad(t *testing.T) {
	m, f := setup(t, "secret://g")
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || h.Message != "connected as Ada's Patterns" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"products", `{}`, `"price":"12.50 USD"`},
		{"products", `{}`, `"revenue":"175.00 USD"`},
		{"sales", `{"after":"2026-11-01","product":"` + pid + `"}`, `"partiallyRefunded":true`},
		{"sales", `{}`, `"nextPageKey":"p2"`},
		{"subscribers", `{"product":"` + pid + `"}`, `"active":2`},
		{"subscribers", `{"product":"` + pid + `"}`, `"total":3`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, goodToken) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	if r, _ := invoke(m, "products", `{}`, false); strings.Contains(string(r.Output), "Gone") {
		t.Fatal(string(r.Output))
	}

	// Disable: preview with amounts, real, undo.
	r, err := invoke(m, "disable_product", `{"product":"`+pid+`"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Disable Pattern pack (12.50 USD, 14 sales, 175.00 USD revenue): nobody can buy it until it's enabled again" || !f.published {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "disable_product", `{"product":"`+pid+`"}`, false)
	if err != nil || f.published || r.Undo == nil || r.Undo.Action != "enable_product" || string(r.Undo.Input) != `{"product":"`+pid+`"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "disable_product", `{"product":"`+pid+`"}`, false); err != nil || !strings.Contains(string(r.Output), "nothing to change") || r.Undo != nil {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || !f.published {
		t.Fatal(err)
	}
	f.ignore = true
	if _, err := invoke(m, "disable_product", `{"product":"`+pid+`"}`, false); err == nil || !strings.Contains(err.Error(), "kept") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "disable_product", `{"product":"nope"}`, false); err == nil || !strings.Contains(err.Error(), "no product") {
		t.Fatal(err)
	}
	for _, a := range m.Manifest().Actions {
		if a.Sensitive {
			t.Fatalf("%s is sensitive; nothing personal is returned", a.Name)
		}
		if a.Name == "disable_product" && (a.Risk != sdk.RiskDestructive || !a.DryRun) {
			t.Fatal("disable_product must be destructive with a preview")
		}
	}
}

func TestGumroadValidation(t *testing.T) {
	m, f := setup(t, "secret://g")
	for _, c := range []struct{ action, in string }{
		{"subscribers", `{}`},
		{"subscribers", `{"product":"../user"}`},
		{"disable_product", `{"product":"a/b"}`},
		{"disable_product", `{"product":"x?y=1"}`},
		{"enable_product", `{}`},
		{"sales", `{"after":"last week"}`},
		{"sales", `{"before":"2026-13-40"}`},
		{"sales", `{"pageKey":"a b&c"}`},
		{"sales", `{"product":"a b"}`},
		{"nope", `{}`},
	} {
		for _, dry := range []bool{false, true} {
			if _, err := invoke(m, c.action, c.in, dry); err == nil {
				t.Fatalf("%s accepted %s", c.action, c.in)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached Gumroad: %v", f.seen)
	}
	// The product changed is the one asked for, whatever the server answers.
	if _, err := invoke(m, "disable_product", `{"product":"other"}`, false); err == nil || len(f.seen) != 1 {
		t.Fatalf("changed another product: %v %v", err, f.seen)
	}
	raw, _ := json.Marshal(Config{Token: goodToken})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
		t.Fatal("accepted a plain token")
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "g"); h.Status != "down" || h.Message != "Gumroad refused the access token" {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, "secret://junk")
	if _, err := invoke(junk, "products", `{}`, false); err == nil || len(fj.seen) != 0 || strings.Contains(err.Error(), "hunter2") {
		t.Fatal(err)
	}
}

func TestGumroadErrorsHideSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"success":false,"message":"bad token `+goodToken+` for seller@example.org `+strings.Repeat("x ", 200)+`"}`)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{Token: "secret://g"})
	m.Configure(context.Background(), fakehost.New(secrets), "g", raw)
	_, err := invoke(m, "products", `{}`, false)
	if err == nil || strings.Contains(err.Error(), goodToken) || strings.Contains(err.Error(), "seller@") || len(err.Error()) > 300 {
		t.Fatalf("error: %v", err)
	}
}

func TestGumroadRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	raw, _ := json.Marshal(Config{Token: "secret://g"})
	m.Configure(context.Background(), fakehost.New(secrets), "g", raw)
	if h := m.Health(context.Background(), "g"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
