package ghostfolio

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeGhostfolio struct {
	mu        sync.Mutex
	seen      []string
	exchanges int
	jwt       string
	oldServer bool
}

func (f *fakeGhostfolio) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	if r.Method == "POST" && r.URL.Path == "/api/v1/auth/anonymous" {
		var b struct {
			AccessToken string `json:"accessToken"`
		}
		json.Unmarshal(body, &b)
		if b.AccessToken != "gf-security-good" {
			w.WriteHeader(403)
			io.WriteString(w, `{"message":"Forbidden","statusCode":403}`)
			return
		}
		f.exchanges++
		f.jwt = "eyJhbGciOiJIUzI1NiJ9.session" + strings.Repeat("x", f.exchanges)
		io.WriteString(w, `{"authToken":"`+f.jwt+`"}`)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+f.jwt || f.jwt == "" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthorized","statusCode":401}`)
		return
	}
	switch r.URL.Path {
	case "/api/v1/user":
		io.WriteString(w, `{"id":"u1","settings":{"baseCurrency":"EUR"},"accessToken":"LEAKME"}`)
	case "/api/v1/account":
		io.WriteString(w, `{"accounts":[{"id":"a1","name":"Broker","currency":"USD","balance":120.5,"balanceInBaseCurrency":110.25,"value":10500.10,"valueInBaseCurrency":9700.01,"isExcluded":false,"transactionCount":12,"comment":"LEAKME","platform":{"name":"Interactive Brokers","url":"https://ib.com"}}],"totalBalanceInBaseCurrency":110.25,"totalValueInBaseCurrency":9700.01}`)
	case "/api/v1/portfolio/details":
		if f.oldServer {
			io.WriteString(w, `{"holdings":{"VWCE.DE":{"symbol":"VWCE.DE","name":"Vanguard FTSE All-World","currency":"EUR","quantity":10,"valueInBaseCurrency":1100.5},"BTC":{"symbol":"BTC","name":"Bitcoin","currency":"USD","quantity":0.01,"valueInBaseCurrency":600}}}`)
			return
		}
		io.WriteString(w, `{"holdings":{},"summary":{"currentValueInBaseCurrency":9700.01,"totalInvestment":8000,"netPerformance":1700.01,"netWorth":9810.26,"emergencyFund":{"assets":1},"activityCount":12,"dateOfFirstActivity":"2021-03-01T00:00:00.000Z","secret":"LEAKME"},"hasError":false}`)
	case "/api/v2/portfolio/performance":
		if r.URL.Query().Get("range") == "" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"chart":[],"firstOrderDate":"2021-03-01","hasErrors":false,"performance":{"currentValueInBaseCurrency":9700.01,"netPerformance":1700.01,"netPerformancePercentage":0.2125,"totalInvestment":8000}}`)
	case "/api/v1/portfolio/holdings":
		if f.oldServer {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Cannot GET","statusCode":404}`)
			return
		}
		io.WriteString(w, `{"holdings":[{"symbol":"BTC","name":"Bitcoin","currency":"USD","assetClass":"LIQUIDITY","quantity":0.01,"marketPrice":60000,"valueInBaseCurrency":600,"allocationInPercentage":0.06},{"symbol":"VWCE.DE","name":"Vanguard FTSE All-World","currency":"EUR","assetClass":"EQUITY","quantity":10,"marketPrice":110.05,"valueInBaseCurrency":1100.5,"allocationInPercentage":0.11}]}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found","statusCode":404}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeGhostfolio) {
	f := &fakeGhostfolio{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL // the cloud default, pointed at the fake
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://gf": "gf-security-good", "secret://bad": "gf-security-bad"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in)})
}

func TestGhostfolio(t *testing.T) {
	m, f := setup(t, "secret://gf")
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || h.Message != "signed in · base currency EUR" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"accounts", `{}`, `"valueInBaseCurrency":9700.01`},
		{"accounts", `{}`, `"platform":"Interactive Brokers"`},
		{"accounts", `{}`, `"totalBalanceInBaseCurrency":110.25`},
		{"summary", `{}`, `"netPerformance":1700.01`},
		{"summary", `{}`, `"activityCount":12`},
		{"performance", `{}`, `"range":"max"`},
		{"performance", `{"range":"2024"}`, `"netPerformancePercentage":0.2125`},
		{"holdings", `{}`, `"holdings":[{"allocation":0.11`},
		{"holdings", `{"query":"btc"}`, `"total":1}`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "eyJ") || strings.Contains(out, "gf-security") {
			t.Fatalf("%s: %s %v", c.action, out, err)
		}
	}
	if f.exchanges != 1 {
		t.Fatalf("signed in %d times", f.exchanges)
	}
	// An expired session signs in again once.
	f.jwt = "expired"
	if _, err := invoke(m, "accounts", `{}`); err != nil || f.exchanges != 2 {
		t.Fatalf("%v %d", err, f.exchanges)
	}
	// Older servers: holdings come from the details, as a map.
	f.oldServer = true
	if r, err := invoke(m, "holdings", `{}`); err != nil || !strings.Contains(string(r.Output), `"holdings":[{"currency":"EUR","name":"Vanguard FTSE All-World","quantity":10,"symbol":"VWCE.DE","valueInBaseCurrency":1100.5}`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, a := range m.Manifest().Actions {
		if !a.Sensitive || a.Risk != sdk.RiskRead {
			t.Fatalf("%s: sensitive=%v risk=%s", a.Name, a.Sensitive, a.Risk)
		}
	}
}

func TestGhostfolioValidation(t *testing.T) {
	m, f := setup(t, "secret://gf")
	for _, c := range []struct{ action, in string }{
		{"performance", `{"range":"forever"}`},
		{"performance", `{"range":"1y&x=1"}`},
		{"holdings", `{"limit":-1}`},
		{"holdings", `{"query":"` + strings.Repeat("a", 101) + `"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Token: "gf-plain"}, {URL: "ghostfolio.example.com", Token: "secret://gf"}, {URL: "https://u:p@gf.example.com", Token: "secret://gf"}, {URL: "https://gf.example.com/?x=1", Token: "secret://gf"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "g")
	if h.Status != "down" || h.Message != "Ghostfolio refused the security token" || strings.Contains(h.Message, "gf-security") {
		t.Fatalf("%+v", h)
	}
	if _, err := invoke(bad, "accounts", `{}`); err == nil || strings.Contains(err.Error(), "gf-security") {
		t.Fatal(err)
	}
}

func TestGhostfolioRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://gf"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://gf": "gf-security-good"}), "g", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "g"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
