package tibber

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

type fakeTibber struct {
	mu   sync.Mutex
	seen []map[string]any
}

const homeID = "96a14971-525a-4420-aae9-e5aedaa129ff"

func (f *fakeTibber) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.Path != "/gql" {
		w.WriteHeader(404)
		return
	}
	if r.Header.Get("Authorization") != "Bearer tib_good" {
		io.WriteString(w, `{"errors":[{"message":"invalid token tib_bad_0123456789abcdefghij","extensions":{"code":"UNAUTHENTICATED"}}]}`)
		return
	}
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	f.seen = append(f.seen, map[string]any{"query": req.Query, "vars": req.Variables})
	f.mu.Unlock()
	if strings.Contains(req.Query, "address") || strings.Contains(req.Query, "latitude") || strings.Contains(req.Query, "owner") {
		io.WriteString(w, `{"errors":[{"message":"asked for personal data"}]}`)
		return
	}
	switch {
	case strings.Contains(req.Query, "homes"):
		io.WriteString(w, `{"data":{"viewer":{"homes":[{"id":"`+homeID+`","appNickname":"Home","type":"HOUSE","timeZone":"Europe/Oslo","features":{"realTimeConsumptionEnabled":true},"currentSubscription":{"status":"running"},"address":{"address1":"LEAKME street 1","latitude":"59.9"}}]}}}`)
	case strings.Contains(req.Query, "priceInfo"):
		if req.Variables["id"] != homeID {
			io.WriteString(w, `{"data":{"viewer":{"home":null}}}`)
			return
		}
		io.WriteString(w, `{"data":{"viewer":{"home":{"id":"`+homeID+`","currentSubscription":{"status":"running","priceInfo":{
			"current":{"total":0.2531,"energy":0.2,"tax":0.0531,"startsAt":"2026-11-04T10:00:00+01:00","level":"NORMAL","currency":"EUR"},
			"today":[{"total":0.3,"startsAt":"2026-11-04T00:00:00+01:00","level":"EXPENSIVE"},{"total":0.1,"startsAt":"2026-11-04T01:00:00+01:00","level":"VERY_CHEAP"}],
			"tomorrow":[]}}}}}}`)
	case strings.Contains(req.Query, "consumption"):
		io.WriteString(w, `{"data":{"viewer":{"home":{"id":"`+homeID+`","consumption":{"nodes":[
			{"from":"2026-11-04T08:00:00+01:00","to":"2026-11-04T09:00:00+01:00","consumption":1.5,"consumptionUnit":"kWh","cost":0.45,"unitPrice":0.3,"currency":"EUR"},
			{"from":"2026-11-04T09:00:00+01:00","to":"2026-11-04T10:00:00+01:00","consumption":0.5,"consumptionUnit":"kWh","cost":0.05,"unitPrice":0.1,"currency":"EUR"}]}}}}}`)
	default:
		io.WriteString(w, `{"errors":[{"message":"unknown"}]}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeTibber) {
	f := &fakeTibber{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "tib_good", "secret://bad": "tib_bad"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in)})
}

func TestTibber(t *testing.T) {
	m, f := setup(t, "secret://t")
	if h := m.Health(context.Background(), "t"); h.Status != "ok" || h.Message != "1 home(s), 1 with a running subscription" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"homes", `{}`, `[{"id":"` + homeID + `","nickname":"Home","realTimeData":true,"subscription":"running","timeZone":"Europe/Oslo","type":"house"}]`},
		{"prices", `{}`, `"current":{"energy":0.2,"level":"normal","startsAt":"2026-11-04T10:00:00+01:00","tax":0.0531,"total":0.2531}`},
		{"prices", `{}`, `"cheapest":{"startsAt":"2026-11-04T01:00:00+01:00","total":0.1}`},
		{"prices", `{}`, `"tomorrow":null`},
		{"consumption", `{"last":2}`, `"total":2,"totalCost":0.5`},
		{"consumption", `{"home":"` + homeID + `","resolution":"daily","last":366}`, `"resolution":"daily"`},
	} {
		r, err := invoke(m, c.action, c.in)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") || strings.Contains(out, "tib_good") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
	}
	// The chosen values travel as variables, never in the query text.
	last := f.seen[len(f.seen)-1]
	if v := last["vars"].(map[string]any); v["res"] != "DAILY" || v["last"] != float64(366) || v["id"] != homeID || strings.Contains(last["query"].(string), homeID) {
		t.Fatal(last)
	}
	if _, err := invoke(m, "prices", `{"home":"00000000-0000-0000-0000-000000000000"}`); err == nil || !strings.Contains(err.Error(), "no home") {
		t.Fatal(err)
	}
}

func TestTibberValidation(t *testing.T) {
	m, f := setup(t, "secret://t")
	for _, c := range []struct{ action, in string }{
		{"consumption", `{"last":0}`},
		{"consumption", `{"last":745}`},
		{"consumption", `{"resolution":"daily","last":367}`},
		{"consumption", `{"resolution":"weekly"}`},
		{"prices", `{"home":"x\") { id } } #"}`},
		{"prices", `{"home":"a b"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, raw := range []string{`{"token":"tib_plain"}`, `{}`, `{"token":5}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	bad, _ := setup(t, "secret://bad")
	h := bad.Health(context.Background(), "t")
	if h.Status != "down" || h.Message != "Tibber refused the access token" {
		t.Fatalf("%+v", h)
	}
}

func TestTibberRedactsErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"errors":[{"message":"failed for token=tib_good_secret_value `+strings.Repeat("x", 400)+`"}]}`)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "tib_good_secret_value"}), "t", json.RawMessage(`{"token":"secret://t"}`))
	_, err := invoke(m, "homes", `{}`)
	if err == nil || strings.Contains(err.Error(), "tib_good") || len(err.Error()) > 260 {
		t.Fatal(err)
	}
}

func TestTibberRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "tib_good"}), "t", json.RawMessage(`{"token":"secret://t"}`))
	if h := m.Health(context.Background(), "t"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
