package googleanalytics

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeGoogle struct {
	mu       sync.Mutex
	key      *rsa.PublicKey
	api      []string
	tokens   int
	claims   map[string]any
	valid    map[string]bool
	lastBody map[string]any
	redirect string
}

func (f *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.URL.Path == "/token" {
		form, _ := url.ParseQuery(string(body))
		f.tokens++
		ok := false
		if form.Get("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			parts := strings.Split(form.Get("assertion"), ".")
			if len(parts) == 3 {
				sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
				sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
				c, _ := base64.RawURLEncoding.DecodeString(parts[1])
				f.claims = map[string]any{}
				json.Unmarshal(c, &f.claims)
				ok = rsa.VerifyPKCS1v15(f.key, crypto.SHA256, sum[:], sig) == nil
			}
		}
		if !ok {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`)
			return
		}
		tok := fmt.Sprintf("ya29.ACCESS-%d", f.tokens)
		f.valid[tok] = true
		fmt.Fprintf(w, `{"access_token":%q,"expires_in":3599}`, tok)
		return
	}
	if !f.valid[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":401,"message":"Request had invalid authentication credentials."}}`)
		return
	}
	f.api = append(f.api, r.Method+" "+r.URL.EscapedPath())
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusTemporaryRedirect)
		return
	}
	f.lastBody = nil
	if len(body) > 0 {
		f.lastBody = map[string]any{}
		json.Unmarshal(body, &f.lastBody)
	}
	switch r.Method + " " + r.URL.EscapedPath() {
	case "GET /v1beta/accountSummaries":
		if r.URL.Query().Get("pageToken") == "" {
			io.WriteString(w, `{"accountSummaries":[{"account":"accounts/9","displayName":"Acme","propertySummaries":[{"property":"properties/123","displayName":"Shop","propertyType":"PROPERTY_TYPE_ORDINARY"}]}],"nextPageToken":"p2"}`)
		} else {
			io.WriteString(w, `{"accountSummaries":[{"account":"accounts/9","displayName":"Acme","propertySummaries":[{"property":"properties/456","displayName":"Blog"},{"property":"properties/../x","displayName":"Evil"}]}]}`)
		}
	case "POST /v1beta/properties/123:runReport":
		io.WriteString(w, `{"dimensionHeaders":[{"name":"pagePath"}],"metricHeaders":[{"name":"activeUsers","type":"TYPE_INTEGER"}],
			"rows":[{"dimensionValues":[{"value":"/"}],"metricValues":[{"value":"120"}]},{"dimensionValues":[{"value":"/pricing"}],"metricValues":[{"value":"40"}]},{"dimensionValues":[{"value":"/x"}],"metricValues":[{"value":"1"}]}],"rowCount":3}`)
	case "POST /v1beta/properties/123:runRealtimeReport":
		io.WriteString(w, `{"metricHeaders":[{"name":"activeUsers"}],"rows":[{"metricValues":[{"value":"7"}]}],"rowCount":1}`)
	case "POST /v1beta/properties/999:runReport":
		w.WriteHeader(403)
		io.WriteString(w, `{"error":{"code":403,"message":"User does not have sufficient permissions for this property."}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"code":404,"message":"Not Found"}}`)
	}
}

func saKey(t *testing.T) (string, *rsa.PublicKey) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	b, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "conduit@proj.iam.gserviceaccount.com", "private_key_id": "kid1",
		"private_key": pemKey, "token_uri": "https://evil.example/token"})
	return string(b), &k.PublicKey
}

func setup(t *testing.T, ref string) (*Module, *fakeGoogle) {
	t.Helper()
	key, pub := saKey(t)
	other, _ := saKey(t)
	f := &fakeGoogle{valid: map[string]bool{}, key: pub}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base, m.TokenURL = srv.URL, srv.URL+"/token"
	raw, _ := json.Marshal(Config{ServiceAccount: ref})
	h := fakehost.New(map[string]string{"secret://sa": key, "secret://other": other, "secret://junk": "not json LEAKME"})
	if err := m.Configure(context.Background(), h, "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func call(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in)})
}

func noLeak(t *testing.T, s string) {
	t.Helper()
	for _, bad := range []string{"ya29.", "LEAKME", "PRIVATE KEY", "assertion"} {
		if strings.Contains(s, bad) {
			t.Fatalf("leaks %q: %s", bad, s)
		}
	}
}

func TestJWTExchangeAndReports(t *testing.T) {
	m, f := setup(t, "secret://sa")
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || h.Message != "1+ properties" {
		t.Fatalf("%+v", h)
	}
	if f.claims["iss"] != "conduit@proj.iam.gserviceaccount.com" || f.claims["scope"] != Scope || !strings.HasSuffix(f.claims["aud"].(string), "/token") || f.claims["sub"] != nil {
		t.Fatalf("claims %v", f.claims)
	}
	r, err := call(m, "properties", `{}`)
	if err != nil || !strings.Contains(string(r.Output), `"property":"456"`) || !strings.Contains(string(r.Output), `"type":"ORDINARY"`) || strings.Contains(string(r.Output), "Evil") {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = call(m, "report", `{"property":"properties/123","dimensions":["pagePath"],"metrics":["activeUsers"],"limit":2,"days":7}`)
	if err != nil || !strings.Contains(string(r.Output), `{"activeUsers":40,"pagePath":"/pricing"}`) || strings.Contains(string(r.Output), `"/x"`) || !strings.Contains(string(r.Output), `"truncated":true`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	dr := f.lastBody["dateRanges"].([]any)[0].(map[string]any)
	if dr["startDate"] != "6daysAgo" || dr["endDate"] != "today" || f.lastBody["limit"] != float64(2) {
		t.Fatalf("%v", f.lastBody)
	}
	if _, err := call(m, "report", `{"property":"123","from":"2026-01-01","to":"2026-12-31"}`); err != nil {
		t.Fatal(err)
	}
	if len(f.lastBody["metrics"].([]any)) != 3 || f.lastBody["dimensions"] != nil {
		t.Fatalf("%v", f.lastBody)
	}
	r, err = call(m, "realtime", `{"property":"123"}`)
	if err != nil || !strings.Contains(string(r.Output), `"activeUsers":7`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if f.tokens != 1 {
		t.Fatalf("token not cached: %d", f.tokens)
	}
	if _, err := call(m, "report", `{"property":"999"}`); err == nil || !strings.Contains(err.Error(), "Viewer") {
		t.Fatal(err)
	}
	noLeak(t, string(r.Output))
}

func TestBadCredentials(t *testing.T) {
	for _, ref := range []string{"secret://other", "secret://junk", "secret://missing"} {
		m, f := setup(t, ref)
		h := m.Health(context.Background(), "g")
		if h.Status != "down" {
			t.Fatalf("%s: %+v", ref, h)
		}
		noLeak(t, h.Message)
		_, err := call(m, "report", `{"property":"123"}`)
		if err == nil {
			t.Fatal(ref)
		}
		noLeak(t, err.Error())
		if len(f.api) != 0 {
			t.Fatal(f.api)
		}
	}
}

func TestSettingsRefused(t *testing.T) {
	for _, raw := range []string{`{}`, `{"serviceAccount":"{\"type\":\"service_account\"}"}`, `{"serviceAccount":"https://x"}`, `[`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestInvalidInputNeverReachesGoogle(t *testing.T) {
	m, f := setup(t, "secret://sa")
	for _, c := range []struct{ action, in string }{
		{"report", `{}`},
		{"report", `{"property":"../123"}`},
		{"report", `{"property":"123/../x"}`},
		{"report", `{"property":"123","dimensions":["page path"]}`},
		{"report", `{"property":"123","dimensions":["customUser:email"]}`},
		{"report", `{"property":"123","dimensions":["userId"]}`},
		{"report", `{"property":"123","metrics":["activeUsers","activeUsers"]}`},
		{"report", `{"property":"123","metrics":["a","b","c","d","e","f","g","h","i","j","k"]}`},
		{"report", `{"property":"123","limit":1001}`},
		{"report", `{"property":"123","limit":-1}`},
		{"report", `{"property":"123","days":367}`},
		{"report", `{"property":"123","from":"2025-01-01","to":"2026-01-02"}`},
		{"report", `{"property":"123","from":"2026-02-01","to":"2026-01-01"}`},
		{"report", `{"property":"123","from":"2026-01-01"}`},
		{"report", `{"property":"123","days":7,"from":"2026-01-01","to":"2026-01-02"}`},
		{"realtime", `{"property":"123","days":7}`},
		{"realtime", `{"property":"123","dimensions":["x\"}"]}`},
	} {
		if _, err := call(m, c.action, c.in); err == nil {
			t.Errorf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.api) != 0 {
		t.Fatalf("invalid input reached Google: %v", f.api)
	}
	for _, a := range m.Manifest().Actions {
		if a.Risk != sdk.RiskRead {
			t.Fatalf("%s isn't read-only", a.Name)
		}
	}
}

func TestCrossHostRedirectRefused(t *testing.T) {
	hits := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer other.Close()
	m, f := setup(t, "secret://sa")
	f.redirect = other.URL + "/x"
	if _, err := call(m, "report", `{"property":"123"}`); !errors.Is(err, rest.ErrCrossHostRedirect) {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatal("followed")
	}
}
