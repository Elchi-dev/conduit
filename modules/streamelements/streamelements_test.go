package streamelements

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	jwt = "eyJhbGciOiJIUzI1NiJ9.eyJjaGFubmVsIjoiNWYxIn0.c2lnbmF0dXJl"
	ch  = "5f1a2b3c4d5e6f7a8b9c0d1e"
)

type fakeSE struct {
	mu       sync.Mutex
	calls    int
	types    []string
	redirect string
}

func (f *fakeSE) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if r.Header.Get("Authorization") != "Bearer "+jwt {
		w.WriteHeader(401)
		io.WriteString(w, `{"statusCode":401,"error":"Unauthorized","message":"invalid token"}`)
		return
	}
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	q := r.URL.Query()
	switch r.URL.Path {
	case "/kappa/v2/channels/me":
		io.WriteString(w, `{"_id":"`+ch+`","username":"streamer","displayName":"Streamer","provider":"twitch","apiToken":"overlay-token-not-for-output"}`)
	case "/kappa/v2/activities/" + ch:
		if q.Get("after") == "" || q.Get("before") == "" || q.Get("limit") == "" {
			w.WriteHeader(400)
			return
		}
		f.types = q["types"]
		io.WriteString(w, `[
			{"type":"follow","provider":"twitch","createdAt":"2026-11-03T10:00:00Z","data":{"username":"bob","displayName":"Bob"}},
			{"type":"tip","provider":"twitch","createdAt":"2026-11-04T10:00:00Z","data":{"username":"alice","amount":5.5,"currency":"EUR","message":"gg"}}]`)
	case "/kappa/v2/points/" + ch + "/top":
		io.WriteString(w, `{"_total":2,"users":[{"username":"alice","points":900},{"username":"bob","points":10}]}`)
	case "/kappa/v2/points/" + ch + "/watchtime":
		io.WriteString(w, `{"_total":1,"users":[{"username":"alice","minutes":6000}]}`)
	case "/kappa/v2/bot/commands/" + ch:
		io.WriteString(w, `[{"command":"discord","reply":"Join us at discord.gg/abc","enabled":true,"accessLevel":100,"cooldown":{"user":15,"global":5},"enabledOnline":true,"enabledOffline":true},
			{"command":"so","reply":"Go follow ${1}","enabled":true,"accessLevel":500,"enabledOnline":true,"enabledOffline":false}]`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, token string) (*Module, *fakeSE) {
	t.Helper()
	f := &fakeSE{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{Base: srv.URL + "/kappa/v2"}
	raw, _ := json.Marshal(Config{Token: "secret://se"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://se": token}), "s", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func call(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: json.RawMessage(in)})
}

func TestStreamElements(t *testing.T) {
	m, f := setup(t, jwt)
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "Streamer (twitch)" {
		t.Fatalf("health %+v", h)
	}
	for _, c := range []struct {
		action, in string
		want       []string
	}{
		{"activities", `{}`, []string{`[{"type":"tip","name":"alice","amount":5.5,"currency":"EUR"`, `"message":"gg"`, `"name":"Bob"`}},
		{"leaderboard", `{}`, []string{`"total":2`, `{"rank":1,"username":"alice","points":900}`}},
		{"leaderboard", `{"kind":"watchtime"}`, []string{`"minutes":6000`}},
		{"commands", `{}`, []string{`"command":"!discord"`, `"cooldown":"15s per user, 5s global"`, `"access":"moderator"`, `"when":"online only"`}},
	} {
		r, err := call(m, c.action, c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.action, err)
		}
		for _, w := range c.want {
			if !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s: want %s in %s", c.action, w, r.Output)
			}
		}
	}
	if _, err := call(m, "activities", `{"types":["tip","follow"]}`); err != nil || strings.Join(f.types, ",") != "tip,follow" {
		t.Fatalf("types %v %v", f.types, err)
	}

	f.mu.Lock()
	before := f.calls
	f.mu.Unlock()
	for _, c := range []struct{ action, in string }{
		{"activities", `{"types":["tip&limit=1000"]}`},
		{"activities", `{"days":365}`},
		{"activities", `{"limit":5000}`},
		{"leaderboard", `{"kind":"../../channels/me"}`},
	} {
		if _, err := call(m, c.action, c.in); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	f.mu.Lock()
	if f.calls != before {
		t.Fatalf("bad input reached the server (%d calls)", f.calls-before)
	}
	f.mu.Unlock()
}

func TestStreamElementsBadToken(t *testing.T) {
	m, _ := setup(t, "eyJhbGciOiJIUzI1NiJ9.eyJ3cm9uZyI6MX0.d3Jvbmc")
	if h := m.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "refused the JWT") {
		t.Fatalf("health %+v", h)
	}
	_, err := call(m, "commands", `{}`)
	if !rest.IsStatus(err, 401) {
		t.Fatalf("want a 401, got %v", err)
	}
	// Something that isn't a JWT (the overlay token, say) is never sent.
	m2, f2 := setup(t, "not-a-jwt-overlay-token")
	if _, err := call(m2, "commands", `{}`); err == nil || f2.calls != 0 {
		t.Fatalf("non-JWT sent: %v %d", err, f2.calls)
	}
}

func TestStreamElementsCrossHostRedirect(t *testing.T) {
	var mu sync.Mutex
	stolen := false
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { mu.Lock(); stolen = true; mu.Unlock() }))
	defer other.Close()
	m, f := setup(t, jwt)
	f.redirect = other.URL + "/x"
	_, err := call(m, "commands", `{}`)
	mu.Lock()
	defer mu.Unlock()
	if !errors.Is(err, rest.ErrCrossHostRedirect) || stolen {
		t.Fatalf("redirect followed: %v %v", err, stolen)
	}
}

func TestStreamElementsSettings(t *testing.T) {
	m := New()
	for _, raw := range []string{
		`{"token":"` + jwt + `"}`,
		`{"token":"secret://se","channelId":"../me"}`,
		`{}`,
	} {
		if err := m.Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
