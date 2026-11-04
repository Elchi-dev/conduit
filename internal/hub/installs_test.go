package hub

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestIPBucket(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":          "203.0.113.7",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
		"::ffff:203.0.113.7":   "::ffff:203.0.113.7",
		"not-an-address":       "not-an-address",
	} {
		if got := ipBucket(in); got != want {
			t.Errorf("ipBucket(%q) = %q, want %q", in, got, want)
		}
	}
}

// One source can't inflate a package's counts with made-up daemon ids, and
// an IPv6 client can't get around that by changing its address in its /64.
func TestInstallPingsCappedPerSource(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.TrustProxy = true })
	evil := newPublisher(h, "e@example.com", "evil")
	good := newPublisher(h, "g@example.com", "good")
	good.publish("weather", "1.0.0", "Forecasts weather")
	w := evil.publish("weather", "1.0.0", "Forecasts weather")
	ping := func(from, name, daemon, event string) bool {
		b, _ := json.Marshal(map[string]string{"name": name, "version": "1.0.0", "event": event, "daemon": daemon})
		req, _ := http.NewRequest("POST", h.ts.URL+"/v1/registry/installs", bytes.NewReader(b))
		req.Header.Set("X-Forwarded-For", from)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]bool
		_ = json.NewDecoder(res.Body).Decode(&out)
		if res.StatusCode != 202 {
			t.Fatalf("ping %d", res.StatusCode)
		}
		return out["counted"]
	}
	for i := 0; i < 50; i++ {
		ping("198.51.100.1", "evil/weather", fmt.Sprintf("fake%020d", i), "install")
		ping(fmt.Sprintf("2001:db8:aa:bb::%x", i+1), "evil/weather", fmt.Sprintf("six%020d", i), "install")
	}
	p := h.do("GET", "/v1/registry/packages/"+w, "", nil, 200)["package"].(map[string]any)
	if p["installs"] != 6.0 || p["downloads"] != 6.0 {
		t.Fatalf("installs %v downloads %v, want 3 per source", p["installs"], p["downloads"])
	}
	// Daemons already counted keep sending heartbeats and uninstalls.
	if !ping("198.51.100.1", "evil/weather", fmt.Sprintf("fake%020d", 0), "heartbeat") {
		t.Fatal("a known daemon's heartbeat wasn't counted")
	}
	ping("198.51.100.1", "evil/weather", fmt.Sprintf("fake%020d", 1), "uninstall")
	p = h.do("GET", "/v1/registry/packages/"+w, "", nil, 200)["package"].(map[string]any)
	if p["installs"] != 5.0 {
		t.Fatalf("after an uninstall %v", p["installs"])
	}
	// The cap is per package: the same source can still count elsewhere,
	// and other sources aren't affected.
	if !ping("198.51.100.1", "good/weather", "realdaemon000000000000", "install") || !ping("198.51.100.2", "evil/weather", "otherdaemon00000000000", "install") {
		t.Fatal("an honest install wasn't counted")
	}
}

// Relevance ties go to the order of magnitude of installs, then rating,
// not to the raw count.
func TestRelevanceNotDominatedByRawInstalls(t *testing.T) {
	h := newHarness(t, nil)
	a := newPublisher(h, "a@example.com", "aaa")
	b := newPublisher(h, "b@example.com", "bbb")
	a.publish("weather", "1.0.0", "Forecasts weather")
	b.publish("weather", "1.0.0", "Forecasts weather")
	ctx := t.Context()
	h.srv.db.Exec(ctx, `UPDATE registry_packages SET installs = 9, rating_sum = 0, rating_count = 0 WHERE name = 'aaa/weather'`)
	h.srv.db.Exec(ctx, `UPDATE registry_packages SET installs = 2, rating_sum = 50, rating_count = 10 WHERE name = 'bbb/weather'`)
	if got := names(h.do("GET", "/v1/registry/packages?q=weather", "", nil, 200)["items"].([]any)); got[0] != "bbb/weather" {
		t.Fatalf("same tier: the better rated one first, got %v", got)
	}
	h.srv.db.Exec(ctx, `UPDATE registry_packages SET installs = 150 WHERE name = 'aaa/weather'`)
	if got := names(h.do("GET", "/v1/registry/packages?q=weather", "", nil, 200)["items"].([]any)); got[0] != "aaa/weather" {
		t.Fatalf("a higher tier wins the tie, got %v", got)
	}
}
