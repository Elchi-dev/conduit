package jellyfin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestJellyfin(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Emby-Token") != "key" {
			w.WriteHeader(401)
			return
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "GET /System/Info":
			io.WriteString(w, `{"ServerName":"den","Version":"10.10.3"}`)
		case "GET /Library/VirtualFolders":
			io.WriteString(w, `[{"Name":"Movies","CollectionType":"movies","Locations":["/media/movies"]}]`)
		case "GET /Items":
			if r.URL.Query().Get("SortBy") != "DateCreated" {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"Items":[{"Name":"Pilot","Type":"Episode","SeriesName":"Severance","DateCreated":"2026-11-02T10:00:00Z"}]}`)
		case "GET /Sessions":
			io.WriteString(w, `[{"Id":"abc-123","UserName":"kim","Client":"Android TV","DeviceName":"Living room","NowPlayingItem":{"Name":"Dune","Type":"Movie","RunTimeTicks":1000},"PlayState":{"IsPaused":false,"PositionTicks":250}}]`)
		case "POST /Library/Refresh", "POST /Sessions/abc-123/Message", "POST /Sessions/abc-123/Playing/Stop":
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	h := fakehost.New(map[string]string{"secret://jf": "key"})
	cfg, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://jf"})
	if err := m.Configure(ctx, h, "j", cfg); err != nil {
		t.Fatal(err)
	}
	call := func(a, in string) (sdk.Result, error) {
		return m.Invoke(ctx, sdk.Call{Instance: "j", Action: a, Input: json.RawMessage(in)})
	}
	if hl := m.Health(ctx, "j"); hl.Status != "ok" || hl.Message != "den 10.10.3" {
		t.Fatalf("health %+v", hl)
	}
	r, err := call("sessions", `{}`)
	if err != nil || !strings.Contains(string(r.Output), `"progressPercent":25`) || !strings.Contains(string(r.Output), `"playing":"Dune"`) {
		t.Fatalf("sessions %s %v", r.Output, err)
	}
	r, err = call("recent", `{}`)
	if err != nil || !strings.Contains(string(r.Output), "Severance: Pilot") {
		t.Fatalf("recent %s %v", r.Output, err)
	}
	if _, err := call("libraries", `{}`); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"scan"} {
		if _, err := call(a, `{}`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := call("message", `{"session":"abc-123","text":"Dinner's ready"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := call("stop", `{"session":"abc-123"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := call("stop", `{"session":"../System/Shutdown"}`); err == nil {
		t.Fatal("path in session id accepted")
	}
	if !strings.Contains(strings.Join(calls, ","), "POST /Sessions/abc-123/Playing/Stop") {
		t.Fatalf("calls %v", calls)
	}
	if err := m.Configure(ctx, h, "x", json.RawMessage(`{"url":"ftp://x","apiKey":"secret://jf"}`)); err == nil {
		t.Fatal("bad url accepted")
	}
	if err := m.Configure(ctx, h, "x", json.RawMessage(`{"url":"http://x","apiKey":"plain"}`)); err == nil {
		t.Fatal("plaintext key accepted")
	}
}
