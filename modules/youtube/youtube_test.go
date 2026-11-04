package youtube

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
	vidMine  = "aaaaaaaaaaa"
	vidOther = "bbbbbbbbbbb"
)

type fakeYT struct {
	mu       sync.Mutex
	title    string
	desc     string
	calls    int
	tokens   int
	puts     []map[string]any
	redirect string
}

func (f *fakeYT) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/token" {
		_ = r.ParseForm()
		if r.Form.Get("client_secret") != "cs" || r.Form.Get("refresh_token") != "rt" || r.Form.Get("grant_type") != "refresh_token" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`)
			return
		}
		f.tokens++
		io.WriteString(w, `{"access_token":"at","expires_in":3599}`)
		return
	}
	f.calls++
	if r.Header.Get("Authorization") != "Bearer at" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":401,"message":"Invalid Credentials"}}`)
		return
	}
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	q := r.URL.Query()
	switch r.Method + " " + r.URL.Path {
	case "GET /yt/channels":
		if q.Get("mine") != "true" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"items":[{"id":"UCme","snippet":{"title":"My Channel","customUrl":"@me","publishedAt":"2015-01-01T00:00:00Z"},"statistics":{"viewCount":"123456","subscriberCount":"789","hiddenSubscriberCount":false,"videoCount":"42"},"contentDetails":{"relatedPlaylists":{"uploads":"UUme"}}}]}`)
	case "GET /yt/playlistItems":
		if q.Get("playlistId") != "UUme" {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"items":[{"contentDetails":{"videoId":"`+vidMine+`"}},{"contentDetails":{"videoId":"../evil"}}]}`)
	case "GET /yt/videos":
		var items []string
		for _, id := range strings.Split(q.Get("id"), ",") {
			switch id {
			case vidMine:
				t, _ := json.Marshal(f.title)
				d, _ := json.Marshal(f.desc)
				items = append(items, `{"id":"`+vidMine+`","snippet":{"channelId":"UCme","title":`+string(t)+`,"description":`+string(d)+`,"categoryId":"20","tags":["speedrun"],"publishedAt":"2026-11-01T10:00:00Z","liveBroadcastContent":"live"},"statistics":{"viewCount":"1000","likeCount":"50","commentCount":"7"},"status":{"privacyStatus":"public"},"liveStreamingDetails":{"concurrentViewers":"321"}}`)
			case vidOther:
				items = append(items, `{"id":"`+vidOther+`","snippet":{"channelId":"UCsomeoneelse","title":"Not yours","categoryId":"20"}}`)
			}
		}
		io.WriteString(w, `{"items":[`+strings.Join(items, ",")+`]}`)
	case "PUT /yt/videos":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.puts = append(f.puts, b)
		sn, _ := b["snippet"].(map[string]any)
		if q.Get("part") != "snippet" || b["id"] != vidMine || sn["categoryId"] != "20" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":{"code":400,"message":"bad update"}}`)
			return
		}
		f.title, _ = sn["title"].(string)
		f.desc, _ = sn["description"].(string)
		io.WriteString(w, `{}`)
	case "GET /yt/liveBroadcasts":
		if q.Get("broadcastStatus") == "active" {
			io.WriteString(w, `{"items":[{"id":"`+vidMine+`","snippet":{"title":"Live now","actualStartTime":"2026-11-04T18:00:00Z"},"status":{"lifeCycleStatus":"live","privacyStatus":"public"}}]}`)
			return
		}
		io.WriteString(w, `{"items":[]}`)
	case "GET /yt/commentThreads":
		if q.Get("allThreadsRelatedToChannelId") != "UCme" && q.Get("videoId") != vidMine {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"items":[{"id":"c1","snippet":{"videoId":"`+vidMine+`","totalReplyCount":2,"topLevelComment":{"snippet":{"authorDisplayName":"viewer1","textOriginal":"great run","likeCount":3,"publishedAt":"2026-11-02T00:00:00Z"}}}}]}`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, refresh string) (*Module, *fakeYT) {
	t.Helper()
	f := &fakeYT{title: "Old title", desc: "Old description"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := &Module{Base: srv.URL + "/yt", Auth: srv.URL + "/token"}
	h := fakehost.New(map[string]string{"secret://cs": "cs", "secret://rt": refresh})
	raw, _ := json.Marshal(Config{ClientID: "123-abc.apps.googleusercontent.com", ClientSecret: "secret://cs", RefreshToken: "secret://rt"})
	if err := m.Configure(context.Background(), h, "y", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func call(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "y", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestYouTube(t *testing.T) {
	m, f := setup(t, "rt")
	if h := m.Health(context.Background(), "y"); h.Status != "ok" || h.Message != "My Channel · 789 subscribers" {
		t.Fatalf("health %+v", h)
	}
	for action, want := range map[string][]string{
		"channel":       {`"subscribers":789`, `"views":123456`, `"videos":42`, `"handle":"@me"`},
		"recent_videos": {`"id":"` + vidMine + `"`, `"views":1000`, `"likes":50`, `"privacy":"public"`},
		"live":          {`"live":true`, `"viewers":321`, `"upcoming":[]`},
		"comments":      {`"author":"viewer1"`, `"text":"great run"`, `"replies":2`},
	} {
		r, err := call(m, action, `{}`, false)
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		for _, w := range want {
			if !strings.Contains(string(r.Output), w) {
				t.Fatalf("%s: want %s in %s", action, w, r.Output)
			}
		}
	}
	if r, _ := call(m, "recent_videos", `{}`, false); strings.Contains(string(r.Output), "evil") {
		t.Fatal("a malformed id was passed on")
	}

	// Dry run: preview old and new, change nothing.
	r, err := call(m, "update_video", `{"videoId":"`+vidMine+`","title":"New title"}`, true)
	if err != nil || r.Plan == nil || f.title != "Old title" || len(f.puts) != 0 {
		t.Fatalf("dry run %v %+v %q", err, r.Plan, f.title)
	}
	if !strings.Contains(string(r.Plan.Changes[0].Before), "Old title") || !strings.Contains(string(r.Plan.Changes[0].After), "New title") {
		t.Fatalf("plan %s → %s", r.Plan.Changes[0].Before, r.Plan.Changes[0].After)
	}
	r, err = call(m, "update_video", `{"videoId":"`+vidMine+`","title":"New title","description":"New text"}`, false)
	if err != nil || f.title != "New title" || f.desc != "New text" || r.Undo == nil {
		t.Fatalf("update %v %q %q", err, f.title, f.desc)
	}
	if tags, _ := f.puts[0]["snippet"].(map[string]any)["tags"].([]any); len(tags) != 1 {
		t.Fatalf("tags were dropped: %v", f.puts[0])
	}
	if _, err := call(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.title != "Old title" || f.desc != "Old description" {
		t.Fatalf("undo %v %q %q", err, f.title, f.desc)
	}
	if _, err := call(m, "update_video", `{"videoId":"`+vidOther+`","title":"Mine now"}`, false); err == nil || !strings.Contains(err.Error(), "isn't on your channel") {
		t.Fatalf("someone else's video: %v", err)
	}

	// Bad input never reaches the server.
	f.mu.Lock()
	before := f.calls
	f.mu.Unlock()
	for _, in := range []string{
		`{"videoId":"../../channels","title":"x"}`,
		`{"videoId":"` + vidMine + `","title":"<script>"}`,
		`{"videoId":"` + vidMine + `","title":"two\nlines"}`,
		`{"videoId":"` + vidMine + `","title":"   "}`,
		`{"videoId":"` + vidMine + `","title":"` + strings.Repeat("x", 101) + `"}`,
		`{"videoId":"` + vidMine + `","description":"` + strings.Repeat("x", 5001) + `"}`,
		`{"videoId":"` + vidMine + `"}`,
	} {
		if _, err := call(m, "update_video", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := call(m, "comments", `{"count":500}`, false); err == nil {
		t.Fatal("count 500 accepted")
	}
	f.mu.Lock()
	if f.calls != before {
		t.Fatalf("bad input reached the server (%d calls)", f.calls-before)
	}
	if f.tokens != 1 {
		t.Fatalf("token fetched %d times, want 1 (cached)", f.tokens)
	}
	f.mu.Unlock()
}

func TestYouTubeBadToken(t *testing.T) {
	m, f := setup(t, "revoked")
	h := m.Health(context.Background(), "y")
	if h.Status != "down" || !strings.Contains(h.Message, "expired or revoked") {
		t.Fatalf("health %+v", h)
	}
	if _, err := call(m, "channel", `{}`, false); err == nil {
		t.Fatal("call with a refused token worked")
	}
	if f.calls != 0 {
		t.Fatal("the API was called without a token")
	}
}

func TestYouTubeCrossHostRedirect(t *testing.T) {
	stolen := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { stolen = true }))
	defer other.Close()
	m, f := setup(t, "rt")
	f.redirect = other.URL + "/steal"
	_, err := call(m, "channel", `{}`, false)
	if !errors.Is(err, rest.ErrCrossHostRedirect) || stolen {
		t.Fatalf("redirect followed: %v %v", err, stolen)
	}
}

func TestYouTubeSettings(t *testing.T) {
	m := New()
	h := fakehost.New(nil)
	for _, raw := range []string{
		`{"clientId":"123-abc.apps.googleusercontent.com","clientSecret":"plain","refreshToken":"secret://rt"}`,
		`{"clientId":"123-abc.apps.googleusercontent.com","clientSecret":"secret://cs","refreshToken":"1//plain"}`,
		`{"clientId":"","clientSecret":"secret://cs","refreshToken":"secret://rt"}`,
		`{"clientId":"a b c d e f g h","clientSecret":"secret://cs","refreshToken":"secret://rt"}`,
		`not json`,
	} {
		if err := m.Configure(context.Background(), h, "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if hl := m.Health(context.Background(), "x"); hl.Status != "unconfigured" {
		t.Fatalf("%+v", hl)
	}
}
