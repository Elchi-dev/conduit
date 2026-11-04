package bluesky

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	appPw  = "abcd-efgh-ijkl-mnop"
	me     = "did:plc:me123"
	bob    = "did:plc:bob456"
	bobURI = "at://did:plc:bob456/app.bsky.feed.post/3kbob"
)

type fake struct {
	mu      sync.Mutex
	seen    []string
	logins  int
	valid   map[string]bool // access tokens accepted
	records map[string]map[string]any
	created []map[string]any
}

func newFake() *fake {
	return &fake{valid: map[string]bool{}, records: map[string]map[string]any{}}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	nsid := strings.TrimPrefix(r.URL.Path, "/xrpc/")
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	enc := json.NewEncoder(w)
	fail := func(code int, e, msg string) {
		w.WriteHeader(code)
		enc.Encode(map[string]string{"error": e, "message": msg})
	}
	switch nsid {
	case "com.atproto.server.createSession":
		f.logins++
		if body["identifier"] != "me.bsky.social" || body["password"] != appPw {
			fail(401, "AuthenticationRequired", "Invalid identifier or password")
			return
		}
		f.valid["acc1"] = true
		enc.Encode(map[string]string{"accessJwt": "acc1", "refreshJwt": "ref1", "did": me, "handle": "me.bsky.social"})
		return
	case "com.atproto.server.refreshSession":
		if r.Header.Get("Authorization") != "Bearer ref1" {
			fail(400, "ExpiredToken", "Token has expired")
			return
		}
		f.valid["acc2"] = true
		enc.Encode(map[string]string{"accessJwt": "acc2", "refreshJwt": "ref2", "did": me, "handle": "me.bsky.social"})
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !f.valid[tok] {
		fail(400, "ExpiredToken", "Token has expired")
		return
	}
	f.seen = append(f.seen, nsid)
	q := r.URL.Query()
	switch nsid {
	case "com.atproto.server.getSession":
		enc.Encode(map[string]string{"did": me, "handle": "me.bsky.social"})
	case "app.bsky.actor.getProfile":
		enc.Encode(map[string]any{"did": q.Get("actor"), "handle": "me.bsky.social", "displayName": "Me", "followersCount": 12, "postsCount": 3})
	case "app.bsky.feed.getTimeline":
		io.WriteString(w, `{"feed":[{"post":{"uri":"`+bobURI+`","cid":"bafybob1","author":{"did":"`+bob+`","handle":"bob.test"},"record":{"text":"hi all","createdAt":"2026-11-04T10:00:00Z"},"likeCount":4}},
			{"post":{"uri":"at://did:plc:x/app.bsky.feed.post/1","cid":"bafyx","author":{"handle":"x.test"},"record":{"text":"boosted"}},"reason":{"$type":"app.bsky.feed.defs#reasonRepost","by":{"handle":"bob.test"}}}]}`)
	case "app.bsky.notification.listNotifications":
		io.WriteString(w, `{"notifications":[{"uri":"at://x","reason":"mention","author":{"handle":"bob.test"},"record":{"text":"@me.bsky.social hey"},"indexedAt":"2026-11-04T10:00:00Z"}]}`)
	case "com.atproto.identity.resolveHandle":
		if q.Get("handle") == "bob.test" {
			enc.Encode(map[string]string{"did": bob})
			return
		}
		fail(400, "InvalidRequest", "Unable to resolve handle")
	case "app.bsky.feed.getPosts":
		uri := q.Get("uris")
		switch {
		case uri == bobURI:
			io.WriteString(w, `{"posts":[{"uri":"`+bobURI+`","cid":"bafybob1","author":{"did":"`+bob+`","handle":"bob.test"},"record":{"text":"hi all","reply":{"root":{"uri":"at://did:plc:root/app.bsky.feed.post/r","cid":"bafyroot"},"parent":{"uri":"at://did:plc:root/app.bsky.feed.post/r","cid":"bafyroot"}}}}]}`)
		case f.records[uri] != nil:
			enc.Encode(map[string]any{"posts": []any{map[string]any{"uri": uri, "cid": "bafymine", "author": map[string]any{"did": me, "handle": "me.bsky.social"}, "record": f.records[uri], "likeCount": 2}}})
		default:
			io.WriteString(w, `{"posts":[]}`)
		}
	case "com.atproto.repo.createRecord":
		if body["repo"] != me || body["collection"] != "app.bsky.feed.post" {
			fail(400, "InvalidRequest", "bad repo")
			return
		}
		rec := body["record"].(map[string]any)
		uri := "at://" + me + "/app.bsky.feed.post/3kmine"
		f.records[uri] = rec
		f.created = append(f.created, rec)
		enc.Encode(map[string]string{"uri": uri, "cid": "bafymine"})
	case "com.atproto.repo.deleteRecord":
		uri := "at://" + body["repo"].(string) + "/app.bsky.feed.post/" + body["rkey"].(string)
		delete(f.records, uri)
		io.WriteString(w, `{}`)
	case "app.bsky.feed.searchPosts":
		if q.Get("q") != "conduit" || q.Get("sort") != "top" {
			fail(400, "InvalidRequest", "bad query")
			return
		}
		io.WriteString(w, `{"posts":[{"uri":"`+bobURI+`","cid":"bafybob1","author":{"handle":"bob.test"},"record":{"text":"conduit is neat"}}]}`)
	default:
		fail(404, "MethodNotImplemented", "no")
	}
}

func setup(t *testing.T, pw string) (*Module, *fake) {
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{Service: srv.URL, Identifier: "@me.bsky.social", Password: "secret://bs"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bs": pw}), "b", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestBluesky(t *testing.T) {
	m, f := setup(t, appPw)
	if h := m.Health(context.Background(), "b"); h.Status != "ok" || h.Message != "@me.bsky.social" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "profile", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"did":"`+me+`"`) || !strings.Contains(string(r.Output), `"followers":12`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "timeline", `{"limit":5}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"url":"https://bsky.app/profile/bob.test/post/3kbob"`) || !strings.Contains(string(r.Output), `"repostedBy":"bob.test"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "notifications", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"type":"mention"`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// Dry run: nothing is created.
	p, err := invoke(m, "post", `{"text":"hello"}`, true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, "Post publicly") || len(f.created) != 0 {
		t.Fatalf("%+v %v", p.Plan, err)
	}

	text := "héllo @bob.test and @nobody.test see https://example.com/a?b=1. #conduit 👍🏽"
	r, err = invoke(m, "post", `{"text":`+string(must(json.Marshal(text)))+`,"langs":["en"]}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete" {
		t.Fatalf("%+v %v", r, err)
	}
	rec := f.created[0]
	if rec["text"] != text || rec["createdAt"] != "2026-11-04T12:00:00.000Z" {
		t.Fatal(rec)
	}
	fs, _ := json.Marshal(rec["facets"])
	// "héllo " is 7 bytes, so @bob.test spans bytes 7-16.
	for _, want := range []string{
		`{"features":[{"$type":"app.bsky.richtext.facet#mention","did":"did:plc:bob456"}],"index":{"byteEnd":16,"byteStart":7}}`,
		`"uri":"https://example.com/a?b=1"`,
		`"tag":"conduit"`,
	} {
		if !strings.Contains(string(fs), want) {
			t.Fatalf("missing %s in %s", want, fs)
		}
	}
	if strings.Contains(string(fs), "nobody") {
		t.Fatal("unresolved mention got a facet", string(fs))
	}

	// Undo: preview, then delete.
	p, err = invoke(m, "delete", string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, "héllo") || len(f.records) != 1 {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := invoke(m, "delete", string(r.Undo.Input), false); err != nil || len(f.records) != 0 {
		t.Fatal(err, f.records)
	}

	// Reply threads under the parent's root.
	r, err = invoke(m, "reply", `{"uri":"`+bobURI+`","text":"agreed"}`, false)
	if err != nil || r.Undo == nil {
		t.Fatal(err)
	}
	reply, _ := json.Marshal(f.created[1]["reply"])
	if !strings.Contains(string(reply), `"root":{"cid":"bafyroot","uri":"at://did:plc:root/app.bsky.feed.post/r"}`) || !strings.Contains(string(reply), `"parent":{"cid":"bafybob1","uri":"`+bobURI+`"}`) {
		t.Fatal(string(reply))
	}

	r, err = invoke(m, "search", `{"query":"conduit","sort":"top"}`, false)
	if err != nil || !strings.Contains(string(r.Output), "conduit is neat") {
		t.Fatalf("%s %v", r.Output, err)
	}

	// An expired access token is refreshed, without a new login.
	f.mu.Lock()
	delete(f.valid, "acc1")
	logins := f.logins
	f.mu.Unlock()
	if _, err := invoke(m, "timeline", `{}`, false); err != nil || f.logins != logins {
		t.Fatal(err, f.logins)
	}
}

func must(b []byte, _ error) []byte { return b }

func TestBlueskyValidation(t *testing.T) {
	m, f := setup(t, appPw)
	long := strings.Repeat("a", 301)
	for _, c := range [][2]string{
		{"post", `{"text":""}`},
		{"post", `{"text":"` + long + `"}`},
		{"post", `{"text":"x","langs":["en;drop"]}`},
		{"reply", `{"uri":"https://bsky.app/x","text":"x"}`},
		{"reply", `{"uri":"at://did:plc:a/app.bsky.feed.post/../x","text":"x"}`},
		{"delete", `{"uri":"at://did:plc:a/app.bsky.feed.like/1"}`},
		{"delete", `{"uri":"` + bobURI + `"}`}, // not ours
		{"profile", `{"actor":"../../x"}`},
		{"search", `{"query":""}`},
		{"search", `{"query":"x","sort":"random"}`},
	} {
		if _, err := invoke(m, c[0], c[1], false); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
	for _, s := range f.seen {
		if s != "com.atproto.server.getSession" {
			t.Fatal("bad input reached the server:", f.seen)
		}
	}
	// 300 graphemes of combined emoji and flags fit.
	ok := strings.Repeat("👍🏽", 150) + strings.Repeat("🇩🇪", 150)
	if n := graphemes(ok); n != 300 {
		t.Fatal(n)
	}
	if n := graphemes("é👨‍👩‍👧\r\n"); n != 3 {
		t.Fatal(n)
	}
	for _, c := range []Config{
		{Identifier: "me.bsky.social", Password: "abcd-efgh-ijkl-mnop"},
		{Service: "https://bsky.social/xrpc", Identifier: "me.bsky.social", Password: "secret://bs"},
		{Service: "ftp://bsky.social", Identifier: "me.bsky.social", Password: "secret://bs"},
		{Identifier: "", Password: "secret://bs"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	raw, _ := json.Marshal(Config{Identifier: "me.bsky.social", Password: "secret://bs"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err != nil {
		t.Fatal("default service refused", err)
	}
}

func TestBlueskyRefusesPasswords(t *testing.T) {
	// A main password is refused before it is sent.
	m, f := setup(t, "hunter2-main-password")
	if h := m.Health(context.Background(), "b"); h.Status != "down" || !strings.Contains(h.Message, "app password") || f.logins != 0 {
		t.Fatalf("%+v %d", h, f.logins)
	}
	// A wrong app password is refused by the server.
	m, _ = setup(t, "zzzz-zzzz-zzzz-zzzz")
	if h := m.Health(context.Background(), "b"); h.Status != "down" || strings.Contains(h.Message, "zzzz") {
		t.Fatalf("%+v", h)
	}
}

func TestBlueskyRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{Service: srv.URL, Identifier: "me.bsky.social", Password: "secret://bs"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bs": appPw}), "b", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "b"); h.Status != "down" || hit || strings.Contains(h.Message, appPw) {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
