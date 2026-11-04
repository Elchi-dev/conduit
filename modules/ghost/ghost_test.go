package ghost

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	keyID     = "6489a1b2c3d4e5f601234567"
	keySecret = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	draftID   = "650000000000000000000001"
	pubID     = "650000000000000000000002"
	newID     = "650000000000000000000003"
)

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type fake struct {
	mu    sync.Mutex
	seen  []string
	posts map[string]map[string]any
	puts  []string
}

// authOK checks the JWT the way Ghost does.
func authOK(h string) bool {
	tok, ok := strings.CutPrefix(h, "Ghost ")
	parts := strings.Split(tok, ".")
	if !ok || len(parts) != 3 {
		return false
	}
	secret, _ := hex.DecodeString(keySecret)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) != parts[2] {
		return false
	}
	var head, body map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	bb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(hb, &head)
	json.Unmarshal(bb, &body)
	return head["kid"] == keyID && head["alg"] == "HS256" && body["aud"] == "/admin/" && body["exp"].(float64)-body["iat"].(float64) <= 300 && body["iat"].(float64) == float64(now.Unix())
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !authOK(r.Header.Get("Authorization")) || r.Header.Get("Accept-Version") != "v5.0" {
		w.WriteHeader(401)
		io.WriteString(w, `{"errors":[{"message":"Invalid token: invalid signature","type":"UnauthorizedError"}]}`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/blog/ghost/api/admin")
	f.seen = append(f.seen, r.Method+" "+path)
	q := r.URL.Query()
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	enc := json.NewEncoder(w)
	switch {
	case path == "/site/":
		io.WriteString(w, `{"site":{"title":"Field Notes","version":"5.101"}}`)
	case path == "/posts/" && r.Method == "GET":
		list := []any{}
		for _, id := range []string{draftID, pubID} {
			if p := f.posts[id]; p != nil && (q.Get("filter") == "" || q.Get("filter") == "status:"+p["status"].(string)) {
				list = append(list, p)
			}
		}
		enc.Encode(map[string]any{"posts": list, "meta": map[string]any{"pagination": map[string]any{"total": len(list)}}})
	case path == "/posts/" && r.Method == "POST":
		if q.Get("source") != "html" {
			w.WriteHeader(400)
			return
		}
		np := body["posts"].([]any)[0].(map[string]any)
		np["id"], np["updated_at"] = newID, "2026-11-04T12:00:00.000Z"
		f.posts[newID] = np
		enc.Encode(map[string]any{"posts": []any{np}})
	case strings.HasPrefix(path, "/posts/"):
		id := strings.Trim(strings.TrimPrefix(path, "/posts/"), "/")
		p := f.posts[id]
		if p == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"errors":[{"message":"Post not found."}]}`)
			return
		}
		switch r.Method {
		case "GET":
			enc.Encode(map[string]any{"posts": []any{p}})
		case "PUT":
			up := body["posts"].([]any)[0].(map[string]any)
			if up["updated_at"] != p["updated_at"] {
				w.WriteHeader(409)
				io.WriteString(w, `{"errors":[{"message":"Saving failed! Someone else is editing this post."}]}`)
				return
			}
			f.puts = append(f.puts, id+" "+up["status"].(string)+" newsletter="+q.Get("newsletter")+" segment="+q.Get("email_segment"))
			p["status"] = up["status"]
			p["updated_at"] = "2026-11-04T12:01:00.000Z"
			enc.Encode(map[string]any{"posts": []any{p}})
		case "DELETE":
			delete(f.posts, id)
			w.WriteHeader(204)
		}
	case path == "/newsletters/":
		if q.Get("filter") == "slug:weekly" || q.Get("filter") == "status:active" {
			io.WriteString(w, `{"newsletters":[{"id":"n1","name":"Weekly","slug":"weekly","status":"active","count":{"members":42}}]}`)
			return
		}
		io.WriteString(w, `{"newsletters":[]}`)
	case path == "/members/":
		total := map[string]int{"": 50, "status:free": 40, "status:paid": 8, "status:comped": 2, "newsletters.slug:weekly": 42, "newsletters.slug:weekly+status:-free": 7}[q.Get("filter")]
		if q.Get("limit") != "1" {
			io.WriteString(w, `{"members":[{"name":"Ana","email":"ana@example.com","status":"paid","newsletters":[{}]}]}`)
			return
		}
		enc.Encode(map[string]any{"members": []any{}, "meta": map[string]any{"pagination": map[string]any{"total": total}}})
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, key string) (*Module, *fake) {
	f := &fake{posts: map[string]map[string]any{
		draftID: {"id": draftID, "title": "Draft one", "status": "draft", "visibility": "public", "updated_at": "2026-11-01T10:00:00.000Z"},
		pubID:   {"id": pubID, "title": "Hello world", "status": "published", "visibility": "public", "url": "https://blog.example.com/hello/", "updated_at": "2026-10-01T10:00:00.000Z", "email": map[string]any{"status": "submitted", "email_count": 40}},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Now = func() time.Time { return now }
	raw, _ := json.Marshal(Config{URL: srv.URL + "/blog/ghost/", AdminKey: "secret://gh"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://gh": key}), "g", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "g", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestGhost(t *testing.T) {
	m, f := setup(t, keyID+":"+keySecret)
	if h := m.Health(context.Background(), "g"); h.Status != "ok" || h.Message != "Field Notes (Ghost 5.101)" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "posts", `{"status":"published"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"url":"https://blog.example.com/hello/"`) || strings.Contains(string(r.Output), "Draft one") {
		t.Fatalf("%s %v", r.Output, err)
	}

	r, err = invoke(m, "create_draft", `{"title":"New post","html":"<p>hi</p>","tags":["news"]}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_post" || f.posts[newID]["status"] != "draft" || f.posts[newID]["html"] != "<p>hi</p>" {
		t.Fatalf("%+v %v", r, err)
	}
	p, err := invoke(m, "delete_post", string(r.Undo.Input), true)
	if err != nil || !strings.Contains(p.Plan.Summary, `the draft post "New post"`) {
		t.Fatal(p.Plan, err)
	}
	if _, err := invoke(m, "delete_post", string(r.Undo.Input), false); err != nil || f.posts[newID] != nil {
		t.Fatal(err)
	}

	// Publishing previews say whether an email goes out.
	p, err = invoke(m, "publish", `{"post":"`+draftID+`"}`, true)
	if err != nil || !strings.Contains(p.Plan.Summary, "No email is sent") {
		t.Fatal(p.Plan, err)
	}
	p, err = invoke(m, "publish", `{"post":"`+draftID+`","newsletter":"weekly","segment":"paid"}`, true)
	if err != nil || !strings.Contains(p.Plan.Summary, `email it with the newsletter "Weekly" to 7 paid subscribers`) || len(f.puts) != 0 {
		t.Fatal(p.Plan, err)
	}
	r, err = invoke(m, "publish", `{"post":"`+draftID+`","newsletter":"weekly"}`, false)
	if err != nil || f.puts[0] != draftID+" published newsletter=weekly segment=all" || !strings.Contains(string(r.Output), `"emailed":true`) {
		t.Fatal(f.puts, err)
	}
	if _, err := invoke(m, "publish", `{"post":"`+draftID+`"}`, false); err == nil {
		t.Fatal("published twice")
	}

	// Unpublish, and undo republishes without email.
	p, err = invoke(m, "unpublish", `{"post":"`+pubID+`"}`, true)
	if err != nil || !strings.Contains(p.Plan.Summary, "https://blog.example.com/hello/ stops working") {
		t.Fatal(p.Plan, err)
	}
	r, err = invoke(m, "unpublish", `{"post":"`+pubID+`"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "publish" || f.puts[1] != pubID+" draft newsletter= segment=" {
		t.Fatal(r, err, f.puts)
	}
	if _, err := invoke(m, "publish", `{"post":"`+pubID+`","newsletter":"weekly"}`, false); err == nil || !strings.Contains(err.Error(), "already emailed") {
		t.Fatal("re-emailed a post", err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.puts[2] != pubID+" published newsletter= segment=" {
		t.Fatal(err, f.puts)
	}

	r, err = invoke(m, "newsletters", `{}`, false)
	if err != nil || string(r.Output) != `[{"name":"Weekly","slug":"weekly","subscribers":42}]` {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "members_count", `{}`, false)
	if err != nil || string(r.Output) != `{"all":50,"comped":2,"free":40,"paid":8}` {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "members", `{"status":"paid"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"email":"ana@example.com"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
}

func TestGhostValidation(t *testing.T) {
	m, f := setup(t, keyID+":"+keySecret)
	for _, c := range [][2]string{
		{"publish", `{"post":"../settings"}`},
		{"publish", `{"post":"` + draftID + `?x=1"}`},
		{"unpublish", `{"post":"abc"}`},
		{"delete_post", `{"post":""}`},
		{"create_draft", `{"title":""}`},
		{"create_draft", `{"title":"x","visibility":"everyone"}`},
		{"create_draft", `{"title":"x","tags":["a,b"]}`},
		{"posts", `{"status":"deleted"}`},
		{"members", `{"status":"all"}`},
	} {
		if _, err := invoke(m, c[0], c[1], false); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
	if len(f.seen) != 0 {
		t.Fatal("bad input reached the server:", f.seen)
	}
	// A bad newsletter or segment is refused before anything is published.
	for _, in := range []string{`{"post":"` + draftID + `","newsletter":"Weekly News"}`, `{"post":"` + draftID + `","newsletter":"monthly"}`, `{"post":"` + draftID + `","segment":"vip"}`} {
		if _, err := invoke(m, "publish", in, false); err == nil || len(f.puts) != 0 {
			t.Fatal("accepted", in)
		}
	}
	for _, c := range []Config{
		{URL: "https://blog.example.com", AdminKey: keyID + ":" + keySecret},
		{URL: "https://blog.example.com/?x=1", AdminKey: "secret://gh"},
		{URL: "ftp://blog.example.com", AdminKey: "secret://gh"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	for _, key := range []string{"contentkey0123456789abcdef", keyID + ":" + strings.Repeat("0", 64)} {
		bad, bf := setup(t, key)
		if h := bad.Health(context.Background(), "g"); h.Status != "down" || strings.Contains(h.Message, key) {
			t.Fatalf("%+v", h)
		}
		if strings.HasPrefix(key, "content") && len(bf.seen) != 0 {
			t.Fatal("a malformed key was sent")
		}
	}
}

func TestGhostRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, AdminKey: "secret://gh"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://gh": keyID + ":" + keySecret}), "g", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "g"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
