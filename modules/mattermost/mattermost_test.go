package mattermost

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

const (
	teamID = "tttttttttttttttttttttttttt"
	chanID = "cccccccccccccccccccccccccc"
	kimID  = "kkkkkkkkkkkkkkkkkkkkkkkkkk"
	samID  = "ssssssssssssssssssssssssss"
	postID = "pppppppppppppppppppppppppp"
)

type fakeMM struct {
	mu    sync.Mutex
	seen  []string
	posts map[string]string
}

func (f *fakeMM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer mmtok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"id":"api.context.session_expired.app_error","message":"Invalid or expired session, please login again.","status_code":401}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	switch r.Method + " " + r.URL.Path {
	case "GET /api/v4/users/me":
		io.WriteString(w, `{"id":"`+kimID+`","username":"kim"}`)
	case "GET /api/v4/teams/name/eng":
		io.WriteString(w, `{"id":"`+teamID+`","name":"eng","display_name":"Engineering"}`)
	case "GET /api/v4/users/me/teams":
		io.WriteString(w, `[{"id":"`+teamID+`","name":"eng"}]`)
	case "GET /api/v4/users/me/teams/" + teamID + "/channels":
		io.WriteString(w, `[{"id":"`+chanID+`","name":"town-square","display_name":"Town Square","type":"O","last_post_at":1800000000000},{"id":"d1","name":"a__b","type":"D"}]`)
	case "GET /api/v4/teams/" + teamID + "/channels/name/town-square":
		io.WriteString(w, `{"id":"`+chanID+`","name":"town-square","team_id":"`+teamID+`","type":"O"}`)
	case "GET /api/v4/channels/" + chanID:
		io.WriteString(w, `{"id":"`+chanID+`","name":"town-square","type":"O"}`)
	case "GET /api/v4/channels/" + chanID + "/posts":
		if r.URL.Query().Get("per_page") != "30" {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `{"order":["p2","p1"],"posts":{"p1":{"id":"p1","user_id":"`+samID+`","message":"deploy done","create_at":1800000000000},"p2":{"id":"p2","user_id":"`+kimID+`","message":"thanks","root_id":"p1","create_at":1800000060000}}}`)
	case "POST /api/v4/users/ids":
		io.WriteString(w, `[{"id":"`+kimID+`","username":"kim"},{"id":"`+samID+`","username":"sam"}]`)
	case "POST /api/v4/users/usernames":
		io.WriteString(w, `[{"id":"`+samID+`","username":"sam"}]`)
	case "GET /api/v4/users":
		if r.URL.Query().Get("in_team") != teamID {
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, `[{"id":"`+kimID+`","username":"kim"},{"id":"`+samID+`","username":"sam"}]`)
	case "POST /api/v4/users/status/ids":
		io.WriteString(w, `[{"user_id":"`+kimID+`","status":"offline"},{"user_id":"`+samID+`","status":"online","last_activity_at":1800000000000}]`)
	case "POST /api/v4/posts":
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		f.posts[postID] = in["message"]
		fmt.Fprintf(w, `{"id":%q,"channel_id":%q,"message":%q,"create_at":1800000000000}`, postID, in["channel_id"], in["message"])
	case "GET /api/v4/posts/" + postID:
		msg, ok := f.posts[postID]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Unable to find the existing post."}`)
			return
		}
		fmt.Fprintf(w, `{"id":%q,"user_id":%q,"message":%q,"create_at":1800000000000}`, postID, kimID, msg)
	case "DELETE /api/v4/posts/" + postID:
		delete(f.posts, postID)
		io.WriteString(w, `{"status":"OK"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"not found"}`)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeMM) {
	t.Helper()
	f := &fakeMM{posts: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.HTTP = srv.Client()
	cfg.URL = srv.URL + "/"
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mm": "mmtok", "secret://bad": "x"}), "mm", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "mm", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestMattermost(t *testing.T) {
	m, f := setup(t, Config{Token: "secret://mm", Team: "eng"})
	if h := m.Health(context.Background(), "mm"); h.Status != "ok" || h.Message != "signed in as kim" {
		t.Fatalf("%+v", h)
	}
	r, err := invoke(m, "channels", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"name":"town-square"`) || strings.Contains(string(r.Output), "a__b") {
		t.Fatalf("%s %v", r.Output, err)
	}
	for _, ch := range []string{"town-square", "eng/town-square", "~town-square", chanID} {
		r, err = invoke(m, "posts", `{"channel":"`+ch+`"}`, false)
		if err != nil || !strings.Contains(string(r.Output), `"message":"deploy done","user":"sam"`) || !strings.Contains(string(r.Output), `"rootId":"p1"`) {
			t.Fatalf("%s: %s %v", ch, r.Output, err)
		}
	}
	r, err = invoke(m, "statuses", `{}`, false)
	if err != nil || !strings.HasPrefix(string(r.Output), `[{"lastActivity":"2027-01-15T08:00:00Z","manual":false,"status":"online","user":"sam"}`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	if r, err = invoke(m, "statuses", `{"users":["@sam"]}`, false); err != nil || !strings.Contains(string(r.Output), `"user":"sam"`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	r, err = invoke(m, "post_message", `{"channel":"town-square","message":"hello"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Post in ~town-square" || len(f.posts) != 0 {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "post_message", `{"channel":"town-square","message":"hello"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_post" || f.posts[postID] != "hello" {
		t.Fatalf("%+v %v", r, err)
	}
	p, err := invoke(m, "delete_post", string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || !strings.HasPrefix(p.Plan.Summary, "Delete kim's post") || f.posts[postID] == "" {
		t.Fatalf("dry %+v %v", p.Plan, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.posts) != 0 {
		t.Fatal("not deleted", err)
	}
}

func TestMattermostValidation(t *testing.T) {
	m, f := setup(t, Config{Token: "secret://mm"})
	for _, in := range []string{
		`{"channel":"town-square","message":"x"}`, // no default team
		`{"channel":"eng/../users","message":"x"}`,
		`{"channel":"../../users/me/x","message":"x"}`,
		`{"channel":"eng/Town Square","message":"x"}`,
		`{"channel":"eng/town-square","message":"  "}`,
		`{"channel":"eng/town-square","message":"x","rootId":"../x"}`,
	} {
		if _, err := invoke(m, "post_message", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if _, err := invoke(m, "delete_post", `{"postId":"../users/me"}`, false); err == nil {
		t.Fatal("accepted post id")
	}
	if _, err := invoke(m, "statuses", `{"users":["a/b"]}`, false); err == nil {
		t.Fatal("accepted user name")
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://chat", Token: "plain"}, {URL: "chat.example.com", Token: "secret://mm"}, {URL: "https://chat", Token: "secret://mm", Team: "a/b"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, Config{Token: "secret://bad"})
	if h := bad.Health(context.Background(), "mm"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestMattermostRefusesRedirect(t *testing.T) {
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://mm"})
	_ = m.Configure(context.Background(), fakehost.New(map[string]string{"secret://mm": "mmtok"}), "mm", raw)
	if h := m.Health(context.Background(), "mm"); h.Status != "down" || leaked != "" {
		t.Fatalf("%+v %q", h, leaked)
	}
}
