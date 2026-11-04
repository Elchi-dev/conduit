package trello

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
	key    = "0123456789abcdef0123456789abcdef"
	board1 = "aaaaaaaaaaaaaaaaaaaaaaaa"
	board2 = "bbbbbbbbbbbbbbbbbbbbbbbb"
	todo   = "111111111111111111111111"
	doing  = "222222222222222222222222"
	other  = "333333333333333333333333" // on board2
	card1  = "c00000000000000000000001"
)

type fakeTrello struct {
	mu    sync.Mutex
	seen  []string
	cards map[string]map[string]any
}

func (f *fakeTrello) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != `OAuth oauth_consumer_key="`+key+`", oauth_token="trtok"` || r.URL.Query().Get("token") != "" {
		w.WriteHeader(401)
		io.WriteString(w, "invalid token")
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	lists := map[string]map[string]any{
		todo:  {"id": todo, "name": "To do", "idBoard": board1},
		doing: {"id": doing, "name": "Doing", "idBoard": board1},
		other: {"id": other, "name": "Inbox", "idBoard": board2},
	}
	open := func() []any {
		var out []any
		for _, c := range f.cards {
			if c["closed"] != true {
				out = append(out, c)
			}
		}
		return out
	}
	p := r.URL.Path
	switch {
	case r.Method == "GET" && p == "/members/me":
		io.WriteString(w, `{"username":"elchi"}`)
	case r.Method == "GET" && p == "/members/me/boards":
		if r.URL.Query().Get("cards") == "open" {
			enc.Encode([]any{map[string]any{"name": "Main", "cards": open()}, map[string]any{"name": "Empty", "cards": []any{}}})
			return
		}
		io.WriteString(w, `[{"id":"`+board1+`","name":"Main","shortUrl":"https://trello.com/b/AbCd1234"}]`)
	case r.Method == "GET" && p == "/boards/AbCd1234/lists", r.Method == "GET" && p == "/boards/"+board1+"/lists":
		enc.Encode([]any{lists[todo], lists[doing]})
	case r.Method == "GET" && p == "/boards/"+board1+"/cards/open":
		enc.Encode(open())
	case r.Method == "GET" && p == "/search":
		if r.URL.Query().Get("modelTypes") != "cards" || r.URL.Query().Get("query") != "report" {
			w.WriteHeader(400)
			return
		}
		c := map[string]any{"board": map[string]any{"name": "Main"}, "list": map[string]any{"name": "To do"}}
		for k, v := range f.cards[card1] {
			c[k] = v
		}
		enc.Encode(map[string]any{"cards": []any{c}})
	case r.Method == "GET" && strings.HasPrefix(p, "/lists/"):
		l := lists[strings.TrimPrefix(p, "/lists/")]
		if l == nil {
			w.WriteHeader(404)
			io.WriteString(w, "The requested resource was not found.")
			return
		}
		enc.Encode(l)
	case r.Method == "POST" && p == "/cards":
		var b map[string]any
		json.Unmarshal(body, &b)
		b["id"] = "c00000000000000000000099"
		b["shortUrl"] = "https://trello.com/c/New12345"
		f.cards[b["id"].(string)] = b
		enc.Encode(b)
	case strings.HasPrefix(p, "/cards/"):
		parts := strings.Split(strings.TrimPrefix(p, "/cards/"), "/")
		id := parts[0]
		if id == "Xyz98765" {
			id = card1
		}
		c := f.cards[id]
		if c == nil {
			w.WriteHeader(404)
			io.WriteString(w, "The requested resource was not found.")
			return
		}
		switch {
		case r.Method == "GET" && len(parts) == 1:
			out := map[string]any{"list": map[string]any{"name": lists[c["idList"].(string)]["name"]}, "board": map[string]any{"name": "Main"}}
			for k, v := range c {
				out[k] = v
			}
			enc.Encode(out)
		case r.Method == "PUT" && len(parts) == 1:
			var b map[string]any
			json.Unmarshal(body, &b)
			for k, v := range b {
				c[k] = v
			}
			enc.Encode(c)
		case r.Method == "POST" && len(parts) == 3 && parts[1] == "actions" && parts[2] == "comments":
			io.WriteString(w, `{"id":"act1"}`)
		default:
			w.WriteHeader(404)
		}
	default:
		w.WriteHeader(404)
		io.WriteString(w, "The requested resource was not found.")
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeTrello) {
	f := &fakeTrello{cards: map[string]map[string]any{
		card1:                      {"id": card1, "name": "Write report", "idList": todo, "idBoard": board1, "due": "2026-11-05T17:00:00Z", "pos": 16384.0, "shortUrl": "https://trello.com/c/Xyz98765", "desc": "details", "labels": []any{map[string]any{"name": "", "color": "red"}}},
		"c00000000000000000000002": {"id": "c00000000000000000000002", "name": "Old thing", "idList": doing, "idBoard": board1, "due": "2026-11-01T09:00:00Z", "pos": 1.0},
		"c00000000000000000000003": {"id": "c00000000000000000000003", "name": "Later", "idList": doing, "idBoard": board1, "due": "2026-12-30T09:00:00Z", "pos": 2.0},
		"c00000000000000000000004": {"id": "c00000000000000000000004", "name": "Done", "idList": doing, "idBoard": board1, "due": "2026-11-04T09:00:00Z", "dueComplete": true, "pos": 3.0},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{Key: key, Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://tr": "trtok", "secret://bad": "nope"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "t", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestTrelloReads(t *testing.T) {
	m, _ := setup(t, "secret://tr")
	if h := m.Health(context.Background(), "t"); h.Status != "ok" || h.Message != "signed in as elchi" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"boards", `{}`, `"name":"Main"`},
		{"lists", `{"board":"https://trello.com/b/AbCd1234/main"}`, `"name":"Doing"`},
		{"cards", `{"board":"` + board1 + `"}`, `"list":"To do"`},
		{"cards", `{"board":"` + board1 + `"}`, `"labels":["red"]`},
		{"search", `{"query":"report"}`, `"board":"Main"`},
		{"card", `{"card":"https://trello.com/c/Xyz98765/12-write-report"}`, `"description":"details"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	r, err := invoke(m, "due_soon", `{"days":3}`, false)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Cards []map[string]any
	}
	json.Unmarshal(r.Output, &out)
	if len(out.Cards) != 2 || out.Cards[0]["name"] != "Old thing" || out.Cards[0]["overdue"] != true || out.Cards[1]["name"] != "Write report" {
		t.Fatalf("due soon: %s", r.Output)
	}
}

func TestTrelloWrites(t *testing.T) {
	m, f := setup(t, "secret://tr")

	r, err := invoke(m, "add_card", `{"list":"`+todo+`","name":"New card","due":"2026-11-10"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Add card "New card" to To do` || len(f.cards) != 4 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_card", `{"list":"`+todo+`","name":"New card","due":"2026-11-10"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "archive_card" {
		t.Fatalf("%+v %v", r, err)
	}
	nc := f.cards["c00000000000000000000099"]
	if nc["due"] != "2026-11-10T12:00:00Z" || nc["pos"] != "bottom" {
		t.Fatalf("sent %v", nc)
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || nc["closed"] != true || r.Undo == nil || r.Undo.Action != "unarchive_card" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || nc["closed"] != false {
		t.Fatal(err)
	}

	// move_card (write) stays on the board: another board may be more public.
	for _, dry := range []bool{true, false} {
		if _, err := invoke(m, "move_card", `{"card":"Xyz98765","list":"`+other+`"}`, dry); err == nil || !strings.Contains(err.Error(), "move_card_to_board") {
			t.Fatal(err)
		}
	}
	if f.cards[card1]["idList"] != todo {
		t.Fatal("moved")
	}
	risk := map[string]sdk.Risk{}
	for _, a := range m.Manifest().Actions {
		risk[a.Name] = a.Risk
	}
	if risk["move_card"] != sdk.RiskWrite || risk["move_card_to_board"] != sdk.RiskDestructive {
		t.Fatalf("%v", risk)
	}
	r, err = invoke(m, "move_card", `{"card":"Xyz98765","list":"`+doing+`"}`, false)
	if err != nil || f.cards[card1]["idList"] != doing || r.Undo == nil || r.Undo.Action != "move_card" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.cards[card1]["idList"] != todo {
		t.Fatal(err)
	}

	// Move to another board: idBoard goes along; undo moves it back to its old list and position.
	r, err = invoke(m, "move_card_to_board", `{"card":"Xyz98765","list":"`+other+`"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Move "Write report" from To do to Inbox` || f.cards[card1]["idList"] != todo {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "move_card_to_board", `{"card":"Xyz98765","list":"`+other+`"}`, false)
	if err != nil || f.cards[card1]["idList"] != other || f.cards[card1]["idBoard"] != board2 || r.Undo == nil || r.Undo.Action != "move_card_to_board" {
		t.Fatalf("%+v %v %v", r, err, f.cards[card1])
	}
	if string(r.Undo.Input) != `{"card":"`+card1+`","list":"`+todo+`","position":16384}` {
		t.Fatal(string(r.Undo.Input))
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.cards[card1]["idList"] != todo || f.cards[card1]["pos"] != 16384.0 {
		t.Fatalf("%v %v", err, f.cards[card1])
	}

	if r, err := invoke(m, "comment", `{"card":"`+card1+`","text":"On it"}`, true); err != nil || r.Plan == nil {
		t.Fatal(err)
	}
	n := len(f.seen)
	if r, err := invoke(m, "comment", `{"card":"`+card1+`","text":"On it"}`, false); err != nil || !strings.Contains(string(r.Output), `"comment":"act1"`) || !strings.Contains(f.seen[n+1], `{"text":"On it"}`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	if r, err := invoke(m, "archive_card", `{"card":"`+card1+`"}`, true); err != nil || r.Plan == nil || f.cards[card1]["closed"] == true {
		t.Fatal(err)
	}
	if _, err := invoke(m, "archive_card", `{"card":"c0000000000000000000dead"}`, false); err == nil || !strings.Contains(err.Error(), "no card") {
		t.Fatal(err)
	}
}

func TestTrelloValidation(t *testing.T) {
	m, f := setup(t, "secret://tr")
	for _, c := range []struct{ action, in string }{
		{"lists", `{"board":"../members/me"}`},
		{"lists", `{"board":"https://evil.example/b/AbCd1234"}`},
		{"cards", `{}`},
		{"cards", `{"list":"AbCd1234"}`},
		{"card", `{"card":"abc/../x"}`},
		{"search", `{"query":" "}`},
		{"add_card", `{"list":"` + todo + `","name":""}`},
		{"add_card", `{"list":"` + todo + `","name":"x","due":"next week"}`},
		{"add_card", `{"list":"` + todo + `","name":"x","position":"middle"}`},
		{"move_card", `{"card":"` + card1 + `","list":"../boards"}`},
		{"comment", `{"card":"` + card1 + `","text":"  "}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{Key: key, Token: "plain"}, {Key: "nothex", Token: "secret://tr"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "t"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestTrelloRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Key: key, Token: "secret://tr"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://tr": "trtok"}), "t", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "t"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}
