package discord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	guild    = "100000000000000001"
	chanID   = "200000000000000002"
	msgID    = "300000000000000003"
	ownerID  = "400000000000000004"
	kimID    = "500000000000000005"
	botID    = "600000000000000006"
	strayID  = "700000000000000007"
	threadID = "800000000000000008"
	replyID  = "900000000000000009"
	partyID  = "110000000000000011"
	leakChan = "120000000000000012"
	hookMsg  = "130000000000000013"
	// otherChan is in another server the bot is in; dmChan a direct message.
	otherChan  = "140000000000000014"
	otherGuild = "150000000000000015"
	dmChan     = "160000000000000016"
	token      = "MTEx.Gq-bot-token-secret-value-0123456789abcdef"
	api        = "/api/v10"
)

type fake struct {
	mu         sync.Mutex
	seen       []string
	reasons    []string
	bodies     map[string]map[string]any
	reactions  map[string]bool
	pinned     bool
	until      *string
	kimIn      bool
	banned     map[string]bool
	archived   bool
	limit429   int
	retryAfter string
	posted     string
}

func newFake() *fake {
	return &fake{bodies: map[string]map[string]any{}, reactions: map[string]bool{}, kimIn: true, banned: map[string]bool{}}
}

func (f *fake) member(id, nick, user, global string) string {
	until := "null"
	if id == kimID && f.until != nil {
		until = `"` + *f.until + `"`
	}
	return fmt.Sprintf(`{"user":{"id":%q,"username":%q,"global_name":%q,"email":"kim@example.com"},"nick":%q,"roles":[%q,"r1"],"joined_at":"2025-01-02T03:04:05.000000+00:00","communication_disabled_until":%s}`,
		id, user, global, nick, guild, until)
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	path := r.URL.Path
	f.seen = append(f.seen, r.Method+" "+path)

	// The webhook.
	if strings.HasPrefix(path, "/api/webhooks/1/abc") {
		switch r.Method + " " + strings.TrimPrefix(path, "/api/webhooks/1/abc") {
		case "GET ":
			io.WriteString(w, `{"name":"alerts"}`)
		case "POST ":
			if r.URL.Query().Get("wait") != "true" {
				w.WriteHeader(400)
				return
			}
			f.posted, _ = body["content"].(string)
			io.WriteString(w, `{"id":"`+hookMsg+`"}`)
		case "GET /messages/" + hookMsg:
			io.WriteString(w, `{"id":"`+hookMsg+`","author":{"username":"alerts"},"content":"Backup finished","timestamp":"2026-11-04T10:00:00+00:00"}`)
		case "DELETE /messages/" + hookMsg:
			f.posted = ""
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
		return
	}

	if f.limit429 > 0 {
		f.limit429--
		w.Header().Set("Retry-After", f.retryAfter)
		w.WriteHeader(429)
		io.WriteString(w, `{"message":"You are being rate limited.","retry_after":0.25,"global":false}`)
		return
	}
	if r.Header.Get("Authorization") != "Bot "+token {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"401: Unauthorized","code":0}`)
		return
	}
	if r.Method != http.MethodGet {
		f.reasons = append(f.reasons, r.Header.Get("X-Audit-Log-Reason"))
	}
	p := strings.TrimPrefix(path, api)
	notFound := func(msg string) {
		w.WriteHeader(404)
		fmt.Fprintf(w, `{"message":%q,"code":10000}`, msg)
	}
	reactions := "/channels/" + chanID + "/messages/" + msgID + "/reactions/"
	if strings.HasPrefix(p, reactions) && strings.HasSuffix(p, "/@me") {
		e := strings.TrimSuffix(strings.TrimPrefix(p, reactions), "/@me")
		if _, id, ok := strings.Cut(e, ":"); ok {
			e = id
		}
		f.reactions[e] = r.Method == http.MethodPut
		w.WriteHeader(204)
		return
	}
	switch r.Method + " " + p {
	case "GET /users/@me":
		io.WriteString(w, `{"id":"`+botID+`","username":"conduit-bot","bot":true}`)
	case "GET /guilds/" + guild:
		if r.URL.Query().Get("with_counts") == "true" {
			io.WriteString(w, `{"name":"Squad","approximate_member_count":40,"approximate_presence_count":9}`)
			return
		}
		io.WriteString(w, `{"name":"Squad","owner_id":"`+ownerID+`"}`)
	case "GET /guilds/" + guild + "/channels":
		io.WriteString(w, `[{"id":"`+chanID+`","name":"general","type":0},{"id":"9","name":"Voice","type":2}]`)
	case "GET /channels/" + chanID:
		io.WriteString(w, `{"id":"`+chanID+`","guild_id":"`+guild+`","name":"general","type":0}`)
	case "GET /channels/" + leakChan:
		io.WriteString(w, `{"id":"`+leakChan+`","guild_id":"`+guild+`","name":"staff","type":0}`)
	case "GET /channels/" + otherChan:
		io.WriteString(w, `{"id":"`+otherChan+`","guild_id":"`+otherGuild+`","name":"elsewhere","type":0}`)
	case "GET /channels/" + dmChan:
		io.WriteString(w, `{"id":"`+dmChan+`","type":1}`)
	case "GET /channels/" + chanID + "/messages":
		if r.URL.Query().Get("limit") != "2" || r.URL.Query().Get("before") != msgID {
			w.WriteHeader(400)
			return
		}
		atts := []string{}
		for i := 0; i < 12; i++ {
			atts = append(atts, fmt.Sprintf(`{"filename":"shot%d.png","url":"https://cdn.example/secret-signed-%d"}`, i, i))
		}
		fmt.Fprintf(w, `[{"id":"%s","author":{"id":"%s","username":"kim","global_name":"Kim"},"content":%q,"timestamp":"2026-11-04T10:00:00.123+00:00","edited_timestamp":"2026-11-04T10:05:00+00:00","attachments":[%s],"message_reference":{"message_id":"%s"}},
			{"id":"%s","author":{"id":"%s","username":"conduit-bot","bot":true},"content":"hi","timestamp":"2026-11-04T09:00:00+00:00","attachments":[],"pinned":true}]`,
			replyID, kimID, strings.Repeat("é", 1500), strings.Join(atts, ","), msgID, msgID, botID)
	case "GET /channels/" + leakChan + "/messages":
		w.WriteHeader(403)
		// The token starts 10 characters before the 300-character cut.
		fmt.Fprintf(w, `{"message":"%s%s Missing Access","code":50001}`, strings.Repeat("a ", 145), token)
	case "GET /channels/" + chanID + "/messages/" + msgID:
		rs := []string{}
		for e, me := range f.reactions {
			if !me {
				continue
			}
			if e == partyID {
				rs = append(rs, `{"count":2,"me":true,"emoji":{"id":"`+partyID+`","name":"party"}}`)
			} else {
				rs = append(rs, `{"count":1,"me":true,"emoji":{"id":null,"name":"`+e+`"}}`)
			}
		}
		fmt.Fprintf(w, `{"id":"%s","author":{"id":"%s","username":"kim","global_name":"Kim"},"content":"Ship it?","timestamp":"2026-11-04T10:00:00+00:00","pinned":%v,"reactions":[%s]}`,
			msgID, kimID, f.pinned, strings.Join(rs, ","))
	case "GET /channels/" + chanID + "/messages/" + replyID:
		io.WriteString(w, `{"id":"`+replyID+`","author":{"username":"conduit-bot"},"content":"On it","timestamp":"2026-11-04T10:00:00+00:00"}`)
	case "POST /channels/" + chanID + "/messages":
		f.bodies[replyID] = body
		io.WriteString(w, `{"id":"`+replyID+`"}`)
	case "DELETE /channels/" + chanID + "/messages/" + replyID:
		delete(f.bodies, replyID)
		w.WriteHeader(204)
	case "PUT /channels/" + chanID + "/messages/pins/" + msgID:
		f.pinned = true
		w.WriteHeader(204)
	case "DELETE /channels/" + chanID + "/messages/pins/" + msgID:
		f.pinned = false
		w.WriteHeader(204)
	case "POST /channels/" + chanID + "/messages/" + msgID + "/threads", "POST /channels/" + chanID + "/threads":
		f.bodies["thread"] = body
		f.archived = false
		typ := 11
		if t, ok := body["type"].(float64); ok {
			typ = int(t)
		}
		fmt.Fprintf(w, `{"id":%q,"name":%q,"type":%d,"parent_id":%q}`, threadID, body["name"], typ, chanID)
	case "GET /channels/" + threadID:
		fmt.Fprintf(w, `{"id":%q,"guild_id":%q,"name":"plans","type":11,"parent_id":%q,"thread_metadata":{"archived":%v}}`, threadID, guild, chanID, f.archived)
	case "PATCH /channels/" + threadID:
		f.archived = body["archived"] == true
		io.WriteString(w, `{}`)
	case "GET /guilds/" + guild + "/threads/active":
		fmt.Fprintf(w, `{"threads":[{"id":%q,"name":"plans","type":11,"parent_id":%q,"message_count":4,"member_count":2,"thread_metadata":{"archived":false,"create_timestamp":"2026-11-04T08:00:00+00:00"}}],"members":[]}`, threadID, chanID)
	case "GET /guilds/" + guild + "/members":
		if r.URL.Query().Get("limit") != "2" {
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `[%s,%s]`, f.member(ownerID, "", "boss", "The Boss"), f.member(kimID, "Kimmy", "kim", "Kim"))
	case "GET /guilds/" + guild + "/roles":
		io.WriteString(w, `[{"id":"`+guild+`","name":"@everyone"},{"id":"r1","name":"Raiders"}]`)
	case "GET /guilds/" + guild + "/members/" + kimID:
		if !f.kimIn {
			notFound("Unknown Member")
			return
		}
		io.WriteString(w, f.member(kimID, "", "kim", "Kim"))
	case "GET /guilds/" + guild + "/members/" + ownerID:
		io.WriteString(w, f.member(ownerID, "", "boss", "The Boss"))
	case "GET /guilds/" + guild + "/members/" + botID:
		io.WriteString(w, f.member(botID, "", "conduit-bot", ""))
	case "GET /users/" + strayID:
		io.WriteString(w, `{"id":"`+strayID+`","username":"drifter"}`)
	case "PATCH /guilds/" + guild + "/members/" + kimID:
		if v, ok := body["communication_disabled_until"].(string); ok {
			f.until = &v
		} else {
			f.until = nil
		}
		io.WriteString(w, f.member(kimID, "", "kim", "Kim"))
	case "DELETE /guilds/" + guild + "/members/" + kimID:
		f.kimIn = false
		w.WriteHeader(204)
	default:
		bans := "/guilds/" + guild + "/bans/"
		if id, ok := strings.CutPrefix(p, bans); ok {
			switch r.Method {
			case http.MethodGet:
				if !f.banned[id] {
					notFound("Unknown Ban")
					return
				}
				io.WriteString(w, `{"reason":"spam","user":{"id":"`+id+`"}}`)
			case http.MethodPut:
				if body["delete_message_seconds"] != 3600.0 {
					w.WriteHeader(400)
					return
				}
				f.banned[id] = true
				w.WriteHeader(204)
			case http.MethodDelete:
				delete(f.banned, id)
				w.WriteHeader(204)
			}
			return
		}
		if strings.HasPrefix(p, "/users/") || strings.HasPrefix(p, "/guilds/"+guild+"/members/") {
			notFound("Unknown User")
			return
		}
		notFound("Unknown")
	}
}

func (f *fake) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

func (f *fake) reset() {
	f.mu.Lock()
	f.seen, f.reasons = nil, nil
	f.mu.Unlock()
}

type rig struct {
	t     *testing.T
	m     *Module
	f     *fake
	slept []time.Duration
	out   []string // every output, plan and error, to check for the token
}

func setup(t *testing.T) *rig {
	t.Helper()
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	g := &rig{t: t, f: f, m: New()}
	g.m.HTTP = srv.Client()
	g.m.sleep = func(_ context.Context, d time.Duration) error { g.slept = append(g.slept, d); return nil }
	host := fakehost.New(map[string]string{"secret://hook": srv.URL + "/api/webhooks/1/abc", "secret://bot": token, "secret://bad": "not-the-token"})
	for id, tok := range map[string]string{"d": "secret://bot", "bad": "secret://bad"} {
		cfg, _ := json.Marshal(Config{Webhook: "secret://hook", BotToken: tok, Guild: guild, API: srv.URL + api})
		if err := g.m.Configure(context.Background(), host, id, cfg); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, s := range g.out {
			if strings.Contains(s, token) || strings.Contains(s, "secret-value") {
				t.Errorf("the token reached the output: %s", s)
			}
		}
	})
	return g
}

func (g *rig) try(action, in string, dry bool) (sdk.Result, error) {
	r, err := g.m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: action, Input: json.RawMessage(in), DryRun: dry})
	g.out = append(g.out, string(r.Output))
	if r.Plan != nil {
		b, _ := json.Marshal(r.Plan)
		g.out = append(g.out, string(b))
	}
	if r.Undo != nil {
		g.out = append(g.out, string(r.Undo.Input))
	}
	if err != nil {
		g.out = append(g.out, err.Error())
	}
	return r, err
}

func (g *rig) run(action, in string, dry bool) sdk.Result {
	g.t.Helper()
	r, err := g.try(action, in, dry)
	if err != nil {
		g.t.Fatalf("%s %s: %v", action, in, err)
	}
	return r
}

func (g *rig) undo(r sdk.Result) sdk.Result {
	g.t.Helper()
	if r.Undo == nil {
		g.t.Fatalf("no undo in %s", r.Output)
	}
	return g.run(r.Undo.Action, string(r.Undo.Input), false)
}

func field(t *testing.T, r sdk.Result) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(r.Output, &v); err != nil {
		t.Fatalf("%s: %v", r.Output, err)
	}
	return v
}

func TestDiscordWebhookAndStatus(t *testing.T) {
	g := setup(t)
	r := g.run("send", `{"message":"Backup finished"}`, false)
	if g.f.posted != "Backup finished" {
		t.Fatalf("send %q", g.f.posted)
	}
	p := g.run(r.Undo.Action, string(r.Undo.Input), true)
	if p.Plan == nil || !strings.Contains(p.Plan.Summary, "alerts's message") || g.f.posted == "" {
		t.Fatalf("dry delete %+v", p.Plan)
	}
	g.undo(r)
	if g.f.posted != "" {
		t.Fatal("undo didn't delete")
	}
	if s := field(t, g.run("server", "", false)); s["online"] != 9.0 || s["name"] != "Squad" {
		t.Fatalf("server %v", s)
	}
	if r := g.run("channels", "", false); !strings.Contains(string(r.Output), `"name":"general","kind":"text"`) {
		t.Fatalf("channels %s", r.Output)
	}
	if h := g.m.Health(context.Background(), "d"); h.Status != "ok" || h.Message != "Bot conduit-bot" {
		t.Fatalf("health %+v", h)
	}
	for _, raw := range []string{`{}`, `{"botToken":"plain-token"}`, `{"botToken":"secret://bot","guild":"12345"}`, `{"webhook":"https://discord.com/api/webhooks/1/x"}`} {
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestDiscordReads(t *testing.T) {
	g := setup(t)
	r := g.run("messages", `{"channel":"`+chanID+`","limit":2,"before":"`+msgID+`"}`, false)
	var got struct {
		Messages []map[string]any `json:"messages"`
		Next     string           `json:"next"`
	}
	_ = json.Unmarshal(r.Output, &got)
	if len(got.Messages) != 2 || got.Next != msgID {
		t.Fatalf("%s", r.Output)
	}
	first := got.Messages[0]
	att, _ := first["attachments"].(map[string]any)
	if first["author"] != "Kim" || first["sent"] != "2026-11-04T10:00:00Z" || first["replyTo"] != msgID ||
		len([]rune(first["text"].(string))) != maxShown+1 || att["count"] != 12.0 || len(att["names"].([]any)) != 10 {
		t.Fatalf("%v", first)
	}
	if strings.Contains(string(r.Output), "cdn.example") || got.Messages[1]["bot"] != true || got.Messages[1]["pinned"] != true {
		t.Fatalf("%s", r.Output)
	}

	r = g.run("threads", "", false)
	if !strings.Contains(string(r.Output), `"channel":"#general"`) || !strings.Contains(string(r.Output), `"messages":4`) {
		t.Fatalf("threads %s", r.Output)
	}

	r = g.run("members", `{"limit":2}`, false)
	if !strings.Contains(string(r.Output), `"name":"Kimmy"`) || !strings.Contains(string(r.Output), `"roles":["Raiders"]`) ||
		!strings.Contains(string(r.Output), `"joined":"2025-01-02T03:04:05Z"`) || field(t, r)["next"] != kimID {
		t.Fatalf("members %s", r.Output)
	}
	if strings.Contains(string(r.Output), "example.com") || strings.Contains(string(r.Output), "email") {
		t.Fatalf("members show an email: %s", r.Output)
	}
}

func TestDiscordChannelActions(t *testing.T) {
	g := setup(t)
	in := `{"channel":"` + chanID + `","id":"` + msgID + `","message":"On it <@` + kimID + `>"}`
	p := g.run("reply", in, true)
	if p.Plan == nil || p.Plan.Summary != "Reply in #general (mentions notify no one)" || len(g.f.bodies) != 0 {
		t.Fatalf("plan %+v", p.Plan)
	}
	r := g.run("reply", in, false)
	b := g.f.bodies[replyID]
	am, _ := b["allowed_mentions"].(map[string]any)
	ref, _ := b["message_reference"].(map[string]any)
	if b["content"] != "On it <@"+kimID+">" || len(am["parse"].([]any)) != 0 || am["replied_user"] != false || ref["message_id"] != msgID {
		t.Fatalf("reply body %v", b)
	}
	if r.Undo.Action != "delete_message" {
		t.Fatalf("%+v", r.Undo)
	}
	g.undo(r)
	if _, ok := g.f.bodies[replyID]; ok {
		t.Fatal("reply not deleted")
	}

	for _, e := range []string{"👍", "<:party:" + partyID + ">", "party:" + partyID} {
		in := `{"channel":"` + chanID + `","id":"` + msgID + `","emoji":"` + e + `"}`
		r := g.run("react", in, false)
		key := "👍"
		if strings.Contains(e, ":") {
			key = partyID
		}
		if !g.f.reactions[key] || r.Undo == nil || r.Undo.Action != "unreact" {
			t.Fatalf("%s: %v %s", e, g.f.reactions, r.Output)
		}
		if again := g.run("react", in, false); again.Undo != nil || !strings.Contains(string(again.Output), "nothing to change") {
			t.Fatalf("%s again: %s", e, again.Output)
		}
		u := g.undo(r)
		if g.f.reactions[key] || u.Undo == nil || u.Undo.Action != "react" {
			t.Fatalf("%s unreact: %v", e, g.f.reactions)
		}
		if again := g.run("unreact", in, false); !strings.Contains(string(again.Output), "nothing to change") {
			t.Fatalf("unreact again %s", again.Output)
		}
	}

	pin := `{"channel":"` + chanID + `","id":"` + msgID + `"}`
	r = g.run("pin_message", pin, false)
	if !g.f.pinned || r.Undo.Action != "unpin_message" {
		t.Fatalf("pin %s", r.Output)
	}
	if again := g.run("pin_message", pin, false); again.Undo != nil || !strings.Contains(string(again.Output), "already pinned") {
		t.Fatalf("%s", again.Output)
	}
	if u := g.undo(r); g.f.pinned || u.Undo.Action != "pin_message" {
		t.Fatal("not unpinned")
	}

	th := `{"channel":"` + chanID + `","id":"` + msgID + `","name":"Plans","archiveAfter":1440}`
	p = g.run("create_thread", th, true)
	if p.Plan == nil || !strings.Contains(p.Plan.Summary, `"Plans" in #general from message`) || g.f.bodies["thread"] != nil {
		t.Fatalf("plan %+v", p.Plan)
	}
	r = g.run("create_thread", th, false)
	if g.f.bodies["thread"]["auto_archive_duration"] != 1440.0 || r.Undo.Action != "archive_thread" {
		t.Fatalf("%v %+v", g.f.bodies["thread"], r.Undo)
	}
	g.undo(r)
	if !g.f.archived || g.f.reasons[len(g.f.reasons)-1] != "Conduit" {
		t.Fatalf("not archived %v", g.f.reasons)
	}
	if again := g.run("archive_thread", string(r.Undo.Input), false); !strings.Contains(string(again.Output), "already archived") {
		t.Fatalf("%s", again.Output)
	}
	g.run("create_thread", `{"channel":"`+chanID+`","name":"Staff","private":true}`, false)
	if g.f.bodies["thread"]["type"] != 12.0 {
		t.Fatalf("%v", g.f.bodies["thread"])
	}
	if _, err := g.try("archive_thread", `{"thread":"`+chanID+`"}`, false); err == nil || !strings.Contains(err.Error(), "not a thread") {
		t.Fatalf("archived a channel: %v", err)
	}
}

func TestDiscordModeration(t *testing.T) {
	g := setup(t)
	kim := `{"user":"` + kimID + `","duration":"2h","reason":"spamming links"}`
	p := g.run("timeout_member", kim, true)
	if p.Plan == nil || !strings.HasPrefix(p.Plan.Summary, "Time out Kim (@kim) in Squad until ") || g.f.until != nil {
		t.Fatalf("plan %+v", p.Plan)
	}
	r := g.run("timeout_member", kim, false)
	end, _ := time.Parse(time.RFC3339, *g.f.until)
	if d := time.Until(end); d < 119*time.Minute || d > 121*time.Minute {
		t.Fatalf("until %s", *g.f.until)
	}
	if got := g.f.reasons[len(g.f.reasons)-1]; got != "Conduit%3A%20spamming%20links" && got != "Conduit:%20spamming%20links" {
		t.Fatalf("audit reason %q", got)
	}
	if r.Undo.Action != "remove_timeout" {
		t.Fatalf("%+v", r.Undo)
	}
	// A second, longer timeout restores the first on undo.
	first := *g.f.until
	r2 := g.run("timeout_member", `{"user":"`+kimID+`","duration":"7d"}`, false)
	if r2.Undo.Action != "timeout_member" || !strings.Contains(string(r2.Undo.Input), first) {
		t.Fatalf("%+v", r2.Undo)
	}
	g.undo(r2)
	if *g.f.until != first {
		t.Fatalf("restored %s, want %s", *g.f.until, first)
	}
	p = g.run("remove_timeout", `{"user":"`+kimID+`"}`, true)
	if p.Plan == nil || !strings.Contains(p.Plan.Summary, "Kim (@kim) in Squad") || g.f.until == nil {
		t.Fatalf("plan %+v", p.Plan)
	}
	g.undo(r)
	if g.f.until != nil {
		t.Fatal("timeout not lifted")
	}
	if again := g.run("remove_timeout", `{"user":"`+kimID+`"}`, false); !strings.Contains(string(again.Output), "nothing to change") {
		t.Fatalf("%s", again.Output)
	}

	for _, who := range []string{ownerID, botID} {
		for _, a := range []string{"timeout_member", "kick_member", "ban_member"} {
			g.f.reset()
			if _, err := g.try(a, `{"user":"`+who+`","duration":"1h"}`, false); err == nil {
				t.Fatalf("%s on %s accepted", a, who)
			}
			for _, c := range g.f.calls() {
				if !strings.HasPrefix(c, "GET ") {
					t.Fatalf("%s on %s reached the server: %s", a, who, c)
				}
			}
		}
	}

	if r := g.run("kick_member", `{"user":"`+strayID+`"}`, false); !strings.Contains(string(r.Output), "nothing to change: @drifter isn't in Squad") {
		t.Fatalf("%s", r.Output)
	}
	p = g.run("kick_member", `{"user":"`+kimID+`"}`, true)
	if p.Plan == nil || !strings.HasPrefix(p.Plan.Summary, "Kick Kim (@kim) in Squad") || !g.f.kimIn {
		t.Fatalf("plan %+v", p.Plan)
	}
	if r := g.run("kick_member", `{"user":"`+kimID+`"}`, false); g.f.kimIn || r.Undo != nil {
		t.Fatalf("kick %s %+v", r.Output, r.Undo)
	}

	ban := `{"user":"` + strayID + `","deleteMessageHours":1}`
	p = g.run("ban_member", ban, true)
	if p.Plan == nil || !strings.Contains(p.Plan.Summary, "Ban @drifter in Squad (not a member now") || g.f.banned[strayID] {
		t.Fatalf("plan %+v", p.Plan)
	}
	r = g.run("ban_member", ban, false)
	if !g.f.banned[strayID] || r.Undo.Action != "unban_member" {
		t.Fatalf("ban %s", r.Output)
	}
	if again := g.run("ban_member", ban, false); !strings.Contains(string(again.Output), "already banned") {
		t.Fatalf("%s", again.Output)
	}
	p = g.run("unban_member", string(r.Undo.Input), true)
	if p.Plan == nil || !strings.Contains(p.Plan.Summary, "Unban @drifter in Squad") || !strings.Contains(string(p.Plan.Changes[0].Before), "spam") {
		t.Fatalf("plan %+v", p.Plan)
	}
	if u := g.undo(r); g.f.banned[strayID] || u.Undo.Action != "ban_member" {
		t.Fatal("not unbanned")
	}
	if again := g.run("unban_member", `{"user":"`+strayID+`"}`, false); !strings.Contains(string(again.Output), "isn't banned") {
		t.Fatalf("%s", again.Output)
	}
	if _, err := g.try("ban_member", `{"user":"999999999999999999"}`, false); err == nil || !strings.Contains(err.Error(), "no Discord user") {
		t.Fatalf("unknown user: %v", err)
	}
}

// Invalid input is refused before anything is sent.
func TestDiscordValidation(t *testing.T) {
	g := setup(t)
	ch, ms := `"channel":"`+chanID+`"`, `"id":"`+msgID+`"`
	long := strings.Repeat("x", maxContent+1)
	for _, c := range []struct{ action, in string }{
		{"send", `{"message":"x","channel":"1/2"}`},
		{"send", `{"message":"ping @everyone"}`},
		{"send", `{"message":"` + long + `"}`},
		{"delete_message", `{"id":"` + msgID + `","channel":"../users/@me"}`},
		{"delete_message", `{"id":"12345"}`},
		{"messages", `{"channel":"../users/@me"}`},
		{"messages", `{` + ch + `,"before":"1/2"}`},
		{"reply", `{` + ch + `,` + ms + `,"message":"hi @here"}`},
		{"reply", `{` + ch + `,` + ms + `,"message":"` + long + `"}`},
		{"reply", `{` + ch + `,` + ms + `,"message":"  "}`},
		{"reply", `{` + ch + `,"id":"123","message":"x"}`},
		{"react", `{` + ch + `,` + ms + `,"emoji":"abc"}`},
		{"react", `{` + ch + `,` + ms + `,"emoji":"👍/../x"}`},
		{"react", `{` + ch + `,` + ms + `,"emoji":"party:123"}`},
		{"react", `{` + ch + `,` + ms + `,"emoji":""}`},
		{"unreact", `{` + ch + `,` + ms + `,"emoji":"👍 👎"}`},
		{"pin_message", `{` + ch + `,"id":"../../x"}`},
		{"unpin_message", `{"channel":"1234567890123456789012",` + ms + `}`},
		{"create_thread", `{` + ch + `,"name":""}`},
		{"create_thread", `{` + ch + `,"name":"` + strings.Repeat("n", 101) + `"}`},
		{"create_thread", `{` + ch + `,"name":"a\nb"}`},
		{"create_thread", `{` + ch + `,"name":"x","archiveAfter":30}`},
		{"create_thread", `{` + ch + `,` + ms + `,"name":"x","private":true}`},
		{"archive_thread", `{"thread":"x"}`},
		{"members", `{"after":"x"}`},
		{"timeout_member", `{"user":"` + kimID + `","duration":"29d"}`},
		{"timeout_member", `{"user":"` + kimID + `","duration":"10y"}`},
		{"timeout_member", `{"user":"` + kimID + `"}`},
		{"timeout_member", `{"user":"` + kimID + `","until":"2020-01-01T00:00:00Z"}`},
		{"timeout_member", `{"user":"` + kimID + `","duration":"1h","until":"2099-01-01T00:00:00Z"}`},
		{"timeout_member", `{"user":"` + kimID + `","duration":"1h","reason":"a\nb"}`},
		{"kick_member", `{"user":"` + kimID + `","reason":"` + strings.Repeat("r", 401) + `"}`},
		{"kick_member", `{"user":"123456789012345678901"}`},
		{"ban_member", `{"user":"` + kimID + `","deleteMessageHours":200}`},
		{"unban_member", `{"user":"../../x"}`},
		{"remove_timeout", `{}`},
	} {
		if _, err := g.try(c.action, c.in, false); err == nil {
			t.Errorf("%s accepted %s", c.action, c.in)
		}
	}
	if seen := g.f.calls(); len(seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", seen)
	}
}

func TestDiscordBadTokenAndRedaction(t *testing.T) {
	g := setup(t)
	h := g.m.Health(context.Background(), "bad")
	if h.Status != "down" || !strings.Contains(h.Message, "refused the bot token") {
		t.Fatalf("%+v", h)
	}
	_, err := g.m.Invoke(context.Background(), sdk.Call{Instance: "bad", Action: "messages", Input: json.RawMessage(`{"channel":"` + chanID + `"}`)})
	if err == nil || !strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "not-the-token") {
		t.Fatalf("%v", err)
	}
	// A server echoing the token is redacted before the message is shortened,
	// so no piece of it survives the cut.
	_, err = g.try("messages", `{"channel":"`+leakChan+`"}`, false)
	if err == nil || strings.Contains(err.Error(), "Gq-bo") || !strings.Contains(err.Error(), "needs a permission") {
		t.Fatalf("%v", err)
	}
}

func TestDiscordRateLimit(t *testing.T) {
	g := setup(t)
	g.f.limit429, g.f.retryAfter = 1, "0.25"
	if r := g.run("server", "", false); field(t, r)["name"] != "Squad" || len(g.slept) != 1 || g.slept[0] != 250*time.Millisecond {
		t.Fatalf("%s %v", r.Output, g.slept)
	}
	g.f.limit429 = 2
	if _, err := g.try("server", "", false); err == nil || !strings.Contains(err.Error(), "rate limiting") || len(g.slept) != 2 {
		t.Fatalf("%v %v", err, g.slept)
	}
	g.f.limit429, g.f.retryAfter = 1, "30"
	if _, err := g.try("server", "", false); err == nil || !strings.Contains(err.Error(), "30 seconds") || len(g.slept) != 2 {
		t.Fatalf("waited out a long limit: %v %v", err, g.slept)
	}
}

func TestDiscordRefusesRedirect(t *testing.T) {
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") + r.Header.Get("X-Audit-Log-Reason")
		io.WriteString(w, `{"id":"1","username":"evil"}`)
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{BotToken: "secret://bot", Guild: guild, API: srv.URL + api})
	_ = m.Configure(context.Background(), fakehost.New(map[string]string{"secret://bot": token}), "d", raw)
	h := m.Health(context.Background(), "d")
	if h.Status != "down" || leaked != "" || strings.Contains(h.Message, token) {
		t.Fatalf("%+v %q", h, leaked)
	}
	_, err := m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: "kick_member", Input: json.RawMessage(`{"user":"` + kimID + `"}`)})
	if !errors.Is(err, rest.ErrCrossHostRedirect) || leaked != "" {
		t.Fatalf("%v %q", err, leaked)
	}
}

func TestParseEmoji(t *testing.T) {
	for in, want := range map[string]string{
		"👍": "👍", "❤️": "❤️", "👩‍💻": "👩‍💻", "1️⃣": "1️⃣", "👍🏽": "👍🏽",
		"party:" + partyID: "party:" + partyID, "<a:dance:" + partyID + ">": "dance:" + partyID,
	} {
		if e, err := parseEmoji(in); err != nil || e.api() != want {
			t.Errorf("%q: %q %v", in, e.api(), err)
		}
	}
	for _, in := range []string{"", "a", "12", "é", "👍 x", "👍?", "%F0", "../👍", ":party:", "party:" + partyID + "/x", strings.Repeat("👍", 17)} {
		if _, err := parseEmoji(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

// Channel actions reach only channels in the configured server: not another
// server the bot is in, nor its direct messages.
func TestDiscordStaysInItsServer(t *testing.T) {
	g := setup(t)
	for _, ch := range []string{otherChan, dmChan} {
		c, ms := `"channel":"`+ch+`"`, `"id":"`+msgID+`"`
		for _, x := range []struct{ action, in string }{
			{"messages", `{` + c + `}`},
			{"send", `{` + c + `,"message":"hi"}`},
			{"reply", `{` + c + `,` + ms + `,"message":"hi"}`},
			{"react", `{` + c + `,` + ms + `,"emoji":"👍"}`},
			{"pin_message", `{` + c + `,` + ms + `}`},
			{"create_thread", `{` + c + `,"name":"x"}`},
			{"delete_message", `{` + c + `,` + ms + `}`},
			{"archive_thread", `{"thread":"` + ch + `"}`},
		} {
			g.f.reset()
			for _, dry := range []bool{true, false} {
				if _, err := g.try(x.action, x.in, dry); err == nil || !strings.Contains(err.Error(), "isn't in this instance's server") {
					t.Errorf("%s in %s: %v", x.action, ch, err)
				}
			}
			if seen := g.f.calls(); len(seen) != 2 || seen[0] != "GET "+api+"/channels/"+ch {
				t.Errorf("%s in %s went further: %v", x.action, ch, seen)
			}
		}
	}
}

// The webhook URL is its secret: an answer Discord's client can't read
// doesn't put it in the error.
func TestDiscordWebhookURLNotInErrors(t *testing.T) {
	const hook = "/api/webhooks/1/Sup3rS3cretWebhookToken"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "<html>oops</html>") }))
	defer srv.Close()
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{Webhook: "secret://hook"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://hook": srv.URL + hook}), "d", raw); err != nil {
		t.Fatal(err)
	}
	_, err := m.Invoke(context.Background(), sdk.Call{Instance: "d", Action: "send", Input: json.RawMessage(`{"message":"x"}`)})
	h := m.Health(context.Background(), "d")
	for _, s := range []string{fmt.Sprint(err), h.Message} {
		if err == nil || strings.Contains(s, "Sup3rS3cret") || strings.Contains(s, "webhooks") || !strings.Contains(s, "unexpected answer") {
			t.Fatalf("%q", s)
		}
	}
}
