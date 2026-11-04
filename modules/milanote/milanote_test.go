package milanote

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func setup(t *testing.T, f *fake, cfg Config, secrets map[string]string) (*Module, func(action, in string, dry bool) (sdk.Result, error)) {
	t.Helper()
	m := New()
	m.HTTP = f.srv.Client()
	m.MinInterval = time.Nanosecond
	if cfg.URL == "" {
		cfg.URL = f.srv.URL
	}
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(secrets), "mn", raw); err != nil {
		t.Fatal(err)
	}
	return m, func(action, in string, dry bool) (sdk.Result, error) {
		return m.Invoke(context.Background(), sdk.Call{Instance: "mn", Action: action, Input: json.RawMessage(in), DryRun: dry})
	}
}

func passwordConfig() (Config, map[string]string) {
	return Config{Email: "Ana@Example.com", Password: "secret://mn-pw"}, map[string]string{"secret://mn-pw": "hunter2"}
}

func out(t *testing.T, r sdk.Result, err error, what string) map[string]any {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	var m map[string]any
	if err := json.Unmarshal(r.Output, &m); err != nil {
		t.Fatalf("%s: %s", what, r.Output)
	}
	return m
}

func content(f *fake, id string) string {
	b, _ := json.Marshal(f.element(id)["content"])
	return string(b)
}

func TestMilanote(t *testing.T) {
	f := newFake(t)
	f.xsrf = true
	cfg, secrets := passwordConfig()
	m, run := setup(t, f, cfg, secrets)
	ctx := context.Background()
	call := func(what, action, in string) map[string]any {
		t.Helper()
		r, err := run(action, in, false)
		return out(t, r, err, what)
	}

	if h := m.Health(ctx, "mn"); h.Status != "ok" || !strings.Contains(h.Message, "Ana Lopez") || !strings.Contains(h.Message, WireVersion) {
		t.Fatalf("health %+v", h)
	}

	// boards: Home > Novel > Research
	r, err := run("boards", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"title":"Research"`) || !strings.Contains(string(r.Output), `"title":"Home"`) {
		t.Fatalf("boards %s %v", r.Output, err)
	}

	// board, by URL
	b := call("board", "board", `{"board":"https://app.milanote.com/`+novel+`/novel"}`)
	md := b["markdown"].(string)
	for _, want := range []string{"# Novel", "Maya finds the **letter**", "## Ideas", "Ferry scene", "**Edits**", "- [ ] Rewrite act one", "- [x] Pick ferry",
		"- [Example](https://example.com)", "- Board: [Research](" + f.srv.URL + "/" + research + ")", "## Unsorted", "old note"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
	if strings.Index(md, "Maya") > strings.Index(md, "## Ideas") || strings.Index(md, "## Ideas") > strings.Index(md, "## Unsorted") {
		t.Errorf("markdown order:\n%s", md)
	}
	els, _ := json.Marshal(b["elements"])
	if !strings.Contains(string(els), `"column":"`+column+`","id":"`+inColumn+`","section":"column"`) ||
		!strings.Contains(string(els), `{"done":true,"id":"task-bbb","text":"Pick ferry"}`) {
		t.Fatalf("elements %s", els)
	}
	if _, err := run("board", `{"board":"1Missing0000000"}`, false); err == nil || !strings.Contains(err.Error(), "no such board") {
		t.Fatalf("missing board %v", err)
	}
	if _, err := run("board", `{"board":"../etc/passwd"}`, false); err == nil {
		t.Fatal("bad board id accepted")
	}

	// search
	r, err = run("search", `{"query":"Ferry"}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"board":"`+novel+`"`) || !strings.Contains(string(r.Output), `"snippet":"ferry scene"`) {
		t.Fatalf("search %s %v", r.Output, err)
	}

	// add_note lands on top of Unsorted, with an id made like the web app's
	n := call("add_note", "add_note", `{"board":"`+novel+`","text":"Call the editor\nabout act two"}`)
	newID := n["id"].(string)
	e := f.element(newID)
	if e == nil || e["elementType"] != "CARD" || parent(e) != novel || e["location"].(map[string]any)["section"] != "INBOX" ||
		!strings.Contains(content(f, newID), `"text":"about act two"`) {
		t.Fatalf("note %v", e)
	}
	r, err = run("add_note", `{"board":"`+novel+`","text":"In a column","column":"`+column+`"}`, false)
	n = out(t, r, err, "add_note column")
	if parent(f.element(n["id"].(string))) != column || r.Undo == nil || r.Undo.Action != "archive" {
		t.Fatalf("column note %v %+v", f.element(n["id"].(string)), r.Undo)
	}
	if _, err := run("add_note", `{"board":"`+novel+`","text":"x","column":"`+note+`"}`, false); err == nil {
		t.Fatal("a note accepted as a column")
	}

	// add_todo
	n = call("add_todo", "add_todo", `{"board":"`+novel+`","title":"Launch","tasks":["Book venue","Print flyers"]}`)
	if f.element(n["id"].(string))["elementType"] != "TASK_LIST" || !strings.Contains(content(f, n["id"].(string)), `"Print flyers"`) {
		t.Fatalf("todo %v", f.element(n["id"].(string)))
	}

	// check_todo by text, then undo
	r, err = run("check_todo", `{"board":"`+novel+`","id":"`+todo+`","task":"Rewrite act one"}`, false)
	if err != nil || !strings.Contains(content(f, todo), `"checked":true,"taskId":"task-aaa"`) || r.Undo == nil {
		t.Fatalf("check_todo %v %s", err, content(f, todo))
	}
	if _, err := run(r.Undo.Action, string(r.Undo.Input), false); err != nil || !strings.Contains(content(f, todo), `"checked":false,"taskId":"task-aaa"`) {
		t.Fatalf("check_todo undo %v %s", err, content(f, todo))
	}
	if _, err := run("check_todo", `{"board":"`+novel+`","id":"`+todo+`","task":"nope"}`, false); err == nil {
		t.Fatal("unknown task ticked")
	}

	// add_link uses the preview
	n = call("add_link", "add_link", `{"board":"`+novel+`","url":"https://example.org/page"}`)
	le := f.element(n["id"].(string))
	if n["title"] != "Example Domain" || le["elementType"] != "LINK" || !strings.Contains(content(f, n["id"].(string)), `"title":"Example Domain"`) {
		t.Fatalf("link %v %v", n, le)
	}
	if _, err := run("add_link", `{"board":"`+novel+`","url":"javascript:alert(1)"}`, false); err == nil {
		t.Fatal("bad link accepted")
	}

	// update_note: preview, edit, undo restores the formatting
	r, err = run("update_note", `{"board":"`+novel+`","id":"`+note+`","text":"Maya burns the letter"}`, true)
	if err != nil || r.Plan == nil || string(r.Plan.Changes[0].Before) != `"Maya finds the letter"` || content(f, note) == "" || strings.Contains(content(f, note), "burns") {
		t.Fatalf("update preview %+v %v", r.Plan, err)
	}
	r, err = run("update_note", `{"board":"`+novel+`","id":"`+note+`","text":"Maya burns the letter"}`, false)
	if err != nil || !strings.Contains(content(f, note), "burns") || r.Undo == nil {
		t.Fatalf("update %v", err)
	}
	if _, err := run(r.Undo.Action, string(r.Undo.Input), false); err != nil || !strings.Contains(content(f, note), `"marks":[{"type":"bold"}]`) {
		t.Fatalf("update undo %v %s", err, content(f, note))
	}
	if _, err := run("update_note", `{"board":"`+novel+`","id":"`+todo+`","text":"x"}`, false); err == nil {
		t.Fatal("a to-do list edited as a note")
	}

	// move to another board, then back to the exact spot
	orig := normalize(f.element(note)["location"])
	r, err = run("move", `{"board":"`+novel+`","id":"`+note+`","toBoard":"`+research+`"}`, true)
	if err != nil || r.Plan == nil || parent(f.element(note)) != novel {
		t.Fatalf("move preview %v", err)
	}
	r, err = run("move", `{"board":"`+novel+`","id":"`+note+`","toBoard":"`+research+`"}`, false)
	if err != nil || parent(f.element(note)) != research || r.Undo == nil {
		t.Fatalf("move %v %v", err, f.element(note))
	}
	if _, err := run(r.Undo.Action, string(r.Undo.Input), false); err != nil || normalize(f.element(note)["location"]).(map[string]any)["parentId"] != novel {
		t.Fatalf("move undo %v %v", err, f.element(note))
	}
	if got := normalize(f.element(note)["location"]); !equalJSON(got, orig) {
		t.Fatalf("move undo location %v, want %v", got, orig)
	}
	if _, err := run("move", `{"board":"`+novel+`","id":"`+research+`","toBoard":"`+research+`"}`, false); err == nil {
		t.Fatal("a board moved into itself")
	}
	if _, err := run("move", `{"board":"`+novel+`","id":"`+note+`","toColumn":"`+column+`"}`, false); err != nil || parent(f.element(note)) != column {
		t.Fatalf("move into column %v", err)
	}

	// archive: preview, trash, undo restores
	r, err = run("archive", `{"board":"`+novel+`","ids":["`+newID+`"]}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 1 || section(f, newID) != "INBOX" {
		t.Fatalf("archive preview %+v %v", r.Plan, err)
	}
	r, err = run("archive", `{"board":"`+novel+`","ids":["`+newID+`"]}`, false)
	if err != nil || section(f, newID) != "TRASH" || parent(f.element(newID)) != novel+"-trash" || r.Undo == nil || r.Undo.Action != "restore" {
		t.Fatalf("archive %v %v", err, f.element(newID))
	}
	if _, err := run(r.Undo.Action, string(r.Undo.Input), false); err != nil || section(f, newID) != "INBOX" || parent(f.element(newID)) != novel {
		t.Fatalf("restore %v %v", err, f.element(newID))
	}

	// delete only takes what is in the trash
	if _, err := run("delete", `{"ids":["`+newID+`"]}`, false); err == nil || !strings.Contains(err.Error(), "archive it first") {
		t.Fatalf("delete outside trash %v", err)
	}
	if _, err := run("archive", `{"board":"`+novel+`","ids":["`+newID+`"]}`, false); err != nil {
		t.Fatal(err)
	}
	if r, err = run("delete", `{"ids":["`+newID+`"]}`, true); err != nil || r.Plan == nil || f.element(newID) == nil {
		t.Fatalf("delete preview %v", err)
	}
	if r, err = run("delete", `{"ids":["`+newID+`"]}`, false); err != nil || f.element(newID) != nil || r.Undo != nil {
		t.Fatalf("delete %v", err)
	}

	// export both ways
	x := call("export", "export", `{"board":"`+novel+`"}`)
	if x["via"] != "conduit" || !strings.Contains(x["markdown"].(string), "# Novel") {
		t.Fatalf("export %v", x)
	}
	x = call("export milanote", "export", `{"board":"`+novel+`","via":"milanote"}`)
	if x["markdown"] != "# Novel\n\nMaya finds the letter\n" || !strings.HasSuffix(x["fileUrl"].(string), novel+".md") {
		t.Fatalf("export milanote %v", x)
	}

	// Milanote signs the session out: the module signs in again by itself
	f.expireAll()
	if _, err := run("board", `{"board":"`+novel+`"}`, false); err != nil {
		t.Fatalf("after expiry %v", err)
	}
	if _, err := run("add_note", `{"board":"`+novel+`","text":"after re-auth"}`, false); err != nil {
		t.Fatalf("write after expiry %v", err)
	}
	f.mu.Lock()
	logins, pongs := f.logins, f.pongs
	f.mu.Unlock()
	if logins != 2 || pongs == 0 {
		t.Fatalf("logins %d pongs %d", logins, pongs)
	}
}

func section(f *fake, id string) string {
	return f.element(id)["location"].(map[string]any)["section"].(string)
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func TestSessionCookie(t *testing.T) {
	f := newFake(t)
	f.sessions["tok-1"] = true
	for _, pasted := range []string{"tok-1", sessionCookie + "=tok-1", "other=1; " + sessionCookie + "=tok-1"} {
		m, run := setup(t, f, Config{SessionCookie: "secret://mn-cookie"}, map[string]string{"secret://mn-cookie": pasted})
		if h := m.Health(context.Background(), "mn"); h.Status != "ok" {
			t.Fatalf("%q: health %+v", pasted, h)
		}
		if _, err := run("add_note", `{"board":"`+novel+`","text":"from a cookie"}`, false); err != nil {
			t.Fatalf("%q: write %v", pasted, err)
		}
	}
	m, _ := setup(t, f, Config{SessionCookie: "secret://mn-cookie"}, map[string]string{"secret://mn-cookie": "tok-1"})
	f.expireAll()
	if h := m.Health(context.Background(), "mn"); h.Status != "down" || !strings.Contains(h.Message, "session cookie has expired") {
		t.Fatalf("expired cookie health %+v", h)
	}
	if f.logins != 0 {
		t.Fatal("signed in without a password")
	}

	// With a password as well, an expired cookie falls back to signing in.
	f.sessions["tok-2"] = true
	cfg, secrets := passwordConfig()
	cfg.SessionCookie, secrets["secret://mn-cookie"] = "secret://mn-cookie", "tok-2"
	m, _ = setup(t, f, cfg, secrets)
	if h := m.Health(context.Background(), "mn"); h.Status != "ok" {
		t.Fatal(h)
	}
	f.expireAll()
	if h := m.Health(context.Background(), "mn"); h.Status != "ok" || f.logins != 1 {
		t.Fatalf("fallback %+v logins %d", h, f.logins)
	}
}

func TestHealthMessages(t *testing.T) {
	cases := []struct {
		mode, password, status, want string
	}{
		{"", "wrong", "down", "sign-in failed: Milanote refused the email or password: Incorrect email or password"},
		{"captcha", "hunter2", "down", "browser check"},
		{"waf", "hunter2", "down", "browser check"},
		{"html", "hunter2", "down", "Milanote changed its web app — the module needs an update"},
		{"limit", "hunter2", "degraded", "rate limiting"},
	}
	for _, c := range cases {
		f := newFake(t)
		f.mode = c.mode
		cfg, secrets := passwordConfig()
		secrets["secret://mn-pw"] = c.password
		m, _ := setup(t, f, cfg, secrets)
		h := m.Health(context.Background(), "mn")
		if h.Status != c.status || !strings.Contains(h.Message, c.want) {
			t.Errorf("%s/%s: %+v", c.mode, c.password, h)
		}
	}
	if h := New().Health(context.Background(), "x"); h.Status != "unconfigured" {
		t.Fatal(h)
	}
}

func TestConfigure(t *testing.T) {
	h := fakehost.New(nil)
	for _, raw := range []string{
		`{}`,
		`{"email":"ana@example.com","password":"hunter2"}`,
		`{"email":"nope","password":"secret://pw"}`,
		`{"sessionCookie":"raw-cookie"}`,
		`{"url":"http://milanote.example.com","sessionCookie":"secret://c"}`,
		`{"url":"https://app.milanote.com/api","sessionCookie":"secret://c"}`,
		`{"sessionCookie":"secret://c","timezone":"Mars/Olympus"}`,
	} {
		if err := New().Configure(context.Background(), h, "x", json.RawMessage(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, raw := range []string{
		`{"sessionCookie":"secret://c"}`,
		`{"email":"ana@example.com","password":"secret://pw","timezone":"Europe/Berlin"}`,
		`{"url":"http://127.0.0.1:8080","sessionCookie":"secret://c"}`,
	} {
		if err := New().Configure(context.Background(), h, "x", json.RawMessage(raw)); err != nil {
			t.Errorf("refused %s: %v", raw, err)
		}
	}
}

func TestRichText(t *testing.T) {
	doc := `{"type":"doc","content":[
		{"type":"heading","attrs":{"level":2},"content":[{"type":"text","text":"Plan"}]},
		{"type":"paragraph","content":[{"type":"text","text":"see "},{"type":"text","text":"site","marks":[{"type":"link","attrs":{"href":"https://x.test"}}]}]},
		{"type":"bulletList","content":[{"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"one"}]}]},{"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"two"}]}]}]},
		{"type":"orderedList","content":[{"type":"listItem","content":[{"type":"paragraph","content":[{"type":"text","text":"first"}]}]}]}]}`
	if got := renderRich(json.RawMessage(doc), true); got != "## Plan\n\nsee [site](https://x.test)\n\n- one\n- two\n\n1. first" {
		t.Errorf("markdown %q", got)
	}
	if got := renderRich(json.RawMessage(doc), false); got != "Plan\nsee site\n- one\n- two\n1. first" {
		t.Errorf("plain %q", got)
	}
	if got := renderRich(json.RawMessage(`{"blocks":[{"text":"a"},{"text":"b"}]}`), false); got != "a\nb" {
		t.Errorf("draft %q", got)
	}
	if base62(0) != "0" || base62(62) != "10" || base62(61) != "Z" {
		t.Error("base62")
	}
}

func TestPacing(t *testing.T) {
	f := newFake(t)
	cfg, secrets := passwordConfig()
	cfg.URL = f.srv.URL
	m := New()
	m.HTTP = f.srv.Client()
	m.MinInterval = 30 * time.Millisecond
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(secrets), "mn", raw); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for range 3 {
		if _, err := m.Invoke(context.Background(), sdk.Call{Instance: "mn", Action: "board", Input: json.RawMessage(`{"board":"` + novel + `"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	// sign-in + 3 board loads = 4 requests, so at least 3 gaps
	if time.Since(start) < 90*time.Millisecond {
		t.Fatalf("requests were not spaced: %v", time.Since(start))
	}
}
