package milanote

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fake is Milanote's web API as client.go understands it: sign-in with a
// session cookie (Better Auth style, Origin-checked), users/me, the board
// load, search, trash, export, link preview, and the socket.io polling
// channel that carries writes.
type fake struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	password string
	sessions map[string]bool
	logins   int
	elements map[string]map[string]any
	queues   map[string][]string
	actions  []string
	pongs    int
	xsrf     bool   // set an XSRF-TOKEN cookie at sign-in and require it on POSTs
	mode     string // "", "captcha", "waf", "limit", "html"
	nextSID  int
	clients  map[string]bool
}

const (
	home     = "1HomeBoard00001"
	novel    = "1ProjBoard00001"
	research = "1SubBoard000001"
	column   = "1ColumnAa00001"
	inColumn = "1InColumn00001"
	note     = "1NoteCard000001"
	todo     = "1TodoList00001"
	link     = "1LinkCard00001"
	legacy   = "1LegacyNote001"
)

func el(id, typ, parent, section string, pos map[string]any, content map[string]any) map[string]any {
	return map[string]any{
		"_id": id, "elementType": typ,
		"location": map[string]any{"parentId": parent, "section": section, "position": pos},
		"content":  content, "meta": map[string]any{"modifiedTime": 1792310400000},
	}
}

func text(s string) map[string]any { return map[string]any{"type": "text", "text": s} }

func para(nodes ...any) map[string]any { return map[string]any{"type": "paragraph", "content": nodes} }

func newFake(t *testing.T) *fake {
	f := &fake{t: t, password: "hunter2", sessions: map[string]bool{}, queues: map[string][]string{}, elements: map[string]map[string]any{}}
	add := func(e map[string]any) { f.elements[e["_id"].(string)] = e }
	add(el(home, "BOARD", "", "CANVAS", nil, map[string]any{"title": "Home"}))
	add(el(novel, "BOARD", home, "CANVAS", map[string]any{"x": 0, "y": 0}, map[string]any{"title": "Novel"}))
	add(el(research, "BOARD", novel, "CANVAS", map[string]any{"x": 400, "y": 0}, map[string]any{"title": "Research"}))
	add(el(note, "CARD", novel, "CANVAS", map[string]any{"x": 0, "y": 10}, map[string]any{"textContent": map[string]any{"type": "doc", "content": []any{
		para(text("Maya finds the "), map[string]any{"type": "text", "text": "letter", "marks": []any{map[string]any{"type": "bold"}}}),
	}}}))
	add(el(column, "COLUMN", novel, "CANVAS", map[string]any{"x": 0, "y": 20}, map[string]any{"title": "Ideas"}))
	add(el(inColumn, "CARD", column, "INBOX", map[string]any{"index": 0, "score": 1}, map[string]any{"textContent": map[string]any{"type": "doc", "content": []any{para(text("Ferry scene"))}}}))
	add(el(todo, "TASK_LIST", novel, "CANVAS", map[string]any{"x": 0, "y": 30}, map[string]any{"version": "V2", "textContent": map[string]any{"type": "doc", "content": []any{
		map[string]any{"type": "taskListTitle", "content": []any{text("Edits")}},
		map[string]any{"type": "taskList", "content": []any{
			map[string]any{"type": "taskItem", "attrs": map[string]any{"taskId": "task-aaa", "checked": false}, "content": []any{para(text("Rewrite act one"))}},
			map[string]any{"type": "taskItem", "attrs": map[string]any{"taskId": "task-bbb", "checked": true}, "content": []any{para(text("Pick ferry"))}},
		}},
	}}}))
	add(el(link, "LINK", novel, "CANVAS", map[string]any{"x": 0, "y": 40}, map[string]any{"link": map[string]any{"url": "https://example.com", "title": "Example"}}))
	add(el(legacy, "CARD", novel, "INBOX", map[string]any{"index": 0, "score": 3}, map[string]any{"textContent": map[string]any{"blocks": []any{map[string]any{"text": "old note"}}}}))
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fake) expireAll() {
	f.mu.Lock()
	f.sessions = map[string]bool{}
	f.mu.Unlock()
}

func (f *fake) element(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.elements[id]
	if e == nil {
		return nil
	}
	b, _ := json.Marshal(e)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch f.mode {
	case "waf":
		w.Header().Set("X-Amzn-Waf-Action", "challenge")
		w.WriteHeader(http.StatusAccepted)
		return
	case "limit":
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/export/") {
		io.WriteString(w, "# Novel\n\nMaya finds the letter\n")
		return
	}
	if r.Method == http.MethodPost && r.Header.Get("Origin") != f.srv.URL {
		f.reply(w, 403, map[string]any{"error": "Invalid origin"})
		return
	}
	if r.URL.Path == "/api/auth/login" {
		f.login(w, r)
		return
	}
	ck, err := r.Cookie(sessionCookie)
	if err != nil || !f.sessions[ck.Value] {
		f.reply(w, 401, map[string]any{"error": map[string]any{"message": "Unauthorized"}})
		return
	}
	if f.xsrf && r.Method == http.MethodPost {
		x, err := r.Cookie(xsrfCookie)
		if err != nil || r.Header.Get("X-XSRF-TOKEN") != x.Value {
			f.reply(w, 403, map[string]any{"error": "CSRF token mismatch"})
			return
		}
	}
	if r.URL.Path == "/socket.io/" {
		f.socket(w, r)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/users/me":
		if f.mode == "html" {
			io.WriteString(w, "<!doctype html><title>Milanote</title>")
			return
		}
		f.reply(w, 200, map[string]any{"user": map[string]any{"_id": "u1", "email": "ana@example.com", "name": map[string]any{"displayName": "Ana Lopez"},
			"rootBoardId": home, "clientId": f.newClient(), "clientTick": 5}})
	case "GET /api/boards":
		q := r.URL.Query()
		id := q.Get("ids")
		if q.Get("excludeSelf") != "false" || q.Get("loadAncestors") != "false" {
			f.reply(w, 400, map[string]any{"error": "bad query"})
			return
		}
		self := f.elements[id]
		if self == nil {
			f.reply(w, 200, map[string]any{"elements": map[string]any{}, "errors": map[string]any{id: map[string]any{"error": map[string]any{"code": "BOARD_NOT_FOUND"}}}})
			return
		}
		out := map[string]any{id: self}
		cols := map[string]bool{}
		for eid, e := range f.elements {
			if parent(e) == id && e["elementType"] == "COLUMN" {
				cols[eid] = true
			}
		}
		for eid, e := range f.elements {
			if p := parent(e); p == id || cols[p] {
				out[eid] = e
			}
		}
		f.reply(w, 200, map[string]any{"elements": out, "comments": map[string]any{}})
	case "GET /api/boards/search":
		q := strings.ToLower(r.URL.Query().Get("query"))
		byBoard := map[string][]any{}
		for eid, e := range f.elements {
			if e["elementType"] != "CARD" {
				continue
			}
			b, _ := json.Marshal(e["content"])
			if strings.Contains(strings.ToLower(string(b)), q) {
				p := parent(e)
				if f.elements[p] != nil && f.elements[p]["elementType"] == "COLUMN" {
					p = parent(f.elements[p])
				}
				byBoard[p] = append(byBoard[p], map[string]any{"_id": eid, "elementType": "CARD", "content": []any{"[hit]" + q + "[/hit] scene"}})
			}
		}
		var results []any
		for bid, hits := range byBoard {
			results = append(results, map[string]any{"_id": bid, "board": map[string]any{"content": f.elements[bid]["content"]},
				"ancestors": []any{map[string]any{"title": "Home"}}, "modifiedTime": 1792310400000, "innerHits": hits})
		}
		f.reply(w, 200, map[string]any{"total": len(results), "results": results})
	case "GET /api/users/me/trash":
		out := map[string]any{}
		for eid, e := range f.elements {
			if e["location"].(map[string]any)["section"] == "TRASH" {
				out[eid] = e
			}
		}
		f.reply(w, 200, map[string]any{"elements": out})
	case "POST /media-service/api/link":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["userId"] != "u1" || b["elementId"] == "" || b["environmentFolder"] != "p" {
			f.reply(w, 400, map[string]any{"error": "bad link request"})
			return
		}
		f.reply(w, 200, map[string]any{"link": map[string]any{"url": b["url"], "title": "Example Domain"}, "mediaType": "NO_MEDIA", "description": "An example page"})
	default:
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/media-service/api/export/") {
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["format"] != "linear" || !strings.HasPrefix(b["fileType"].(string), "text/markdown") {
				f.reply(w, 400, map[string]any{"error": "bad export"})
				return
			}
			f.reply(w, 200, map[string]any{"fileUrl": f.srv.URL + "/export/" + strings.TrimPrefix(r.URL.Path, "/media-service/api/export/") + ".md"})
			return
		}
		f.reply(w, 404, map[string]any{"error": "not found"})
	}
}

func parent(e map[string]any) string {
	l, _ := e["location"].(map[string]any)
	p, _ := l["parentId"].(string)
	return p
}

func (f *fake) login(w http.ResponseWriter, r *http.Request) {
	var b map[string]any
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		f.reply(w, 400, map[string]any{"error": "bad body"})
		return
	}
	if _, ok := b["recaptchaToken"]; !ok || b["platform"] == nil {
		f.reply(w, 400, map[string]any{"error": "missing fields"})
		return
	}
	if f.mode == "captcha" {
		f.reply(w, 400, map[string]any{"error": map[string]any{"message": "reCAPTCHA verification failed"}})
		return
	}
	if b["email"] != "ana@example.com" || b["password"] != f.password {
		f.reply(w, 401, map[string]any{"error": map[string]any{"message": "Incorrect email or password"}})
		return
	}
	f.logins++
	tok := "sess-" + strconv.Itoa(f.logins)
	f.sessions[tok] = true
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	if f.xsrf {
		http.SetCookie(w, &http.Cookie{Name: xsrfCookie, Value: "x-" + tok, Path: "/"})
	}
	f.reply(w, 200, map[string]any{"user": map[string]any{"_id": "u1"}})
}

func (f *fake) socket(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("userId") != "u1" || q.Get("EIO") != "4" || q.Get("transport") != "polling" {
		w.WriteHeader(400)
		return
	}
	sid := q.Get("sid")
	if sid == "" {
		f.nextSID++
		sid = "S" + strconv.Itoa(f.nextSID)
		f.queues[sid] = nil
		io.WriteString(w, `0{"sid":"`+sid+`","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}`)
		return
	}
	if _, ok := f.queues[sid]; !ok {
		w.WriteHeader(400)
		io.WriteString(w, `{"code":1,"message":"Session ID unknown"}`)
		return
	}
	if r.Method == http.MethodGet {
		packets := f.queues[sid]
		f.queues[sid] = nil
		if len(packets) == 0 {
			packets = []string{"6"}
		}
		io.WriteString(w, strings.Join(packets, packetSep))
		return
	}
	body, _ := io.ReadAll(r.Body)
	for _, p := range strings.Split(string(body), packetSep) {
		switch {
		case p == "40":
			f.queues[sid] = append(f.queues[sid], "2", `40{"sid":"io-`+sid+`"}`) // a ping first, to be answered
		case p == "3":
			f.pongs++
		case p == "1":
			delete(f.queues, sid)
		case strings.HasPrefix(p, "42"):
			i := 2
			for i < len(p) && p[i] >= '0' && p[i] <= '9' {
				i++
			}
			n := p[2:i]
			var ev []json.RawMessage
			status := 200
			var action map[string]any
			if json.Unmarshal([]byte(p[i:]), &ev) != nil || len(ev) != 2 || string(ev[0]) != `"action"` || json.Unmarshal(ev[1], &action) != nil {
				status = 400
			} else {
				status = f.apply(action)
			}
			f.queues[sid] = append(f.queues[sid], "43"+n+`[{"status":`+strconv.Itoa(status)+`}]`)
		}
	}
	io.WriteString(w, "ok")
}

// apply runs one action as Milanote's sync server would and returns the ack status.
func (f *fake) apply(a map[string]any) int {
	user, _ := a["user"].(map[string]any)
	chans, _ := a["channels"].([]any)
	if a["sync"] != true || user["_id"] != "u1" || !f.clients[str(user["clientId"])] || len(chans) == 0 {
		return 400
	}
	typ, _ := a["type"].(string)
	f.actions = append(f.actions, typ)
	merge := func(id string, changes map[string]any) int {
		e := f.elements[id]
		if e == nil {
			return 404
		}
		ct, _ := e["content"].(map[string]any)
		if ct == nil {
			ct = map[string]any{}
			e["content"] = ct
		}
		for k, v := range changes {
			ct[k] = v
		}
		return 200
	}
	switch typ {
	case "ELEMENT_CREATE":
		id, _ := a["id"].(string)
		if !strings.Contains(id, str(user["clientId"])) || f.elements[id] != nil || a["elementType"] == nil {
			return 400
		}
		f.elements[id] = map[string]any{"_id": id, "elementType": a["elementType"], "location": a["location"], "content": a["content"], "meta": a["meta"]}
	case "ELEMENT_UPDATE":
		ups, _ := a["updates"].([]any)
		for _, u := range ups {
			m := u.(map[string]any)
			if s := merge(m["id"].(string), m["changes"].(map[string]any)); s != 200 {
				return s
			}
		}
	case "ELEMENT_SET_TYPE":
		id, _ := a["id"].(string)
		if f.elements[id] == nil {
			return 404
		}
		f.elements[id]["elementType"] = a["elementType"]
		return merge(id, a["changes"].(map[string]any))
	case "ELEMENT_MOVE_MULTI":
		moves, _ := a["moves"].([]any)
		for _, mv := range moves {
			m := mv.(map[string]any)
			e := f.elements[m["id"].(string)]
			if e == nil {
				return 404
			}
			if !reflect.DeepEqual(normalize(e["location"]), normalize(m["from"])) {
				return 409
			}
			e["location"] = m["location"]
		}
	case "ELEMENT_DELETE":
		id, _ := a["id"].(string)
		e := f.elements[id]
		if e == nil || e["location"].(map[string]any)["section"] != "TRASH" || a["elementType"] != e["elementType"] {
			return 403
		}
		delete(f.elements, id)
	default:
		return 400
	}
	return 200
}

func normalize(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

// newClient hands out a fresh client id, as Milanote does on every users/me.
func (f *fake) newClient() string {
	if f.clients == nil {
		f.clients = map[string]bool{}
	}
	id := "cl" + strconv.Itoa(1000+len(f.clients))
	f.clients[id] = true
	return id
}

func str(v any) string { s, _ := v.(string); return s }
