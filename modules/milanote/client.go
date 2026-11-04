package milanote

// This file is the only place that knows Milanote's private web API: URLs,
// headers, cookies, JSON shapes, the rich-text document format and the
// socket.io write channel. Milanote does not publish this API and changes it
// without notice; when the module breaks, fix it here and bump WireVersion.
//
// Sources (see docs/modules/milanote.md):
//   - Milanote's own web bundle (app.milanote.com/login, main-*.js): the sign-in
//     call POST /api/auth/login {email, password, recaptchaToken, platform},
//     the legacy bearer token in its answer, the Better Auth session cookie,
//     the AWS WAF challenge header and the ELEMENT_DELETE action.
//   - milanote-api-mcp 1.0.4 (PyPI, recorded 18.10.2026): users/me, board
//     load, search, trash, export, link preview, and the socket.io actions
//     ELEMENT_CREATE / ELEMENT_UPDATE / ELEMENT_MOVE_MULTI / ELEMENT_SET_TYPE.
//   - milanote-unofficial-api 1.0.0 (PyPI): the older element shapes ("id",
//     Draft.js "blocks", separate TASK elements), still read here.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WireVersion dates the snapshot of Milanote's web API this file speaks.
const WireVersion = "2026-10-18"

const (
	defaultBase   = "https://app.milanote.com"
	sessionCookie = "__Secure-milanote.session_token" // Better Auth session
	xsrfCookie    = "XSRF-TOKEN"                      // not seen at Milanote; echoed if it ever appears
	wireLocale    = "en-au"
	maxBody       = 16 << 20
	ackPolls      = 3 // long polls to wait for a write's ack (the server holds each up to ~25 s)
)

var (
	errSignIn       = errors.New("sign-in failed")
	errChanged      = errors.New("Milanote changed its web app — the module needs an update")
	errBlocked      = errors.New("Milanote asked for a browser check (reCAPTCHA or firewall challenge); use a session cookie copied from your browser instead")
	errLimited      = errors.New("Milanote is rate limiting this account; try again in a few minutes")
	errNotFound     = errors.New("Milanote has no such board, or this account can't see it")
	errCookieDead   = errors.New("the session cookie has expired or was signed out; copy a fresh one from your browser")
	errUnauthorized = errors.New("signed out") // internal: a 401 before re-auth
)

func changed(detail string) error {
	return fmt.Errorf("%w (wire format %s: %s)", errChanged, WireVersion, detail)
}

// client is one signed-in Milanote session.
type client struct {
	base   *url.URL
	http   *http.Client
	gap    time.Duration // minimum time between two requests
	tz     string
	creds  func(ctx context.Context) (email, password string, err error) // nil: no password sign-in
	cookie func(ctx context.Context) (string, error)                     // nil: no session cookie

	gate sync.Mutex // one request at a time, at least gap apart
	last time.Time

	auth       sync.Mutex // one sign-in at a time
	mu         sync.Mutex // guards the fields below
	jar        map[string]string
	bearer     string
	ready      bool
	fromCookie bool
	cookieDead bool
	user       *User
	tick       int64
}

// User is the signed-in account.
type User struct {
	ID        string
	Email     string
	Name      string
	RootBoard string
	ClientID  string
}

func (c *client) origin() string { return c.base.Scheme + "://" + c.base.Host }

func (c *client) boardURL(id string) string { return c.origin() + "/" + id }

type reply struct {
	status int
	header http.Header
	body   []byte
}

// send makes one request, politely spaced from the last. With creds it adds
// the session's cookies, bearer token and the Origin/Referer the web app
// sends (Better Auth checks Origin on state-changing requests), and keeps
// the cookies the answer sets.
func (c *client) send(ctx context.Context, method, rawURL string, body []byte, ctype, accept string, creds bool) (*reply, error) {
	c.gate.Lock()
	defer c.gate.Unlock()
	if wait := c.gap - time.Since(c.last); wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	defer func() { c.last = time.Now() }()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Conduit-Milanote/"+moduleVersion)
	req.Header.Set("Accept", accept)
	req.Header.Set("Cache-Control", "no-cache")
	if body != nil {
		req.Header.Set("Content-Type", ctype)
	}
	if creds {
		req.Header.Set("Origin", c.origin())
		req.Header.Set("Referer", c.origin()+"/")
		c.mu.Lock()
		if len(c.jar) > 0 {
			names := make([]string, 0, len(c.jar))
			for n := range c.jar {
				names = append(names, n)
			}
			sort.Strings(names)
			parts := make([]string, len(names))
			for i, n := range names {
				parts[i] = n + "=" + c.jar[n]
			}
			req.Header.Set("Cookie", strings.Join(parts, "; "))
		}
		if v := c.jar[xsrfCookie]; v != "" && method != http.MethodGet {
			if u, err := url.QueryUnescape(v); err == nil {
				v = u
			}
			req.Header.Set("X-XSRF-TOKEN", v)
		}
		if c.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+c.bearer)
		}
		c.mu.Unlock()
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Milanote did not answer: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if creds {
		c.mu.Lock()
		for _, ck := range res.Cookies() {
			if c.jar == nil {
				c.jar = map[string]string{}
			}
			if ck.MaxAge < 0 || ck.Value == "" {
				delete(c.jar, ck.Name)
			} else {
				c.jar[ck.Name] = ck.Value
			}
		}
		c.mu.Unlock()
	}
	return &reply{status: res.StatusCode, header: res.Header, body: raw}, nil
}

// classify turns an answer's status into one of the module's errors.
func classify(r *reply) error {
	if r.header.Get("X-Amzn-Waf-Action") != "" {
		return errBlocked
	}
	head := strings.ToLower(string(r.body[:min(len(r.body), 20000)]))
	switch s := r.status; {
	case s == http.StatusUnauthorized:
		return errUnauthorized
	case s >= 300 && s < 400:
		if strings.Contains(r.header.Get("Location"), "/login") {
			return errUnauthorized
		}
		return changed("unexpected redirect to " + r.header.Get("Location"))
	case s == http.StatusTooManyRequests:
		return errLimited
	case s == http.StatusNotFound:
		return errNotFound
	case s == http.StatusForbidden && (strings.Contains(head, "captcha") || strings.Contains(head, "challenge")):
		return errBlocked
	case s >= 500:
		return fmt.Errorf("Milanote is having trouble (%d)", s)
	case s >= 400:
		return fmt.Errorf("Milanote refused the request (%d%s)", s, errText(r.body))
	}
	return nil
}

func errText(body []byte) string {
	var e struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	var inner struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	}
	var s string
	switch {
	case json.Unmarshal(e.Error, &s) == nil && s != "":
	case json.Unmarshal(e.Error, &inner) == nil && (inner.Message != "" || inner.Code != ""):
		s = inner.Message
		if s == "" {
			s = inner.Code
		}
	default:
		s = e.Message
	}
	if s == "" {
		return ""
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return ": " + s
}

// api calls a JSON endpoint under the app's origin, signing in first and
// once more after a 401 when a password is set.
func (c *client) api(ctx context.Context, method, path string, q url.Values, in, out any) error {
	u := c.origin() + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		if err := c.ensure(ctx); err != nil {
			return err
		}
		r, err := c.send(ctx, method, u, body, "application/json", "application/json", true)
		if err != nil {
			return err
		}
		err = classify(r)
		if errors.Is(err, errUnauthorized) {
			c.drop()
			if attempt == 0 && c.creds != nil {
				continue
			}
			return c.signedOut()
		}
		if err != nil {
			return err
		}
		return decode(r.body, out, path)
	}
}

func decode(body []byte, out any, what string) error {
	if out == nil {
		return nil
	}
	t := bytes.TrimSpace(body)
	if len(t) == 0 {
		return changed(what + " answered with nothing")
	}
	if t[0] == '<' {
		return changed(what + " answered with a web page instead of data")
	}
	if err := json.Unmarshal(t, out); err != nil {
		return changed(what + ": " + err.Error())
	}
	return nil
}

func (c *client) signedOut() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.creds == nil && c.cookie != nil {
		return errCookieDead
	}
	return fmt.Errorf("%w: Milanote signed the session out and signing in again did not help", errSignIn)
}

// drop forgets the session after a 401.
func (c *client) drop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fromCookie {
		c.cookieDead = true
	}
	c.jar, c.bearer, c.ready, c.user = nil, "", false, nil
}

// ensure makes sure there is a session: the configured cookie, or a fresh
// sign-in with the email and password.
func (c *client) ensure(ctx context.Context) error {
	c.mu.Lock()
	ready := c.ready
	c.mu.Unlock()
	if ready {
		return nil
	}
	c.auth.Lock()
	defer c.auth.Unlock()
	c.mu.Lock()
	ready, dead := c.ready, c.cookieDead
	c.mu.Unlock()
	if ready {
		return nil
	}
	if c.cookie != nil && !dead {
		v, err := c.cookie(ctx)
		if err != nil {
			return err
		}
		pairs := cookiePairs(v)
		if len(pairs) == 0 {
			return errors.New("the session cookie setting is empty")
		}
		c.mu.Lock()
		c.jar, c.ready, c.fromCookie = pairs, true, true
		c.mu.Unlock()
		return nil
	}
	if c.creds != nil {
		return c.signIn(ctx)
	}
	return errCookieDead
}

// cookiePairs reads what the owner pasted: the session cookie's value, or
// "name=value; name2=value2" as copied from a Cookie request header.
func cookiePairs(v string) map[string]string {
	v = strings.TrimSpace(v)
	if len(v) > 7 && strings.EqualFold(v[:7], "cookie:") {
		v = strings.TrimSpace(v[7:])
	}
	if v == "" {
		return nil
	}
	if !strings.HasPrefix(v, sessionCookie+"=") && !strings.Contains(v, "; ") {
		return map[string]string{sessionCookie: v}
	}
	out := map[string]string{}
	for _, part := range strings.Split(v, ";") {
		name, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && name != "" && val != "" && !strings.ContainsAny(name, " \t\r\n") {
			out[name] = val
		}
	}
	return out
}

// signIn posts the email and password as the web app's sign-in form does.
// The browser adds a reCAPTCHA v3 token; Conduit cannot make one and sends
// null, so Milanote may refuse (the error then says to use a cookie).
func (c *client) signIn(ctx context.Context) error {
	email, pw, err := c.creds(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.jar, c.bearer = nil, ""
	c.mu.Unlock()
	body, _ := json.Marshal(map[string]any{
		"email": strings.ToLower(strings.TrimSpace(email)), "password": pw,
		"recaptchaToken": nil, "platform": "web",
	})
	r, err := c.send(ctx, http.MethodPost, c.origin()+"/api/auth/login", body, "application/json", "application/json", true)
	if err != nil {
		return fmt.Errorf("%w: %v", errSignIn, err)
	}
	if err := classify(r); err != nil {
		low := strings.ToLower(string(r.body))
		switch {
		case errors.Is(err, errBlocked), strings.Contains(low, "recaptcha"), strings.Contains(low, "captcha"):
			return fmt.Errorf("%w: %w", errSignIn, errBlocked)
		case errors.Is(err, errLimited):
			return fmt.Errorf("%w: %w", errSignIn, errLimited)
		case errors.Is(err, errChanged), errors.Is(err, errNotFound):
			return changed("the sign-in form moved")
		case r.status >= 400 && r.status < 500:
			return fmt.Errorf("%w: Milanote refused the email or password%s", errSignIn, errText(r.body))
		}
		return fmt.Errorf("%w: %v", errSignIn, err)
	}
	var out struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(r.body, &out)
	c.mu.Lock()
	defer c.mu.Unlock()
	if out.Token != "" {
		c.bearer = out.Token
	}
	if c.bearer == "" && len(c.jar) == 0 {
		return changed("sign-in answered without a session cookie or token")
	}
	c.ready, c.fromCookie = true, false
	return nil
}

// me asks who is signed in: GET /api/users/me.
func (c *client) me(ctx context.Context) (*User, error) {
	var out struct {
		User *struct {
			ID          string          `json:"_id"`
			Email       string          `json:"email"`
			Name        json.RawMessage `json:"name"`
			RootBoardID string          `json:"rootBoardId"`
			ClientID    string          `json:"clientId"`
			ClientTick  json.Number     `json:"clientTick"`
		} `json:"user"`
	}
	if err := c.api(ctx, http.MethodGet, "/api/users/me", nil, nil, &out); err != nil {
		return nil, err
	}
	if out.User == nil || out.User.ID == "" {
		return nil, changed("/api/users/me has no user")
	}
	if out.User.RootBoardID == "" {
		return nil, changed("/api/users/me has no rootBoardId")
	}
	var name string
	if json.Unmarshal(out.User.Name, &name) != nil {
		var n struct {
			DisplayName string `json:"displayName"`
		}
		_ = json.Unmarshal(out.User.Name, &n)
		name = n.DisplayName
	}
	u := &User{ID: out.User.ID, Email: out.User.Email, Name: name, RootBoard: out.User.RootBoardID, ClientID: out.User.ClientID}
	if u.ClientID == "" {
		u.ClientID = randomBase62(6)
	}
	tick, _ := out.User.ClientTick.Int64()
	c.mu.Lock()
	c.user = u
	if tick > c.tick {
		c.tick = tick
	}
	c.mu.Unlock()
	return u, nil
}

func (c *client) currentUser(ctx context.Context) (*User, error) {
	c.mu.Lock()
	u := c.user
	c.mu.Unlock()
	if u != nil {
		return u, nil
	}
	return c.me(ctx)
}

// ---- elements ----

// Element is one thing on a board, normalized from Milanote's shapes.
type Element struct {
	ID       string
	Kind     string // note, link, todo, task, board, column, image, file, comment, ...
	WireType string // Milanote's elementType, e.g. CARD
	Parent   string
	Section  string // canvas, unsorted, trash (Milanote's CANVAS, INBOX, TRASH)
	Column   string // set by loadBoard for cards inside a column
	Title    string
	Text     string // plain text
	Markdown string // the same text as Markdown
	URL      string
	Tasks    []Task
	Done     bool // older separate TASK elements
	Modified time.Time

	x, y, score float64
	location    json.RawMessage
	content     json.RawMessage
}

// Task is one item of a to-do list.
type Task struct {
	ID   string `json:"id"`
	Text string `json:"text"`
	Done bool   `json:"done"`
}

var kinds = map[string]string{
	"CARD": "note", "LINK": "link", "IMAGE": "image", "FILE": "file", "TASK_LIST": "todo", "TASK": "task",
	"BOARD": "board", "ALIAS": "board", "COLUMN": "column", "COMMENT_THREAD": "comment", "DOCUMENT": "document",
	"SKETCH": "sketch", "COLOR_SWATCH": "color", "ANNOTATION": "annotation",
}

func parseElement(raw json.RawMessage) (Element, error) {
	var w struct {
		ID          string          `json:"_id"`
		LegacyID    string          `json:"id"`
		ElementType string          `json:"elementType"`
		Location    json.RawMessage `json:"location"`
		Content     json.RawMessage `json:"content"`
		Meta        struct {
			Modified json.Number `json:"modifiedTime"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return Element{}, changed("element: " + err.Error())
	}
	e := Element{ID: w.ID, WireType: w.ElementType, location: w.Location, content: w.Content}
	if e.ID == "" {
		e.ID = w.LegacyID
	}
	if e.ID == "" || e.WireType == "" {
		return Element{}, changed("element without _id or elementType")
	}
	if e.Kind = kinds[e.WireType]; e.Kind == "" {
		e.Kind = strings.ToLower(e.WireType)
	}
	if ms, err := w.Meta.Modified.Int64(); err == nil && ms > 0 {
		e.Modified = time.UnixMilli(ms).UTC()
	}
	var loc struct {
		ParentID string                     `json:"parentId"`
		Section  string                     `json:"section"`
		Position map[string]json.RawMessage `json:"position"`
	}
	_ = json.Unmarshal(w.Location, &loc)
	e.Parent = loc.ParentID
	switch loc.Section {
	case "", "CANVAS":
		e.Section = "canvas"
	case "INBOX":
		e.Section = "unsorted"
	default:
		e.Section = strings.ToLower(loc.Section)
	}
	num := func(k string) float64 {
		var f float64
		_ = json.Unmarshal(loc.Position[k], &f)
		return f
	}
	e.x, e.y, e.score = num("x"), num("y"), num("score")
	if _, ok := loc.Position["score"]; !ok {
		e.score = num("index")
	}

	var ct map[string]json.RawMessage
	_ = json.Unmarshal(w.Content, &ct)
	str := func(raw json.RawMessage) string {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		return renderRich(raw, false)
	}
	type sub struct {
		URL      string `json:"url"`
		Title    string `json:"title"`
		Original string `json:"original"`
		Filename string `json:"filename"`
	}
	field := func(k string) (o sub) {
		_ = json.Unmarshal(ct[k], &o)
		return
	}
	text := ct["textContent"]
	switch e.Kind {
	case "note", "document", "annotation":
		e.Text, e.Markdown = renderRich(text, false), renderRich(text, true)
	case "link":
		l := field("link")
		e.URL, e.Title = l.URL, l.Title
		if e.URL == "" {
			e.URL = str(ct["url"])
		}
		e.Text = renderRich(ct["caption"], false)
		e.Markdown = e.Text
	case "todo":
		e.Title = taskListTitle(text)
		if e.Title == "" {
			var show bool
			_ = json.Unmarshal(ct["showTitle"], &show)
			if show {
				e.Title = str(ct["title"])
			}
		}
		e.Tasks = tasksOf(text)
	case "task":
		e.Text = renderRich(text, false)
		_ = json.Unmarshal(ct["isComplete"], &e.Done)
	case "board", "column":
		e.Title = str(ct["title"])
		if e.Title == "" {
			e.Title = str(ct["originalTitle"])
		}
	case "image":
		e.URL = field("image").Original
		e.Title = field("file").Filename
	case "file":
		f := field("file")
		e.Title, e.URL = f.Filename, f.URL
	default:
		e.Text, e.Markdown = renderRich(text, false), renderRich(text, true)
	}
	return e, nil
}

// Board is a board with every element Milanote sent for it.
type Board struct {
	Self     Element
	All      map[string]Element
	Children []Element // on the board or in its columns, not in the trash, in reading order
}

// loadBoard is the web app's own board load:
// GET /api/boards?excludeSelf=false&loadAncestors=false&ids=<id>.
func (c *client) loadBoard(ctx context.Context, id string) (*Board, error) {
	var out struct {
		Elements map[string]json.RawMessage `json:"elements"`
		Errors   map[string]struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		} `json:"errors"`
	}
	q := url.Values{"excludeSelf": {"false"}, "loadAncestors": {"false"}, "ids": {id}}
	if err := c.api(ctx, http.MethodGet, "/api/boards", q, nil, &out); err != nil {
		return nil, err
	}
	if e, ok := out.Errors[id]; ok {
		if e.Error.Code == "BOARD_NOT_FOUND" || e.Error.Code == "" {
			return nil, errNotFound
		}
		return nil, fmt.Errorf("Milanote won't open that board (%s)", e.Error.Code)
	}
	if out.Elements == nil {
		return nil, changed("board load has no elements")
	}
	if _, ok := out.Elements[id]; !ok {
		return nil, errNotFound
	}
	b := &Board{All: map[string]Element{}}
	for _, raw := range out.Elements {
		e, err := parseElement(raw)
		if err != nil {
			return nil, err
		}
		b.All[e.ID] = e
	}
	b.Self = b.All[id]
	switch b.Self.WireType {
	case "BOARD":
	case "SKELETON":
		return nil, errors.New("this account can't open that board")
	default:
		return nil, fmt.Errorf("%s is a %s, not a board", id, b.Self.Kind)
	}
	cols := map[string]bool{}
	for _, e := range b.All {
		if e.Kind == "column" && e.Parent == id && e.Section != "trash" {
			cols[e.ID] = true
		}
	}
	lists := map[string]int{}
	for _, e := range b.All {
		if e.ID == id || e.Section == "trash" || (e.Parent != id && !cols[e.Parent]) {
			continue
		}
		if e.Parent != id {
			e.Column = e.Parent
		}
		b.Children = append(b.Children, e)
	}
	sort.SliceStable(b.Children, func(i, j int) bool { return before(b.Children[i], b.Children[j]) })
	for i, e := range b.Children {
		if e.Kind == "todo" {
			lists[e.ID] = i
		}
	}
	// Older to-do lists keep each task as its own TASK element inside the list.
	var tasks []Element
	for _, e := range b.All {
		if _, ok := lists[e.Parent]; ok && e.Kind == "task" && e.Section != "trash" {
			tasks = append(tasks, e)
		}
	}
	sort.SliceStable(tasks, func(i, j int) bool { return before(tasks[i], tasks[j]) })
	for _, t := range tasks {
		i := lists[t.Parent]
		b.Children[i].Tasks = append(b.Children[i].Tasks, Task{ID: t.ID, Text: t.Text, Done: t.Done})
	}
	return b, nil
}

func before(a, b Element) bool {
	if a.Section != b.Section {
		return a.Section == "canvas"
	}
	if a.Section == "canvas" && a.Column == "" && b.Column == "" {
		if a.y != b.y {
			return a.y < b.y
		}
		return a.x < b.x
	}
	if a.score != b.score {
		return a.score < b.score
	}
	return a.ID < b.ID
}

// SearchHit is a board that matched a search.
type SearchHit struct {
	Board    string        `json:"board"`
	Title    string        `json:"title"`
	URL      string        `json:"url"`
	Path     []string      `json:"path,omitempty"`
	Modified string        `json:"modified,omitempty"`
	Matches  []SearchMatch `json:"matches,omitempty"`
}

// SearchMatch is one card inside a matching board.
type SearchMatch struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Snippet string `json:"snippet"`
}

// search is GET /api/boards/search; sort is "viewed" or "modified".
func (c *client) search(ctx context.Context, query, sortBy string) (int, []SearchHit, error) {
	var out struct {
		Total   *int `json:"total"`
		Results []struct {
			ID    string `json:"_id"`
			Board struct {
				ID      string `json:"_id"`
				Content struct {
					Title string `json:"title"`
				} `json:"content"`
			} `json:"board"`
			Ancestors []struct {
				Title string `json:"title"`
			} `json:"ancestors"`
			Modified  json.Number `json:"modifiedTime"`
			InnerHits []struct {
				ID          string   `json:"_id"`
				ElementType string   `json:"elementType"`
				Content     []string `json:"content"`
			} `json:"innerHits"`
		} `json:"results"`
	}
	q := url.Values{"query": {query}, "offset": {"0"}, "sort": {sortBy}, "locale": {wireLocale}}
	if err := c.api(ctx, http.MethodGet, "/api/boards/search", q, nil, &out); err != nil {
		return 0, nil, err
	}
	if out.Results == nil && out.Total == nil {
		return 0, nil, changed("search answer has no results")
	}
	hits := []SearchHit{}
	for _, r := range out.Results {
		id := r.ID
		if id == "" {
			id = r.Board.ID
		}
		h := SearchHit{Board: id, Title: r.Board.Content.Title, URL: c.boardURL(id)}
		for _, a := range r.Ancestors {
			h.Path = append(h.Path, a.Title)
		}
		if ms, err := r.Modified.Int64(); err == nil && ms > 0 {
			h.Modified = time.UnixMilli(ms).UTC().Format(time.RFC3339)
		}
		for _, m := range r.InnerHits {
			kind := kinds[m.ElementType]
			if kind == "" {
				kind = strings.ToLower(m.ElementType)
			}
			snip := strings.NewReplacer("[hit]", "", "[/hit]", "").Replace(strings.Join(m.Content, " "))
			h.Matches = append(h.Matches, SearchMatch{ID: m.ID, Type: kind, Snippet: snip})
		}
		hits = append(hits, h)
	}
	total := len(hits)
	if out.Total != nil {
		total = *out.Total
	}
	return total, hits, nil
}

// trash lists the account's trash: GET /api/users/me/trash?other-users=false.
func (c *client) trash(ctx context.Context) (map[string]Element, error) {
	var out struct {
		Elements map[string]json.RawMessage `json:"elements"`
	}
	if err := c.api(ctx, http.MethodGet, "/api/users/me/trash", url.Values{"other-users": {"false"}}, nil, &out); err != nil {
		return nil, err
	}
	if out.Elements == nil {
		return nil, changed("trash answer has no elements")
	}
	all := map[string]Element{}
	for _, raw := range out.Elements {
		e, err := parseElement(raw)
		if err != nil {
			return nil, err
		}
		all[e.ID] = e
	}
	return all, nil
}

// exportMarkdown asks Milanote's export service for a board as Markdown, the
// Export menu's "Markdown": POST /media-service/api/export/<id>, then fetch
// the fileUrl it answers with.
func (c *client) exportMarkdown(ctx context.Context, id string) (string, string, error) {
	body := map[string]any{
		"format": "linear", "fileType": "text/markdown; charset=UTF-8", "includeChildBoards": false,
		"permissionId": nil, "locale": wireLocale, "timezone": c.tz, "emojiStyle": "twitter",
	}
	var out struct {
		FileURL string `json:"fileUrl"`
	}
	if err := c.api(ctx, http.MethodPost, "/media-service/api/export/"+url.PathEscape(id), nil, body, &out); err != nil {
		return "", "", err
	}
	if out.FileURL == "" {
		return "", "", changed("export answer has no fileUrl")
	}
	u, err := url.Parse(out.FileURL)
	host := ""
	if err == nil {
		host = strings.ToLower(u.Hostname())
	}
	same := err == nil && u.Host == c.base.Host && u.Scheme == c.base.Scheme
	if !same && (err != nil || u.Scheme != "https" || (host != "milanote.com" && !strings.HasSuffix(host, ".milanote.com"))) {
		return "", "", changed("export file is outside milanote.com")
	}
	r, err := c.send(ctx, http.MethodGet, u.String(), nil, "", "text/markdown, text/plain, */*", same)
	if err != nil {
		return "", "", err
	}
	if err := classify(r); err != nil {
		return "", "", fmt.Errorf("Milanote made the export but the file did not open: %w", err)
	}
	return out.FileURL, string(r.body), nil
}

// ---- rich text (ProseMirror documents; older Draft.js "blocks") ----

type richNode struct {
	Type    string                     `json:"type"`
	Text    string                     `json:"text"`
	Attrs   map[string]json.RawMessage `json:"attrs"`
	Content []richNode                 `json:"content"`
	Marks   []struct {
		Type  string `json:"type"`
		Attrs struct {
			Href string `json:"href"`
		} `json:"attrs"`
	} `json:"marks"`
	Blocks []struct {
		Text string `json:"text"`
	} `json:"blocks"`
}

func renderRich(raw json.RawMessage, md bool) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n richNode
	if json.Unmarshal(raw, &n) != nil {
		return ""
	}
	if len(n.Blocks) > 0 {
		lines := make([]string, len(n.Blocks))
		for i, b := range n.Blocks {
			lines[i] = b.Text
		}
		return strings.Join(lines, "\n")
	}
	return strings.Trim(block(n, md), "\n")
}

func block(n richNode, md bool) string {
	sep := "\n"
	if md {
		sep = "\n\n"
	}
	kids := func(join string) string {
		var parts []string
		for _, k := range n.Content {
			if t := block(k, md); t != "" {
				parts = append(parts, t)
			}
		}
		return strings.Join(parts, join)
	}
	switch n.Type {
	case "doc", "blockquote":
		t := kids(sep)
		if n.Type == "blockquote" && md {
			t = "> " + strings.ReplaceAll(t, "\n", "\n> ")
		}
		return t
	case "paragraph", "taskListTitle":
		return inline(n.Content, md)
	case "heading":
		t := inline(n.Content, md)
		if md {
			var lvl int
			_ = json.Unmarshal(n.Attrs["level"], &lvl)
			t = strings.Repeat("#", max(1, min(lvl, 6))) + " " + t
		}
		return t
	case "bulletList", "orderedList", "taskList":
		var lines []string
		for i, item := range n.Content {
			mark := "- "
			switch {
			case n.Type == "orderedList":
				mark = strconv.Itoa(i+1) + ". "
			case item.Type == "taskItem":
				var done bool
				_ = json.Unmarshal(item.Attrs["checked"], &done)
				mark = "- [ ] "
				if done {
					mark = "- [x] "
				}
			}
			body := strings.Join(itemLines(item, md), "\n  ")
			lines = append(lines, mark+body)
		}
		return strings.Join(lines, "\n")
	case "codeBlock":
		t := inline(n.Content, false)
		if md {
			t = "```\n" + t + "\n```"
		}
		return t
	case "horizontalRule":
		if md {
			return "---"
		}
		return ""
	case "text", "hardBreak":
		return inline([]richNode{n}, md)
	}
	if len(n.Content) > 0 {
		return kids(sep)
	}
	return ""
}

func itemLines(item richNode, md bool) []string {
	var out []string
	for _, k := range item.Content {
		if t := block(k, md); t != "" {
			out = append(out, strings.Split(t, "\n")...)
		}
	}
	return out
}

func inline(ns []richNode, md bool) string {
	var b strings.Builder
	for _, n := range ns {
		switch n.Type {
		case "hardBreak":
			b.WriteString("\n")
			continue
		case "text":
		default:
			b.WriteString(inline(n.Content, md))
			continue
		}
		t := n.Text
		if md {
			for _, m := range n.Marks {
				switch m.Type {
				case "bold", "strong":
					t = "**" + t + "**"
				case "italic", "em":
					t = "*" + t + "*"
				case "code":
					t = "`" + t + "`"
				case "strike", "strikethrough":
					t = "~~" + t + "~~"
				case "link":
					if m.Attrs.Href != "" {
						t = "[" + t + "](" + m.Attrs.Href + ")"
					}
				}
			}
		}
		b.WriteString(t)
	}
	return b.String()
}

func taskListTitle(raw json.RawMessage) string {
	var n richNode
	if json.Unmarshal(raw, &n) != nil {
		return ""
	}
	for _, k := range n.Content {
		if k.Type == "taskListTitle" {
			return inline(k.Content, false)
		}
	}
	return ""
}

func tasksOf(raw json.RawMessage) []Task {
	var n richNode
	if json.Unmarshal(raw, &n) != nil {
		return nil
	}
	var out []Task
	var walk func(richNode)
	walk = func(n richNode) {
		if n.Type == "taskItem" {
			t := Task{Text: strings.Join(itemLines(n, false), "\n")}
			_ = json.Unmarshal(n.Attrs["taskId"], &t.ID)
			_ = json.Unmarshal(n.Attrs["checked"], &t.Done)
			out = append(out, t)
			return
		}
		for _, k := range n.Content {
			walk(k)
		}
	}
	walk(n)
	return out
}

// plainDoc is plain text as Milanote's rich-text document, one paragraph a line.
func plainDoc(text string) map[string]any {
	var paras []any
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			paras = append(paras, map[string]any{"type": "paragraph"})
		} else {
			paras = append(paras, map[string]any{"type": "paragraph", "content": []any{map[string]any{"type": "text", "text": line}}})
		}
	}
	return map[string]any{"type": "doc", "content": paras}
}

// noteContent is a new note's content.
func noteContent(text string) map[string]any { return map[string]any{"textContent": plainDoc(text)} }

// noteChanges replaces a note's text; raw, when set, is an earlier
// textContent restored as it was (undo).
func noteChanges(text string, raw json.RawMessage) map[string]any {
	if len(raw) > 0 {
		return map[string]any{"textContent": raw}
	}
	return map[string]any{"textContent": plainDoc(text)}
}

// noteDoc returns a note's textContent, for undo.
func noteDoc(e Element) json.RawMessage {
	var ct map[string]json.RawMessage
	_ = json.Unmarshal(e.content, &ct)
	return ct["textContent"]
}

// todoContent is a new to-do list (V2: tasks live in the list's document).
func todoContent(title string, items []string) (map[string]any, []Task) {
	var nodes []any
	var tasks []Task
	for _, text := range items {
		id := "task-" + randomBase62(13)
		nodes = append(nodes, map[string]any{
			"type": "taskItem",
			"attrs": map[string]any{
				"taskId": id, "checked": false, "dueDate": nil, "assignments": []any{}, "labels": []any{},
				"reactions": []any{}, "showAssignments": false, "showDueDate": false,
			},
			"content": []any{map[string]any{"type": "paragraph", "content": []any{map[string]any{"type": "text", "text": text}}}},
		})
		tasks = append(tasks, Task{ID: id, Text: text})
	}
	var doc []any
	if title != "" {
		doc = append(doc, map[string]any{"type": "taskListTitle", "content": []any{map[string]any{"type": "text", "text": title}}})
	}
	doc = append(doc, map[string]any{"type": "taskList", "content": nodes})
	return map[string]any{
		"title": nil, "showTitle": false, "version": "V2",
		"textContent": map[string]any{"type": "doc", "attrs": map[string]any{"hiddenTaskListTitle": nil}, "content": doc},
	}, tasks
}

var errNoTask = errors.New("no task in this list has that id or text")

// checkTask ticks one task, found by id or exact text, keeping everything
// else in the list's document as it was. It returns the changes and the
// task's id and state before.
func checkTask(e Element, wanted string, done bool) (map[string]any, Task, error) {
	if e.WireType != "TASK_LIST" {
		return nil, Task{}, errors.New("that card isn't a to-do list")
	}
	var ct map[string]any
	if err := json.Unmarshal(e.content, &ct); err != nil {
		return nil, Task{}, changed("to-do list content")
	}
	doc, ok := ct["textContent"].(map[string]any)
	if !ok {
		return nil, Task{}, errors.New("this is an older kind of to-do list the module can't tick yet")
	}
	var found []map[string]any
	var prev []Task
	var walk func(any)
	walk = func(v any) {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		if m["type"] == "taskItem" {
			attrs, _ := m["attrs"].(map[string]any)
			if attrs == nil {
				attrs = map[string]any{}
				m["attrs"] = attrs
			}
			b, _ := json.Marshal(m)
			var n richNode
			_ = json.Unmarshal(b, &n)
			text := strings.TrimSpace(strings.Join(itemLines(n, false), "\n"))
			id, _ := attrs["taskId"].(string)
			if wanted == id || wanted == text {
				was, _ := attrs["checked"].(bool)
				found = append(found, attrs)
				prev = append(prev, Task{ID: id, Text: text, Done: was})
			}
			return
		}
		if kids, ok := m["content"].([]any); ok {
			for _, k := range kids {
				walk(k)
			}
		}
	}
	walk(doc)
	switch len(found) {
	case 0:
		return nil, Task{}, errNoTask
	case 1:
	default:
		return nil, Task{}, errors.New("several tasks have that text; give the task's id")
	}
	found[0]["checked"] = done
	return map[string]any{"textContent": doc}, prev[0], nil
}

// ---- locations ----

// topOf is the top of a board's Unsorted panel, or of a column: where the web
// app puts cards added from outside, so they never cover the canvas.
func topOf(b *Board, parent string) json.RawMessage {
	top := 0.0
	for _, e := range b.Children {
		if e.Parent == parent && (e.Section == "unsorted" || e.Column != "") {
			top = math.Min(top, e.score)
		}
	}
	loc, _ := json.Marshal(map[string]any{"parentId": parent, "section": "INBOX", "position": map[string]any{"index": 0, "score": top - 1}})
	return loc
}

// restoreTarget is where a card in the trash came from.
func restoreTarget(e Element) (json.RawMessage, error) {
	var loc struct {
		Position struct {
			Restore json.RawMessage `json:"restoreLocation"`
		} `json:"position"`
	}
	_ = json.Unmarshal(e.location, &loc)
	var back struct {
		ParentID string `json:"parentId"`
	}
	if json.Unmarshal(loc.Position.Restore, &back) != nil || back.ParentID == "" {
		return nil, errors.New("Milanote doesn't know where " + e.ID + " came from")
	}
	return loc.Position.Restore, nil
}

// locationParent reads parentId out of a raw location.
func locationParent(raw json.RawMessage) string {
	var l struct {
		ParentID string `json:"parentId"`
	}
	_ = json.Unmarshal(raw, &l)
	return l.ParentID
}

// ---- writes: socket.io (Engine.IO 4) over HTTP long polling ----

// The web app sends every change as an "action" event on its socket.io
// connection and waits for the ack [{"status":200}]. The same server answers
// the polling transport, so plain requests work: open (GET), connect
// (POST "40"), one POST "42<n>[...]" per action, then GETs until "43<n>".
type syncConn struct {
	c       *client
	user    *User
	url     string
	ack     int
	sent    int
	device  string
	session string
}

const packetSep = "\x1e"

func (c *client) openSync(ctx context.Context) (*syncConn, error) {
	u, err := c.currentUser(ctx)
	if err != nil {
		return nil, err
	}
	now := base62(time.Now().Unix())
	s := &syncConn{c: c, user: u, device: "mdid-" + now + randomBase62(4), session: "msid-" + now + randomBase62(4)}
	s.url = c.origin() + "/socket.io/?" + url.Values{"userId": {u.ID}, "EIO": {"4"}, "transport": {"polling"}}.Encode()
	packets, err := s.get(ctx)
	if err != nil {
		return nil, err
	}
	var open struct {
		SID string `json:"sid"`
	}
	if len(packets) == 0 || !strings.HasPrefix(packets[0], "0") || json.Unmarshal([]byte(packets[0][1:]), &open) != nil || open.SID == "" {
		return nil, changed("socket.io handshake")
	}
	s.url += "&sid=" + url.QueryEscape(open.SID)
	if err := s.post(ctx, "40"); err != nil {
		return nil, err
	}
	for range ackPolls {
		packets, err := s.get(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range packets {
			switch {
			case strings.HasPrefix(p, "40"):
				return s, nil
			case strings.HasPrefix(p, "44"):
				return nil, fmt.Errorf("Milanote refused the live connection%s", errText([]byte(p[2:])))
			case p == "2":
				if err := s.post(ctx, "3"); err != nil {
					return nil, err
				}
			}
		}
	}
	return nil, changed("socket.io connect was not confirmed")
}

func (s *syncConn) get(ctx context.Context) ([]string, error) {
	r, err := s.c.send(ctx, http.MethodGet, s.url, nil, "", "*/*", true)
	if err != nil {
		return nil, err
	}
	if err := classify(r); err != nil {
		return nil, err
	}
	return strings.Split(string(r.body), packetSep), nil
}

func (s *syncConn) post(ctx context.Context, packet string) error {
	r, err := s.c.send(ctx, http.MethodPost, s.url, []byte(packet), "text/plain;charset=UTF-8", "*/*", true)
	if err != nil {
		return err
	}
	return classify(r)
}

func (s *syncConn) close(ctx context.Context) { _ = s.post(ctx, "1") }

// emit sends one action stamped the way the web app stamps them, and waits
// for Milanote's ack.
func (s *syncConn) emit(ctx context.Context, action map[string]any, channels []string) error {
	s.c.mu.Lock()
	tick := s.c.tick
	s.c.mu.Unlock()
	action["sync"] = true
	action["user"] = map[string]any{"_id": s.user.ID, "clientId": s.user.ClientID, "clientTick": tick}
	action["tokens"] = []any{}
	action["deviceId"] = s.device
	action["sessionId"] = s.session
	action["channels"] = channels
	b, err := json.Marshal([]any{"action", action})
	if err != nil {
		return err
	}
	n := strconv.Itoa(s.ack)
	s.ack++
	if err := s.post(ctx, "42"+n+string(b)); err != nil {
		return err
	}
	s.sent++
	prefix := "43" + n + "["
	for range ackPolls {
		packets, err := s.get(ctx)
		if err != nil {
			return err
		}
		for _, p := range packets {
			switch {
			case p == "2":
				if err := s.post(ctx, "3"); err != nil {
					return err
				}
			case strings.HasPrefix(p, prefix):
				var ack []struct {
					Status json.Number `json:"status"`
				}
				if json.Unmarshal([]byte(p[len(prefix)-1:]), &ack) != nil || len(ack) == 0 {
					return changed("unreadable ack")
				}
				if ack[0].Status != "200" {
					return fmt.Errorf("Milanote rejected the change (status %s)", ack[0].Status)
				}
				return nil
			case strings.HasPrefix(p, "41"), p == "1":
				return errors.New("Milanote closed the live connection")
			}
		}
	}
	return errors.New("Milanote did not confirm the change in time; check the board before trying again")
}

// write runs fn on a fresh sync connection. A 401 before anything was sent
// signs in again (with a password) and starts over; after that a write is
// never repeated, so a change can't land twice.
func (c *client) write(ctx context.Context, fn func(s *syncConn) error) error {
	for attempt := 0; ; attempt++ {
		if err := c.ensure(ctx); err != nil {
			return err
		}
		s, err := c.openSync(ctx)
		if err == nil {
			err = fn(s)
			s.close(ctx)
		}
		if errors.Is(err, errUnauthorized) {
			c.drop()
			if attempt == 0 && c.creds != nil && (s == nil || s.sent == 0) {
				continue
			}
			return c.signedOut()
		}
		return err
	}
}

// newID makes an element id the way the web app does: base62 seconds, the
// client id from /api/users/me and a per-client counter.
func (s *syncConn) newID() string {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	s.c.tick++
	return base62(time.Now().Unix()) + s.user.ClientID + base62(s.c.tick)
}

func nowMS() int64 { return time.Now().UnixMilli() }

func (s *syncConn) create(ctx context.Context, wireType string, loc json.RawMessage, content map[string]any) (string, error) {
	return s.createAs(ctx, s.newID(), wireType, loc, content)
}

func (s *syncConn) createAs(ctx context.Context, id, wireType string, loc json.RawMessage, content map[string]any) (string, error) {
	now := nowMS()
	parent := locationParent(loc)
	err := s.emit(ctx, map[string]any{
		"type": "ELEMENT_CREATE", "id": id, "elementType": wireType, "location": loc, "content": content,
		"meta": map[string]any{
			"creator": s.user.ID, "modifiedBy": s.user.ID, "createdTime": now, "modifiedTime": now,
			"platform": "Desktop web", "locationSectionModifiedTime": now,
		},
		"timestamp": now, "creationSource": "TOOLBAR", "markAsFetched": true,
		"activity": map[string]any{"track": false, "boardId": parent},
	}, []string{parent})
	return id, err
}

func (s *syncConn) update(ctx context.Context, board, id string, changes map[string]any) error {
	return s.emit(ctx, map[string]any{
		"type": "ELEMENT_UPDATE", "updates": []any{map[string]any{"id": id, "changes": changes}},
		"timestamp": nowMS(), "recalculateChannels": false,
		"activity": map[string]any{"track": false, "boardId": board},
	}, []string{board})
}

// Move is one element moved from one location to another.
type Move struct {
	ID   string
	To   json.RawMessage
	From json.RawMessage
}

// move is drag and drop (operation DROP), to the trash (TRASH) or back.
func (s *syncConn) move(ctx context.Context, moves []Move, operation string) error {
	chans := map[string]bool{}
	var list []any
	for _, m := range moves {
		for _, loc := range []json.RawMessage{m.To, m.From} {
			if p := strings.TrimSuffix(locationParent(loc), "-trash"); p != "" {
				chans[p] = true
			}
		}
		list = append(list, map[string]any{"id": m.ID, "location": m.To, "from": m.From})
	}
	channels := make([]string, 0, len(chans))
	for c := range chans {
		channels = append(channels, c)
	}
	sort.Strings(channels)
	return s.emit(ctx, map[string]any{
		"type": "ELEMENT_MOVE_MULTI", "moves": list, "timestamp": nowMS(), "moveOperation": operation,
		"monitoring": map[string]any{"operation": operation}, "activity": map[string]any{"track": false},
	}, channels)
}

// trashMove is what the Delete key does: into the board's trash, with the
// location to restore to.
func trashMove(e Element) Move {
	to, _ := json.Marshal(map[string]any{
		"parentId": e.Parent + "-trash", "section": "TRASH",
		"position": map[string]any{"addedDate": nowMS(), "restoreLocation": e.location},
	})
	return Move{ID: e.ID, To: to, From: e.location}
}

// fromHere is a move of e from where it is now.
func fromHere(e Element, to json.RawMessage) Move { return Move{ID: e.ID, To: to, From: e.location} }

// addLink makes a link card as the web app does: Milanote's link preview
// first (POST /media-service/api/link), then an empty LINK and an
// ELEMENT_SET_TYPE with the preview, so an unreadable link leaves no card.
func (s *syncConn) addLink(ctx context.Context, board string, loc json.RawMessage, link string) (string, string, error) {
	id := s.newID()
	var p struct {
		Link        map[string]any `json:"link"`
		Image       any            `json:"image"`
		MediaType   string         `json:"mediaType"`
		Provider    any            `json:"provider"`
		Description string         `json:"description"`
		ElementType string         `json:"elementType"`
	}
	body := map[string]any{"url": link, "elementId": id, "environmentFolder": "p", "userId": s.user.ID, "locale": wireLocale}
	if err := s.c.api(ctx, http.MethodPost, "/media-service/api/link", nil, body, &p); err != nil {
		return "", "", err
	}
	made, err := s.createAs(ctx, id, "LINK", loc, map[string]any{"url": nil})
	if err != nil {
		return "", "", err
	}
	if p.Link == nil {
		p.Link = map[string]any{"url": link}
	}
	if p.Image == nil {
		p.Image = map[string]any{}
	}
	if p.Provider == nil {
		p.Provider = map[string]any{}
	}
	if p.MediaType == "" {
		p.MediaType = "NO_MEDIA"
	}
	if p.ElementType == "" {
		p.ElementType = "LINK"
	}
	changes := map[string]any{"image": p.Image, "mediaType": p.MediaType, "link": p.Link, "provider": p.Provider}
	if p.Description != "" {
		changes["caption"] = plainDoc(p.Description)
		changes["showCaption"] = true
	}
	err = s.emit(ctx, map[string]any{
		"type": "ELEMENT_SET_TYPE", "id": made, "elementType": p.ElementType, "changes": changes,
		"timestamp": nowMS(), "activity": map[string]any{"track": false, "boardId": board},
	}, []string{board})
	title, _ := p.Link["title"].(string)
	return made, title, err
}

// deleteForever removes an element for good: ELEMENT_DELETE, field names as
// in Milanote's web bundle ({type, id, location, elementType, sync}).
func (s *syncConn) deleteForever(ctx context.Context, e Element) error {
	board := strings.TrimSuffix(e.Parent, "-trash")
	return s.emit(ctx, map[string]any{
		"type": "ELEMENT_DELETE", "id": e.ID, "location": e.location, "elementType": e.WireType,
		"timestamp": nowMS(),
	}, []string{board})
}

// ---- ids ----

const alphabet62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func base62(n int64) string {
	if n <= 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{alphabet62[n%62]}, b...)
		n /= 62
	}
	return string(b)
}

func randomBase62(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet62[int(b[i])%62]
	}
	return string(b)
}
