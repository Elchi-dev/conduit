// Package bluesky works with a Bluesky account (or any AT Protocol PDS)
// through XRPC with an app password: profile, home timeline, notifications,
// posting with link, mention and hashtag facets, replying, deleting a post
// and searching posts.
//
// The module logs in with com.atproto.server.createSession and keeps the
// session in memory, refreshing it when the access token expires. Only app
// passwords are accepted: an account's main password can change its email,
// handle and password, which nothing here needs.
package bluesky

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one account.
type Config struct {
	Service    string `json:"service"`    // PDS, default https://bsky.social
	Identifier string `json:"identifier"` // handle or email
	Password   string `json:"password"`   // secret:// app password
}

const (
	defaultService = "https://bsky.social"
	maxGraphemes   = 300
	postCollection = "app.bsky.feed.post"
)

type session struct {
	access, refresh, did, handle string
}

type conn struct {
	h        sdk.Host
	base     string // https://bsky.social/xrpc
	http     *http.Client
	ident    string
	password string

	mu   sync.Mutex
	sess *session
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Bluesky module.
func New() *Module { return &Module{} }

func (m *Module) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

var (
	appPasswordRe = regexp.MustCompile(`^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$`)
	didRe         = regexp.MustCompile(`^did:[a-z]+:[A-Za-z0-9._:%-]{1,1000}$`)
	handleRe      = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	postURIRe     = regexp.MustCompile(`^at://(did:[a-z]+:[A-Za-z0-9._:%-]{1,1000})/app\.bsky\.feed\.post/([A-Za-z0-9._~:-]{1,512})$`)
	cidRe         = regexp.MustCompile(`^[A-Za-z0-9]{8,128}$`)
	langRe        = regexp.MustCompile(`^[a-zA-Z]{2,3}(-[A-Za-z0-9]{1,8}){0,3}$`)
	identRe       = regexp.MustCompile(`^[^\s\x00-\x1f\x7f]{3,254}$`)

	linkRe    = regexp.MustCompile(`https?://[^\s<>"'` + "`" + `]+`)
	mentionRe = regexp.MustCompile(`(?:^|[\s(])(@(([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))`)
	tagRe     = regexp.MustCompile(`(?:^|\s)(#[^\s#\x{FE0F}\x{20E3}]+)`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := `"limit":{"type":"integer","default":20,"minimum":1,"maximum":100}`
	text := `"text":{"type":"string","description":"Up to 300 characters (graphemes). Links, @handle mentions and #hashtags become rich text."},"langs":{"type":"array","items":{"type":"string"},"maxItems":3,"description":"Language tags, e.g. en"}`
	return sdk.Manifest{
		ID: "bluesky", Name: "Bluesky", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "Your Bluesky account (or another AT Protocol server): profile, timeline, notifications, post, reply, delete and search posts.",
		Presets:     []string{"team", "gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["identifier","password"],"properties":{
			"service":{"type":"string","default":"https://bsky.social","description":"Your PDS; https://bsky.social for accounts hosted by Bluesky"},
			"identifier":{"type":"string","description":"Your handle (e.g. alice.bsky.social) or account email"},
			"password":{"type":"string","x-secret":true,"description":"An app password (Settings, Privacy and security, App passwords), like abcd-efgh-ijkl-mnop. Your main password is refused."}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "profile", Title: "Profile", Description: "A profile's handle, name, bio and follower, following and post counts; yours when no actor is given.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"actor":{"type":"string","description":"Handle or DID (default: you)"}}}`)},
			{Name: "timeline", Title: "Timeline", Description: "Your home timeline, newest first, with reposts marked.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit + `}}`)},
			{Name: "notifications", Title: "Notifications", Description: "Likes, reposts, follows, mentions, replies and quotes, newest first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit + `}}`)},
			{Name: "post", Title: "Post", Description: "Posts to your public feed, for anyone to see; mentioned accounts are notified. Destructive because it publishes and reaches strangers. The preview lists the accounts it mentions. Undo deletes the post.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["text"],"properties":{` + text + `}}`)},
			{Name: "reply", Title: "Reply", Description: "Replies publicly to a post, in its thread; its author and mentioned accounts are notified. Destructive because it publishes and reaches strangers. The preview names the author and the accounts it mentions. Undo deletes the reply.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["uri","text"],"properties":{"uri":{"type":"string","description":"at:// URI of the post to reply to"},` + text + `}}`)},
			{Name: "delete", Title: "Delete a post", Description: "Deletes one of your posts for good, with its likes and reposts. The preview quotes it.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["uri"],"properties":{"uri":{"type":"string","description":"at:// URI of your post"}}}`)},
			{Name: "search", Title: "Search posts", Description: "Searches public posts.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string","maxLength":300},"sort":{"type":"string","enum":["latest","top"],"default":"latest"},` + limit + `}}`)},
		},
	}
}

func baseURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = defaultService
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("the service is your PDS address, like https://bsky.social")
	}
	return u.Scheme + "://" + u.Host, nil
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	base, err := baseURL(c.Service)
	if err != nil {
		return err
	}
	ident := strings.TrimPrefix(strings.TrimSpace(c.Identifier), "@")
	if !identRe.MatchString(ident) {
		return errors.New("the identifier is your handle (alice.bsky.social) or account email")
	}
	if !strings.HasPrefix(c.Password, "secret://") {
		return errors.New("store the app password in the vault and enter its secret:// reference")
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 20*time.Second)
	}
	m.set.Put(id, &conn{h: h, base: base + "/xrpc", http: rest.SameHostOnly(hc), ident: ident, password: c.Password})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// xrpc makes one call with the given bearer token ("" for none).
func (c *conn) xrpc(ctx context.Context, method, nsid string, q url.Values, body any, bearer string, out any) error {
	api := &rest.Client{Base: c.base, HTTP: c.http, Header: http.Header{}}
	if bearer != "" {
		api.Auth = func(_ context.Context, r *http.Request) error {
			r.Header.Set("Authorization", "Bearer "+bearer)
			return nil
		}
	}
	_, err := api.Do(ctx, method, "/"+nsid, q, body, out)
	return err
}

func expired(err error) bool {
	var e *rest.Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Status == http.StatusUnauthorized || (e.Status == http.StatusBadRequest && strings.Contains(strings.ToLower(e.Message), "expired"))
}

type sessionOut struct {
	AccessJwt  string `json:"accessJwt"`
	RefreshJwt string `json:"refreshJwt"`
	DID        string `json:"did"`
	Handle     string `json:"handle"`
}

func (s sessionOut) valid() (*session, error) {
	if s.AccessJwt == "" || !didRe.MatchString(s.DID) {
		return nil, errors.New("unexpected answer to the login from the server")
	}
	return &session{access: s.AccessJwt, refresh: s.RefreshJwt, did: s.DID, handle: s.Handle}, nil
}

// login creates a session with the app password.
func (c *conn) login(ctx context.Context) (*session, error) {
	pw, err := c.h.Secret(ctx, c.password)
	if err != nil {
		return nil, err
	}
	pw = strings.TrimSpace(pw)
	if !appPasswordRe.MatchString(pw) {
		return nil, errors.New("the password isn't an app password (like abcd-efgh-ijkl-mnop); make one in Settings, Privacy and security, App passwords")
	}
	var out sessionOut
	if err := c.xrpc(ctx, http.MethodPost, "com.atproto.server.createSession", nil, map[string]string{"identifier": c.ident, "password": pw}, "", &out); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) || rest.IsStatus(err, http.StatusBadRequest) {
			return nil, errors.New("the server refused the handle or app password")
		}
		return nil, err
	}
	return out.valid()
}

// session returns the current session, logging in when there's none.
func (c *conn) session(ctx context.Context) (*session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != nil {
		return c.sess, nil
	}
	s, err := c.login(ctx)
	if err != nil {
		return nil, err
	}
	c.sess = s
	return s, nil
}

// renew replaces an expired session: refreshSession first, a new login when
// the refresh token is gone too.
func (c *conn) renew(ctx context.Context, old *session) (*session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != nil && c.sess != old {
		return c.sess, nil // another call renewed it
	}
	c.sess = nil
	if old != nil && old.refresh != "" {
		var out sessionOut
		if err := c.xrpc(ctx, http.MethodPost, "com.atproto.server.refreshSession", nil, nil, old.refresh, &out); err == nil {
			if s, err := out.valid(); err == nil {
				c.sess = s
				return s, nil
			}
		}
	}
	s, err := c.login(ctx)
	if err != nil {
		return nil, err
	}
	c.sess = s
	return s, nil
}

// call makes an authenticated XRPC call, renewing the session once.
func (c *conn) call(ctx context.Context, method, nsid string, q url.Values, body, out any) (*session, error) {
	s, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	err = c.xrpc(ctx, method, nsid, q, body, s.access, out)
	if expired(err) {
		if s, err = c.renew(ctx, s); err != nil {
			return nil, err
		}
		err = c.xrpc(ctx, method, nsid, q, body, s.access, out)
	}
	return s, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var out struct {
		Handle string `json:"handle"`
	}
	if _, err := c.call(ctx, http.MethodGet, "com.atproto.server.getSession", nil, nil, &out); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "@" + clip(out.Handle, 100)}
}

// graphemes counts user-perceived characters the way Bluesky's 300 limit
// does, closely enough for text people write: combining marks, variation
// selectors, emoji skin tones and tags, zero-width-joiner sequences and
// flag pairs each count once with what they attach to.
func graphemes(s string) int {
	n := 0
	join, flag := false, false
	prevCR := false
	for _, r := range s {
		switch {
		case r == 0x200D:
			join = true
			continue
		case unicode.In(r, unicode.Mn, unicode.Me, unicode.Mc), r >= 0xFE00 && r <= 0xFE0F, r >= 0x1F3FB && r <= 0x1F3FF, r >= 0xE0020 && r <= 0xE007F:
			continue
		case r >= 0x1F1E6 && r <= 0x1F1FF:
			if flag {
				flag = false
				join = false
				continue
			}
			flag = true
		default:
			flag = false
		}
		if join {
			join = false
			continue
		}
		if r == '\n' && prevCR {
			prevCR = false
			continue
		}
		prevCR = r == '\r'
		n++
	}
	return n
}

type facet struct {
	Index    map[string]int   `json:"index"`
	Features []map[string]any `json:"features"`
}

func span(start, end int) map[string]int { return map[string]int{"byteStart": start, "byteEnd": end} }

// facets finds links, mentions and hashtags in text, with UTF-8 byte
// offsets. Mentions of handles that don't resolve are left as plain text.
func (c *conn) facets(ctx context.Context, text string) ([]facet, error) {
	out := []facet{}
	for _, loc := range linkRe.FindAllStringIndex(text, -1) {
		s, e := loc[0], loc[1]
		for e > s && strings.ContainsRune(".,;:!?)]}'\"", rune(text[e-1])) {
			e--
		}
		u, err := url.Parse(text[s:e])
		if err != nil || u.Host == "" {
			continue
		}
		out = append(out, facet{Index: span(s, e), Features: []map[string]any{{"$type": "app.bsky.richtext.facet#link", "uri": text[s:e]}}})
	}
	for i, loc := range mentionRe.FindAllStringSubmatchIndex(text, -1) {
		if i >= 20 {
			break
		}
		s, e := loc[2], loc[3]
		handle := strings.ToLower(text[s+1 : e])
		var r struct {
			DID string `json:"did"`
		}
		if _, err := c.call(ctx, http.MethodGet, "com.atproto.identity.resolveHandle", url.Values{"handle": {handle}}, nil, &r); err != nil {
			if rest.IsStatus(err, http.StatusBadRequest) || rest.IsStatus(err, http.StatusNotFound) {
				continue
			}
			return nil, err
		}
		if !didRe.MatchString(r.DID) {
			continue
		}
		out = append(out, facet{Index: span(s, e), Features: []map[string]any{{"$type": "app.bsky.richtext.facet#mention", "did": r.DID}}})
	}
	for _, loc := range tagRe.FindAllStringSubmatchIndex(text, -1) {
		s, e := loc[2], loc[3]
		for e > s+1 && strings.ContainsRune(".,;:!?)]}'\"", rune(text[e-1])) {
			e--
		}
		tag := text[s+1 : e]
		if tag == "" || graphemes(tag) > 64 || strings.Trim(tag, "0123456789") == "" {
			continue
		}
		out = append(out, facet{Index: span(s, e), Features: []map[string]any{{"$type": "app.bsky.richtext.facet#tag", "tag": tag}}})
	}
	return out, nil
}

func checkText(text string, langs []string) (string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", errors.New("write something to post")
	}
	if n := graphemes(text); n > maxGraphemes {
		return "", fmt.Errorf("the post is %d characters; Bluesky allows %d", n, maxGraphemes)
	}
	if len(text) > 3000 {
		return "", errors.New("the post is too long")
	}
	if len(langs) > 3 {
		return "", errors.New("give at most 3 languages")
	}
	for _, l := range langs {
		if !langRe.MatchString(l) {
			return "", fmt.Errorf("%q isn't a language tag like en or pt-BR", clip(l, 20))
		}
	}
	return text, nil
}

type ref struct {
	URI string `json:"uri"`
	CID string `json:"cid"`
}

type author struct {
	DID         string `json:"did"`
	Handle      string `json:"handle"`
	DisplayName string `json:"displayName"`
}

type postView struct {
	URI    string `json:"uri"`
	CID    string `json:"cid"`
	Author author `json:"author"`
	Record struct {
		Text      string `json:"text"`
		CreatedAt string `json:"createdAt"`
		Reply     *struct {
			Root   ref `json:"root"`
			Parent ref `json:"parent"`
		} `json:"reply"`
	} `json:"record"`
	ReplyCount  int    `json:"replyCount"`
	RepostCount int    `json:"repostCount"`
	LikeCount   int    `json:"likeCount"`
	QuoteCount  int    `json:"quoteCount"`
	IndexedAt   string `json:"indexedAt"`
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func webURL(uri, handle string) string {
	mm := postURIRe.FindStringSubmatch(uri)
	if mm == nil {
		return ""
	}
	who := mm[1]
	if handleRe.MatchString(handle) {
		who = handle
	}
	return "https://bsky.app/profile/" + who + "/post/" + mm[2]
}

func (p postView) brief() map[string]any {
	out := map[string]any{"uri": p.URI, "author": p.Author.Handle, "text": clip(p.Record.Text, 3000), "created": p.Record.CreatedAt,
		"replies": p.ReplyCount, "reposts": p.RepostCount, "likes": p.LikeCount, "quotes": p.QuoteCount}
	if p.Author.DisplayName != "" {
		out["name"] = clip(p.Author.DisplayName, 100)
	}
	if u := webURL(p.URI, p.Author.Handle); u != "" {
		out["url"] = u
	}
	if p.Record.Reply != nil {
		out["replyTo"] = p.Record.Reply.Parent.URI
	}
	return out
}

func limitOf(n int) string {
	if n <= 0 {
		n = 20
	}
	if n > 100 {
		n = 100
	}
	return strconv.Itoa(n)
}

func (c *conn) getPost(ctx context.Context, uri string) (postView, error) {
	var out struct {
		Posts []postView `json:"posts"`
	}
	if _, err := c.call(ctx, http.MethodGet, "app.bsky.feed.getPosts", url.Values{"uris": {uri}}, nil, &out); err != nil {
		return postView{}, err
	}
	if len(out.Posts) == 0 || out.Posts[0].URI != uri {
		return postView{}, errors.New("there's no such post (it may have been deleted)")
	}
	return out.Posts[0], nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Actor string   `json:"actor"`
		Limit int      `json:"limit"`
		Text  string   `json:"text"`
		Langs []string `json:"langs"`
		URI   string   `json:"uri"`
		Query string   `json:"query"`
		Sort  string   `json:"sort"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "profile":
		actor := strings.TrimPrefix(strings.TrimSpace(p.Actor), "@")
		if actor != "" && !handleRe.MatchString(actor) && !didRe.MatchString(actor) {
			return sdk.Result{}, errors.New("the actor is a handle like alice.bsky.social or a did:")
		}
		if actor == "" {
			s, err := c.session(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			actor = s.did
		}
		var pr struct {
			DID         string `json:"did"`
			Handle      string `json:"handle"`
			DisplayName string `json:"displayName"`
			Description string `json:"description"`
			Followers   int    `json:"followersCount"`
			Follows     int    `json:"followsCount"`
			Posts       int    `json:"postsCount"`
			CreatedAt   string `json:"createdAt"`
		}
		if _, err := c.call(ctx, http.MethodGet, "app.bsky.actor.getProfile", url.Values{"actor": {actor}}, nil, &pr); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"did": pr.DID, "handle": pr.Handle, "name": clip(pr.DisplayName, 100), "bio": clip(pr.Description, 1000),
			"followers": pr.Followers, "following": pr.Follows, "posts": pr.Posts, "created": pr.CreatedAt})

	case "timeline":
		var out struct {
			Feed []struct {
				Post   postView `json:"post"`
				Reason *struct {
					Type string `json:"$type"`
					By   author `json:"by"`
				} `json:"reason"`
			} `json:"feed"`
		}
		if _, err := c.call(ctx, http.MethodGet, "app.bsky.feed.getTimeline", url.Values{"limit": {limitOf(p.Limit)}}, nil, &out); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, f := range out.Feed {
			b := f.Post.brief()
			if f.Reason != nil && strings.HasSuffix(f.Reason.Type, "#reasonRepost") {
				b["repostedBy"] = f.Reason.By.Handle
			}
			list = append(list, b)
		}
		return sdk.JSON(list)

	case "notifications":
		var out struct {
			Notifications []struct {
				URI       string `json:"uri"`
				Author    author `json:"author"`
				Reason    string `json:"reason"`
				IsRead    bool   `json:"isRead"`
				IndexedAt string `json:"indexedAt"`
				Record    struct {
					Text string `json:"text"`
				} `json:"record"`
				ReasonSubject string `json:"reasonSubject"`
			} `json:"notifications"`
		}
		if _, err := c.call(ctx, http.MethodGet, "app.bsky.notification.listNotifications", url.Values{"limit": {limitOf(p.Limit)}}, nil, &out); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, n := range out.Notifications {
			e := map[string]any{"type": n.Reason, "from": n.Author.Handle, "when": n.IndexedAt, "read": n.IsRead}
			if n.Record.Text != "" {
				e["text"], e["uri"] = clip(n.Record.Text, 3000), n.URI
			}
			if n.ReasonSubject != "" {
				e["subject"] = n.ReasonSubject
			}
			list = append(list, e)
		}
		return sdk.JSON(list)

	case "post", "reply":
		text, err := checkText(p.Text, p.Langs)
		if err != nil {
			return sdk.Result{}, err
		}
		var parent postView
		if call.Action == "reply" {
			if !postURIRe.MatchString(p.URI) {
				return sdk.Result{}, errors.New("the uri is the at:// URI of a post (from timeline, notifications or search)")
			}
			if parent, err = c.getPost(ctx, p.URI); err != nil {
				return sdk.Result{}, err
			}
			if !cidRe.MatchString(parent.CID) {
				return sdk.Result{}, errors.New("unexpected answer from the server")
			}
		}
		fs, err := c.facets(ctx, text)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			// Everyone the post reaches beyond its readers: the accounts
			// its mentions notify and, for a reply, the author it answers.
			mentions := []map[string]string{}
			for _, f := range fs {
				for _, ft := range f.Features {
					if ft["$type"] == "app.bsky.richtext.facet#mention" {
						mentions = append(mentions, map[string]string{"handle": text[f.Index["byteStart"]+1 : f.Index["byteEnd"]], "did": fmt.Sprint(ft["did"])})
					}
				}
			}
			summary := fmt.Sprintf("Post publicly: %q", clip(text, 80))
			target := "your public feed"
			after := map[string]any{"text": text, "characters": graphemes(text), "visibility": "public", "mentions": mentions}
			if call.Action == "reply" {
				summary = fmt.Sprintf("Reply publicly to @%s: %q", parent.Author.Handle, clip(text, 80))
				target = p.URI
				after["replyTo"] = map[string]string{"handle": parent.Author.Handle, "did": parent.Author.DID, "uri": parent.URI}
			}
			if len(mentions) > 0 {
				hs := make([]string, len(mentions))
				for i, mm := range mentions {
					hs[i] = "@" + mm["handle"]
				}
				summary += "; notifies " + strings.Join(hs, ", ")
			}
			b, _ := json.Marshal(after)
			return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: target, Op: "create", After: b}}}}, nil
		}
		rec := map[string]any{"$type": postCollection, "text": text, "createdAt": m.now().UTC().Format("2006-01-02T15:04:05.000Z")}
		if len(fs) > 0 {
			rec["facets"] = fs
		}
		if len(p.Langs) > 0 {
			rec["langs"] = p.Langs
		}
		if call.Action == "reply" {
			root := ref{URI: parent.URI, CID: parent.CID}
			if parent.Record.Reply != nil && postURIRe.MatchString(parent.Record.Reply.Root.URI) && parent.Record.Reply.Root.CID != "" {
				root = parent.Record.Reply.Root
			}
			rec["reply"] = map[string]ref{"root": root, "parent": {URI: parent.URI, CID: parent.CID}}
		}
		s, err := c.session(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var out ref
		if _, err := c.call(ctx, http.MethodPost, "com.atproto.repo.createRecord", nil, map[string]any{"repo": s.did, "collection": postCollection, "record": rec}, &out); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"uri": out.URI, "url": webURL(out.URI, s.handle), "characters": graphemes(text), "facets": len(fs)})
		if mm := postURIRe.FindStringSubmatch(out.URI); mm != nil && mm[1] == s.did {
			what := "post"
			if call.Action == "reply" {
				what = "reply"
			}
			res.Undo = sdk.UndoWith("delete", map[string]string{"uri": out.URI}, "Delete the "+what)
		}
		return res, err

	case "delete":
		mm := postURIRe.FindStringSubmatch(p.URI)
		if mm == nil {
			return sdk.Result{}, errors.New("the uri is the at:// URI of one of your posts")
		}
		s, err := c.session(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if mm[1] != s.did {
			return sdk.Result{}, errors.New("that post isn't yours; you can only delete your own posts")
		}
		if call.DryRun {
			pv, err := c.getPost(ctx, p.URI)
			if err != nil {
				return sdk.Result{}, err
			}
			before, _ := json.Marshal(pv.brief())
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete the post %q (%d likes, %d reposts)", clip(pv.Record.Text, 80), pv.LikeCount, pv.RepostCount),
				Changes: []sdk.Change{{Target: p.URI, Op: "delete", Before: before}}}}, nil
		}
		if _, err := c.call(ctx, http.MethodPost, "com.atproto.repo.deleteRecord", nil, map[string]string{"repo": s.did, "collection": postCollection, "rkey": mm[2]}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": p.URI})

	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" || len([]rune(q)) > 300 || strings.ContainsAny(q, "\x00\r\n") {
			return sdk.Result{}, errors.New("the query is up to 300 characters on one line")
		}
		sort := p.Sort
		if sort == "" {
			sort = "latest"
		}
		if sort != "latest" && sort != "top" {
			return sdk.Result{}, errors.New("sort is latest or top")
		}
		var out struct {
			Posts     []postView `json:"posts"`
			HitsTotal int        `json:"hitsTotal"`
		}
		if _, err := c.call(ctx, http.MethodGet, "app.bsky.feed.searchPosts", url.Values{"q": {q}, "sort": {sort}, "limit": {limitOf(p.Limit)}}, nil, &out); err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, pv := range out.Posts {
			list = append(list, pv.brief())
		}
		return sdk.JSON(list)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
