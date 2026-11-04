// Package discourse works with a Discourse forum through its API with an
// API key and the username it acts as: categories, the latest and unread
// topics, reading a topic in the categories the instance allows, and
// replying there.
//
// A reply is posted where the topic's readers (for a public category, the
// whole internet) see it and watchers are notified, and it can't be taken
// back from their inboxes, so replying is destructive. Flagging and
// moderation aren't offered.
package discourse

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one forum and the account the API key acts as.
type Config struct {
	URL               string   `json:"url"`      // e.g. https://forum.example.com
	APIKey            string   `json:"apiKey"`   // secret://
	Username          string   `json:"username"` // Api-Username
	AllowedCategories []string `json:"allowedCategories"`
	Fingerprint       string   `json:"fingerprint"`
}

type conn struct {
	http    *http.Client
	base    string
	user    string
	key     string
	host    sdk.Host
	allowed map[string]bool // slugs (lowercase) and ids
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Discourse module.
func New() *Module { return &Module{} }

var (
	userRe = regexp.MustCompile(`^[\p{L}\p{N}_.-]{1,60}$`)
	slugRe = regexp.MustCompile(`^[\p{Ll}\p{N}-]{1,100}$`)
	tagRe  = regexp.MustCompile(`(?s)<[^>]*>`)
	wsRe   = regexp.MustCompile(`[ \t]+`)
	nlRe   = regexp.MustCompile(`\n{3,}`)
)

const maxRaw = 32000 // Discourse's default max_post_length

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	topic := `"topic":{"type":"integer","minimum":1,"description":"Topic id (the number in its address)"}`
	return sdk.Manifest{
		ID: "discourse", Name: "Discourse", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "A Discourse forum: categories, latest and unread topics, reading topics and replying in allowed categories.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey","username"],"properties":{
			"url":{"type":"string","description":"The forum's address, e.g. https://forum.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"An API key (Admin, API, New API key), ideally for a single user with read and write scopes"},
			"username":{"type":"string","description":"The user the key acts as"},
			"allowedCategories":{"type":"array","items":{"type":"string"},"description":"Categories whose topics Conduit may read and reply to: a top-level category's slug, parent/child for a subcategory, or an id. Subcategories are listed on their own"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "categories", Title: "Categories", Description: "The forum's categories, whether each is private, and whether it's allowed.", Risk: sdk.RiskRead},
			{Name: "latest", Title: "Latest topics", Description: "Topics with the latest activity: title, category, posts and unread counts.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":30,"minimum":1,"maximum":100}}}`)},
			{Name: "unread", Title: "Unread", Description: "Topics with unread posts and new topics, for the account the key acts as.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "read_topic", Title: "Read a topic", Description: "A topic in an allowed category: title and up to 20 posts as text, from the start or around a post number.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["topic"],"properties":{` + topic + `,"post":{"type":"integer","minimum":1,"description":"Start near this post number"}}}`)},
			{Name: "reply", Title: "Reply to a topic", Description: "Posts a reply (Markdown) to a topic in an allowed category. Everyone who can read the category sees it and watchers are notified, so it's destructive. No undo.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["topic","text"],"properties":{` + topic + `,"text":{"type":"string","maxLength":32000},"replyTo":{"type":"integer","minimum":1,"description":"Post number being replied to (its author is notified)"}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "category", Title: "Categories", ListAction: "categories", ViewHint: "table"}},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is like https://forum.example.com")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	user := strings.TrimPrefix(strings.TrimSpace(c.Username), "@")
	if !userRe.MatchString(user) {
		return errors.New("the username is the forum user the key acts as, e.g. system")
	}
	allowed := map[string]bool{}
	for _, a := range c.AllowedCategories {
		a = strings.ToLower(strings.TrimSpace(a))
		if _, err := strconv.ParseUint(a, 10, 32); err != nil && !slugPath(a) {
			return fmt.Errorf("%q isn't a category slug (as in its address), parent/child for a subcategory, or id", a)
		}
		allowed[a] = true
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, false)
		if err != nil {
			return err
		}
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	base := u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
	m.set.Put(id, &conn{http: rest.SameHostOnly(client), base: base, user: user, key: c.APIKey, host: h, allowed: allowed})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// do calls the API. Discourse answers errors as {"errors":["…"]}.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	key, err := c.host.Secret(ctx, c.key)
	if err != nil {
		return err
	}
	req.Header.Set("Api-Key", strings.TrimSpace(key))
	req.Header.Set("Api-Username", c.user)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return rest.TransportError(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		var e struct {
			Errors    []string `json:"errors"`
			ErrorType string   `json:"error_type"`
		}
		_ = json.Unmarshal(raw, &e)
		switch {
		case res.StatusCode == http.StatusTooManyRequests:
			return &rest.Error{Status: res.StatusCode, Message: "the forum's rate limit was hit; try again shortly"}
		case e.ErrorType == "invalid_access" && strings.Contains(strings.Join(e.Errors, " "), "API"):
			return &rest.Error{Status: res.StatusCode, Message: "the forum refused the API key or username"}
		case len(e.Errors) > 0:
			return &rest.Error{Status: res.StatusCode, Message: clip(rest.Redact(strings.Join(e.Errors, "; ")), 300)}
		}
		return &rest.Error{Status: res.StatusCode, Message: res.Status}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("unexpected answer from %s: %w", rest.ShortURL(c.base), err)
		}
	}
	return nil
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// text turns a post's cooked HTML into plain text.
func text(cooked string) string {
	s := strings.NewReplacer("<br>", "\n", "<br/>", "\n", "</p>", "\n\n", "</li>", "\n", "</blockquote>", "\n", "</pre>", "\n").Replace(cooked)
	s = html.UnescapeString(tagRe.ReplaceAllString(s, ""))
	s = wsRe.ReplaceAllString(s, " ")
	return nlRe.ReplaceAllString(strings.TrimSpace(s), "\n\n")
}

type category struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	Slug           string `json:"slug"`
	ReadRestricted bool   `json:"read_restricted"`
	Parent         int64  `json:"parent_category_id"`
}

func (c *conn) categories(ctx context.Context) (map[int64]category, error) {
	var s struct {
		Categories []category `json:"categories"`
	}
	if err := c.do(ctx, http.MethodGet, "/site.json", nil, nil, &s); err != nil {
		return nil, err
	}
	out := map[int64]category{}
	for _, ct := range s.Categories {
		out[ct.ID] = ct
	}
	return out, nil
}

// slugPath reports whether s is a slug or slugs joined by / (parent/child).
func slugPath(s string) bool {
	parts := strings.Split(s, "/")
	if len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if !slugRe.MatchString(p) {
			return false
		}
	}
	return true
}

// categoryPath is a category's slugs from the top level down
// (parent/child), or "" when a parent is missing from cats or the
// parents loop. A subcategory's slug is unique only within its parent, so
// a bare slug names a top-level category only.
func categoryPath(ct category, cats map[int64]category) string {
	path := strings.ToLower(ct.Slug)
	seen := map[int64]bool{ct.ID: true}
	for p := ct.Parent; p != 0; {
		pc, ok := cats[p]
		if !ok || seen[p] || len(seen) > 3 {
			return ""
		}
		seen[p] = true
		path = strings.ToLower(pc.Slug) + "/" + path
		p = pc.Parent
	}
	return path
}

// categoryAllowed reports whether a category is on the allow list: by id,
// or by its path (a bare slug for a top-level category, parent/child for a
// subcategory). A path that more than one category has is refused.
func (c *conn) categoryAllowed(ct category, cats map[int64]category) bool {
	if c.allowed[strconv.FormatInt(ct.ID, 10)] {
		return true
	}
	path := categoryPath(ct, cats)
	if path == "" || !c.allowed[path] {
		return false
	}
	n := 0
	for _, o := range cats {
		if categoryPath(o, cats) == path {
			n++
		}
	}
	return n == 1
}

// allowedIn returns categoryAllowed against one list of categories.
func (c *conn) allowedIn(cats map[int64]category) func(category) bool {
	return func(ct category) bool { return c.categoryAllowed(ct, cats) }
}

type topicRow struct {
	ID           int64  `json:"id"`
	Title        string `json:"title"`
	PostsCount   int    `json:"posts_count"`
	LastPostedAt string `json:"last_posted_at"`
	CategoryID   int64  `json:"category_id"`
	UnreadPosts  int    `json:"unread_posts"`
	NewPosts     int    `json:"new_posts"`
	Closed       bool   `json:"closed"`
	Archived     bool   `json:"archived"`
	Pinned       bool   `json:"pinned"`
}

func (c *conn) topicList(ctx context.Context, path string) ([]topicRow, error) {
	var r struct {
		TopicList struct {
			Topics []topicRow `json:"topics"`
		} `json:"topic_list"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &r); err != nil {
		return nil, err
	}
	return r.TopicList.Topics, nil
}

func row(t topicRow, cats map[int64]category, allowed func(category) bool) map[string]any {
	ct := cats[t.CategoryID]
	out := map[string]any{"id": t.ID, "title": clip(t.Title, 300), "category": ct.Slug, "posts": t.PostsCount, "lastPost": t.LastPostedAt, "allowed": allowed(ct)}
	if ct.ReadRestricted {
		out["private"] = true
	}
	if n := t.UnreadPosts + t.NewPosts; n > 0 {
		out["unread"] = n
	}
	for k, v := range map[string]bool{"closed": t.Closed, "archived": t.Archived, "pinned": t.Pinned} {
		if v {
			out[k] = true
		}
	}
	return out
}

type post struct {
	ID         int64  `json:"id"`
	Username   string `json:"username"`
	CreatedAt  string `json:"created_at"`
	Cooked     string `json:"cooked"`
	PostNumber int    `json:"post_number"`
	ReplyTo    int    `json:"reply_to_post_number"`
}

type topic struct {
	ID         int64  `json:"id"`
	Title      string `json:"title"`
	CategoryID int64  `json:"category_id"`
	PostsCount int    `json:"posts_count"`
	Closed     bool   `json:"closed"`
	Archived   bool   `json:"archived"`
	Archetype  string `json:"archetype"`
	PostStream struct {
		Posts []post `json:"posts"`
	} `json:"post_stream"`
}

// topic loads a topic and checks that its category is allowed.
func (c *conn) topic(ctx context.Context, id int64, near int) (topic, category, error) {
	if id <= 0 {
		return topic{}, category{}, errors.New("topic is a topic id (the number in its address)")
	}
	if len(c.allowed) == 0 {
		return topic{}, category{}, errors.New("no categories are allowed yet (add them to allowedCategories)")
	}
	cats, err := c.categories(ctx)
	if err != nil {
		return topic{}, category{}, err
	}
	path := "/t/" + strconv.FormatInt(id, 10)
	if near > 0 {
		path += "/" + strconv.Itoa(near)
	}
	var t topic
	if err := c.do(ctx, http.MethodGet, path+".json", nil, nil, &t); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusForbidden) {
			return topic{}, category{}, fmt.Errorf("no topic %d that this account can see", id)
		}
		return topic{}, category{}, err
	}
	ct, ok := cats[t.CategoryID]
	if t.ID != id || t.Archetype == "private_message" || !ok || !c.categoryAllowed(ct, cats) {
		return topic{}, category{}, fmt.Errorf("topic %d isn't in an allowed category", id)
	}
	return t, ct, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s struct {
		CurrentUser struct {
			Username string `json:"username"`
		} `json:"current_user"`
	}
	if err := c.do(ctx, http.MethodGet, "/session/current.json", nil, nil, &s); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "the forum refused the API key or username"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + clip(s.CurrentUser.Username, 60)
	if len(c.allowed) == 0 {
		return sdk.Health{Status: "degraded", Message: msg + "; no categories are allowed yet (add them to allowedCategories)"}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%s, %d allowed categories", msg, len(c.allowed))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Topic   int64  `json:"topic"`
		Post    int    `json:"post"`
		Text    string `json:"text"`
		ReplyTo int    `json:"replyTo"`
		Limit   int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "categories":
		cats, err := c.categories(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, ct := range cats {
			r := map[string]any{"id": ct.ID, "name": clip(ct.Name, 100), "slug": ct.Slug, "private": ct.ReadRestricted, "allowed": c.categoryAllowed(ct, cats)}
			if pc, ok := cats[ct.Parent]; ok && ct.Parent != 0 {
				r["parent"] = pc.Slug
			}
			out = append(out, r)
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["id"].(int64) < out[j]["id"].(int64) })
		return sdk.JSON(out)

	case "latest":
		n := p.Limit
		if n <= 0 {
			n = 30
		}
		if n > 100 {
			n = 100
		}
		cats, err := c.categories(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		ts, err := c.topicList(ctx, "/latest.json")
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range ts {
			if len(out) == n {
				break
			}
			out = append(out, row(t, cats, c.allowedIn(cats)))
		}
		return sdk.JSON(out)

	case "unread":
		cats, err := c.categories(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		unread, err := c.topicList(ctx, "/unread.json")
		if err != nil {
			return sdk.Result{}, err
		}
		fresh, err := c.topicList(ctx, "/new.json")
		if err != nil {
			return sdk.Result{}, err
		}
		u, nw := []map[string]any{}, []map[string]any{}
		for _, t := range unread {
			u = append(u, row(t, cats, c.allowedIn(cats)))
		}
		for _, t := range fresh {
			nw = append(nw, row(t, cats, c.allowedIn(cats)))
		}
		return sdk.JSON(map[string]any{"unread": u, "new": nw})

	case "read_topic":
		if p.Post < 0 {
			return sdk.Result{}, errors.New("post is a post number")
		}
		t, ct, err := c.topic(ctx, p.Topic, p.Post)
		if err != nil {
			return sdk.Result{}, err
		}
		posts := []map[string]any{}
		for _, ps := range t.PostStream.Posts {
			r := map[string]any{"number": ps.PostNumber, "from": ps.Username, "when": ps.CreatedAt, "text": clip(text(ps.Cooked), 4000)}
			if ps.ReplyTo > 0 {
				r["replyTo"] = ps.ReplyTo
			}
			posts = append(posts, r)
		}
		return sdk.JSON(map[string]any{"id": t.ID, "title": clip(t.Title, 300), "category": ct.Slug, "private": ct.ReadRestricted,
			"posts": t.PostsCount, "closed": t.Closed, "archived": t.Archived, "shown": posts})

	case "reply":
		body := strings.TrimSpace(p.Text)
		if body == "" {
			return sdk.Result{}, errors.New("write the reply")
		}
		if len([]rune(body)) > maxRaw {
			return sdk.Result{}, fmt.Errorf("the reply is longer than Discourse allows (%d characters)", maxRaw)
		}
		if p.ReplyTo < 0 {
			return sdk.Result{}, errors.New("replyTo is a post number")
		}
		t, ct, err := c.topic(ctx, p.Topic, p.ReplyTo)
		if err != nil {
			return sdk.Result{}, err
		}
		if t.Closed || t.Archived {
			return sdk.Result{}, fmt.Errorf("topic %d is closed", t.ID)
		}
		to := ""
		if p.ReplyTo > 0 {
			for _, ps := range t.PostStream.Posts {
				if ps.PostNumber == p.ReplyTo {
					to = ps.Username
				}
			}
			if to == "" {
				return sdk.Result{}, fmt.Errorf("topic %d has no post number %d", t.ID, p.ReplyTo)
			}
		}
		if call.DryRun {
			audience := "public"
			if ct.ReadRestricted {
				audience = "private"
			}
			sum := fmt.Sprintf("Reply in %q (%s category %s)", clip(t.Title, 120), audience, ct.Slug)
			if to != "" {
				sum += ", to " + to + "'s post #" + strconv.Itoa(p.ReplyTo) + " (notifies them)"
			}
			after, _ := json.Marshal(map[string]any{"raw": body, "replyTo": p.ReplyTo})
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: c.base + "/t/" + strconv.FormatInt(t.ID, 10), Op: "create", After: after}}}}, nil
		}
		in := map[string]any{"topic_id": t.ID, "raw": body}
		if p.ReplyTo > 0 {
			in["reply_to_post_number"] = p.ReplyTo
		}
		var out post
		if err := c.do(ctx, http.MethodPost, "/posts.json", nil, in, &out); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"topic": t.ID, "post": out.PostNumber, "id": out.ID,
			"url": c.base + "/t/" + strconv.FormatInt(t.ID, 10) + "/" + strconv.Itoa(out.PostNumber)})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
