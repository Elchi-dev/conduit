// Package lemmy works with a Lemmy account through the instance's API (v3):
// subscribed communities, posts and comments, and posting and commenting.
//
// Lemmy is public and federated: a post or comment is copied to every
// instance that follows the community the moment it's made, and replies
// notify the people replied to, so posting and commenting are destructive
// and have no undo.
package lemmy

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/modules/internal/urlguard"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one account on one Lemmy instance. It signs in with the
// username and password (a JWT is fetched and kept in memory) or uses a JWT
// directly, for accounts with two-factor authentication.
type Config struct {
	URL                string   `json:"url"` // e.g. https://lemmy.example.org
	Username           string   `json:"username"`
	Password           string   `json:"password"` // secret://
	Token              string   `json:"token"`    // secret:// JWT, instead of username and password
	AllowedCommunities []string `json:"allowedCommunities"`
	Fingerprint        string   `json:"fingerprint"`
}

type conn struct {
	api     *rest.Client
	host    sdk.Host
	user    string
	pass    string
	token   string
	domain  string
	allowed map[string]bool // community@instance, lowercase

	mu  sync.Mutex
	jwt string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Lemmy module.
func New() *Module { return &Module{} }

var (
	userRe      = regexp.MustCompile(`^[A-Za-z0-9_]{1,50}$`)
	communityRe = regexp.MustCompile(`^!?([a-z0-9_]{1,50})(@([a-z0-9.-]{1,253}))?$`)
)

const (
	maxTitle = 200
	maxBody  = 10000
)

var sorts = map[string]string{"new": "New", "hot": "Hot", "active": "Active", "top_day": "TopDay", "top_week": "TopWeek", "top": "TopAll"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	comm := `"community":{"type":"string","description":"Community name, or name@instance for one from another instance"}`
	return sdk.Manifest{
		ID: "lemmy", Name: "Lemmy", Version: "0.1.0", Category: "Communication", Icon: "network",
		Description: "A Lemmy account: subscribed communities, posts and comments, and posting and commenting (public and federated).",
		Presets:     []string{"homelab", "gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url"],"properties":{
			"url":{"type":"string","description":"Your instance's address, e.g. https://lemmy.example.org"},
			"username":{"type":"string","description":"Your user name on the instance (with password)"},
			"password":{"type":"string","x-secret":true,"description":"The account's password; Conduit signs in and keeps the session in memory"},
			"token":{"type":"string","x-secret":true,"description":"Instead of a password: a session token (JWT), for accounts with two-factor authentication"},
			"allowedCommunities":{"type":"array","items":{"type":"string"},"description":"If set, posts and comments only go to these communities (name, or name@instance)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "communities", Title: "Subscribed communities", Description: "Communities the account is subscribed to.", Risk: sdk.RiskRead},
			{Name: "posts", Title: "Posts", Description: "Posts from subscribed communities, the instance, everything, or one community.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + comm + `,"feed":{"type":"string","enum":["subscribed","local","all"],"default":"subscribed"},"sort":{"type":"string","enum":["new","hot","active","top_day","top_week","top"],"default":"hot"},"limit":{"type":"integer","default":20,"minimum":1,"maximum":50}}}`)},
			{Name: "comments", Title: "Comments", Description: "Comments on a post, as text with authors and scores.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["post"],"properties":{"post":{"type":"integer","minimum":1},"sort":{"type":"string","enum":["hot","top","new"],"default":"top"},"limit":{"type":"integer","default":50,"minimum":1,"maximum":50}}}`)},
			{Name: "create_post", Title: "Post", Description: "Publishes a post to a community: public and copied to other instances at once, so it's destructive. No undo.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["community","title"],"properties":{` + comm + `,"title":{"type":"string","maxLength":200},"body":{"type":"string","maxLength":10000},"url":{"type":"string","description":"Link to share (the instance fetches it for a preview)"},"nsfw":{"type":"boolean","default":false}}}`)},
			{Name: "create_comment", Title: "Comment", Description: "Comments on a post or replies to a comment: public, federated and notifies the author replied to, so it's destructive. No undo.", Risk: sdk.RiskDestructive, DryRun: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["post","text"],"properties":{"post":{"type":"integer","minimum":1},"parent":{"type":"integer","minimum":1,"description":"Comment id being replied to"},"text":{"type":"string","maxLength":10000}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "community", Title: "Communities", ListAction: "communities", ViewHint: "table"}},
	}
}

// community normalises "name", "!name" or "name@instance" to name and
// name@instance (the instance being this one when left out).
func (c *conn) community(raw string) (string, string, error) {
	m := communityRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(raw)))
	if m == nil {
		return "", "", errors.New("the community is its name, or name@instance (lowercase letters, digits and _)")
	}
	full := m[1] + "@" + c.domain
	if m[3] != "" {
		full = m[1] + "@" + m[3]
	}
	// The API takes a local community by name alone.
	if m[3] == "" || m[3] == c.domain {
		return m[1], full, nil
	}
	return full, full, nil
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("the address is your instance, like https://lemmy.example.org")
	}
	cn := &conn{host: h, domain: strings.ToLower(u.Hostname()), allowed: map[string]bool{}}
	switch {
	case c.Token != "":
		if !strings.HasPrefix(c.Token, "secret://") {
			return errors.New("store the token in the vault and enter its secret:// reference")
		}
		cn.token = c.Token
	case c.Password != "":
		if !strings.HasPrefix(c.Password, "secret://") {
			return errors.New("store the password in the vault and enter its secret:// reference")
		}
		if !userRe.MatchString(strings.TrimSpace(c.Username)) {
			return errors.New("enter your user name on the instance (letters, digits and _)")
		}
		cn.user, cn.pass = strings.TrimSpace(c.Username), c.Password
	default:
		return errors.New("enter a user name and password, or a token")
	}
	for _, a := range c.AllowedCommunities {
		_, full, err := cn.community(a)
		if err != nil {
			return fmt.Errorf("%q: %w", a, err)
		}
		cn.allowed[full] = true
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
	cn.api = rest.New(u.Scheme+"://"+u.Host+"/api/v3", func(ctx context.Context, r *http.Request) error {
		if r.URL.Path == "/api/v3/user/login" {
			return nil
		}
		t, err := cn.session(ctx, false)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	cn.api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// session returns the JWT: the configured token, or one from signing in
// (again, when renew is set).
func (c *conn) session(ctx context.Context, renew bool) (string, error) {
	if c.token != "" {
		t, err := c.host.Secret(ctx, c.token)
		return strings.TrimSpace(t), err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jwt != "" && !renew {
		return c.jwt, nil
	}
	pw, err := c.host.Secret(ctx, c.pass)
	if err != nil {
		return "", err
	}
	var r struct {
		JWT string `json:"jwt"`
	}
	if _, err := c.api.Do(ctx, http.MethodPost, "/user/login", nil, map[string]string{"username_or_email": c.user, "password": pw}, &r); err != nil {
		var e *rest.Error
		if errors.As(err, &e) {
			switch {
			case strings.Contains(e.Message, "missing_totp_token"):
				return "", errors.New("the account uses two-factor authentication; use a token instead of the password")
			case e.Status == http.StatusTooManyRequests:
				return "", errors.New("the instance's rate limit was hit; try again shortly")
			case e.Status < 500:
				return "", errors.New("the instance refused the user name and password")
			}
		}
		return "", err
	}
	if r.JWT == "" {
		return "", errors.New("the instance didn't sign the account in (is the email verified and the application approved?)")
	}
	c.jwt = r.JWT
	return c.jwt, nil
}

func expired(err error) bool {
	var e *rest.Error
	return errors.As(err, &e) && (e.Status == http.StatusUnauthorized || e.Message == "not_logged_in" || e.Message == "incorrect_login")
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if err != nil && expired(err) && c.token == "" {
		if _, lerr := c.session(ctx, true); lerr != nil {
			return lerr
		}
		_, err = c.api.Do(ctx, method, path, q, body, out)
	}
	if err != nil {
		var e *rest.Error
		if errors.As(err, &e) {
			switch {
			case expired(err):
				return errors.New("the instance refused the session; check the token or password")
			case e.Status == http.StatusTooManyRequests || e.Message == "rate_limit_error":
				return errors.New("the instance's rate limit was hit; try again shortly")
			}
		}
	}
	return err
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

type person struct {
	Name    string `json:"name"`
	ActorID string `json:"actor_id"`
}

type community struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Title      string `json:"title"`
	ActorID    string `json:"actor_id"`
	Removed    bool   `json:"removed"`
	Deleted    bool   `json:"deleted"`
	ModsOnly   bool   `json:"posting_restricted_to_mods"`
	Visibility string `json:"visibility"`
}

// handle is name@instance, from the actor id's host.
func handle(name, actor string) string {
	if u, err := url.Parse(actor); err == nil && u.Hostname() != "" {
		return name + "@" + strings.ToLower(u.Hostname())
	}
	return name
}

type postView struct {
	Post struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		URL       string `json:"url"`
		Body      string `json:"body"`
		Published string `json:"published"`
		Locked    bool   `json:"locked"`
		ApID      string `json:"ap_id"`
	} `json:"post"`
	Creator   person    `json:"creator"`
	Community community `json:"community"`
	Counts    struct {
		Score    int `json:"score"`
		Comments int `json:"comments"`
	} `json:"counts"`
}

type commentView struct {
	Comment struct {
		ID        int64  `json:"id"`
		PostID    int64  `json:"post_id"`
		Content   string `json:"content"`
		Path      string `json:"path"`
		Published string `json:"published"`
		Deleted   bool   `json:"deleted"`
		Removed   bool   `json:"removed"`
		ApID      string `json:"ap_id"`
	} `json:"comment"`
	Creator person `json:"creator"`
	Counts  struct {
		Score int `json:"score"`
	} `json:"counts"`
}

func (c *conn) checkAllowed(full string) error {
	if len(c.allowed) > 0 && !c.allowed[full] {
		return fmt.Errorf("!%s isn't in this instance's allowedCommunities", full)
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s struct {
		MyUser *struct {
			LocalUserView struct {
				Person person `json:"person"`
			} `json:"local_user_view"`
		} `json:"my_user"`
	}
	if err := c.do(ctx, http.MethodGet, "/site", nil, nil, &s); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if s.MyUser == nil {
		return sdk.Health{Status: "down", Message: "the instance refused the session; check the token or password"}
	}
	return sdk.Health{Status: "ok", Message: "signed in as " + clip(s.MyUser.LocalUserView.Person.Name, 50)}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Community string `json:"community"`
		Feed      string `json:"feed"`
		Sort      string `json:"sort"`
		Limit     int    `json:"limit"`
		Post      int64  `json:"post"`
		Parent    int64  `json:"parent"`
		Title     string `json:"title"`
		Body      string `json:"body"`
		URL       string `json:"url"`
		NSFW      bool   `json:"nsfw"`
		Text      string `json:"text"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	limit := func(def, max int) string {
		n := p.Limit
		if n <= 0 {
			n = def
		}
		if n > max {
			n = max
		}
		return strconv.Itoa(n)
	}
	switch call.Action {
	case "communities":
		var s struct {
			MyUser *struct {
				Follows []struct {
					Community community `json:"community"`
				} `json:"follows"`
			} `json:"my_user"`
		}
		if err := c.do(ctx, http.MethodGet, "/site", nil, nil, &s); err != nil {
			return sdk.Result{}, err
		}
		if s.MyUser == nil {
			return sdk.Result{}, errors.New("the instance refused the session; check the token or password")
		}
		out := []map[string]any{}
		for _, f := range s.MyUser.Follows {
			h := handle(f.Community.Name, f.Community.ActorID)
			out = append(out, map[string]any{"community": h, "title": clip(f.Community.Title, 100), "allowed": len(c.allowed) == 0 || c.allowed[h]})
		}
		return sdk.JSON(out)

	case "posts":
		q := url.Values{"limit": {limit(20, 50)}, "page": {"1"}}
		feed := map[string]string{"": "Subscribed", "subscribed": "Subscribed", "local": "Local", "all": "All"}[p.Feed]
		if feed == "" {
			return sdk.Result{}, errors.New("feed is subscribed, local or all")
		}
		s, ok := sorts[p.Sort]
		if p.Sort == "" {
			s, ok = "Hot", true
		}
		if !ok {
			return sdk.Result{}, errors.New("sort is new, hot, active, top_day, top_week or top")
		}
		q.Set("sort", s)
		if strings.TrimSpace(p.Community) != "" {
			name, _, err := c.community(p.Community)
			if err != nil {
				return sdk.Result{}, err
			}
			q.Set("community_name", name)
			q.Set("type_", "All")
		} else {
			q.Set("type_", feed)
		}
		var r struct {
			Posts []postView `json:"posts"`
		}
		if err := c.do(ctx, http.MethodGet, "/post/list", q, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, v := range r.Posts {
			row := map[string]any{"id": v.Post.ID, "title": clip(v.Post.Name, maxTitle), "community": handle(v.Community.Name, v.Community.ActorID),
				"from": handle(v.Creator.Name, v.Creator.ActorID), "when": v.Post.Published, "score": v.Counts.Score, "comments": v.Counts.Comments}
			if v.Post.URL != "" {
				row["url"] = clip(rest.StripUserinfo(v.Post.URL), 2000)
			}
			if v.Post.Body != "" {
				row["text"] = clip(v.Post.Body, 2000)
			}
			if v.Post.Locked {
				row["locked"] = true
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "comments":
		if p.Post <= 0 {
			return sdk.Result{}, errors.New("post is a post id (a positive number)")
		}
		s := map[string]string{"": "Top", "top": "Top", "hot": "Hot", "new": "New"}[p.Sort]
		if s == "" {
			return sdk.Result{}, errors.New("sort is hot, top or new")
		}
		q := url.Values{"post_id": {strconv.FormatInt(p.Post, 10)}, "sort": {s}, "limit": {limit(50, 50)}, "type_": {"All"}, "max_depth": {"8"}}
		var r struct {
			Comments []commentView `json:"comments"`
		}
		if err := c.do(ctx, http.MethodGet, "/comment/list", q, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, v := range r.Comments {
			row := map[string]any{"id": v.Comment.ID, "from": handle(v.Creator.Name, v.Creator.ActorID), "when": v.Comment.Published, "score": v.Counts.Score}
			if v.Comment.Deleted || v.Comment.Removed {
				row["removed"] = true
			} else {
				row["text"] = clip(v.Comment.Content, 4000)
			}
			// path is "0.<ancestor ids>.<id>"
			if parts := strings.Split(v.Comment.Path, "."); len(parts) > 2 {
				if pid, err := strconv.ParseInt(parts[len(parts)-2], 10, 64); err == nil {
					row["parent"] = pid
				}
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"post": p.Post, "comments": out})

	case "create_post":
		title := strings.TrimSpace(p.Title)
		if title == "" || len([]rune(title)) > maxTitle || strings.ContainsAny(title, "\r\n") {
			return sdk.Result{}, fmt.Errorf("the title is one line of up to %d characters", maxTitle)
		}
		body := strings.TrimSpace(p.Body)
		if len([]rune(body)) > maxBody {
			return sdk.Result{}, fmt.Errorf("the body is up to %d characters", maxBody)
		}
		link := ""
		if strings.TrimSpace(p.URL) != "" {
			u, err := urlguard.URL(ctx, p.URL)
			if err != nil {
				return sdk.Result{}, err
			}
			link = u.String()
		}
		name, full, err := c.community(p.Community)
		if err != nil {
			return sdk.Result{}, err
		}
		if err := c.checkAllowed(full); err != nil {
			return sdk.Result{}, err
		}
		var cv struct {
			CommunityView struct {
				Community community `json:"community"`
			} `json:"community_view"`
		}
		if err := c.do(ctx, http.MethodGet, "/community", url.Values{"name": {name}}, nil, &cv); err != nil {
			return sdk.Result{}, err
		}
		cm := cv.CommunityView.Community
		if cm.ID <= 0 || handle(cm.Name, cm.ActorID) != full {
			return sdk.Result{}, fmt.Errorf("the instance answered with a different community for !%s", full)
		}
		if cm.Removed || cm.Deleted {
			return sdk.Result{}, fmt.Errorf("!%s was removed", full)
		}
		if call.DryRun {
			sum := fmt.Sprintf("Post publicly to !%s", full)
			if !strings.HasSuffix(full, "@"+c.domain) {
				sum += " (hosted on another instance)"
			}
			sum += "; it's copied to every instance that follows it"
			if cm.ModsOnly {
				sum += " (only moderators may post there)"
			}
			after, _ := json.Marshal(map[string]any{"title": title, "body": body, "url": link, "nsfw": p.NSFW})
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "!" + full, Op: "create", After: after}}}}, nil
		}
		in := map[string]any{"name": title, "community_id": cm.ID, "nsfw": p.NSFW}
		if body != "" {
			in["body"] = body
		}
		if link != "" {
			in["url"] = link
		}
		var r struct {
			PostView postView `json:"post_view"`
		}
		if err := c.do(ctx, http.MethodPost, "/post", nil, in, &r); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"id": r.PostView.Post.ID, "community": full, "url": rest.CleanURL(r.PostView.Post.ApID)})

	case "create_comment":
		text := strings.TrimSpace(p.Text)
		if text == "" || len([]rune(text)) > maxBody {
			return sdk.Result{}, fmt.Errorf("the comment is 1 to %d characters", maxBody)
		}
		if p.Post <= 0 {
			return sdk.Result{}, errors.New("post is a post id (a positive number)")
		}
		if p.Parent < 0 {
			return sdk.Result{}, errors.New("parent is a comment id (a positive number)")
		}
		var pv struct {
			PostView postView `json:"post_view"`
		}
		if err := c.do(ctx, http.MethodGet, "/post", url.Values{"id": {strconv.FormatInt(p.Post, 10)}}, nil, &pv); err != nil {
			return sdk.Result{}, err
		}
		v := pv.PostView
		if v.Post.ID != p.Post {
			return sdk.Result{}, fmt.Errorf("no post %d", p.Post)
		}
		full := handle(v.Community.Name, v.Community.ActorID)
		if err := c.checkAllowed(full); err != nil {
			return sdk.Result{}, err
		}
		if v.Post.Locked {
			return sdk.Result{}, fmt.Errorf("post %d is locked", p.Post)
		}
		to := handle(v.Creator.Name, v.Creator.ActorID)
		if p.Parent > 0 {
			var cv struct {
				CommentView commentView `json:"comment_view"`
			}
			if err := c.do(ctx, http.MethodGet, "/comment", url.Values{"id": {strconv.FormatInt(p.Parent, 10)}}, nil, &cv); err != nil {
				return sdk.Result{}, err
			}
			if cv.CommentView.Comment.ID != p.Parent || cv.CommentView.Comment.PostID != p.Post {
				return sdk.Result{}, fmt.Errorf("comment %d isn't on post %d", p.Parent, p.Post)
			}
			to = handle(cv.CommentView.Creator.Name, cv.CommentView.Creator.ActorID)
		}
		if call.DryRun {
			what := "post"
			if p.Parent > 0 {
				what = "comment"
			}
			sum := fmt.Sprintf("Comment publicly in !%s, replying to %s's %s (notifies them); it's copied to every instance that follows the community", full, to, what)
			after, _ := json.Marshal(map[string]any{"text": text, "post": p.Post, "parent": p.Parent})
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: rest.CleanURL(v.Post.ApID), Op: "create", After: after}}}}, nil
		}
		in := map[string]any{"content": text, "post_id": p.Post}
		if p.Parent > 0 {
			in["parent_id"] = p.Parent
		}
		var r struct {
			CommentView commentView `json:"comment_view"`
		}
		if err := c.do(ctx, http.MethodPost, "/comment", nil, in, &r); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"id": r.CommentView.Comment.ID, "post": p.Post, "url": rest.CleanURL(r.CommentView.Comment.ApID)})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
