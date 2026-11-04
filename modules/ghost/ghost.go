// Package ghost works with a Ghost site through its Admin API with a custom
// integration's Admin API key: posts (drafts, scheduled, published),
// creating a draft, publishing (optionally emailing a newsletter),
// unpublishing, deleting a post, newsletters and members.
//
// The key ("id:secret") signs a short-lived JWT for each request, as Ghost
// requires; the secret never leaves the module. Publishing makes a post
// public and can email it to members, which can't be taken back, so it is
// destructive and its preview says whether a newsletter goes out and to how
// many members.
package ghost

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Ghost site.
type Config struct {
	URL      string `json:"url"`      // https://blog.example.com (the admin URL, when it differs)
	AdminKey string `json:"adminKey"` // secret:// Admin API key, id:secret
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Ghost module.
func New() *Module { return &Module{} }

func (m *Module) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

var (
	keyRe    = regexp.MustCompile(`^([0-9a-f]{24}):([0-9a-f]{64})$`)
	idRe     = regexp.MustCompile(`^[0-9a-f]{24}$`)
	slugRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,190}$`)
	prefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
	tagRe    = regexp.MustCompile(`^[^\x00-\x1f\x7f,]{1,191}$`)
)

var segments = map[string]string{"all": "all", "free": "status:free", "paid": "status:-free"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	post := `"post":{"type":"string","description":"Post id (24 hex characters, see posts)"}`
	return sdk.Manifest{
		ID: "ghost", Name: "Ghost", Version: "0.1.0", Category: "Productivity", Icon: "document",
		Description: "A Ghost site through the Admin API: posts, create drafts, publish (with or without a newsletter email), unpublish, delete, newsletters and members.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","adminKey"],"properties":{
			"url":{"type":"string","description":"Your site's admin address, e.g. https://blog.example.com or https://example.ghost.io"},
			"adminKey":{"type":"string","x-secret":true,"description":"Admin API key of a custom integration (Settings, Integrations, Add custom integration), like 6489...:a1b2..."}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "posts", Title: "Posts", Description: "Posts, most recently updated first, with status, URL, visibility and dates.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["all","draft","scheduled","published"],"default":"all"},"limit":{"type":"integer","default":15,"minimum":1,"maximum":100}}}`)},
			{Name: "create_draft", Title: "Create a draft", Description: "Creates a draft post from HTML; nothing is published or emailed. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["title"],"properties":{"title":{"type":"string","maxLength":255},"html":{"type":"string","maxLength":1000000},"excerpt":{"type":"string","maxLength":300},"tags":{"type":"array","items":{"type":"string"},"maxItems":10},"visibility":{"type":"string","enum":["public","members","paid"],"default":"public"}}}`)},
			{Name: "publish", Title: "Publish a post", Description: "Publishes a draft or scheduled post on the site now. With a newsletter it is also emailed to that newsletter's subscribers (all, free or paid), which can't be recalled. The preview says whether an email goes out and to how many members.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["post"],"properties":{` + post + `,"newsletter":{"type":"string","description":"Newsletter slug to email the post with (see newsletters); leave out to publish without emailing"},"segment":{"type":"string","enum":["all","free","paid"],"default":"all","description":"Which subscribers of the newsletter get the email"}}}`)},
			{Name: "unpublish", Title: "Unpublish a post", Description: "Turns a published post back into a draft: it leaves the site and its URL stops working; emails already sent stay sent. Undo publishes it again, without emailing.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["post"],"properties":{` + post + `}}`)},
			{Name: "delete_post", Title: "Delete a post", Description: "Deletes a post for good, from the site and the editor. The preview names it.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["post"],"properties":{` + post + `}}`)},
			{Name: "newsletters", Title: "Newsletters", Description: "Active newsletters with slug and subscriber count.", Risk: sdk.RiskRead},
			{Name: "members_count", Title: "Member count", Description: "How many members the site has: all, free and paid.", Risk: sdk.RiskRead},
			{Name: "members", Title: "Members", Description: "Recent members with name, email and status (personal data).", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["free","paid","comped"]},"limit":{"type":"integer","default":20,"minimum":1,"maximum":100}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	s := strings.TrimSpace(c.URL)
	if s != "" && !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	prefix := ""
	if err == nil {
		prefix = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/ghost")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return errors.New("the url is your site's address, like https://blog.example.com")
	}
	if !strings.HasPrefix(c.AdminKey, "secret://") {
		return errors.New("store the Admin API key in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	ref := c.AdminKey
	api := rest.New(u.Scheme+"://"+u.Host+prefix+"/ghost/api/admin", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		tok, err := token(strings.TrimSpace(k), m.now())
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Ghost "+tok)
		return nil
	})
	api.Header.Set("Accept-Version", "v5.0")
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// token signs the 5-minute JWT Ghost's Admin API expects.
func token(key string, now time.Time) (string, error) {
	mm := keyRe.FindStringSubmatch(key)
	if mm == nil {
		return "", errors.New("the Admin API key isn't in the id:secret form Ghost shows (a Content API key won't do)")
	}
	secret, _ := hex.DecodeString(mm[2])
	enc := base64.RawURLEncoding
	head, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT", "kid": mm[1]})
	body, _ := json.Marshal(map[string]any{"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "aud": "/admin/"})
	msg := enc.EncodeToString(head) + "." + enc.EncodeToString(body)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	return msg + "." + enc.EncodeToString(mac.Sum(nil)), nil
}

func friendly(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Ghost refused the Admin API key")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("Ghost has no such post")
	case rest.IsStatus(err, http.StatusConflict):
		return errors.New("the post changed in the editor meanwhile; try again")
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

type post struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Slug        string  `json:"slug"`
	Status      string  `json:"status"`
	URL         string  `json:"url"`
	Visibility  string  `json:"visibility"`
	UpdatedAt   string  `json:"updated_at"`
	PublishedAt *string `json:"published_at"`
	Email       *struct {
		Status         string `json:"status"`
		EmailCount     int    `json:"email_count"`
		DeliveredCount int    `json:"delivered_count"`
		OpenedCount    int    `json:"opened_count"`
	} `json:"email"`
	Newsletter *struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	} `json:"newsletter"`
}

func (p post) brief() map[string]any {
	out := map[string]any{"post": p.ID, "title": clip(p.Title, 255), "status": p.Status, "visibility": p.Visibility, "updated": p.UpdatedAt}
	if p.Status == "published" && p.URL != "" {
		out["url"] = p.URL
	}
	if p.PublishedAt != nil && *p.PublishedAt != "" {
		out["published"] = *p.PublishedAt
	}
	if p.Email != nil {
		out["email"] = map[string]any{"status": p.Email.Status, "sent": p.Email.EmailCount, "delivered": p.Email.DeliveredCount, "opened": p.Email.OpenedCount}
	}
	return out
}

func (c *conn) post(ctx context.Context, id string) (post, error) {
	if !idRe.MatchString(id) {
		return post{}, errors.New("the post is its id, 24 hex characters (see posts)")
	}
	var res struct {
		Posts []post `json:"posts"`
	}
	if err := c.do(ctx, http.MethodGet, "/posts/"+id+"/", url.Values{"include": {"email,newsletter"}, "formats": {"html"}}, nil, &res); err != nil {
		return post{}, err
	}
	if len(res.Posts) != 1 || res.Posts[0].ID != id || res.Posts[0].UpdatedAt == "" {
		return post{}, errors.New("unexpected answer from Ghost")
	}
	return res.Posts[0], nil
}

func (c *conn) count(ctx context.Context, path, filter string) (int, error) {
	q := url.Values{"limit": {"1"}}
	if filter != "" {
		q.Set("filter", filter)
	}
	var res struct {
		Meta struct {
			Pagination struct {
				Total int `json:"total"`
			} `json:"pagination"`
		} `json:"meta"`
	}
	err := c.do(ctx, http.MethodGet, path, q, nil, &res)
	return res.Meta.Pagination.Total, err
}

type newsletter struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Status string `json:"status"`
	Count  *struct {
		Members int `json:"members"`
	} `json:"count"`
}

func (c *conn) newsletter(ctx context.Context, slug string) (newsletter, error) {
	var res struct {
		Newsletters []newsletter `json:"newsletters"`
	}
	if err := c.do(ctx, http.MethodGet, "/newsletters/", url.Values{"filter": {"slug:" + slug}, "limit": {"1"}}, nil, &res); err != nil {
		return newsletter{}, err
	}
	if len(res.Newsletters) == 0 || res.Newsletters[0].Slug != slug {
		return newsletter{}, fmt.Errorf("there's no newsletter %q (see newsletters)", slug)
	}
	if res.Newsletters[0].Status != "active" {
		return newsletter{}, fmt.Errorf("the newsletter %q is archived", slug)
	}
	return res.Newsletters[0], nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	// /site/ answers without a key, so check the key on a posts listing.
	if _, err := c.count(ctx, "/posts/", ""); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var site struct {
		Site struct {
			Title   string `json:"title"`
			Version string `json:"version"`
		} `json:"site"`
	}
	if err := c.do(ctx, http.MethodGet, "/site/", nil, nil, &site); err != nil {
		return sdk.Health{Status: "degraded", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: clip(site.Site.Title+" (Ghost "+site.Site.Version+")", 120)}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Post       string   `json:"post"`
		Status     string   `json:"status"`
		Limit      int      `json:"limit"`
		Title      string   `json:"title"`
		HTML       string   `json:"html"`
		Excerpt    string   `json:"excerpt"`
		Tags       []string `json:"tags"`
		Visibility string   `json:"visibility"`
		Newsletter string   `json:"newsletter"`
		Segment    string   `json:"segment"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	limit := func(def int) string {
		n := p.Limit
		if n <= 0 {
			n = def
		}
		if n > 100 {
			n = 100
		}
		return strconv.Itoa(n)
	}
	switch call.Action {
	case "posts":
		q := url.Values{"limit": {limit(15)}, "order": {"updated_at desc"}, "fields": {"id,title,slug,status,url,visibility,updated_at,published_at"}}
		switch p.Status {
		case "", "all":
		case "draft", "scheduled", "published":
			q.Set("filter", "status:"+p.Status)
		default:
			return sdk.Result{}, errors.New("status is all, draft, scheduled or published")
		}
		var res struct {
			Posts []post `json:"posts"`
		}
		if err := c.do(ctx, http.MethodGet, "/posts/", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, ps := range res.Posts {
			out = append(out, ps.brief())
		}
		return sdk.JSON(out)

	case "create_draft":
		title := strings.TrimSpace(p.Title)
		if title == "" || len([]rune(title)) > 255 || strings.ContainsAny(title, "\r\n\x00") {
			return sdk.Result{}, errors.New("the title is up to 255 characters on one line")
		}
		if len(p.HTML) > 1000000 {
			return sdk.Result{}, errors.New("the html is too long")
		}
		if len([]rune(p.Excerpt)) > 300 {
			return sdk.Result{}, errors.New("the excerpt is up to 300 characters")
		}
		vis := p.Visibility
		if vis == "" {
			vis = "public"
		}
		if vis != "public" && vis != "members" && vis != "paid" {
			return sdk.Result{}, errors.New("visibility is public, members or paid")
		}
		if len(p.Tags) > 10 {
			return sdk.Result{}, errors.New("give at most 10 tags")
		}
		tags := []map[string]string{}
		for _, t := range p.Tags {
			t = strings.TrimSpace(t)
			if !tagRe.MatchString(t) {
				return sdk.Result{}, fmt.Errorf("%q isn't a tag name", clip(t, 50))
			}
			tags = append(tags, map[string]string{"name": t})
		}
		if call.DryRun {
			after, _ := json.Marshal(map[string]any{"title": title, "visibility": vis, "tags": p.Tags, "htmlLength": len(p.HTML)})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create the draft %q; nothing is published or emailed", clip(title, 80)),
				Changes: []sdk.Change{{Target: "post " + clip(title, 80), Op: "create", After: after}}}}, nil
		}
		np := map[string]any{"title": title, "status": "draft", "visibility": vis}
		if p.HTML != "" {
			np["html"] = p.HTML
		}
		if p.Excerpt != "" {
			np["custom_excerpt"] = strings.TrimSpace(p.Excerpt)
		}
		if len(tags) > 0 {
			np["tags"] = tags
		}
		var res struct {
			Posts []post `json:"posts"`
		}
		if err := c.do(ctx, http.MethodPost, "/posts/", url.Values{"source": {"html"}}, map[string]any{"posts": []any{np}}, &res); err != nil {
			return sdk.Result{}, err
		}
		if len(res.Posts) != 1 {
			return sdk.Result{}, errors.New("unexpected answer from Ghost")
		}
		r, err := sdk.JSON(res.Posts[0].brief())
		if idRe.MatchString(res.Posts[0].ID) {
			r.Undo = sdk.UndoWith("delete_post", map[string]string{"post": res.Posts[0].ID}, "Delete the draft")
		}
		return r, err

	case "publish":
		ps, err := c.post(ctx, p.Post)
		if err != nil {
			return sdk.Result{}, err
		}
		if ps.Status == "published" {
			return sdk.Result{}, errors.New("the post is already published")
		}
		slug := strings.TrimSpace(p.Newsletter)
		seg := p.Segment
		if seg == "" {
			seg = "all"
		}
		filter, ok := segments[seg]
		if !ok {
			return sdk.Result{}, errors.New("segment is all, free or paid")
		}
		if slug != "" && !slugRe.MatchString(slug) {
			return sdk.Result{}, errors.New("the newsletter is its slug (see newsletters)")
		}
		if slug != "" && ps.Email != nil {
			return sdk.Result{}, errors.New("this post was already emailed; publish it without a newsletter")
		}
		var nl newsletter
		if slug != "" {
			if nl, err = c.newsletter(ctx, slug); err != nil {
				return sdk.Result{}, err
			}
		}
		if call.DryRun {
			where := "publicly"
			if ps.Visibility != "public" {
				where = "on the site for " + ps.Visibility + " members"
			}
			summary := fmt.Sprintf("Publish %q %s now. No email is sent.", clip(ps.Title, 80), where)
			changes := []sdk.Change{{Target: "post " + ps.ID, Op: "publish", Before: json.RawMessage(strconv.Quote(ps.Status)), After: json.RawMessage(`"published"`)}}
			if slug != "" {
				mf := "newsletters.slug:" + slug
				if seg != "all" {
					mf += "+" + filter
				}
				n, err := c.count(ctx, "/members/", mf)
				if err != nil {
					return sdk.Result{}, err
				}
				who := map[string]string{"all": "", "free": "free ", "paid": "paid "}[seg]
				summary = fmt.Sprintf("Publish %q %s now and email it with the newsletter %q to %d %ssubscribers. Sent emails can't be recalled.", clip(ps.Title, 80), where, clip(nl.Name, 80), n, who)
				after, _ := json.Marshal(map[string]any{"newsletter": slug, "segment": seg, "members": n})
				changes = append(changes, sdk.Change{Target: "newsletter " + slug, Op: "email", After: after})
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: changes}}, nil
		}
		q := url.Values{}
		if slug != "" {
			q.Set("newsletter", slug)
			q.Set("email_segment", filter)
		}
		var res struct {
			Posts []post `json:"posts"`
		}
		if err := c.do(ctx, http.MethodPut, "/posts/"+ps.ID+"/", q, map[string]any{"posts": []any{map[string]string{"status": "published", "updated_at": ps.UpdatedAt}}}, &res); err != nil {
			return sdk.Result{}, err
		}
		if len(res.Posts) != 1 {
			return sdk.Result{}, errors.New("unexpected answer from Ghost")
		}
		out := res.Posts[0].brief()
		out["emailed"] = slug != ""
		return sdk.JSON(out)

	case "unpublish":
		ps, err := c.post(ctx, p.Post)
		if err != nil {
			return sdk.Result{}, err
		}
		if ps.Status != "published" {
			return sdk.Result{}, fmt.Errorf("the post is %s, not published", ps.Status)
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Unpublish %q: it leaves the site and %s stops working", clip(ps.Title, 80), ps.URL),
				Changes: []sdk.Change{{Target: "post " + ps.ID, Op: "update", Before: json.RawMessage(`"published"`), After: json.RawMessage(`"draft"`)}}}}, nil
		}
		var res struct {
			Posts []post `json:"posts"`
		}
		if err := c.do(ctx, http.MethodPut, "/posts/"+ps.ID+"/", nil, map[string]any{"posts": []any{map[string]string{"status": "draft", "updated_at": ps.UpdatedAt}}}, &res); err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"post": ps.ID, "status": "draft"})
		r.Undo = sdk.UndoWith("publish", map[string]string{"post": ps.ID}, "Publish the post again (no email)")
		return r, err

	case "delete_post":
		ps, err := c.post(ctx, p.Post)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			before, _ := json.Marshal(ps.brief())
			what := "the " + ps.Status + " post"
			if ps.Status == "published" {
				what += " (it leaves " + ps.URL + ")"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete %s %q for good", what, clip(ps.Title, 80)),
				Changes: []sdk.Change{{Target: "post " + ps.ID, Op: "delete", Before: before}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/posts/"+ps.ID+"/", nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": ps.ID})

	case "newsletters":
		var res struct {
			Newsletters []newsletter `json:"newsletters"`
		}
		if err := c.do(ctx, http.MethodGet, "/newsletters/", url.Values{"filter": {"status:active"}, "include": {"count.members"}, "limit": {"all"}}, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, n := range res.Newsletters {
			e := map[string]any{"slug": n.Slug, "name": clip(n.Name, 200)}
			if n.Count != nil {
				e["subscribers"] = n.Count.Members
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "members_count":
		out := map[string]int{}
		for k, f := range map[string]string{"all": "", "free": "status:free", "paid": "status:paid", "comped": "status:comped"} {
			n, err := c.count(ctx, "/members/", f)
			if err != nil {
				return sdk.Result{}, err
			}
			out[k] = n
		}
		return sdk.JSON(out)

	case "members":
		q := url.Values{"limit": {limit(20)}, "order": {"created_at desc"}}
		switch p.Status {
		case "":
		case "free", "paid", "comped":
			q.Set("filter", "status:"+p.Status)
		default:
			return sdk.Result{}, errors.New("status is free, paid or comped")
		}
		var res struct {
			Members []struct {
				Name        string `json:"name"`
				Email       string `json:"email"`
				Status      string `json:"status"`
				CreatedAt   string `json:"created_at"`
				Newsletters []any  `json:"newsletters"`
			} `json:"members"`
		}
		if err := c.do(ctx, http.MethodGet, "/members/", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, mb := range res.Members {
			out = append(out, map[string]any{"name": clip(mb.Name, 200), "email": clip(mb.Email, 254), "status": mb.Status, "created": mb.CreatedAt, "newsletters": len(mb.Newsletters)})
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
