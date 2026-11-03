// Package mastodon posts to and reads from a Mastodon account (and other
// servers with the Mastodon API: GoToSocial, Pleroma, Akkoma).
package mastodon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one account on one instance.
type Config struct {
	Instance string `json:"instance"` // e.g. https://mastodon.social
	Token    string `json:"token"`    // secret:// access token
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Mastodon module.
func New() *Module { return &Module{} }

var idRe = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

var visibilities = map[string]bool{"public": true, "unlisted": true, "private": true, "direct": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "mastodon", Name: "Mastodon", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "Post to your Mastodon account and catch up on notifications. Works with GoToSocial, Pleroma and Akkoma too.",
		Presets:     []string{"team", "gamer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["instance","token"],"properties":{
			"instance":{"type":"string","description":"Your server, e.g. https://mastodon.social"},
			"token":{"type":"string","x-secret":true,"description":"Access token (Preferences, Development, New application; scopes read and write:statuses)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "post", Title: "Post", Risk: sdk.RiskWrite, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["text"],"properties":{
					"text":{"type":"string","maxLength":5000},
					"visibility":{"type":"string","enum":["public","unlisted","private","direct"],"default":"public","description":"public, unlisted (not in public timelines), private (followers only) or direct (mentioned people only)"},
					"warning":{"type":"string","description":"Content warning shown before the text"},
					"replyTo":{"type":"string","description":"Status id to reply to"}}}`)},
			{Name: "delete", Title: "Delete a post", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}`)},
			{Name: "notifications", Title: "Notifications", Description: "Mentions, follows, boosts and favourites.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":20,"maximum":40}}}`)},
			{Name: "mine", Title: "My recent posts", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":20,"maximum":40}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	s := strings.TrimSpace(c.Instance)
	if s != "" && !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("the instance is an address like https://mastodon.social")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	tok := c.Token
	api := rest.New(u.Scheme+"://"+u.Host+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	}
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

type account struct {
	ID       string `json:"id"`
	Acct     string `json:"acct"`
	Display  string `json:"display_name"`
	Follower int    `json:"followers_count"`
}

type status struct {
	ID         string  `json:"id"`
	URL        string  `json:"url"`
	CreatedAt  string  `json:"created_at"`
	Content    string  `json:"content"`
	Visibility string  `json:"visibility"`
	Spoiler    string  `json:"spoiler_text"`
	Replies    int     `json:"replies_count"`
	Reblogs    int     `json:"reblogs_count"`
	Favs       int     `json:"favourites_count"`
	Account    account `json:"account"`
	Reblog     *status `json:"reblog"`
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

// plain turns status HTML into readable text.
func plain(s string) string {
	s = strings.NewReplacer("<br>", "\n", "<br/>", "\n", "<br />", "\n", "</p><p>", "\n\n").Replace(s)
	return strings.TrimSpace(html.UnescapeString(tagRe.ReplaceAllString(s, "")))
}

func (st status) brief() map[string]any {
	out := map[string]any{"id": st.ID, "url": st.URL, "created": st.CreatedAt, "text": plain(st.Content), "visibility": st.Visibility,
		"replies": st.Replies, "boosts": st.Reblogs, "favourites": st.Favs}
	if st.Spoiler != "" {
		out["warning"] = st.Spoiler
	}
	if st.Reblog != nil {
		out["boostOf"] = st.Reblog.Account.Acct
		out["text"] = plain(st.Reblog.Content)
	}
	return out
}

func (m *Module) me(ctx context.Context, c *conn) (account, error) {
	var a account
	_, err := c.api.Do(ctx, http.MethodGet, "/accounts/verify_credentials", nil, nil, &a)
	if err == nil && !idRe.MatchString(a.ID) {
		err = errors.New("unexpected account id from the server")
	}
	return a, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	a, err := m.me(ctx, c)
	if err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "the server refused the token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "@" + a.Acct}
}

func limitOf(n int) string {
	if n <= 0 {
		n = 20
	}
	if n > 40 {
		n = 40
	}
	return strconv.Itoa(n)
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Text       string `json:"text"`
		Visibility string `json:"visibility"`
		Warning    string `json:"warning"`
		ReplyTo    string `json:"replyTo"`
		ID         string `json:"id"`
		Limit      int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "post":
		text := strings.TrimSpace(p.Text)
		if text == "" {
			return sdk.Result{}, errors.New("write something to post")
		}
		if len([]rune(text)) > 5000 {
			return sdk.Result{}, errors.New("the post is too long")
		}
		vis := p.Visibility
		if vis == "" {
			vis = "public"
		}
		if !visibilities[vis] {
			return sdk.Result{}, errors.New("visibility is public, unlisted, private or direct")
		}
		body := map[string]any{"status": text, "visibility": vis}
		if p.Warning != "" {
			body["spoiler_text"] = p.Warning
		}
		if p.ReplyTo != "" {
			if !idRe.MatchString(p.ReplyTo) {
				return sdk.Result{}, errors.New("replyTo is a status id")
			}
			body["in_reply_to_id"] = p.ReplyTo
		}
		var st status
		if _, err := c.api.Do(ctx, http.MethodPost, "/statuses", nil, body, &st); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"id": st.ID, "url": st.URL, "visibility": st.Visibility})
		if idRe.MatchString(st.ID) {
			res.Undo = sdk.UndoWith("delete", map[string]string{"id": st.ID}, "Delete the post")
		}
		return res, err

	case "delete":
		if !idRe.MatchString(p.ID) {
			return sdk.Result{}, errors.New("the id is the status id from mine or post")
		}
		var st status
		if _, err := c.api.Do(ctx, http.MethodGet, "/statuses/"+p.ID, nil, nil, &st); err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			before, _ := json.Marshal(st.brief())
			txt := []rune(plain(st.Content))
			if len(txt) > 80 {
				txt = append(txt[:80], '…')
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete the post %q", string(txt)),
				Changes: []sdk.Change{{Target: st.URL, Op: "delete", Before: before}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodDelete, "/statuses/"+p.ID, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": p.ID})

	case "notifications":
		var ns []struct {
			ID        string  `json:"id"`
			Type      string  `json:"type"`
			CreatedAt string  `json:"created_at"`
			Account   account `json:"account"`
			Status    *status `json:"status"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/notifications", url.Values{"limit": {limitOf(p.Limit)}}, nil, &ns); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, n := range ns {
			e := map[string]any{"type": n.Type, "from": n.Account.Acct, "created": n.CreatedAt}
			if n.Status != nil {
				e["status"] = n.Status.ID
				e["text"] = plain(n.Status.Content)
			}
			out = append(out, e)
		}
		return sdk.JSON(out)

	case "mine":
		a, err := m.me(ctx, c)
		if err != nil {
			return sdk.Result{}, err
		}
		var sts []status
		if _, err := c.api.Do(ctx, http.MethodGet, "/accounts/"+a.ID+"/statuses", url.Values{"limit": {limitOf(p.Limit)}}, nil, &sts); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, st := range sts {
			out = append(out, st.brief())
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
