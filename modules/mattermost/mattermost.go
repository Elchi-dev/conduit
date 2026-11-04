// Package mattermost works with a Mattermost server (API v4): channels,
// recent posts, who is online, and posting (with undo).
package mattermost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Mattermost server and account.
type Config struct {
	URL   string `json:"url"`   // e.g. https://chat.example.com
	Token string `json:"token"` // secret:// personal access token or bot token
	Team  string `json:"team"`  // default team name, e.g. "engineering"
}

type conn struct {
	api  *rest.Client
	team string
	base string
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
}

// New returns the Mattermost module.
func New() *Module { return &Module{} }

var (
	idRe   = regexp.MustCompile(`^[a-z0-9]{26}$`)
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	userRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	ch := `"channel":{"type":"string","description":"Channel name (in the default team), team/channel, or a channel id"}`
	return sdk.Manifest{
		ID: "mattermost", Name: "Mattermost", Version: "0.1.0", Category: "Communication", Icon: "chat",
		Description: "Mattermost channels and recent posts, who's online, and posting messages.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://chat.example.com"},
			"token":{"type":"string","x-secret":true,"description":"A personal access token (Profile, Security) or a bot account's token"},
			"team":{"type":"string","description":"Default team name (the part of the address after the server), e.g. engineering"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "channels", Title: "Channels", Description: "Public and private channels the account is in.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"team":{"type":"string","description":"Only this team"}}}`)},
			{Name: "posts", Title: "Recent posts", Description: "The latest posts in a channel, newest first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["channel"],"properties":{` + ch + `,"limit":{"type":"integer","default":30,"maximum":200}}}`)},
			{Name: "statuses", Title: "Who's online", Description: "Online, away, do not disturb or offline, for named users or the default team.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"users":{"type":"array","items":{"type":"string"},"description":"User names; empty means the default team's members"}}}`)},
			{Name: "post_message", Title: "Post a message", Description: "Markdown; a rootId replies in a thread. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["channel","message"],"properties":{` + ch + `,"message":{"type":"string","maxLength":16383},"rootId":{"type":"string","description":"Post id of the thread to reply in"}}}`)},
			{Name: "delete_post", Title: "Delete a post", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["postId"],"properties":{"postId":{"type":"string"}}}`)},
		},
		Resources: []sdk.ResourceSpec{{Kind: "channel", Title: "Channels", ListAction: "channels", ViewHint: "table"}},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return errors.New("the address is like https://chat.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	c.Team = strings.ToLower(strings.TrimSpace(c.Team))
	if c.Team != "" && !nameRe.MatchString(c.Team) {
		return errors.New("the team is its name as in the address, e.g. engineering")
	}
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v4")
	tok := c.Token
	api := rest.New(base+"/api/v4", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api, team: c.Team, base: base})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

type team struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type channel struct {
	ID          string `json:"id"`
	TeamID      string `json:"team_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Type        string `json:"type"`
	Purpose     string `json:"purpose"`
	LastPostAt  int64  `json:"last_post_at"`
}

type post struct {
	ID         string `json:"id"`
	CreateAt   int64  `json:"create_at"`
	UserID     string `json:"user_id"`
	ChannelID  string `json:"channel_id"`
	RootID     string `json:"root_id"`
	Message    string `json:"message"`
	Type       string `json:"type"`
	ReplyCount int    `json:"reply_count"`
}

type user struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

func stamp(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

func (c *conn) teamByName(ctx context.Context, name string) (team, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !nameRe.MatchString(name) {
		return team{}, fmt.Errorf("%q isn't a team name", name)
	}
	var t team
	if _, err := c.api.Do(ctx, http.MethodGet, "/teams/name/"+name, nil, nil, &t); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return team{}, fmt.Errorf("no team %s (or the account isn't in it)", name)
		}
		return team{}, err
	}
	return t, nil
}

// channel resolves "name", "team/name" or an id.
func (c *conn) channel(ctx context.Context, s string) (channel, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "~")
	var ch channel
	if idRe.MatchString(s) {
		if _, err := c.api.Do(ctx, http.MethodGet, "/channels/"+s, nil, nil, &ch); err == nil {
			return ch, nil
		} else if !rest.IsStatus(err, http.StatusNotFound) && !rest.IsStatus(err, http.StatusForbidden) {
			return ch, err
		}
	}
	tname, cname, ok := strings.Cut(s, "/")
	if !ok {
		tname, cname = c.team, s
		if tname == "" {
			return ch, errors.New("write the channel as team/channel, or set a default team")
		}
	}
	cname = strings.ToLower(cname)
	if !nameRe.MatchString(cname) {
		return ch, errors.New("the channel is its name as in the address (lowercase letters, digits, - and _), team/channel, or an id")
	}
	t, err := c.teamByName(ctx, tname)
	if err != nil {
		return ch, err
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/teams/"+t.ID+"/channels/name/"+cname, nil, nil, &ch); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) || rest.IsStatus(err, http.StatusForbidden) {
			return ch, fmt.Errorf("no channel %s in %s that this account can see", cname, t.Name)
		}
		return ch, err
	}
	return ch, nil
}

func (c *conn) usernames(ctx context.Context, ids []string) map[string]string {
	out := map[string]string{}
	if len(ids) == 0 {
		return out
	}
	var us []user
	if _, err := c.api.Do(ctx, http.MethodPost, "/users/ids", nil, ids, &us); err == nil {
		for _, u := range us {
			out[u.ID] = u.Username
		}
	}
	return out
}

func kind(t string) string {
	switch t {
	case "O":
		return "public"
	case "P":
		return "private"
	case "D":
		return "direct"
	case "G":
		return "group"
	}
	return t
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u user
	if _, err := c.api.Do(ctx, http.MethodGet, "/users/me", nil, nil, &u); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "the server refused the token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + u.Username
	if c.team != "" {
		if _, err := c.teamByName(ctx, c.team); err != nil {
			return sdk.Health{Status: "degraded", Message: msg + "; " + err.Error()}
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Team    string   `json:"team"`
		Channel string   `json:"channel"`
		Limit   int      `json:"limit"`
		Users   []string `json:"users"`
		Message string   `json:"message"`
		RootID  string   `json:"rootId"`
		PostID  string   `json:"postId"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "channels":
		var teams []team
		if p.Team != "" {
			t, err := c.teamByName(ctx, p.Team)
			if err != nil {
				return sdk.Result{}, err
			}
			teams = []team{t}
		} else if _, err := c.api.Do(ctx, http.MethodGet, "/users/me/teams", nil, nil, &teams); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range teams {
			var chs []channel
			if _, err := c.api.Do(ctx, http.MethodGet, "/users/me/teams/"+t.ID+"/channels", nil, nil, &chs); err != nil {
				return sdk.Result{}, err
			}
			for _, ch := range chs {
				if ch.Type != "O" && ch.Type != "P" {
					continue
				}
				out = append(out, map[string]any{"team": t.Name, "name": ch.Name, "displayName": ch.DisplayName, "type": kind(ch.Type),
					"purpose": ch.Purpose, "lastPost": stamp(ch.LastPostAt), "id": ch.ID})
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i]["lastPost"].(string) > out[j]["lastPost"].(string) })
		return sdk.JSON(out)

	case "posts":
		ch, err := c.channel(ctx, p.Channel)
		if err != nil {
			return sdk.Result{}, err
		}
		limit := p.Limit
		if limit <= 0 {
			limit = 30
		}
		if limit > 200 {
			limit = 200
		}
		var r struct {
			Order []string        `json:"order"`
			Posts map[string]post `json:"posts"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/channels/"+ch.ID+"/posts", url.Values{"per_page": {strconv.Itoa(limit)}, "page": {"0"}}, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		var ids []string
		seen := map[string]bool{}
		for _, id := range r.Order {
			if u := r.Posts[id].UserID; u != "" && !seen[u] {
				seen[u] = true
				ids = append(ids, u)
			}
		}
		names := c.usernames(ctx, ids)
		out := []map[string]any{}
		for _, id := range r.Order {
			ps, ok := r.Posts[id]
			if !ok {
				continue
			}
			msg := ps.Message
			if len(msg) > 4000 {
				cut := 4000
				for cut > 0 && !utf8.RuneStart(msg[cut]) {
					cut--
				}
				msg = msg[:cut] + "…"
			}
			row := map[string]any{"id": ps.ID, "user": names[ps.UserID], "message": msg, "created": stamp(ps.CreateAt)}
			if ps.RootID != "" {
				row["rootId"] = ps.RootID
			}
			if ps.ReplyCount > 0 {
				row["replies"] = ps.ReplyCount
			}
			if ps.Type != "" {
				row["type"] = ps.Type
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"channel": ch.Name, "posts": out})

	case "statuses":
		var us []user
		if len(p.Users) > 0 {
			if len(p.Users) > 200 {
				return sdk.Result{}, errors.New("ask for up to 200 users at a time")
			}
			names := []string{}
			for _, n := range p.Users {
				n = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(n), "@"))
				if !userRe.MatchString(n) {
					return sdk.Result{}, fmt.Errorf("%q isn't a user name", n)
				}
				names = append(names, n)
			}
			if _, err := c.api.Do(ctx, http.MethodPost, "/users/usernames", nil, names, &us); err != nil {
				return sdk.Result{}, err
			}
		} else {
			q := url.Values{"per_page": {"200"}, "active": {"true"}}
			if c.team != "" {
				t, err := c.teamByName(ctx, c.team)
				if err != nil {
					return sdk.Result{}, err
				}
				q.Set("in_team", t.ID)
			}
			if _, err := c.api.Do(ctx, http.MethodGet, "/users", q, nil, &us); err != nil {
				return sdk.Result{}, err
			}
		}
		out := []map[string]any{}
		if len(us) == 0 {
			return sdk.JSON(out)
		}
		ids := make([]string, 0, len(us))
		byID := map[string]string{}
		for _, u := range us {
			ids = append(ids, u.ID)
			byID[u.ID] = u.Username
		}
		var st []struct {
			UserID       string `json:"user_id"`
			Status       string `json:"status"`
			Manual       bool   `json:"manual"`
			LastActivity int64  `json:"last_activity_at"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/users/status/ids", nil, ids, &st); err != nil {
			return sdk.Result{}, err
		}
		for _, s := range st {
			out = append(out, map[string]any{"user": byID[s.UserID], "status": s.Status, "manual": s.Manual, "lastActivity": stamp(s.LastActivity)})
		}
		rank := map[string]int{"online": 0, "away": 1, "dnd": 2, "offline": 3}
		sort.SliceStable(out, func(i, j int) bool {
			a, b := rank[out[i]["status"].(string)], rank[out[j]["status"].(string)]
			if a != b {
				return a < b
			}
			return out[i]["user"].(string) < out[j]["user"].(string)
		})
		return sdk.JSON(out)

	case "post_message":
		if strings.TrimSpace(p.Message) == "" {
			return sdk.Result{}, errors.New("write the message")
		}
		if utf8.RuneCountInString(p.Message) > 16383 {
			return sdk.Result{}, errors.New("the message is longer than Mattermost allows (16383 characters)")
		}
		if p.RootID != "" && !idRe.MatchString(p.RootID) {
			return sdk.Result{}, errors.New("rootId is a post id (26 letters and digits)")
		}
		ch, err := c.channel(ctx, p.Channel)
		if err != nil {
			return sdk.Result{}, err
		}
		target := "~" + ch.Name
		if call.DryRun {
			after, _ := json.Marshal(map[string]string{"message": p.Message, "rootId": p.RootID})
			sum := "Post in " + target
			if p.RootID != "" {
				sum = "Reply in a thread in " + target
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: target, Op: "create", After: after}}}}, nil
		}
		body := map[string]any{"channel_id": ch.ID, "message": p.Message}
		if p.RootID != "" {
			body["root_id"] = p.RootID
		}
		var ps post
		if _, err := c.api.Do(ctx, http.MethodPost, "/posts", nil, body, &ps); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"id": ps.ID, "channel": ch.Name, "created": stamp(ps.CreateAt)})
		res.Undo = sdk.UndoWith("delete_post", map[string]string{"postId": ps.ID}, "Delete the message in "+target)
		return res, err

	case "delete_post":
		if !idRe.MatchString(p.PostID) {
			return sdk.Result{}, errors.New("postId is a post id (26 letters and digits)")
		}
		var ps post
		if _, err := c.api.Do(ctx, http.MethodGet, "/posts/"+p.PostID, nil, nil, &ps); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("no post %s", p.PostID)
			}
			return sdk.Result{}, err
		}
		if call.DryRun {
			names := c.usernames(ctx, []string{ps.UserID})
			before, _ := json.Marshal(map[string]string{"user": names[ps.UserID], "message": ps.Message, "created": stamp(ps.CreateAt)})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete %s's post from %s", names[ps.UserID], stamp(ps.CreateAt)),
				Changes: []sdk.Change{{Target: c.base + "/_redirect/pl/" + ps.ID, Op: "delete", Before: before}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodDelete, "/posts/"+p.PostID, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": p.PostID})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
