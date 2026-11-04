// Package youtube reads your YouTube channel through the YouTube Data API v3
// with an OAuth refresh token: channel stats, recent uploads with their
// views, whether you're live, and the comments on your videos. It can also
// change a video's title and description, which everyone watching sees.
package youtube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Scopes are what the refresh token needs: reading the channel and its
// comments (youtube.force-ssl covers comment threads) and editing videos.
var Scopes = []string{"https://www.googleapis.com/auth/youtube.force-ssl"}

// Config is one YouTube channel's settings.
type Config struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"` // secret://
	RefreshToken string `json:"refreshToken"` // secret://
}

type conn struct {
	cfg  Config
	host sdk.Host
	http *http.Client
	api  *rest.Client
	auth string

	mu      sync.Mutex
	access  string
	expires time.Time
	channel string // the token's channel id, once known
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// Base replaces https://www.googleapis.com/youtube/v3, Auth the token
	// endpoint and HTTP the client (tests). They aren't settings, so an
	// instance can't send its token anywhere else.
	Base string
	Auth string
	HTTP *http.Client
}

// New returns the YouTube module.
func New() *Module { return &Module{} }

var (
	videoIDRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)
	clientIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{8,200}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "youtube", Name: "YouTube", Version: "0.1.0", Category: "Media", Icon: "video",
		Description: "Your YouTube channel: subscribers and views, recent videos, live status and comments; change a video's title and description.",
		Presets:     []string{"gamer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["clientId","clientSecret","refreshToken"],"properties":{
			"clientId":{"type":"string","description":"OAuth client ID from Google Cloud Console (APIs & Services, Credentials), with the YouTube Data API v3 enabled"},
			"clientSecret":{"type":"string","x-secret":true},
			"refreshToken":{"type":"string","x-secret":true,"description":"A refresh token with the youtube.force-ssl scope; the module docs show how to get one"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "channel", Title: "Channel stats", Description: "Your channel's name, subscribers, total views and video count.", Risk: sdk.RiskRead},
			{Name: "recent_videos", Title: "Recent videos", Description: "Your latest uploads with views, likes, comments and privacy.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"count":{"type":"integer","minimum":1,"maximum":50,"default":10}}}`)},
			{Name: "live", Title: "Live status", Description: "Whether you're live now, with concurrent viewers, and your upcoming scheduled broadcasts.", Risk: sdk.RiskRead},
			{Name: "update_video", Title: "Change a video's title or description", Description: "Sets a video's title and/or description, which everyone watching sees. Preview shows the old and new text; undo puts the old ones back.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["videoId"],"properties":{"videoId":{"type":"string","pattern":"^[A-Za-z0-9_-]{11}$"},"title":{"type":"string","minLength":1,"maxLength":100},"description":{"type":"string","maxLength":5000}}}`)},
			{Name: "comments", Title: "Comments", Description: "Recent comments on your videos (or one video), newest first. They name viewers and quote them, so this is sensitive.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"videoId":{"type":"string","pattern":"^[A-Za-z0-9_-]{11}$"},"count":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	c.ClientID = strings.TrimSpace(c.ClientID)
	if !clientIDRe.MatchString(c.ClientID) {
		return errors.New("add the OAuth client ID (it ends in .apps.googleusercontent.com)")
	}
	if !strings.HasPrefix(c.ClientSecret, "secret://") || !strings.HasPrefix(c.RefreshToken, "secret://") {
		return errors.New("store the client secret and the refresh token in the vault and enter their secret:// references")
	}
	cl := m.HTTP
	if cl == nil {
		cl = sdk.HTTPClient(h, 20*time.Second)
	}
	cl = rest.SameHostOnly(cl)
	base, auth := m.Base, m.Auth
	if base == "" {
		base = "https://www.googleapis.com/youtube/v3"
	}
	if auth == "" {
		auth = "https://oauth2.googleapis.com/token"
	}
	cn := &conn{cfg: c, host: h, http: cl, auth: auth}
	cn.api = rest.New(base, func(ctx context.Context, r *http.Request) error {
		tok, err := cn.token(ctx)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		return nil
	})
	cn.api.HTTP = cl
	m.set.Put(id, cn)
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// token returns an access token, refreshing it a minute before it expires.
func (c *conn) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.access != "" && time.Now().Before(c.expires.Add(-time.Minute)) {
		return c.access, nil
	}
	secret, err := c.host.Secret(ctx, c.cfg.ClientSecret)
	if err != nil {
		return "", err
	}
	refresh, err := c.host.Secret(ctx, c.cfg.RefreshToken)
	if err != nil {
		return "", err
	}
	form := url.Values{"client_id": {c.cfg.ClientID}, "client_secret": {strings.TrimSpace(secret)},
		"refresh_token": {strings.TrimSpace(refresh)}, "grant_type": {"refresh_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.auth, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Conduit")
	res, err := c.http.Do(req)
	if err != nil {
		return "", rest.TransportError(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var t struct {
		Access    string `json:"access_token"`
		ExpiresIn int    `json:"expires_in"`
		Error     string `json:"error"`
		Desc      string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &t)
	if res.StatusCode != http.StatusOK || t.Access == "" {
		msg := t.Desc
		if msg == "" {
			msg = t.Error
		}
		if msg == "" {
			msg = res.Status
		}
		return "", fmt.Errorf("Google didn't accept the client secret or refresh token (%s); get a new refresh token as the module docs describe", rest.Redact(msg))
	}
	if t.ExpiresIn <= 0 {
		t.ExpiresIn = 3600
	}
	c.access, c.expires = t.Access, time.Now().Add(time.Duration(t.ExpiresIn)*time.Second)
	return c.access, nil
}

// do calls the Data API; a 401 drops the cached token and tries once more.
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	if rest.IsStatus(err, http.StatusUnauthorized) {
		c.mu.Lock()
		c.access = ""
		c.mu.Unlock()
		_, err = c.api.Do(ctx, method, path, q, body, out)
	}
	if rest.IsStatus(err, http.StatusForbidden) && strings.Contains(strings.ToLower(err.Error()), "quota") {
		return &rest.Error{Status: http.StatusForbidden, Message: "the Google Cloud project's YouTube API quota for today is used up; it resets at midnight Pacific time"}
	}
	return err
}

type channelInfo struct {
	ID      string `json:"id"`
	Snippet struct {
		Title       string `json:"title"`
		CustomURL   string `json:"customUrl"`
		PublishedAt string `json:"publishedAt"`
	} `json:"snippet"`
	Statistics struct {
		Views       string `json:"viewCount"`
		Subscribers string `json:"subscriberCount"`
		Hidden      bool   `json:"hiddenSubscriberCount"`
		Videos      string `json:"videoCount"`
	} `json:"statistics"`
	ContentDetails struct {
		Related struct {
			Uploads string `json:"uploads"`
		} `json:"relatedPlaylists"`
	} `json:"contentDetails"`
}

func (c *conn) mine(ctx context.Context) (channelInfo, error) {
	var out struct {
		Items []channelInfo `json:"items"`
	}
	if err := c.do(ctx, "GET", "/channels", url.Values{"part": {"snippet,statistics,contentDetails"}, "mine": {"true"}}, nil, &out); err != nil {
		return channelInfo{}, err
	}
	if len(out.Items) == 0 {
		return channelInfo{}, errors.New("the Google account behind the refresh token has no YouTube channel")
	}
	c.mu.Lock()
	c.channel = out.Items[0].ID
	c.mu.Unlock()
	return out.Items[0], nil
}

func (c *conn) channelID(ctx context.Context) (string, error) {
	c.mu.Lock()
	id := c.channel
	c.mu.Unlock()
	if id != "" {
		return id, nil
	}
	ch, err := c.mine(ctx)
	return ch.ID, err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	ch, err := c.mine(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := ch.Snippet.Title
	if !ch.Statistics.Hidden && ch.Statistics.Subscribers != "" {
		msg += " · " + ch.Statistics.Subscribers + " subscribers"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type video struct {
	ID      string `json:"id"`
	Snippet struct {
		ChannelID       string   `json:"channelId"`
		Title           string   `json:"title"`
		Description     string   `json:"description"`
		PublishedAt     string   `json:"publishedAt"`
		CategoryID      string   `json:"categoryId"`
		Tags            []string `json:"tags,omitempty"`
		DefaultLanguage string   `json:"defaultLanguage,omitempty"`
		LiveContent     string   `json:"liveBroadcastContent"`
	} `json:"snippet"`
	Statistics struct {
		Views    string `json:"viewCount"`
		Likes    string `json:"likeCount"`
		Comments string `json:"commentCount"`
	} `json:"statistics"`
	Status struct {
		Privacy string `json:"privacyStatus"`
	} `json:"status"`
	Live struct {
		Viewers string `json:"concurrentViewers"`
	} `json:"liveStreamingDetails"`
}

func (c *conn) videos(ctx context.Context, part string, ids []string) ([]video, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var out struct {
		Items []video `json:"items"`
	}
	if err := c.do(ctx, "GET", "/videos", url.Values{"part": {part}, "id": {strings.Join(ids, ",")}, "maxResults": {"50"}}, nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func num(s string) int64 {
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int64(r-'0')
	}
	return n
}

// validText checks a title or description: YouTube refuses < and >.
func validText(s string, max int, what string, oneLine bool) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("the %s isn't valid text", what)
	}
	if utf8.RuneCountInString(s) > max {
		return fmt.Errorf("the %s is at most %d characters", what, max)
	}
	if strings.ContainsAny(s, "<>") {
		return fmt.Errorf("YouTube doesn't allow < or > in a %s", what)
	}
	for _, r := range s {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (oneLine && (r == '\n' || r == '\t')) {
			return fmt.Errorf("the %s can't contain control characters", what)
		}
	}
	return nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Count       int     `json:"count"`
		VideoID     string  `json:"videoId"`
		Title       *string `json:"title"`
		Description *string `json:"description"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	if p.VideoID != "" && !videoIDRe.MatchString(p.VideoID) {
		return sdk.Result{}, errors.New("a video id is the 11 characters after watch?v= in its address")
	}
	count := func(def, max int) (int, error) {
		if p.Count == 0 {
			return def, nil
		}
		if p.Count < 1 || p.Count > max {
			return 0, fmt.Errorf("count is 1 to %d", max)
		}
		return p.Count, nil
	}
	switch call.Action {
	case "channel":
		ch, err := c.mine(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"id": ch.ID, "title": ch.Snippet.Title, "handle": ch.Snippet.CustomURL,
			"views": num(ch.Statistics.Views), "videos": num(ch.Statistics.Videos), "created": ch.Snippet.PublishedAt}
		if ch.Statistics.Hidden {
			out["subscribersHidden"] = true
		} else {
			out["subscribers"] = num(ch.Statistics.Subscribers)
		}
		return sdk.JSON(out)

	case "recent_videos":
		n, err := count(10, 50)
		if err != nil {
			return sdk.Result{}, err
		}
		ch, err := c.mine(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		uploads := ch.ContentDetails.Related.Uploads
		type row struct {
			ID        string `json:"id"`
			Title     string `json:"title"`
			Published string `json:"published"`
			Privacy   string `json:"privacy,omitempty"`
			Views     int64  `json:"views"`
			Likes     int64  `json:"likes"`
			Comments  int64  `json:"comments"`
			Live      string `json:"live,omitempty"`
			URL       string `json:"url"`
		}
		rows := []row{}
		if uploads == "" {
			return sdk.JSON(rows)
		}
		var items struct {
			Items []struct {
				ContentDetails struct {
					VideoID string `json:"videoId"`
				} `json:"contentDetails"`
			} `json:"items"`
		}
		if err := c.do(ctx, "GET", "/playlistItems", url.Values{"part": {"contentDetails"}, "playlistId": {uploads}, "maxResults": {fmt.Sprint(n)}}, nil, &items); err != nil {
			return sdk.Result{}, err
		}
		var ids []string
		for _, it := range items.Items {
			if videoIDRe.MatchString(it.ContentDetails.VideoID) {
				ids = append(ids, it.ContentDetails.VideoID)
			}
		}
		vs, err := c.videos(ctx, "snippet,statistics,status", ids)
		if err != nil {
			return sdk.Result{}, err
		}
		byID := map[string]video{}
		for _, v := range vs {
			byID[v.ID] = v
		}
		for _, id := range ids {
			v, ok := byID[id]
			if !ok {
				continue
			}
			live := v.Snippet.LiveContent
			if live == "none" {
				live = ""
			}
			rows = append(rows, row{ID: id, Title: v.Snippet.Title, Published: v.Snippet.PublishedAt, Privacy: v.Status.Privacy,
				Views: num(v.Statistics.Views), Likes: num(v.Statistics.Likes), Comments: num(v.Statistics.Comments), Live: live,
				URL: "https://www.youtube.com/watch?v=" + id})
		}
		return sdk.JSON(rows)

	case "live":
		type bc struct {
			ID        string `json:"id"`
			Title     string `json:"title"`
			Status    string `json:"status"`
			Privacy   string `json:"privacy,omitempty"`
			Scheduled string `json:"scheduledStart,omitempty"`
			Started   string `json:"startedAt,omitempty"`
			Viewers   *int64 `json:"viewers,omitempty"`
			URL       string `json:"url"`
		}
		get := func(status string) ([]bc, error) {
			var out struct {
				Items []struct {
					ID      string `json:"id"`
					Snippet struct {
						Title     string `json:"title"`
						Scheduled string `json:"scheduledStartTime"`
						Started   string `json:"actualStartTime"`
					} `json:"snippet"`
					Status struct {
						Life    string `json:"lifeCycleStatus"`
						Privacy string `json:"privacyStatus"`
					} `json:"status"`
				} `json:"items"`
			}
			q := url.Values{"part": {"snippet,status"}, "broadcastStatus": {status}, "broadcastType": {"all"}, "maxResults": {"10"}}
			if err := c.do(ctx, "GET", "/liveBroadcasts", q, nil, &out); err != nil {
				return nil, err
			}
			var r []bc
			for _, it := range out.Items {
				if !videoIDRe.MatchString(it.ID) {
					continue
				}
				r = append(r, bc{ID: it.ID, Title: it.Snippet.Title, Status: it.Status.Life, Privacy: it.Status.Privacy,
					Scheduled: it.Snippet.Scheduled, Started: it.Snippet.Started, URL: "https://www.youtube.com/watch?v=" + it.ID})
			}
			return r, nil
		}
		active, err := get("active")
		if err != nil {
			return sdk.Result{}, err
		}
		upcoming, err := get("upcoming")
		if err != nil {
			return sdk.Result{}, err
		}
		if len(active) > 0 {
			var ids []string
			for _, b := range active {
				ids = append(ids, b.ID)
			}
			vs, err := c.videos(ctx, "liveStreamingDetails", ids)
			if err != nil {
				return sdk.Result{}, err
			}
			for _, v := range vs {
				for i := range active {
					if active[i].ID == v.ID && v.Live.Viewers != "" {
						n := num(v.Live.Viewers)
						active[i].Viewers = &n
					}
				}
			}
		}
		if active == nil {
			active = []bc{}
		}
		if upcoming == nil {
			upcoming = []bc{}
		}
		return sdk.JSON(map[string]any{"live": len(active) > 0, "active": active, "upcoming": upcoming})

	case "update_video":
		if p.VideoID == "" {
			return sdk.Result{}, errors.New("name the video by its id")
		}
		if p.Title == nil && p.Description == nil {
			return sdk.Result{}, errors.New("give a new title, a new description, or both")
		}
		if p.Title != nil {
			if strings.TrimSpace(*p.Title) == "" {
				return sdk.Result{}, errors.New("a title can't be empty")
			}
			if err := validText(*p.Title, 100, "title", true); err != nil {
				return sdk.Result{}, err
			}
		}
		if p.Description != nil {
			if err := validText(*p.Description, 5000, "description", false); err != nil {
				return sdk.Result{}, err
			}
			if len(*p.Description) > 5000 {
				return sdk.Result{}, errors.New("the description is at most 5000 bytes")
			}
		}
		me, err := c.channelID(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		vs, err := c.videos(ctx, "snippet", []string{p.VideoID})
		if err != nil {
			return sdk.Result{}, err
		}
		if len(vs) == 0 {
			return sdk.Result{}, errors.New("no video with that id")
		}
		v := vs[0]
		if v.Snippet.ChannelID != me {
			return sdk.Result{}, errors.New("that video isn't on your channel")
		}
		before := map[string]string{"title": v.Snippet.Title, "description": v.Snippet.Description}
		after := map[string]string{"title": v.Snippet.Title, "description": v.Snippet.Description}
		if p.Title != nil {
			after["title"] = *p.Title
		}
		if p.Description != nil {
			after["description"] = *p.Description
		}
		if call.DryRun {
			b, _ := json.Marshal(before)
			a, _ := json.Marshal(after)
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Change the title or description of %q (public to its viewers)", v.Snippet.Title),
				Changes: []sdk.Change{{Target: "youtube.com/watch?v=" + p.VideoID, Op: "update", Before: b, After: a}}}}, nil
		}
		// videos.update replaces the whole snippet: send back what's kept.
		snippet := map[string]any{"title": after["title"], "description": after["description"], "categoryId": v.Snippet.CategoryID}
		if len(v.Snippet.Tags) > 0 {
			snippet["tags"] = v.Snippet.Tags
		}
		if v.Snippet.DefaultLanguage != "" {
			snippet["defaultLanguage"] = v.Snippet.DefaultLanguage
		}
		if err := c.do(ctx, "PUT", "/videos", url.Values{"part": {"snippet"}}, map[string]any{"id": p.VideoID, "snippet": snippet}, nil); err != nil {
			return sdk.Result{}, err
		}
		r, _ := sdk.JSON(map[string]string{"videoId": p.VideoID, "title": after["title"], "description": after["description"]})
		r.Undo = sdk.UndoWith("update_video", map[string]string{"videoId": p.VideoID, "title": before["title"], "description": before["description"]},
			"Put the previous title and description back")
		return r, nil

	case "comments":
		n, err := count(20, 100)
		if err != nil {
			return sdk.Result{}, err
		}
		q := url.Values{"part": {"snippet"}, "order": {"time"}, "maxResults": {fmt.Sprint(n)}, "textFormat": {"plainText"}}
		if p.VideoID != "" {
			q.Set("videoId", p.VideoID)
		} else {
			me, err := c.channelID(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			q.Set("allThreadsRelatedToChannelId", me)
		}
		var out struct {
			Items []struct {
				ID      string `json:"id"`
				Snippet struct {
					VideoID string `json:"videoId"`
					Replies int    `json:"totalReplyCount"`
					Top     struct {
						Snippet struct {
							Author    string `json:"authorDisplayName"`
							Text      string `json:"textOriginal"`
							Likes     int    `json:"likeCount"`
							Published string `json:"publishedAt"`
						} `json:"snippet"`
					} `json:"topLevelComment"`
				} `json:"snippet"`
			} `json:"items"`
		}
		if err := c.do(ctx, "GET", "/commentThreads", q, nil, &out); err != nil {
			if rest.IsStatus(err, http.StatusForbidden) {
				return sdk.Result{}, errors.New("comments are turned off for that video, or the token lacks the youtube.force-ssl scope")
			}
			return sdk.Result{}, err
		}
		type row struct {
			VideoID   string `json:"videoId"`
			Author    string `json:"author"`
			Text      string `json:"text"`
			Likes     int    `json:"likes"`
			Replies   int    `json:"replies"`
			Published string `json:"published"`
		}
		rows := []row{}
		for _, it := range out.Items {
			s := it.Snippet
			rows = append(rows, row{VideoID: s.VideoID, Author: s.Top.Snippet.Author, Text: s.Top.Snippet.Text, Likes: s.Top.Snippet.Likes, Replies: s.Replies, Published: s.Top.Snippet.Published})
		}
		return sdk.JSON(rows)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
