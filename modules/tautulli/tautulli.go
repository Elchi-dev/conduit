// Package tautulli works with Tautulli, the Plex monitoring server, through
// its API v2 and API key: current streams with their bandwidth and
// transcode decisions, watch history, the home page's top lists, Plex
// server status, and terminating a stream.
//
// Tautulli takes its API key as a query parameter, so every error the
// module returns has the request URL's query removed: a transport error
// would otherwise carry the key.
package tautulli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Tautulli.
type Config struct {
	URL                string `json:"url"`    // e.g. http://tautulli.local:8181
	APIKey             string `json:"apiKey"` // secret://
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces the clock (tests).
	Now func() time.Time
}

// New returns the Tautulli module.
func New() *Module { return &Module{} }

var (
	pathRe      = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	cmdRe       = regexp.MustCompile(`^[a-z_]{1,40}$`)
)

var mediaTypes = map[string]bool{"movie": true, "episode": true, "track": true, "live": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "tautulli", Name: "Tautulli", Version: "0.1.0", Category: "Media", Icon: "chart",
		Description: "Tautulli for Plex: current streams and bandwidth, watch history, top lists, server status, and stopping a stream.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"Tautulli's address, e.g. http://tautulli.local:8181 (with its HTTP root, if set)"},
			"apiKey":{"type":"string","x-secret":true,"description":"The API key from Settings → Web Interface → API"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "activity", Title: "Activity", Description: "Current streams: who is watching what on which player, from which address, progress, state, direct play or transcode, and bandwidth; with totals for LAN and WAN.", Risk: sdk.RiskRead, Sensitive: true},
			{Name: "history", Title: "History", Description: "Watch history, newest first: who watched what, when, for how long, how far, on which player and address.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{
					"days":{"type":"integer","minimum":1,"maximum":3650,"description":"Only the last days"},
					"user":{"type":"string","description":"Only this Plex username"},
					"mediaType":{"type":"string","enum":["movie","episode","track","live"]},
					"limit":{"type":"integer","minimum":1,"maximum":200,"default":25}}}`)},
			{Name: "top", Title: "Top lists", Description: "The home page statistics: most watched and most popular movies, shows and music, top users, platforms and libraries, and most concurrent streams.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{
					"days":{"type":"integer","minimum":1,"maximum":3650,"default":30},
					"count":{"type":"integer","minimum":1,"maximum":25,"default":5},
					"by":{"type":"string","enum":["plays","duration"],"default":"plays"}}}`)},
			{Name: "server", Title: "Server status", Description: "Whether Tautulli is connected to Plex, the Plex server's name, version, platform and Plex Pass, and Tautulli's version.", Risk: sdk.RiskRead},
			{Name: "terminate", Title: "Stop a stream", Description: "Stops a stream on Plex, showing the viewer an optional message. Needs Plex Pass on the server. There's no undo: the viewer has to start playing again.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{
					"sessionKey":{"type":"integer","minimum":1,"description":"The stream's session key, from activity"},
					"sessionId":{"type":"string","description":"Or its session id"},
					"message":{"type":"string","maxLength":200,"description":"Shown to the viewer"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like http://tautulli.local:8181")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h)
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	ref := c.APIKey
	base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v2"), "/home")
	api := rest.New(u.Scheme+"://"+u.Host+base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		q := r.URL.Query()
		q.Set("apikey", strings.TrimSpace(k))
		r.URL.RawQuery = q.Encode()
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// scrub drops the query (with the API key) from URLs in transport errors.
func scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		if p, perr := url.Parse(ue.URL); perr == nil {
			p.RawQuery = ""
			return &url.Error{Op: ue.Op, URL: p.String(), Err: ue.Err}
		}
		return &url.Error{Op: ue.Op, URL: "(Tautulli)", Err: ue.Err}
	}
	return err
}

// call runs one API command and decodes response.data into out.
func (c *conn) call(ctx context.Context, cmd string, q url.Values, out any) error {
	if !cmdRe.MatchString(cmd) {
		return errors.New("invalid command")
	}
	if q == nil {
		q = url.Values{}
	}
	q.Set("cmd", cmd)
	var env struct {
		Response struct {
			Result  string          `json:"result"`
			Message *string         `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"response"`
	}
	_, err := c.api.Do(ctx, http.MethodGet, "/api/v2", q, nil, &env)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Tautulli refused the API key")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no Tautulli API at this address (check the HTTP root)")
	case err != nil:
		return scrub(err)
	}
	if env.Response.Result != "success" {
		msg := ""
		if env.Response.Message != nil {
			msg = *env.Response.Message
		}
		if strings.Contains(strings.ToLower(msg), "apikey") || strings.Contains(strings.ToLower(msg), "api key") {
			return errors.New("Tautulli refused the API key")
		}
		if env.Response.Result == "" {
			return errors.New("unexpected answer: is this Tautulli?")
		}
		if msg == "" {
			msg = "Tautulli reported an error running " + cmd
		}
		return errors.New(msg)
	}
	if out != nil && len(env.Response.Data) > 0 && string(env.Response.Data) != "null" {
		if err := json.Unmarshal(env.Response.Data, out); err != nil {
			return fmt.Errorf("unexpected answer from Tautulli: %w", err)
		}
	}
	return nil
}

// flex decodes the numbers Tautulli sends as numbers or strings.
type flex float64

func (f *flex) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*f = 0
		return nil
	}
	*f = flex(v)
	return nil
}

type session struct {
	SessionKey    flex   `json:"session_key"`
	SessionID     string `json:"session_id"`
	User          string `json:"user"`
	FriendlyName  string `json:"friendly_name"`
	IP            string `json:"ip_address"`
	Location      string `json:"location"`
	FullTitle     string `json:"full_title"`
	MediaType     string `json:"media_type"`
	State         string `json:"state"`
	Progress      flex   `json:"progress_percent"`
	Player        string `json:"player"`
	Platform      string `json:"platform"`
	Product       string `json:"product"`
	Quality       string `json:"quality_profile"`
	Decision      string `json:"transcode_decision"`
	VideoDecision string `json:"video_decision"`
	Bandwidth     flex   `json:"bandwidth"`
	Library       string `json:"library_name"`
	Secure        any    `json:"secure"`
	Relayed       any    `json:"relayed"`
}

type activity struct {
	StreamCount    flex      `json:"stream_count"`
	DirectPlay     flex      `json:"stream_count_direct_play"`
	DirectStream   flex      `json:"stream_count_direct_stream"`
	Transcode      flex      `json:"stream_count_transcode"`
	TotalBandwidth flex      `json:"total_bandwidth"`
	LANBandwidth   flex      `json:"lan_bandwidth"`
	WANBandwidth   flex      `json:"wan_bandwidth"`
	Sessions       []session `json:"sessions"`
}

func mbit(kbps flex) float64 { return math.Round(float64(kbps)/10) / 100 }

func (s session) name() string {
	if s.FriendlyName != "" {
		return s.FriendlyName
	}
	return s.User
}

func (s session) out() map[string]any {
	o := map[string]any{"sessionKey": int64(s.SessionKey), "sessionId": s.SessionID, "user": s.name(), "title": s.FullTitle, "mediaType": s.MediaType,
		"state": s.State, "progressPercent": float64(s.Progress), "player": s.Player, "platform": s.Platform, "product": s.Product,
		"decision": s.Decision, "bandwidthMbps": mbit(s.Bandwidth)}
	for k, v := range map[string]string{"ip": s.IP, "location": s.Location, "quality": s.Quality, "videoDecision": s.VideoDecision, "library": s.Library} {
		if v != "" {
			o[k] = v
		}
	}
	return o
}

// streamTitle names a stream without who is watching it, for plans and
// the terminate output.
func (s session) streamTitle() string {
	t := s.FullTitle
	if t == "" {
		t = "a stream"
	}
	if s.Player != "" {
		t += " on " + s.Player
	}
	return t
}

type input struct {
	Days       *int   `json:"days"`
	User       string `json:"user"`
	MediaType  string `json:"mediaType"`
	Limit      *int   `json:"limit"`
	Count      *int   `json:"count"`
	By         string `json:"by"`
	SessionKey *int64 `json:"sessionKey"`
	SessionID  string `json:"sessionId"`
	Message    string `json:"message"`
}

func intIn(p *int, def, lo, hi int, what string) (int, error) {
	if p == nil {
		return def, nil
	}
	if *p < lo || *p > hi {
		return 0, fmt.Errorf("%s is %d to %d", what, lo, hi)
	}
	return *p, nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func (m *Module) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var st struct {
		Connected bool `json:"connected"`
	}
	if err := c.call(ctx, "server_status", nil, &st); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if !st.Connected {
		return sdk.Health{Status: "degraded", Message: "Tautulli can't reach the Plex server"}
	}
	var a activity
	if err := c.call(ctx, "get_activity", nil, &a); err != nil {
		return sdk.Health{Status: "degraded", Message: "Plex connected · " + err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("Plex connected · %d stream(s)", int(a.StreamCount))}
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p input
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "activity":
		var a activity
		if err := c.call(ctx, "get_activity", nil, &a); err != nil {
			return sdk.Result{}, err
		}
		streams := []map[string]any{}
		for _, s := range a.Sessions {
			streams = append(streams, s.out())
		}
		return sdk.JSON(map[string]any{"streams": int(a.StreamCount), "directPlay": int(a.DirectPlay), "directStream": int(a.DirectStream), "transcode": int(a.Transcode),
			"bandwidthMbps": mbit(a.TotalBandwidth), "lanMbps": mbit(a.LANBandwidth), "wanMbps": mbit(a.WANBandwidth), "sessions": streams})

	case "history":
		return c.history(ctx, m.now(), p)

	case "top":
		return c.top(ctx, p)

	case "server":
		var st struct {
			Connected bool `json:"connected"`
		}
		if err := c.call(ctx, "server_status", nil, &st); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{"connected": st.Connected}
		var info struct {
			Name     string `json:"pms_name"`
			Version  string `json:"pms_version"`
			Platform string `json:"pms_platform"`
			PlexPass any    `json:"pms_plexpass"`
			Remote   any    `json:"pms_is_remote"`
			SSL      any    `json:"pms_ssl"`
		}
		if err := c.call(ctx, "get_server_info", nil, &info); err == nil {
			out["name"], out["version"], out["platform"] = info.Name, info.Version, info.Platform
			out["plexPass"], out["remote"], out["ssl"] = truthy(info.PlexPass), truthy(info.Remote), truthy(info.SSL)
		}
		var ti struct {
			Version string `json:"tautulli_version"`
		}
		if c.call(ctx, "get_tautulli_info", nil, &ti) == nil && ti.Version != "" {
			out["tautulliVersion"] = ti.Version
		}
		return sdk.JSON(out)

	case "terminate":
		return c.terminate(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x == "1" || strings.EqualFold(x, "true")
	}
	return false
}

func (c *conn) history(ctx context.Context, now time.Time, p input) (sdk.Result, error) {
	limit, err := intIn(p.Limit, 25, 1, 200, "limit")
	if err != nil {
		return sdk.Result{}, err
	}
	q := url.Values{"length": {strconv.Itoa(limit)}, "order_column": {"date"}, "order_dir": {"desc"}}
	if p.Days != nil {
		d, err := intIn(p.Days, 0, 1, 3650, "days")
		if err != nil {
			return sdk.Result{}, err
		}
		q.Set("after", now.AddDate(0, 0, -d).Format("2006-01-02"))
	}
	if p.User != "" {
		if len(p.User) > 128 || hasControl(p.User) || strings.TrimSpace(p.User) != p.User {
			return sdk.Result{}, errors.New("user is a Plex username")
		}
		q.Set("user", p.User)
	}
	if p.MediaType != "" {
		if !mediaTypes[p.MediaType] {
			return sdk.Result{}, errors.New(`mediaType is "movie", "episode", "track" or "live"`)
		}
		q.Set("media_type", p.MediaType)
	}
	var h struct {
		Total    flex `json:"recordsFiltered"`
		Duration any  `json:"total_duration"`
		Data     []struct {
			Date         flex   `json:"date"`
			Stopped      flex   `json:"stopped"`
			User         string `json:"user"`
			FriendlyName string `json:"friendly_name"`
			FullTitle    string `json:"full_title"`
			MediaType    string `json:"media_type"`
			Platform     string `json:"platform"`
			Player       string `json:"player"`
			Product      string `json:"product"`
			IP           string `json:"ip_address"`
			Duration     flex   `json:"duration"`
			Paused       flex   `json:"paused_counter"`
			Percent      flex   `json:"percent_complete"`
			Watched      flex   `json:"watched_status"`
			Decision     string `json:"transcode_decision"`
		} `json:"data"`
	}
	if err := c.call(ctx, "get_history", q, &h); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, x := range h.Data {
		user := x.FriendlyName
		if user == "" {
			user = x.User
		}
		e := map[string]any{"at": time.Unix(int64(x.Date), 0).UTC().Format(time.RFC3339), "user": user, "title": x.FullTitle, "mediaType": x.MediaType,
			"player": x.Player, "platform": x.Platform, "durationSeconds": int64(x.Duration), "percentComplete": float64(x.Percent),
			"watched": map[float64]string{1: "watched", 0.5: "partial", 0: "not watched"}[float64(x.Watched)], "decision": x.Decision}
		if x.IP != "" {
			e["ip"] = x.IP
		}
		if x.Paused > 0 {
			e["pausedSeconds"] = int64(x.Paused)
		}
		out = append(out, e)
	}
	return sdk.JSON(map[string]any{"total": int64(h.Total), "plays": out})
}

func (c *conn) top(ctx context.Context, p input) (sdk.Result, error) {
	days, err := intIn(p.Days, 30, 1, 3650, "days")
	if err != nil {
		return sdk.Result{}, err
	}
	count, err := intIn(p.Count, 5, 1, 25, "count")
	if err != nil {
		return sdk.Result{}, err
	}
	by := p.By
	switch by {
	case "":
		by = "plays"
	case "plays", "duration":
	default:
		return sdk.Result{}, errors.New(`by is "plays" or "duration"`)
	}
	q := url.Values{"time_range": {strconv.Itoa(days)}, "stats_count": {strconv.Itoa(count)}, "stats_type": {by}}
	var stats []struct {
		ID    string           `json:"stat_id"`
		Title string           `json:"stat_title"`
		Rows  []map[string]any `json:"rows"`
	}
	if err := c.call(ctx, "get_home_stats", q, &stats); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, s := range stats {
		rows := []map[string]any{}
		for i, r := range s.Rows {
			if i >= count {
				break
			}
			e := map[string]any{}
			for from, to := range map[string]string{"title": "title", "friendly_name": "user", "platform": "platform", "section_name": "library",
				"total_plays": "plays", "total_duration": "durationSeconds", "users_watched": "users", "count": "streams", "started": "at", "last_watch": "lastWatched"} {
				if v, ok := r[from]; ok && v != nil && v != "" {
					e[to] = v
				}
			}
			if s.ID == "top_users" || s.ID == "top_platforms" {
				delete(e, "title")
			}
			rows = append(rows, e)
		}
		out = append(out, map[string]any{"id": s.ID, "title": s.Title, "rows": rows})
	}
	return sdk.JSON(map[string]any{"days": days, "by": by, "stats": out})
}

func (c *conn) terminate(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if (p.SessionKey == nil) == (p.SessionID == "") {
		return sdk.Result{}, errors.New("name the stream by its sessionKey or its sessionId (one of them), from activity")
	}
	if p.SessionKey != nil && (*p.SessionKey < 1 || *p.SessionKey > math.MaxInt32) {
		return sdk.Result{}, errors.New("sessionKey is a positive number from activity")
	}
	if p.SessionID != "" && !sessionIDRe.MatchString(p.SessionID) {
		return sdk.Result{}, errors.New("sessionId is letters and digits from activity")
	}
	if len(p.Message) > 200 || hasControl(p.Message) {
		return sdk.Result{}, errors.New("the message is one line of up to 200 characters")
	}
	var a activity
	if err := c.call(ctx, "get_activity", nil, &a); err != nil {
		return sdk.Result{}, err
	}
	var s *session
	for i := range a.Sessions {
		x := &a.Sessions[i]
		if (p.SessionKey != nil && int64(x.SessionKey) == *p.SessionKey) || (p.SessionID != "" && x.SessionID == p.SessionID) {
			s = x
			break
		}
	}
	if s == nil {
		return sdk.Result{}, fmt.Errorf("there's no such stream playing now (%d stream(s) are)", len(a.Sessions))
	}
	q := url.Values{}
	if s.SessionID != "" && sessionIDRe.MatchString(s.SessionID) {
		q.Set("session_id", s.SessionID)
	} else {
		q.Set("session_key", strconv.FormatInt(int64(s.SessionKey), 10))
	}
	if p.Message != "" {
		q.Set("message", p.Message)
	}
	target := s.streamTitle()
	if call.DryRun {
		after := map[string]string{"state": "stopped"}
		if p.Message != "" {
			after["message"] = p.Message
		}
		return sdk.Result{Plan: &sdk.Plan{Summary: "Stop " + target, Changes: []sdk.Change{{Target: target, Op: "terminate",
			Before: mustJSON(map[string]any{"state": s.State, "progressPercent": float64(s.Progress)}), After: mustJSON(after)}}}}, nil
	}
	if err := c.call(ctx, "terminate_session", q, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"terminated": true, "stream": target, "sessionKey": int64(s.SessionKey)})
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
