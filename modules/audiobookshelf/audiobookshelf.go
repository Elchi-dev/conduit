// Package audiobookshelf works with an Audiobookshelf server through its
// REST API and an API token: libraries, the books and podcasts in progress,
// listening stats, recent listening sessions, and starting a library scan.
package audiobookshelf

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://abs.example.com
	Token              string `json:"token"` // secret:// API token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api *rest.Client
	now func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Audiobookshelf module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "audiobookshelf", Name: "Audiobookshelf", Version: "0.1.0", Category: "Media", Icon: "book",
		Description: "Audiobookshelf: libraries, books and podcasts in progress, listening stats and sessions, library scans.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://abs.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An API key (Settings → API Keys) or a user's API token"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "libraries", Title: "Libraries", Description: "The libraries with their media type (books or podcasts) and folders.", Risk: sdk.RiskRead},
			{Name: "in_progress", Title: "In progress", Description: "Books and podcast episodes the user has started and not finished, most recent first, with progress and time left.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "listening_stats", Title: "Listening stats", Description: "Total and today's listening time, the last days, and the most listened items.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":90,"default":7}}}`)},
			{Name: "sessions", Title: "Recent sessions", Description: "The latest listening sessions: what, how long, on which client, from where in the book.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "scan_library", Title: "Scan a library", Description: "Starts a scan of a library's folders for new and changed items (an admin is needed). force rescans every item.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["library"],"properties":{"library":{"type":"string","description":"Library name or id"},"force":{"type":"boolean","default":false}}}`)},
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
		return errors.New("the address is like https://abs.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API token in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
		if err != nil {
			return err
		}
		tr := sdk.Transport(h) // through the instance's network, if any
		tr.TLSClientConfig = tc
		client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	}
	ref := c.Token
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api"), func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, now: time.Now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, method, path, q, nil, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Audiobookshelf refused the API token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Audiobookshelf refused the request: the token's user lacks the permission (an admin is needed)")
	}
	return err
}

type me struct {
	Username      string     `json:"username"`
	Type          string     `json:"type"`
	MediaProgress []progress `json:"mediaProgress"`
}

type progress struct {
	LibraryItemID string  `json:"libraryItemId"`
	EpisodeID     string  `json:"episodeId"`
	Duration      float64 `json:"duration"`
	Progress      float64 `json:"progress"`
	CurrentTime   float64 `json:"currentTime"`
	IsFinished    bool    `json:"isFinished"`
	HideFromCont  bool    `json:"hideFromContinueListening"`
	LastUpdate    int64   `json:"lastUpdate"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u me
	if err := c.do(ctx, http.MethodGet, "/api/me", nil, &u); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Audiobookshelf API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + u.Username
	if u.Type != "" {
		msg += " (" + u.Type + ")"
	}
	var st struct {
		ServerVersion string `json:"serverVersion"`
	}
	if c.do(ctx, http.MethodGet, "/status", nil, &st) == nil && st.ServerVersion != "" {
		msg += " · Audiobookshelf " + st.ServerVersion
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type library struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	MediaType string `json:"mediaType"`
	Folders   []struct {
		FullPath string `json:"fullPath"`
	} `json:"folders"`
}

func (c *conn) libraries(ctx context.Context) ([]library, error) {
	var r struct {
		Libraries []library `json:"libraries"`
	}
	err := c.do(ctx, http.MethodGet, "/api/libraries", nil, &r)
	return r.Libraries, err
}

func stamp(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

func secs(f float64) int64 { return int64(f + 0.5) }

type metadata struct {
	Title      string `json:"title"`
	AuthorName string `json:"authorName"`
	Author     string `json:"author"`
	SeriesName string `json:"seriesName"`
}

func (md metadata) author() string {
	if md.AuthorName != "" {
		return md.AuthorName
	}
	return md.Author
}

type input struct {
	Limit   int    `json:"limit"`
	Days    int    `json:"days"`
	Library string `json:"library"`
	Force   bool   `json:"force"`
}

func limit(n, def, max int) (int, error) {
	if n == 0 {
		return def, nil
	}
	if n < 1 || n > max {
		return 0, fmt.Errorf("limit is between 1 and %d", max)
	}
	return n, nil
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
	case "libraries":
		libs, err := c.libraries(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, l := range libs {
			folders := []string{}
			for _, f := range l.Folders {
				folders = append(folders, f.FullPath)
			}
			out = append(out, map[string]any{"id": l.ID, "name": l.Name, "mediaType": l.MediaType, "folders": folders})
		}
		return sdk.JSON(out)

	case "in_progress":
		n, err := limit(p.Limit, 25, 100)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.inProgress(ctx, n)

	case "listening_stats":
		days := p.Days
		if days == 0 {
			days = 7
		}
		if days < 1 || days > 90 {
			return sdk.Result{}, errors.New("days is between 1 and 90")
		}
		return c.stats(ctx, days)

	case "sessions":
		n, err := limit(p.Limit, 20, 100)
		if err != nil {
			return sdk.Result{}, err
		}
		var r struct {
			Total    int `json:"total"`
			Sessions []struct {
				LibraryItemID string  `json:"libraryItemId"`
				EpisodeID     string  `json:"episodeId"`
				MediaType     string  `json:"mediaType"`
				DisplayTitle  string  `json:"displayTitle"`
				DisplayAuthor string  `json:"displayAuthor"`
				Duration      float64 `json:"duration"`
				TimeListening float64 `json:"timeListening"`
				StartTime     float64 `json:"startTime"`
				CurrentTime   float64 `json:"currentTime"`
				StartedAt     int64   `json:"startedAt"`
				UpdatedAt     int64   `json:"updatedAt"`
				PlayMethod    int     `json:"playMethod"`
				MediaPlayer   string  `json:"mediaPlayer"`
				DeviceInfo    struct {
					ClientName    string `json:"clientName"`
					ClientVersion string `json:"clientVersion"`
					DeviceName    string `json:"deviceName"`
					OSName        string `json:"osName"`
					BrowserName   string `json:"browserName"`
				} `json:"deviceInfo"`
			} `json:"sessions"`
		}
		if err := c.do(ctx, http.MethodGet, "/api/me/listening-sessions", url.Values{"itemsPerPage": {strconv.Itoa(n)}, "page": {"0"}}, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range r.Sessions {
			client := strings.TrimSpace(s.DeviceInfo.ClientName + " " + s.DeviceInfo.ClientVersion)
			device := s.DeviceInfo.DeviceName
			if device == "" {
				device = strings.TrimSpace(s.DeviceInfo.BrowserName + " " + s.DeviceInfo.OSName)
			}
			e := map[string]any{"itemId": s.LibraryItemID, "title": s.DisplayTitle, "author": s.DisplayAuthor, "mediaType": s.MediaType,
				"listenedSeconds": secs(s.TimeListening), "fromSecond": secs(s.StartTime), "toSecond": secs(s.CurrentTime), "durationSeconds": secs(s.Duration),
				"started": stamp(s.StartedAt), "updated": stamp(s.UpdatedAt)}
			if s.EpisodeID != "" {
				e["episodeId"] = s.EpisodeID
			}
			if client != "" {
				e["client"] = client
			}
			if device != "" {
				e["device"] = device
			}
			if s.MediaPlayer != "" {
				e["player"] = s.MediaPlayer
			}
			out = append(out, e)
		}
		return sdk.JSON(map[string]any{"total": r.Total, "sessions": out})

	case "scan_library":
		ref := strings.TrimSpace(p.Library)
		if ref == "" || len(ref) > 200 {
			return sdk.Result{}, errors.New("enter the library's name or id")
		}
		libs, err := c.libraries(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var lib *library
		for i := range libs {
			if libs[i].ID == ref || strings.EqualFold(libs[i].Name, ref) {
				lib = &libs[i]
				break
			}
		}
		if lib == nil {
			have := []string{}
			for _, l := range libs {
				have = append(have, l.Name)
			}
			return sdk.Result{}, fmt.Errorf("there's no library %s (libraries: %s)", ref, strings.Join(have, ", "))
		}
		if !idRe.MatchString(lib.ID) {
			return sdk.Result{}, errors.New("unexpected library id from Audiobookshelf")
		}
		what := "Scan " + lib.Name + " for new and changed items"
		if p.Force {
			what = "Rescan every item in " + lib.Name
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: what, Changes: []sdk.Change{{Target: "library " + lib.Name, Op: "scan"}}}}, nil
		}
		var q url.Values
		if p.Force {
			q = url.Values{"force": {"1"}}
		}
		if err := c.do(ctx, http.MethodPost, "/api/libraries/"+lib.ID+"/scan", q, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"library": lib.Name, "scanStarted": true, "force": p.Force})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) inProgress(ctx context.Context, n int) (sdk.Result, error) {
	var r struct {
		LibraryItems []struct {
			ID                 string `json:"id"`
			LibraryID          string `json:"libraryId"`
			MediaType          string `json:"mediaType"`
			ProgressLastUpdate int64  `json:"progressLastUpdate"`
			Media              struct {
				Metadata metadata `json:"metadata"`
				Duration float64  `json:"duration"`
			} `json:"media"`
			RecentEpisode *struct {
				ID    string `json:"id"`
				Title string `json:"title"`
			} `json:"recentEpisode"`
		} `json:"libraryItems"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/me/items-in-progress", url.Values{"limit": {strconv.Itoa(n)}}, &r); err != nil {
		return sdk.Result{}, err
	}
	var u me
	if err := c.do(ctx, http.MethodGet, "/api/me", nil, &u); err != nil {
		return sdk.Result{}, err
	}
	prog := map[string]progress{}
	for _, mp := range u.MediaProgress {
		prog[mp.LibraryItemID+"/"+mp.EpisodeID] = mp
	}
	out := []map[string]any{}
	for _, it := range r.LibraryItems {
		if len(out) >= n {
			break
		}
		md := it.Media.Metadata
		e := map[string]any{"id": it.ID, "libraryId": it.LibraryID, "mediaType": it.MediaType, "title": md.Title}
		if a := md.author(); a != "" {
			e["author"] = a
		}
		if md.SeriesName != "" {
			e["series"] = md.SeriesName
		}
		key := it.ID + "/"
		if it.RecentEpisode != nil {
			e["episode"], e["episodeId"] = it.RecentEpisode.Title, it.RecentEpisode.ID
			key += it.RecentEpisode.ID
		}
		if mp, ok := prog[key]; ok {
			e["percent"] = float64(int(mp.Progress*1000+0.5)) / 10
			e["positionSeconds"] = secs(mp.CurrentTime)
			if mp.Duration > 0 {
				e["durationSeconds"] = secs(mp.Duration)
				e["leftSeconds"] = max(secs(mp.Duration-mp.CurrentTime), 0)
			}
			e["lastListened"] = stamp(mp.LastUpdate)
		} else if it.ProgressLastUpdate > 0 {
			e["lastListened"] = stamp(it.ProgressLastUpdate)
		}
		out = append(out, e)
	}
	return sdk.JSON(out)
}

func (c *conn) stats(ctx context.Context, days int) (sdk.Result, error) {
	var r struct {
		TotalTime float64            `json:"totalTime"`
		Today     float64            `json:"today"`
		Days      map[string]float64 `json:"days"`
		Items     map[string]struct {
			ID            string   `json:"id"`
			TimeListening float64  `json:"timeListening"`
			MediaMetadata metadata `json:"mediaMetadata"`
		} `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/me/listening-stats", nil, &r); err != nil {
		return sdk.Result{}, err
	}
	now := c.now()
	last := []map[string]any{}
	for i := days - 1; i >= 0; i-- {
		d := now.AddDate(0, 0, -i).Format("2006-01-02")
		last = append(last, map[string]any{"date": d, "seconds": secs(r.Days[d])})
	}
	type top struct {
		id, title, author string
		t                 float64
	}
	var tops []top
	for id, it := range r.Items {
		tops = append(tops, top{id, it.MediaMetadata.Title, it.MediaMetadata.author(), it.TimeListening})
	}
	sort.Slice(tops, func(i, j int) bool {
		if tops[i].t != tops[j].t {
			return tops[i].t > tops[j].t
		}
		return tops[i].id < tops[j].id
	})
	most := []map[string]any{}
	for i, t := range tops {
		if i == 10 {
			break
		}
		e := map[string]any{"id": t.id, "title": t.title, "seconds": secs(t.t)}
		if t.author != "" {
			e["author"] = t.author
		}
		most = append(most, e)
	}
	return sdk.JSON(map[string]any{"totalSeconds": secs(r.TotalTime), "todaySeconds": secs(r.Today), "days": last, "mostListened": most})
}
