// Package seerr works with Overseerr or Jellyseerr through their shared
// API v1 and an API key: media requests (pending first) with their status,
// approving and declining them, searching for movies and shows, and making
// a request, whose undo deletes it again.
package seerr

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

// Config is one Overseerr or Jellyseerr.
type Config struct {
	URL                string `json:"url"`    // e.g. http://overseerr.local:5055
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
}

// New returns the Overseerr/Jellyseerr module.
func New() *Module { return &Module{} }

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

const (
	maxTitles  = 25 // requests whose title is looked up one by one
	maxSeasons = 100
	maxQuery   = 200
)

var filters = map[string]bool{"all": true, "pending": true, "approved": true, "processing": true, "available": true, "unavailable": true, "failed": true}

var requestStatus = map[int]string{1: "pending", 2: "approved", 3: "declined", 4: "failed", 5: "completed"}
var mediaStatus = map[int]string{1: "unknown", 2: "pending", 3: "processing", 4: "partially available", 5: "available", 6: "deleted"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	id := `"id":{"type":"integer","minimum":1,"description":"Request id"}`
	return sdk.Manifest{
		ID: "seerr", Name: "Overseerr / Jellyseerr", Version: "0.1.0", Category: "Media", Icon: "film",
		Description: "Overseerr or Jellyseerr: pending media requests, approving and declining them, searching, and requesting movies and shows.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"Overseerr's or Jellyseerr's address, e.g. http://overseerr.local:5055"},
			"apiKey":{"type":"string","x-secret":true,"description":"The API key from Settings → General"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-signed certificate to trust"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "requests", Title: "Requests", Description: "Media requests, newest first (pending by default): title, movie or show, seasons, 4K, request and media status, who asked and when; with counts by status.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{
					"filter":{"type":"string","enum":["pending","approved","processing","available","unavailable","failed","all"],"default":"pending"},
					"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "request", Title: "Request", Description: "One request's status, its media's status (pending, processing, available), seasons, who asked and who approved or declined it.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
			{Name: "approve", Title: "Approve request", Description: "Approves a pending request, which sends it to Radarr or Sonarr to download. Destructive because it can't be taken back: declining afterwards doesn't remove it from Radarr or Sonarr, and the download uses disk and bandwidth.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
			{Name: "decline", Title: "Decline request", Description: "Declines a pending request. Nothing is deleted and the person can request it again, so it's a write; there's no undo because Overseerr can't set a request back to pending.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
			{Name: "search", Title: "Search", Description: "Movies and shows matching a title, with their TMDB id, year, and whether they're already available or requested.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["query"],"properties":{"query":{"type":"string","maxLength":200},"page":{"type":"integer","minimum":1,"maximum":20,"default":1}}}`)},
			{Name: "create_request", Title: "Request media", Description: "Requests a movie or a show (all seasons or some) by TMDB id, as the API key's user. Destructive because that user is usually an admin, whose requests are approved at once and sent to Radarr or Sonarr to download, like approve. Undo deletes the request, but what Radarr or Sonarr already started stays.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["mediaType","tmdbId"],"properties":{
					"mediaType":{"type":"string","enum":["movie","tv"]},
					"tmdbId":{"type":"integer","minimum":1},
					"seasons":{"description":"For a show: \"all\" (the default) or season numbers","oneOf":[{"type":"string","enum":["all"]},{"type":"array","items":{"type":"integer","minimum":0}}]},
					"is4k":{"type":"boolean","default":false}}}`)},
			{Name: "delete_request", Title: "Delete request", Description: "Deletes a request. What Radarr or Sonarr already downloaded stays.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
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
		return errors.New("the address is like http://overseerr.local:5055")
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
	api := rest.New(u.Scheme+"://"+u.Host+strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1"), func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-Api-Key", strings.TrimSpace(k))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Overseerr refused the API key")
	case rest.IsStatus(err, http.StatusNotFound) && strings.HasPrefix(path, "/api/v1/request/"):
		return errors.New("there's no such request")
	case rest.IsStatus(err, http.StatusNotFound) && (strings.HasPrefix(path, "/api/v1/movie/") || strings.HasPrefix(path, "/api/v1/tv/")):
		return errors.New("TMDB has no such movie or show")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("not found (is this Overseerr or Jellyseerr?)")
	}
	return err
}

type user struct {
	DisplayName string `json:"displayName"`
	// email, Plex and Jellyfin usernames are deliberately not decoded.
}

type mediaRequest struct {
	ID        int64  `json:"id"`
	Status    int    `json:"status"`
	Type      string `json:"type"`
	Is4K      bool   `json:"is4k"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	Media     struct {
		TMDBID   int64  `json:"tmdbId"`
		Status   int    `json:"status"`
		Status4K int    `json:"status4k"`
		Type     string `json:"mediaType"`
	} `json:"media"`
	Seasons []struct {
		SeasonNumber int `json:"seasonNumber"`
		Status       int `json:"status"`
	} `json:"seasons"`
	RequestedBy *user `json:"requestedBy"`
	ModifiedBy  *user `json:"modifiedBy"`
}

func (r mediaRequest) kind() string {
	if r.Type != "" {
		return r.Type
	}
	return r.Media.Type
}

func statusName(m map[int]string, s int) string {
	if n, ok := m[s]; ok {
		return n
	}
	return strconv.Itoa(s)
}

type titled struct {
	Title string
	Year  string
}

// title looks up a movie's or show's name by TMDB id.
func (c *conn) title(ctx context.Context, kind string, tmdb int64) (titled, error) {
	if tmdb < 1 || tmdb > math.MaxInt32 || (kind != "movie" && kind != "tv") {
		return titled{}, errors.New("invalid media")
	}
	var d struct {
		Title        string `json:"title"`
		Name         string `json:"name"`
		ReleaseDate  string `json:"releaseDate"`
		FirstAirDate string `json:"firstAirDate"`
		MediaInfo    *struct {
			Status   int `json:"status"`
			Status4K int `json:"status4k"`
			Requests []struct {
				ID     int64 `json:"id"`
				Status int   `json:"status"`
				Is4K   bool  `json:"is4k"`
			} `json:"requests"`
		} `json:"mediaInfo"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/"+kind+"/"+strconv.FormatInt(tmdb, 10), nil, nil, &d); err != nil {
		return titled{}, err
	}
	t := titled{Title: d.Title + d.Name, Year: d.ReleaseDate + d.FirstAirDate}
	if len(t.Year) >= 4 {
		t.Year = t.Year[:4]
	}
	return t, nil
}

func (t titled) String() string {
	if t.Year != "" {
		return t.Title + " (" + t.Year + ")"
	}
	return t.Title
}

func (r mediaRequest) out(t *titled) map[string]any {
	o := map[string]any{"id": r.ID, "status": statusName(requestStatus, r.Status), "type": r.kind(), "tmdbId": r.Media.TMDBID,
		"mediaStatus": statusName(mediaStatus, r.Media.Status), "requestedAt": r.CreatedAt}
	if r.Is4K {
		o["is4k"] = true
		o["mediaStatus"] = statusName(mediaStatus, r.Media.Status4K)
	}
	if t != nil && t.Title != "" {
		o["title"] = t.Title
		if t.Year != "" {
			o["year"] = t.Year
		}
	}
	if len(r.Seasons) > 0 {
		s := []int{}
		for _, x := range r.Seasons {
			s = append(s, x.SeasonNumber)
		}
		o["seasons"] = s
	}
	if r.RequestedBy != nil && r.RequestedBy.DisplayName != "" {
		o["requestedBy"] = r.RequestedBy.DisplayName
	}
	if r.ModifiedBy != nil && r.ModifiedBy.DisplayName != "" && r.Status != 1 {
		o["modifiedBy"] = r.ModifiedBy.DisplayName
		o["modifiedAt"] = r.UpdatedAt
	}
	return o
}

func (c *conn) get(ctx context.Context, id int64) (mediaRequest, error) {
	var r mediaRequest
	if id < 1 || id > math.MaxInt32 {
		return r, errors.New("id is a request id (a positive number)")
	}
	err := c.do(ctx, http.MethodGet, "/api/v1/request/"+strconv.FormatInt(id, 10), nil, nil, &r)
	return r, err
}

// encodeURIComponent escapes a search the way Overseerr's request
// validator expects (it rejects "+" for spaces and unescaped reserved
// characters).
func encodeURIComponent(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', strings.IndexByte("-_.!~*'()", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

type input struct {
	ID        *int64          `json:"id"`
	Filter    string          `json:"filter"`
	Limit     *int            `json:"limit"`
	Query     string          `json:"query"`
	Page      *int            `json:"page"`
	MediaType string          `json:"mediaType"`
	TMDBID    *int64          `json:"tmdbId"`
	Seasons   json.RawMessage `json:"seasons"`
	Is4K      bool            `json:"is4k"`
}

func (p input) id() (int64, error) {
	if p.ID == nil || *p.ID < 1 || *p.ID > math.MaxInt32 {
		return 0, errors.New("id is a request id (a positive number)")
	}
	return *p.ID, nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

type counts struct {
	Total      int `json:"total"`
	Movie      int `json:"movie"`
	TV         int `json:"tv"`
	Pending    int `json:"pending"`
	Approved   int `json:"approved"`
	Declined   int `json:"declined"`
	Processing int `json:"processing"`
	Available  int `json:"available"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var st struct {
		Version         string `json:"version"`
		UpdateAvailable bool   `json:"updateAvailable"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/status", nil, nil, &st); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if st.Version == "" {
		return sdk.Health{Status: "down", Message: "unexpected answer: is this Overseerr or Jellyseerr?"}
	}
	// /status is public; the count needs the key.
	var n counts
	if err := c.do(ctx, http.MethodGet, "/api/v1/request/count", nil, nil, &n); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("version %s · %d pending request(s)", st.Version, n.Pending)
	if st.UpdateAvailable {
		msg += " · update available"
	}
	return sdk.Health{Status: "ok", Message: msg}
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
	case "requests":
		filter := p.Filter
		if filter == "" {
			filter = "pending"
		}
		if !filters[filter] {
			return sdk.Result{}, errors.New("filter is pending, approved, processing, available, unavailable, failed or all")
		}
		limit := 20
		if p.Limit != nil {
			if *p.Limit < 1 || *p.Limit > 100 {
				return sdk.Result{}, errors.New("limit is 1 to 100")
			}
			limit = *p.Limit
		}
		var res struct {
			PageInfo struct {
				Results int `json:"results"`
			} `json:"pageInfo"`
			Results []mediaRequest `json:"results"`
		}
		q := url.Values{"take": {strconv.Itoa(limit)}, "skip": {"0"}, "filter": {filter}, "sort": {"added"}}
		if err := c.do(ctx, http.MethodGet, "/api/v1/request", q, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		var n counts
		_ = c.do(ctx, http.MethodGet, "/api/v1/request/count", nil, nil, &n)
		out := []map[string]any{}
		for i, r := range res.Results {
			var t *titled
			if i < maxTitles {
				if x, err := c.title(ctx, r.kind(), r.Media.TMDBID); err == nil {
					t = &x
				}
			}
			out = append(out, r.out(t))
		}
		return sdk.JSON(map[string]any{"filter": filter, "matching": res.PageInfo.Results, "requests": out, "counts": n})

	case "request":
		id, err := p.id()
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := c.get(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		var t *titled
		if x, err := c.title(ctx, r.kind(), r.Media.TMDBID); err == nil {
			t = &x
		}
		return sdk.JSON(r.out(t))

	case "approve", "decline":
		return c.decide(ctx, call, p)

	case "search":
		q := strings.TrimSpace(p.Query)
		if q == "" || len(q) > maxQuery || hasControl(q) {
			return sdk.Result{}, fmt.Errorf("query is a title of up to %d characters", maxQuery)
		}
		page := 1
		if p.Page != nil {
			if *p.Page < 1 || *p.Page > 20 {
				return sdk.Result{}, errors.New("page is 1 to 20")
			}
			page = *p.Page
		}
		var res struct {
			TotalResults int `json:"totalResults"`
			TotalPages   int `json:"totalPages"`
			Results      []struct {
				ID           int64  `json:"id"`
				MediaType    string `json:"mediaType"`
				Title        string `json:"title"`
				Name         string `json:"name"`
				ReleaseDate  string `json:"releaseDate"`
				FirstAirDate string `json:"firstAirDate"`
				Overview     string `json:"overview"`
				MediaInfo    *struct {
					Status int `json:"status"`
				} `json:"mediaInfo"`
			} `json:"results"`
		}
		path := "/api/v1/search?query=" + encodeURIComponent(q) + "&page=" + strconv.Itoa(page)
		if err := c.do(ctx, http.MethodGet, path, nil, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, r := range res.Results {
			if r.MediaType != "movie" && r.MediaType != "tv" {
				continue // people
			}
			e := map[string]any{"tmdbId": r.ID, "mediaType": r.MediaType, "title": r.Title + r.Name, "status": "not requested"}
			if y := r.ReleaseDate + r.FirstAirDate; len(y) >= 4 {
				e["year"] = y[:4]
			}
			if r.MediaInfo != nil && r.MediaInfo.Status > 1 {
				e["status"] = statusName(mediaStatus, r.MediaInfo.Status)
			}
			ov := r.Overview
			if rs := []rune(ov); len(rs) > 300 {
				ov = string(rs[:300]) + "…"
			}
			if ov != "" {
				e["overview"] = ov
			}
			out = append(out, e)
		}
		return sdk.JSON(map[string]any{"results": out, "page": page, "pages": res.TotalPages, "total": res.TotalResults})

	case "create_request":
		return c.create(ctx, call, p)

	case "delete_request":
		id, err := p.id()
		if err != nil {
			return sdk.Result{}, err
		}
		r, err := c.get(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		target := fmt.Sprintf("request %d", id)
		if t, err := c.title(ctx, r.kind(), r.Media.TMDBID); err == nil && t.Title != "" {
			target += " for " + t.String()
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Delete " + target, Changes: []sdk.Change{{Target: target, Op: "delete",
				Before: mustJSON(map[string]string{"status": statusName(requestStatus, r.Status)})}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/api/v1/request/"+strconv.FormatInt(id, 10), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": id, "request": target})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) decide(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	id, err := p.id()
	if err != nil {
		return sdk.Result{}, err
	}
	r, err := c.get(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	verb, want := "Approve", "approved"
	if call.Action == "decline" {
		verb, want = "Decline", "declined"
	}
	target := fmt.Sprintf("request %d", id)
	if t, err := c.title(ctx, r.kind(), r.Media.TMDBID); err == nil && t.Title != "" {
		target += " for " + t.String()
	}
	if r.Status != 1 {
		return sdk.Result{}, fmt.Errorf("%s isn't pending; it's %s", target, statusName(requestStatus, r.Status))
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: verb + " " + target, Changes: []sdk.Change{{Target: target, Op: strings.ToLower(verb),
			Before: mustJSON(map[string]string{"status": "pending"}), After: mustJSON(map[string]string{"status": want})}}}}, nil
	}
	var after mediaRequest
	if err := c.do(ctx, http.MethodPost, "/api/v1/request/"+strconv.FormatInt(id, 10)+"/"+strings.ToLower(verb), nil, nil, &after); err != nil {
		return sdk.Result{}, err
	}
	st := want
	if after.ID == id {
		st = statusName(requestStatus, after.Status)
	}
	return sdk.JSON(map[string]any{"id": id, "request": target, "status": st})
}

func (c *conn) create(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	if p.MediaType != "movie" && p.MediaType != "tv" {
		return sdk.Result{}, errors.New(`mediaType is "movie" or "tv"`)
	}
	if p.TMDBID == nil || *p.TMDBID < 1 || *p.TMDBID > math.MaxInt32 {
		return sdk.Result{}, errors.New("tmdbId is a positive TMDB id (from search)")
	}
	body := map[string]any{"mediaType": p.MediaType, "mediaId": *p.TMDBID, "is4k": p.Is4K}
	seasonText := ""
	if p.MediaType == "tv" {
		var all string
		var list []int
		switch {
		case len(p.Seasons) == 0 || string(p.Seasons) == "null":
			body["seasons"], seasonText = "all", "all seasons"
		case json.Unmarshal(p.Seasons, &all) == nil:
			if all != "all" {
				return sdk.Result{}, errors.New(`seasons is "all" or a list of season numbers`)
			}
			body["seasons"], seasonText = "all", "all seasons"
		case json.Unmarshal(p.Seasons, &list) == nil:
			if len(list) == 0 || len(list) > maxSeasons {
				return sdk.Result{}, fmt.Errorf("list 1 to %d seasons", maxSeasons)
			}
			seen := map[int]bool{}
			parts := []string{}
			for _, s := range list {
				if s < 0 || s > 1000 || seen[s] {
					return sdk.Result{}, errors.New("season numbers are 0 (specials) or more, each once")
				}
				seen[s] = true
				parts = append(parts, strconv.Itoa(s))
			}
			body["seasons"], seasonText = list, "seasons "+strings.Join(parts, ", ")
		default:
			return sdk.Result{}, errors.New(`seasons is "all" or a list of season numbers`)
		}
	} else if len(p.Seasons) > 0 && string(p.Seasons) != "null" {
		return sdk.Result{}, errors.New("seasons are only for shows")
	}
	t, err := c.title(ctx, p.MediaType, *p.TMDBID)
	if err != nil {
		return sdk.Result{}, err
	}
	target := t.String()
	if seasonText != "" {
		target += ", " + seasonText
	}
	if p.Is4K {
		target += " in 4K"
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: "Request " + target, Changes: []sdk.Change{{Target: target, Op: "create", After: mustJSON(body)}}}}, nil
	}
	var r mediaRequest
	if err := c.do(ctx, http.MethodPost, "/api/v1/request", nil, body, &r); err != nil {
		if rest.IsStatus(err, http.StatusConflict) {
			return sdk.Result{}, fmt.Errorf("%s is already requested", t.String())
		}
		return sdk.Result{}, err
	}
	if r.ID < 1 {
		return sdk.Result{}, errors.New("Overseerr didn't return the new request")
	}
	res, err := sdk.JSON(map[string]any{"id": r.ID, "request": target, "status": statusName(requestStatus, r.Status)})
	res.Undo = sdk.UndoWith("delete_request", map[string]int64{"id": r.ID}, "Delete the request for "+t.String())
	return res, err
}
