// Package photoprism works with a PhotoPrism photo library through its REST
// API and an app password: library counts, recent photos, albums, and
// starting an index of new files. Where photos were taken is personal, so
// it comes only from a separate sensitive action; sharing links aren't
// offered.
package photoprism

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one PhotoPrism server.
type Config struct {
	URL                string `json:"url"`   // e.g. https://photos.example.com
	Token              string `json:"token"` // secret:// app password or access token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string
	// indexWait is how long start_index waits for PhotoPrism, which only
	// answers when indexing is done.
	indexWait time.Duration
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// IndexWait replaces how long start_index waits for an answer (tests).
	IndexWait time.Duration
}

// New returns the PhotoPrism module.
func New() *Module { return &Module{} }

var (
	pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	// An index path is a folder under originals: plain names, no "..".
	indexPathRe = regexp.MustCompile(`^[\p{L}\p{N} _.,()&+@'-]+(/[\p{L}\p{N} _.,()&+@'-]+)*$`)
)

// recentFilters are the search filters recent_photos accepts: none of them
// finds photos by where they were taken. Everything else (place, keyword,
// path, title and free-text search, which matches keywords made from
// place names) is refused there.
var recentFilters = map[string]bool{"label": true, "year": true, "month": true, "day": true, "before": true, "after": true,
	"favorite": true, "type": true, "video": true, "photo": true, "live": true}

// hasControl reports Unicode control and format characters (newlines,
// NUL, zero-width and direction marks), which have no place in a search.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

// recentQuery checks a recent_photos search and returns it as PhotoPrism
// will read it. It splits the search the way PhotoPrism does (on any
// Unicode space, quotes dropped, keys lower-cased) and requires every term
// to be key:value with a key from recentFilters. What's sent is rebuilt
// from the checked terms, so PhotoPrism can't read it differently.
func recentQuery(q string) (string, error) {
	var terms []string
	for _, t := range strings.FieldsFunc(strings.ReplaceAll(q, `"`, ""), unicode.IsSpace) {
		k, v, ok := strings.Cut(t, ":")
		k = strings.ToLower(k)
		if !ok {
			return "", errors.New("recent_photos takes only filters such as label:cat year:2025 favorite:true; free-text search can match places, so use photo_places for that")
		}
		if !recentFilters[k] {
			return "", fmt.Errorf("recent_photos doesn't take %s: (it may find photos by where they were taken); use photo_places for that", k)
		}
		if v == "" {
			return "", fmt.Errorf("%s: needs a value", k)
		}
		terms = append(terms, k+":"+v)
	}
	return strings.Join(terms, " "), nil
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	photos := `{"type":"object","properties":{"query":{"type":"string","maxLength":500,"description":"PhotoPrism search, e.g. near:… country:de label:cat"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`
	recent := `{"type":"object","properties":{"query":{"type":"string","maxLength":500,"description":"Filters only: label, year, month, day, before, after, favorite, type, video, photo, live, e.g. label:cat year:2025 favorite:true"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`
	return sdk.Manifest{
		ID: "photoprism", Name: "PhotoPrism", Version: "0.1.0", Category: "Media", Icon: "photo",
		Description: "Your PhotoPrism library: counts, recent photos and albums, and indexing new files. Where photos were taken stays out unless asked.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"PhotoPrism's address, e.g. https://photos.example.com"},
			"token":{"type":"string","x-secret":true,"description":"An app password from Settings → Account → Apps and Devices (or a photoprism auth add token). It acts as that user"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "library_stats", Title: "Library", Description: "How many photos, videos, albums, people and labels the library has, and what's waiting for review.", Risk: sdk.RiskRead},
			{Name: "recent_photos", Title: "Recent photos", Description: "The newest photos with when they were taken, type and favourite. No places, coordinates or file names; titles that name a place are left out. The search takes only label, year, month, day, before, after, favorite, type, video, photo and live filters; free text and place filters are refused here (use photo_places).", Risk: sdk.RiskRead,
				Input: sdk.Schema(recent)},
			{Name: "photo_places", Title: "Where photos were taken", Description: "The newest photos with their place, coordinates, full title and caption, with any PhotoPrism search (near:, country:, free text). Private, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(photos)},
			{Name: "albums", Title: "Albums", Description: "Albums (or months) with how many photos each has. The query matches titles; filters (key:value) aren't taken. Folders are in folders.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"type":{"type":"string","enum":["album","month"],"default":"album"},"query":{"type":"string","maxLength":200,"description":"Words in the title"},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}}}`)},
			{Name: "folders", Title: "Folders", Description: "Folders of originals with how many photos each has. Folder names often name places (2026/Italy-trip), so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string","maxLength":200,"description":"Words in the folder's name"},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}}}`)},
			{Name: "start_index", Title: "Index new files", Description: "Has PhotoPrism index the originals folder (or a subfolder), adding new and changed files; a full rescan re-reads every file. It runs in the background on the server and can take long. Needs a user allowed to update the library.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{"path":{"type":"string","description":"Subfolder of originals, e.g. 2026/11 (default: everything)"},"rescan":{"type":"boolean","default":false}}}`)},
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
		return errors.New("the address is like https://photos.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the app password in the vault and enter its secret:// reference")
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
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api/v1"), "/api")
	api := rest.New(origin+"/api/v1", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	wait := m.IndexWait
	if wait == 0 {
		wait = 20 * time.Second
	}
	m.set.Put(id, &conn{api: api, origin: origin, indexWait: wait})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func explain(err error) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("PhotoPrism refused the app password")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("PhotoPrism refused the request (the user may not be allowed to): %v", err)
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return explain(err)
}

type config struct {
	Version   string         `json:"version"`
	SiteTitle string         `json:"siteTitle"`
	Count     map[string]int `json:"count"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var cfg config
	if err := c.do(ctx, http.MethodGet, "/config", nil, nil, &cfg); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no PhotoPrism API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if cfg.Version == "" {
		return sdk.Health{Status: "ok"}
	}
	return sdk.Health{Status: "ok", Message: "PhotoPrism " + cfg.Version}
}

type photo struct {
	UID          string  `json:"UID"`
	Type         string  `json:"Type"`
	TakenAt      string  `json:"TakenAt"`
	TakenAtLocal string  `json:"TakenAtLocal"`
	Title        string  `json:"Title"`
	Caption      string  `json:"Caption"`
	Description  string  `json:"Description"`
	Favorite     bool    `json:"Favorite"`
	Private      bool    `json:"Private"`
	Lat          float64 `json:"Lat"`
	Lng          float64 `json:"Lng"`
	PlaceID      string  `json:"PlaceID"`
	PlaceLabel   string  `json:"PlaceLabel"`
	PlaceCity    string  `json:"PlaceCity"`
	PlaceState   string  `json:"PlaceState"`
	PlaceCountry string  `json:"PlaceCountry"`
}

func (p photo) hasPlace() bool {
	return (p.PlaceID != "" && p.PlaceID != "zz") || p.Lat != 0 || p.Lng != 0
}

// safeTitle is the title unless it could tell where the photo was taken.
// PhotoPrism makes titles from the place ("Berlin / 2025"), and search
// results don't say where a title came from, so a photo with a place keeps
// its title only when it names none of the place's parts and isn't in
// PhotoPrism's "a / b" form.
func (p photo) safeTitle() string {
	t := strings.TrimSpace(p.Title)
	if t == "" || !p.hasPlace() {
		return t
	}
	if strings.Contains(t, "/") {
		return ""
	}
	lt := strings.ToLower(t)
	parts := []string{p.PlaceCity, p.PlaceState}
	parts = append(parts, strings.Split(p.PlaceLabel, ",")...)
	for _, s := range parts {
		if s = strings.ToLower(strings.TrimSpace(s)); len(s) >= 2 && strings.Contains(lt, s) {
			return ""
		}
	}
	return t
}

func taken(p photo) string {
	if p.TakenAtLocal != "" && !strings.HasPrefix(p.TakenAtLocal, "0001-") {
		return strings.TrimSuffix(p.TakenAtLocal, "Z")
	}
	return p.TakenAt
}

func (c *conn) photos(ctx context.Context, p input, places bool) (sdk.Result, error) {
	q := strings.TrimSpace(p.Query)
	if len([]rune(q)) > 500 {
		return sdk.Result{}, errors.New("the query is too long")
	}
	if hasControl(q) {
		return sdk.Result{}, errors.New("the query has control characters")
	}
	if !places {
		var err error
		if q, err = recentQuery(q); err != nil {
			return sdk.Result{}, err
		}
	}
	limit := p.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	v := url.Values{"count": {strconv.Itoa(limit)}, "offset": {"0"}, "order": {"newest"}, "merged": {"true"}}
	if q != "" {
		v.Set("q", q)
	}
	var ps []photo
	if err := c.do(ctx, http.MethodGet, "/photos", v, nil, &ps); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, x := range ps {
		r := map[string]any{"uid": x.UID, "type": x.Type, "taken": taken(x), "open": c.origin + "/library/browse?view=cards&q=uid:" + url.QueryEscape(x.UID)}
		if x.Favorite {
			r["favorite"] = true
		}
		if x.Private {
			r["private"] = true
		}
		if places {
			if x.Title != "" {
				r["title"] = x.Title
			}
			if d := strings.TrimSpace(x.Caption + x.Description); d != "" {
				r["caption"] = d
			}
			if x.hasPlace() {
				r["place"] = x.PlaceLabel
				for k, s := range map[string]string{"city": x.PlaceCity, "state": x.PlaceState, "country": x.PlaceCountry} {
					if s != "" && s != "zz" && s != "Unknown" {
						r[k] = s
					}
				}
				if x.Lat != 0 || x.Lng != 0 {
					r["lat"], r["lng"] = x.Lat, x.Lng
				}
			}
		} else if t := x.safeTitle(); t != "" {
			r["title"] = t
		}
		out = append(out, r)
	}
	return sdk.JSON(map[string]any{"photos": out})
}

type input struct {
	Query  string `json:"query"`
	Limit  int    `json:"limit"`
	Type   string `json:"type"`
	Path   string `json:"path"`
	Rescan bool   `json:"rescan"`
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
	case "library_stats":
		var cfg config
		if err := c.do(ctx, http.MethodGet, "/config", nil, nil, &cfg); err != nil {
			return sdk.Result{}, err
		}
		out := map[string]any{}
		// Counts only; places, states and countries would sketch where
		// you've been.
		for _, k := range []string{"all", "photos", "videos", "live", "albums", "folders", "months", "favorites", "private", "archived", "review", "people", "labels", "files"} {
			if v, ok := cfg.Count[k]; ok {
				out[k] = v
			}
		}
		if cfg.Version != "" {
			out["version"] = cfg.Version
		}
		return sdk.JSON(out)

	case "recent_photos":
		return c.photos(ctx, p, false)
	case "photo_places":
		return c.photos(ctx, p, true)

	case "albums", "folders":
		typ := p.Type
		if call.Action == "folders" {
			typ = "folder"
		} else if typ == "" {
			typ = "album"
		}
		if typ == "folder" && call.Action == "albums" {
			return sdk.Result{}, errors.New("folder names can name places; use folders for them")
		}
		if typ != "album" && typ != "folder" && typ != "month" {
			return sdk.Result{}, errors.New("the type is album or month")
		}
		q := strings.TrimSpace(p.Query)
		if len([]rune(q)) > 200 {
			return sdk.Result{}, errors.New("the query is too long")
		}
		if hasControl(q) {
			return sdk.Result{}, errors.New("the query has control characters")
		}
		// PhotoPrism reads key:value in an album search as filters, which
		// could ask for another type (type:moment) or more; only words in
		// the title are taken.
		if strings.Contains(q, ":") {
			return sdk.Result{}, errors.New("the query is words in the title; filters (key:value) aren't taken")
		}
		limit := p.Limit
		if limit <= 0 || limit > 200 {
			limit = 50
		}
		v := url.Values{"count": {strconv.Itoa(limit)}, "offset": {"0"}, "type": {typ}}
		if q != "" {
			v.Set("q", q)
		}
		var as []struct {
			UID        string `json:"UID"`
			Title      string `json:"Title"`
			Type       string `json:"Type"`
			PhotoCount int    `json:"PhotoCount"`
			Favorite   bool   `json:"Favorite"`
			Private    bool   `json:"Private"`
			UpdatedAt  string `json:"UpdatedAt"`
		}
		if err := c.do(ctx, http.MethodGet, "/albums", v, nil, &as); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, a := range as {
			r := map[string]any{"uid": a.UID, "title": a.Title, "photos": a.PhotoCount, "updated": a.UpdatedAt}
			if a.Favorite {
				r["favorite"] = true
			}
			if a.Private {
				r["private"] = true
			}
			out = append(out, r)
		}
		if call.Action == "folders" {
			return sdk.JSON(map[string]any{"folders": out})
		}
		return sdk.JSON(map[string]any{"type": typ, "albums": out})

	case "start_index":
		return c.index(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) index(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	path := strings.Trim(strings.TrimSpace(p.Path), "/")
	if path != "" {
		if len(path) > 500 || !indexPathRe.MatchString(path) {
			return sdk.Result{}, errors.New("the path is a folder under originals, like 2026/11")
		}
		for _, seg := range strings.Split(path, "/") {
			if strings.Trim(seg, ". ") == "" || strings.HasPrefix(seg, ".") {
				return sdk.Result{}, errors.New("the path is a folder under originals, like 2026/11")
			}
		}
	}
	what := "originals"
	if path != "" {
		what = "originals/" + path
	}
	how := "Index new and changed files in "
	if p.Rescan {
		how = "Rescan every file in "
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: how + what, Changes: []sdk.Change{{Target: what, Op: "index",
			After: json.RawMessage(fmt.Sprintf(`{"path":%q,"rescan":%v}`, "/"+path, p.Rescan))}}}}, nil
	}
	body, _ := json.Marshal(map[string]any{"path": "/" + path, "rescan": p.Rescan, "cleanup": false})
	// PhotoPrism answers when indexing is done, which can take hours; it
	// carries on when the request ends. Wait a while, then report it
	// started, but only if the request reached the server.
	var sent atomic.Bool
	tctx, cancel := context.WithTimeout(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			if i.Err == nil {
				sent.Store(true)
			}
		},
	}), c.indexWait)
	defer cancel()
	var res struct {
		Message string `json:"message"`
	}
	_, err := c.api.Do(tctx, http.MethodPost, "/index", nil, json.RawMessage(body), &res)
	switch {
	case err == nil:
		return sdk.JSON(map[string]any{"indexed": what, "rescan": p.Rescan, "done": true, "message": res.Message})
	case ctx.Err() == nil && tctx.Err() != nil && sent.Load():
		return sdk.JSON(map[string]any{"indexing": what, "rescan": p.Rescan, "done": false,
			"note": "PhotoPrism is still indexing; it carries on in the background (see Library → Index)"})
	case rest.IsStatus(err, http.StatusInsufficientStorage):
		return sdk.Result{}, errors.New("PhotoPrism won't index: its storage is almost full")
	}
	return sdk.Result{}, explain(err)
}
