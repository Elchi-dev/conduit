// Package arr works with the *arr suite (Sonarr, Radarr, Lidarr, Readarr and
// Prowlarr) through an API key: system status and health, the download
// queue, the calendar, wanted items, the library, adding a series, movie,
// artist or author by lookup, search commands, history and indexers.
//
// One module covers all five because they share one codebase and API shape;
// the instance's `app` setting picks the API version (v3 for Sonarr and
// Radarr, v1 for the others) and the resource names.
package arr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// Config is one *arr server.
type Config struct {
	App                string `json:"app"`    // sonarr, radarr, lidarr, readarr, prowlarr
	URL                string `json:"url"`    // e.g. http://nas.lan:8989 (with its URL base, if any)
	APIKey             string `json:"apiKey"` // secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

// app describes what differs between the apps.
type app struct {
	id, name, api string
	item          string // library resource: series, movie, artist, author
	noun          string // what one library item is called
	idField       string // the lookup result's unique id
	idPrefix      string // lookup term prefix that finds one id, "" when none works
	idRe          *regexp.Regexp
	titleField    string   // the library item's name field
	include       []string // queue/history/calendar include flags
	searchCmd     string   // command that searches one library item
	searchParam   string   // its id parameter
	searchList    bool     // the id parameter is a list
	missingCmd    string   // command that searches every missing item
	metaProfile   bool     // needs a metadata profile when adding
	hasLibrary    bool
}

var (
	digitsRe = regexp.MustCompile(`^[0-9]{1,12}$`)
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	wordRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

var apps = map[string]*app{
	"sonarr": {id: "sonarr", name: "Sonarr", api: "/api/v3", item: "series", noun: "series", idField: "tvdbId", idPrefix: "tvdb:", idRe: digitsRe,
		titleField: "title", include: []string{"includeSeries", "includeEpisode"}, searchCmd: "SeriesSearch", searchParam: "seriesId",
		missingCmd: "MissingEpisodeSearch", hasLibrary: true},
	"radarr": {id: "radarr", name: "Radarr", api: "/api/v3", item: "movie", noun: "movie", idField: "tmdbId", idPrefix: "tmdb:", idRe: digitsRe,
		titleField: "title", include: []string{"includeMovie"}, searchCmd: "MoviesSearch", searchParam: "movieIds", searchList: true,
		missingCmd: "MissingMoviesSearch", hasLibrary: true},
	"lidarr": {id: "lidarr", name: "Lidarr", api: "/api/v1", item: "artist", noun: "artist", idField: "foreignArtistId", idPrefix: "lidarr:", idRe: uuidRe,
		titleField: "artistName", include: []string{"includeArtist", "includeAlbum"}, searchCmd: "ArtistSearch", searchParam: "artistId",
		missingCmd: "MissingAlbumSearch", metaProfile: true, hasLibrary: true},
	"readarr": {id: "readarr", name: "Readarr", api: "/api/v1", item: "author", noun: "author", idField: "foreignAuthorId", idRe: wordRe,
		titleField: "authorName", include: []string{"includeAuthor", "includeBook"}, searchCmd: "AuthorSearch", searchParam: "authorId",
		missingCmd: "MissingBookSearch", metaProfile: true, hasLibrary: true},
	"prowlarr": {id: "prowlarr", name: "Prowlarr", api: "/api/v1"},
}

type conn struct {
	app    *app
	base   string // scheme://host/urlbase + /api/vN
	origin string // scheme://host/urlbase, for links
	http   *http.Client
	key    func(ctx context.Context) (string, error)
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	now  func() time.Time
}

// New returns the *arr module.
func New() *Module { return &Module{now: time.Now} }

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	limit := func(def, max int) string {
		return fmt.Sprintf(`"limit":{"type":"integer","default":%d,"minimum":1,"maximum":%d}`, def, max)
	}
	id := `"id":{"type":"integer","minimum":1,"description":"Library id (from library or add)"}`
	return sdk.Manifest{
		ID: "arr", Name: "Sonarr, Radarr and the *arrs", Version: "0.1.0", Category: "Media", Icon: "film",
		Description: "Sonarr, Radarr, Lidarr, Readarr and Prowlarr: status, queue, calendar, wanted, library, adding by lookup, searches, history and indexers.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["app","url","apiKey"],"properties":{
			"app":{"type":"string","enum":["sonarr","radarr","lidarr","readarr","prowlarr"],"description":"Which app this server runs"},
			"url":{"type":"string","description":"The app's address with its URL base, if any, e.g. http://nas.lan:8989 or https://media.example.com/sonarr"},
			"apiKey":{"type":"string","x-secret":true,"description":"API key (Settings, General, Security). It has full control of the app"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "System status", Description: "Version, start time, OS, and the app's own health checks (warnings and errors).", Risk: sdk.RiskRead},
			{Name: "queue", Title: "Download queue", Description: "What's downloading, with progress, time left, client and any warnings. Not Prowlarr.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit(50, 200) + `}}`)},
			{Name: "calendar", Title: "Upcoming", Description: "Episodes, movies, albums or books coming out in the next days. Not Prowlarr.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","default":7,"minimum":1,"maximum":90},"pastDays":{"type":"integer","default":0,"minimum":0,"maximum":30},"includeUnmonitored":{"type":"boolean","default":false}}}`)},
			{Name: "wanted", Title: "Wanted (missing)", Description: "Monitored items that are out but not downloaded yet. Not Prowlarr.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit(50, 200) + `}}`)},
			{Name: "library", Title: "Search the library", Description: "Series, movies, artists or authors already in the library, by name. Not Prowlarr.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string","description":"Part of the name; empty lists everything"},` + limit(50, 500) + `}}`)},
			{Name: "lookup", Title: "Look up something to add", Description: "Searches the app's metadata source (TheTVDB, TMDb, MusicBrainz, Goodreads) and says what's already in the library. Not Prowlarr.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["term"],"properties":{"term":{"type":"string"},` + limit(10, 50) + `}}`)},
			{Name: "add", Title: "Add to the library", Description: "Adds a series, movie, artist or author found by lookup, monitored, optionally searching for it right away. Undo removes it again, keeping any files.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{
					"id":{"type":"string","description":"The lookup result's id: TVDB id (Sonarr), TMDb id (Radarr), MusicBrainz artist id (Lidarr), foreign author id (Readarr)"},
					"term":{"type":"string","description":"The lookup term to find it with (needed for Readarr; otherwise looked up by id)"},
					"qualityProfile":{"type":"string","description":"Quality profile name or id (default: the first)"},
					"metadataProfile":{"type":"string","description":"Lidarr and Readarr: metadata profile name or id (default: the first)"},
					"rootFolder":{"type":"string","description":"Root folder path (default: the first)"},
					"monitored":{"type":"boolean","default":true},
					"search":{"type":"boolean","default":true,"description":"Search for it as soon as it's added"},
					"minimumAvailability":{"type":"string","enum":["announced","inCinemas","released"],"default":"released","description":"Radarr only"},
					"seriesType":{"type":"string","enum":["standard","daily","anime"],"default":"standard","description":"Sonarr only"}}}`)},
			{Name: "remove", Title: "Remove from the library", Description: "Removes a series, movie, artist or author. Files stay on disk unless deleteFiles is set.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `,"deleteFiles":{"type":"boolean","default":false,"description":"Also delete its files from disk"}}}`)},
			{Name: "search", Title: "Search for downloads", Description: "Starts a search on the indexers for one library item, or for everything missing when no id is given. Not Prowlarr.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + id + `}}`)},
			{Name: "history", Title: "History", Description: "Recent grabs, imports, failures and deletions (Prowlarr: queries and grabs).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + limit(30, 200) + `}}`)},
			{Name: "indexers", Title: "Indexers", Description: "Configured indexers, whether they're enabled, and any that are failing or disabled for now.", Risk: sdk.RiskRead},
			{Name: "test_indexers", Title: "Test indexers", Description: "Tests one indexer, or all when no id is given, and reports which fail and why.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"id":{"type":"integer","minimum":1,"description":"Indexer id (from indexers)"}}}`)},
		},
	}
}

func httpClient(h sdk.Host, override *http.Client, fp string, insecure bool) (*http.Client, error) {
	c := override
	if c == nil {
		c = sdk.HTTPClient(h, 30*time.Second) // through the instance's network, if any
		if fp != "" || insecure {
			tc, err := tlspin.Config(fp, insecure)
			if err != nil {
				return nil, err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			c = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	return rest.SameHostOnly(c), nil
}

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	a := apps[strings.ToLower(strings.TrimSpace(c.App))]
	if a == nil {
		return errors.New("pick the app: sonarr, radarr, lidarr, readarr or prowlarr")
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like http://nas.lan:8989 or https://media.example.com/sonarr")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	client, err := httpClient(h, m.HTTP, c.Fingerprint, c.InsecureSkipVerify)
	if err != nil {
		return err
	}
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(strings.TrimSuffix(p, "/api/v3"), "/api/v1")
	origin := u.Scheme + "://" + u.Host + p
	ref := c.APIKey
	m.set.Put(id, &conn{app: a, base: origin + a.api, origin: origin, http: client,
		key: func(ctx context.Context) (string, error) {
			k, err := h.Secret(ctx, ref)
			return strings.TrimSpace(k), err
		}})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// apiError is an error answer from the app.
type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func isStatus(err error, s int) bool {
	var e *apiError
	return errors.As(err, &e) && e.status == s
}

// send makes one call and returns the response, whatever its status.
func (c *conn) send(ctx context.Context, method, path string, q url.Values, body any) (*http.Response, error) {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	key, err := c.key(ctx)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Conduit")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// request is send that turns an error status into an *apiError.
func (c *conn) request(ctx context.Context, method, path string, q url.Values, body any) (*http.Response, error) {
	res, err := c.send(ctx, method, path, q, body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		defer res.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return nil, &apiError{status: res.StatusCode, msg: c.message(res, raw)}
	}
	return res, nil
}

func (c *conn) message(res *http.Response, raw []byte) string {
	switch res.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return c.app.name + " refused the API key"
	case http.StatusNotFound:
		return "not found"
	}
	var obj struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	var list []struct {
		PropertyName string `json:"propertyName"`
		ErrorMessage string `json:"errorMessage"`
	}
	switch {
	case json.Unmarshal(raw, &obj) == nil && (obj.Message != "" || obj.Error != ""):
		if obj.Message != "" {
			return obj.Message
		}
		return obj.Error
	case json.Unmarshal(raw, &list) == nil && len(list) > 0:
		var parts []string
		for _, f := range list {
			parts = append(parts, f.ErrorMessage)
		}
		return strings.Join(parts, "; ")
	}
	return res.Status
}

// do calls the API and decodes the JSON answer into out (if non-nil).
func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	res, err := c.request(ctx, method, path, q, body)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return err
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("unexpected answer from %s: %w", c.app.name, err)
		}
	}
	return nil
}

// each streams a JSON array, so a library of thousands of movies isn't held
// in memory at once.
func (c *conn) each(ctx context.Context, path string, fn func(map[string]any)) error {
	res, err := c.request(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	dec := json.NewDecoder(io.LimitReader(res.Body, 512<<20))
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return fmt.Errorf("unexpected answer from %s", c.app.name)
	}
	for dec.More() {
		var v map[string]any
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("unexpected answer from %s: %w", c.app.name, err)
		}
		fn(v)
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
		AppName string `json:"appName"`
		Version string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "/system/status", nil, nil, &s); err != nil {
		if isStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no " + c.app.name + " API at this address (check the app setting and URL base)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if s.AppName != "" && !strings.EqualFold(s.AppName, c.app.name) {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("this server is %s, but the instance is set up for %s", s.AppName, c.app.name)}
	}
	msg := c.app.name + " " + s.Version
	var checks []check
	if err := c.do(ctx, http.MethodGet, "/health", nil, nil, &checks); err == nil {
		var errs, warns []string
		for _, ch := range checks {
			switch strings.ToLower(ch.Type) {
			case "error":
				errs = append(errs, ch.Message)
			case "warning":
				warns = append(warns, ch.Message)
			}
		}
		if len(errs) > 0 {
			return sdk.Health{Status: "degraded", Message: msg + " · " + errs[0]}
		}
		if len(warns) > 0 {
			msg += fmt.Sprintf(" · %d warnings", len(warns))
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type check struct {
	Source  string `json:"source"`
	Type    string `json:"type"`
	Message string `json:"message"`
	WikiURL any    `json:"wikiUrl"`
}

type input struct {
	Limit               int    `json:"limit"`
	Days                int    `json:"days"`
	PastDays            int    `json:"pastDays"`
	IncludeUnmonitored  bool   `json:"includeUnmonitored"`
	Query               string `json:"query"`
	Term                string `json:"term"`
	ID                  any    `json:"id"`
	QualityProfile      any    `json:"qualityProfile"`
	MetadataProfile     any    `json:"metadataProfile"`
	RootFolder          string `json:"rootFolder"`
	Monitored           *bool  `json:"monitored"`
	Search              *bool  `json:"search"`
	MinimumAvailability string `json:"minimumAvailability"`
	SeriesType          string `json:"seriesType"`
	DeleteFiles         bool   `json:"deleteFiles"`
}

// intID reads a positive library or indexer id; zero means none given.
func intID(v any) (int, error) {
	switch x := v.(type) {
	case nil:
		return 0, nil
	case float64:
		if x >= 1 && x == float64(int(x)) && x < 1e12 {
			return int(x), nil
		}
	}
	return 0, errors.New("the id is a positive whole number")
}

func clamp(n, def, max int) int {
	if n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
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
	case "queue", "calendar", "wanted", "library", "lookup", "add", "remove", "search":
		if !c.app.hasLibrary {
			return sdk.Result{}, fmt.Errorf("%s has no %s; this works with Sonarr, Radarr, Lidarr and Readarr", c.app.name, call.Action)
		}
	}
	switch call.Action {
	case "status":
		return c.status(ctx)
	case "queue":
		return c.queue(ctx, clamp(p.Limit, 50, 200))
	case "calendar":
		return c.calendar(ctx, m.now(), clamp(p.Days, 7, 90), clamp(p.PastDays, 0, 30), p.IncludeUnmonitored)
	case "wanted":
		return c.wanted(ctx, clamp(p.Limit, 50, 200))
	case "library":
		return c.library(ctx, p.Query, clamp(p.Limit, 50, 500))
	case "lookup":
		return c.lookup(ctx, p.Term, clamp(p.Limit, 10, 50))
	case "add":
		return c.add(ctx, call.DryRun, p)
	case "remove":
		id, err := intID(p.ID)
		if err != nil || id == 0 {
			return sdk.Result{}, errors.New("enter the library id (from library)")
		}
		return c.remove(ctx, call.DryRun, id, p.DeleteFiles)
	case "search":
		id, err := intID(p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.search(ctx, call.DryRun, id)
	case "history":
		return c.history(ctx, clamp(p.Limit, 30, 200))
	case "indexers":
		return c.indexers(ctx)
	case "test_indexers":
		id, err := intID(p.ID)
		if err != nil {
			return sdk.Result{}, err
		}
		return c.testIndexers(ctx, id)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// small readers for the decoded JSON maps.

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func num(m map[string]any, k string) float64 {
	f, _ := m[k].(float64)
	return f
}

func obj(m map[string]any, k string) map[string]any {
	o, _ := m[k].(map[string]any)
	if o == nil {
		return map[string]any{}
	}
	return o
}

func idString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatInt(int64(x), 10)
	}
	return ""
}

func (c *conn) status(ctx context.Context) (sdk.Result, error) {
	var s map[string]any
	if err := c.do(ctx, http.MethodGet, "/system/status", nil, nil, &s); err != nil {
		return sdk.Result{}, err
	}
	var checks []check
	if err := c.do(ctx, http.MethodGet, "/health", nil, nil, &checks); err != nil {
		return sdk.Result{}, err
	}
	hc := []map[string]any{}
	for _, ch := range checks {
		e := map[string]any{"type": ch.Type, "source": ch.Source, "message": ch.Message}
		if w := idString(ch.WikiURL); w != "" {
			e["wiki"] = w
		} else if o, ok := ch.WikiURL.(map[string]any); ok && str(o, "fullUri") != "" {
			e["wiki"] = str(o, "fullUri")
		}
		hc = append(hc, e)
	}
	out := map[string]any{"app": str(s, "appName"), "version": str(s, "version"), "instanceName": str(s, "instanceName"),
		"branch": str(s, "branch"), "startTime": str(s, "startTime"), "os": strings.TrimSpace(str(s, "osName") + " " + str(s, "osVersion")),
		"docker": s["isDocker"], "runtime": strings.TrimSpace(str(s, "runtimeName") + " " + str(s, "runtimeVersion")), "health": hc, "url": c.origin}
	return sdk.JSON(out)
}

func (c *conn) includes() url.Values {
	q := url.Values{}
	for _, k := range c.app.include {
		q.Set(k, "true")
	}
	return q
}

// itemName is the series, movie, artist or author a record belongs to.
func (c *conn) itemName(r map[string]any) string {
	switch c.app.id {
	case "sonarr":
		return str(obj(r, "series"), "title")
	case "radarr":
		mv := obj(r, "movie")
		if t := str(mv, "title"); t != "" {
			if y := num(mv, "year"); y > 0 {
				return fmt.Sprintf("%s (%d)", t, int(y))
			}
			return t
		}
	case "lidarr":
		return str(obj(r, "artist"), "artistName")
	case "readarr":
		return str(obj(r, "author"), "authorName")
	}
	return ""
}

// part is the episode, album or book within the item.
func (c *conn) part(r map[string]any) string {
	switch c.app.id {
	case "sonarr":
		ep := obj(r, "episode")
		if len(ep) == 0 {
			ep = r
		}
		if _, ok := ep["episodeNumber"]; ok {
			return strings.TrimSpace(fmt.Sprintf("S%02dE%02d %s", int(num(ep, "seasonNumber")), int(num(ep, "episodeNumber")), str(ep, "title")))
		}
	case "lidarr":
		return str(obj(r, "album"), "title")
	case "readarr":
		return str(obj(r, "book"), "title")
	}
	return ""
}

func (c *conn) queue(ctx context.Context, limit int) (sdk.Result, error) {
	q := c.includes()
	q.Set("page", "1")
	q.Set("pageSize", strconv.Itoa(limit))
	var pg struct {
		TotalRecords int              `json:"totalRecords"`
		Records      []map[string]any `json:"records"`
	}
	if err := c.do(ctx, http.MethodGet, "/queue", q, nil, &pg); err != nil {
		return sdk.Result{}, err
	}
	items := []map[string]any{}
	for _, r := range pg.Records {
		size, left := num(r, "size"), num(r, "sizeleft")
		e := map[string]any{"id": r["id"], "title": str(r, "title"), "status": str(r, "status"),
			"state": str(r, "trackedDownloadState"), "downloadStatus": str(r, "trackedDownloadStatus"),
			"sizeMB": int64(size / (1 << 20)), "leftMB": int64(left / (1 << 20)), "client": str(r, "downloadClient"),
			"protocol": str(r, "protocol"), "indexer": str(r, "indexer")}
		if size > 0 {
			e["progress"] = float64(int((size-left)/size*1000)) / 10
		}
		if t := str(r, "timeleft"); t != "" {
			e["timeLeft"] = t
		}
		if t := str(r, "estimatedCompletionTime"); t != "" {
			e["eta"] = t
		}
		if n := c.itemName(r); n != "" {
			e["item"] = n
		}
		if p := c.part(r); p != "" {
			e["part"] = p
		}
		if msg := str(r, "errorMessage"); msg != "" {
			e["error"] = msg
		}
		var warn []string
		if sm, ok := r["statusMessages"].([]any); ok {
			for _, x := range sm {
				if o, ok := x.(map[string]any); ok {
					if ms, ok := o["messages"].([]any); ok {
						for _, s := range ms {
							if s, ok := s.(string); ok {
								warn = append(warn, s)
							}
						}
					}
				}
			}
		}
		if len(warn) > 0 {
			e["warnings"] = warn
		}
		items = append(items, e)
	}
	return sdk.JSON(map[string]any{"total": pg.TotalRecords, "items": items})
}

func (c *conn) calendar(ctx context.Context, now time.Time, days, past int, unmonitored bool) (sdk.Result, error) {
	q := c.includes()
	q.Del("includeEpisode")
	q.Del("includeAlbum")
	q.Del("includeBook")
	q.Del("includeMovie")
	start := now.UTC().AddDate(0, 0, -past).Truncate(24 * time.Hour)
	end := now.UTC().AddDate(0, 0, days)
	q.Set("start", start.Format(time.RFC3339))
	q.Set("end", end.Format(time.RFC3339))
	q.Set("unmonitored", strconv.FormatBool(unmonitored))
	var list []map[string]any
	if err := c.do(ctx, http.MethodGet, "/calendar", q, nil, &list); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, r := range list {
		e := map[string]any{"monitored": r["monitored"]}
		var date string
		switch c.app.id {
		case "sonarr":
			e["series"] = str(obj(r, "series"), "title")
			e["episode"] = c.part(r)
			date = str(r, "airDateUtc")
			e["downloaded"] = r["hasFile"]
		case "radarr":
			e["title"] = str(r, "title")
			e["year"] = r["year"]
			e["downloaded"] = r["hasFile"]
			// The release the window caught: the first of these inside it.
			for _, k := range []string{"inCinemas", "digitalRelease", "physicalRelease"} {
				if d := str(r, k); d != "" {
					e[k] = d
					if t, err := time.Parse(time.RFC3339, d); err == nil && date == "" && !t.Before(start) && !t.After(end) {
						date = d
					}
				}
			}
		case "lidarr":
			e["artist"] = str(obj(r, "artist"), "artistName")
			e["album"] = str(r, "title")
			date = str(r, "releaseDate")
		case "readarr":
			e["author"] = str(obj(r, "author"), "authorName")
			e["book"] = str(r, "title")
			date = str(r, "releaseDate")
		}
		e["date"] = date
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i]["date"].(string) < out[j]["date"].(string) })
	return sdk.JSON(map[string]any{"from": start.Format(time.RFC3339), "to": end.Format(time.RFC3339), "items": out})
}

func (c *conn) wanted(ctx context.Context, limit int) (sdk.Result, error) {
	q := c.includes()
	q.Set("page", "1")
	q.Set("pageSize", strconv.Itoa(limit))
	q.Set("monitored", "true")
	q.Set("sortDirection", "descending")
	switch c.app.id {
	case "sonarr":
		q.Set("sortKey", "airDateUtc")
	case "lidarr", "readarr":
		q.Set("sortKey", "releaseDate")
	}
	var pg struct {
		TotalRecords int              `json:"totalRecords"`
		Records      []map[string]any `json:"records"`
	}
	err := c.do(ctx, http.MethodGet, "/wanted/missing", q, nil, &pg)
	if c.app.id == "radarr" && isStatus(err, http.StatusNotFound) {
		return c.radarrMissing(ctx, limit) // Radarr before v5
	}
	if err != nil {
		return sdk.Result{}, err
	}
	items := []map[string]any{}
	for _, r := range pg.Records {
		e := map[string]any{}
		switch c.app.id {
		case "sonarr":
			e["series"], e["episode"], e["aired"], e["seriesId"] = str(obj(r, "series"), "title"), c.part(r), str(r, "airDateUtc"), r["seriesId"]
		case "radarr":
			e["id"], e["title"], e["year"] = r["id"], str(r, "title"), r["year"]
		case "lidarr":
			e["artist"], e["album"], e["released"], e["artistId"] = str(obj(r, "artist"), "artistName"), str(r, "title"), str(r, "releaseDate"), r["artistId"]
		case "readarr":
			e["author"], e["book"], e["released"], e["authorId"] = str(obj(r, "author"), "authorName"), str(r, "title"), str(r, "releaseDate"), r["authorId"]
		}
		items = append(items, e)
	}
	return sdk.JSON(map[string]any{"total": pg.TotalRecords, "items": items})
}

func (c *conn) radarrMissing(ctx context.Context, limit int) (sdk.Result, error) {
	items := []map[string]any{}
	total := 0
	err := c.each(ctx, "/movie", func(r map[string]any) {
		if r["monitored"] != true || r["hasFile"] == true || r["isAvailable"] != true {
			return
		}
		total++
		if len(items) < limit {
			items = append(items, map[string]any{"id": r["id"], "title": str(r, "title"), "year": r["year"]})
		}
	})
	if err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"total": total, "items": items})
}

// summary describes one library item without its many internal fields.
func (c *conn) summary(r map[string]any) map[string]any {
	e := map[string]any{"title": str(r, c.app.titleField, "title"), "monitored": r["monitored"]}
	if id := num(r, "id"); id > 0 {
		e["id"] = int(id)
	}
	if y := num(r, "year"); y > 0 {
		e["year"] = int(y)
	}
	if s := str(r, "status"); s != "" {
		e["status"] = s
	}
	if v := idString(r[c.app.idField]); v != "" && v != "0" {
		e[c.app.idField] = v
	}
	st := obj(r, "statistics")
	switch c.app.id {
	case "sonarr":
		e["network"] = str(r, "network")
		if len(st) > 0 {
			e["episodes"] = fmt.Sprintf("%d/%d", int(num(st, "episodeFileCount")), int(num(st, "episodeCount")))
		}
		if s, ok := r["seasons"].([]any); ok {
			e["seasons"] = len(s)
		}
	case "radarr":
		e["downloaded"] = r["hasFile"]
		if s := str(r, "studio"); s != "" {
			e["studio"] = s
		}
	case "lidarr":
		if len(st) > 0 {
			e["tracks"] = fmt.Sprintf("%d/%d", int(num(st, "trackFileCount")), int(num(st, "totalTrackCount")))
		}
	case "readarr":
		if len(st) > 0 {
			e["books"] = fmt.Sprintf("%d/%d", int(num(st, "bookFileCount")), int(num(st, "bookCount")))
		}
	}
	size := num(r, "sizeOnDisk")
	if size == 0 {
		size = num(st, "sizeOnDisk")
	}
	if size > 0 {
		e["sizeGB"] = float64(int(size/(1<<30)*10)) / 10
	}
	for k, v := range e {
		if v == nil || v == "" {
			delete(e, k)
		}
	}
	return e
}

func (c *conn) library(ctx context.Context, query string, limit int) (sdk.Result, error) {
	needle := strings.ToLower(strings.TrimSpace(query))
	items := []map[string]any{}
	total := 0
	err := c.each(ctx, "/"+c.app.item, func(r map[string]any) {
		if needle != "" && !strings.Contains(strings.ToLower(str(r, c.app.titleField)), needle) &&
			!strings.Contains(strings.ToLower(str(r, "sortTitle", "sortName")), needle) {
			return
		}
		total++
		items = append(items, c.summary(r))
	})
	if err != nil {
		return sdk.Result{}, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		return strings.ToLower(fmt.Sprint(items[i]["title"])) < strings.ToLower(fmt.Sprint(items[j]["title"]))
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return sdk.JSON(map[string]any{"matches": total, "items": items})
}

// display is an item's title with its year, for plans and undo labels.
func (c *conn) display(r map[string]any) string {
	t := str(r, c.app.titleField, "title")
	if y := num(r, "year"); y > 0 {
		return fmt.Sprintf("%s (%d)", t, int(y))
	}
	return t
}

func (c *conn) lookupRaw(ctx context.Context, term string) ([]map[string]any, error) {
	var list []map[string]any
	err := c.do(ctx, http.MethodGet, "/"+c.app.item+"/lookup", url.Values{"term": {term}}, nil, &list)
	return list, err
}

func (c *conn) lookup(ctx context.Context, term string, limit int) (sdk.Result, error) {
	term = strings.TrimSpace(term)
	if term == "" || len(term) > 200 {
		return sdk.Result{}, errors.New("enter what to look up")
	}
	list, err := c.lookupRaw(ctx, term)
	if err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, r := range list {
		if len(out) == limit {
			break
		}
		e := c.summary(r)
		delete(e, "id")
		e["inLibrary"] = num(r, "id") > 0
		if num(r, "id") > 0 {
			e["libraryId"] = int(num(r, "id"))
		}
		e["addWith"] = idString(r[c.app.idField])
		if o := str(r, "overview"); o != "" {
			if rs := []rune(o); len(rs) > 300 {
				o = string(rs[:300]) + "…"
			}
			e["overview"] = o
		}
		out = append(out, e)
	}
	return sdk.JSON(out)
}

type profile struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
	// root folders
	Accessible *bool `json:"accessible"`
}

// pick chooses a profile by id or name (case-insensitive), or the first.
func pick(list []profile, want any, kind string, skip string) (profile, error) {
	w := strings.TrimSpace(fmt.Sprint(want))
	if want == nil || w == "" {
		for _, p := range list {
			if p.Name != skip || skip == "" {
				return p, nil
			}
		}
		return profile{}, fmt.Errorf("there's no %s to use; create one first", kind)
	}
	if f, ok := want.(float64); ok {
		w = strconv.Itoa(int(f))
	}
	var names []string
	for _, p := range list {
		if strconv.Itoa(p.ID) == w || strings.EqualFold(p.Name, w) {
			return p, nil
		}
		names = append(names, p.Name)
	}
	return profile{}, fmt.Errorf("there's no %s %q (there are: %s)", kind, w, strings.Join(names, ", "))
}

func (c *conn) add(ctx context.Context, dry bool, p input) (sdk.Result, error) {
	a := c.app
	id := strings.TrimSpace(idString(p.ID))
	if !a.idRe.MatchString(id) {
		return sdk.Result{}, fmt.Errorf("enter the %s from lookup", a.idField)
	}
	term := strings.TrimSpace(p.Term)
	if term == "" {
		if a.idPrefix == "" {
			return sdk.Result{}, fmt.Errorf("%s needs the lookup term too", a.name)
		}
		term = a.idPrefix + id
	}
	if len(term) > 200 {
		return sdk.Result{}, errors.New("the term is too long")
	}
	if p.MinimumAvailability != "" && p.MinimumAvailability != "announced" && p.MinimumAvailability != "inCinemas" && p.MinimumAvailability != "released" {
		return sdk.Result{}, errors.New("minimumAvailability is announced, inCinemas or released")
	}
	if p.SeriesType != "" && p.SeriesType != "standard" && p.SeriesType != "daily" && p.SeriesType != "anime" {
		return sdk.Result{}, errors.New("seriesType is standard, daily or anime")
	}
	list, err := c.lookupRaw(ctx, term)
	if err != nil {
		return sdk.Result{}, err
	}
	var item map[string]any
	for _, r := range list {
		if strings.EqualFold(idString(r[a.idField]), id) {
			item = r
			break
		}
	}
	if item == nil {
		return sdk.Result{}, fmt.Errorf("no lookup result has %s %s; run lookup to find it", a.idField, id)
	}
	title := c.display(item)
	if lib := num(item, "id"); lib > 0 {
		return sdk.Result{}, fmt.Errorf("%v is already in the library (id %d)", title, int(lib))
	}

	var qps, roots, mps []profile
	if err := c.do(ctx, http.MethodGet, "/qualityprofile", nil, nil, &qps); err != nil {
		return sdk.Result{}, err
	}
	qp, err := pick(qps, p.QualityProfile, "quality profile", "")
	if err != nil {
		return sdk.Result{}, err
	}
	if err := c.do(ctx, http.MethodGet, "/rootfolder", nil, nil, &roots); err != nil {
		return sdk.Result{}, err
	}
	var root profile
	if p.RootFolder == "" {
		for _, r := range roots {
			if r.Accessible == nil || *r.Accessible {
				root = r
				break
			}
		}
		if root.Path == "" {
			return sdk.Result{}, errors.New("there's no usable root folder; add one in the app first")
		}
	} else {
		var paths []string
		for _, r := range roots {
			if strings.TrimRight(r.Path, "/\\") == strings.TrimRight(p.RootFolder, "/\\") {
				root = r
			}
			paths = append(paths, r.Path)
		}
		if root.Path == "" {
			return sdk.Result{}, fmt.Errorf("there's no root folder %q (there are: %s)", p.RootFolder, strings.Join(paths, ", "))
		}
	}
	monitored, search := p.Monitored == nil || *p.Monitored, p.Search == nil || *p.Search
	item["qualityProfileId"] = qp.ID
	item["rootFolderPath"] = root.Path
	item["monitored"] = monitored
	changes := []sdk.Change{{Target: fmt.Sprintf("%s %v", a.noun, title), Op: "add"}}
	detail := map[string]any{"qualityProfile": qp.Name, "rootFolder": root.Path, "monitored": monitored, "search": search}
	switch a.id {
	case "sonarr":
		st := p.SeriesType
		if st == "" {
			st = "standard"
		}
		item["seriesType"], item["seasonFolder"] = st, true
		item["addOptions"] = map[string]any{"searchForMissingEpisodes": search, "monitor": "all"}
		if seasons, ok := item["seasons"].([]any); ok {
			for _, s := range seasons {
				if s, ok := s.(map[string]any); ok {
					s["monitored"] = monitored && num(s, "seasonNumber") > 0 // not specials
				}
			}
		}
		var langs []profile // Sonarr v3 only; v4 has no language profiles
		if err := c.do(ctx, http.MethodGet, "/languageprofile", nil, nil, &langs); err == nil && len(langs) > 0 {
			item["languageProfileId"] = langs[0].ID
		}
		detail["seriesType"] = st
	case "radarr":
		ma := p.MinimumAvailability
		if ma == "" {
			ma = "released"
		}
		item["minimumAvailability"] = ma
		item["addOptions"] = map[string]any{"searchForMovie": search, "monitor": "movieOnly"}
		detail["minimumAvailability"] = ma
	case "lidarr", "readarr":
		if err := c.do(ctx, http.MethodGet, "/metadataprofile", nil, nil, &mps); err != nil {
			return sdk.Result{}, err
		}
		mp, err := pick(mps, p.MetadataProfile, "metadata profile", "None")
		if err != nil {
			return sdk.Result{}, err
		}
		item["metadataProfileId"] = mp.ID
		item["monitorNewItems"] = "all"
		opt := map[string]any{"monitor": "all"}
		if a.id == "lidarr" {
			opt["searchForMissingAlbums"] = search
		} else {
			opt["searchForMissingBooks"] = search
		}
		item["addOptions"] = opt
		detail["metadataProfile"] = mp.Name
	}
	after, _ := json.Marshal(detail)
	changes[0].After = after
	if dry {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add %s %v to %s", a.noun, title, a.name), Changes: changes}}, nil
	}
	var created map[string]any
	if err := c.do(ctx, http.MethodPost, "/"+a.item, nil, item, &created); err != nil {
		return sdk.Result{}, err
	}
	newID := int(num(created, "id"))
	out := c.summary(created)
	out["searching"] = search
	res, err := sdk.JSON(out)
	if newID > 0 {
		res.Undo = sdk.UndoWith("remove", map[string]any{"id": newID, "deleteFiles": false}, fmt.Sprintf("Remove %v from %s (keeping files)", title, a.name))
	}
	return res, err
}

func (c *conn) item(ctx context.Context, id int) (map[string]any, error) {
	var r map[string]any
	if err := c.do(ctx, http.MethodGet, "/"+c.app.item+"/"+strconv.Itoa(id), nil, nil, &r); err != nil {
		if isStatus(err, http.StatusNotFound) {
			return nil, fmt.Errorf("there's no %s with id %d in the library", c.app.noun, id)
		}
		return nil, err
	}
	return r, nil
}

func (c *conn) remove(ctx context.Context, dry bool, id int, deleteFiles bool) (sdk.Result, error) {
	r, err := c.item(ctx, id)
	if err != nil {
		return sdk.Result{}, err
	}
	s := c.summary(r)
	op := "remove from library (files kept)"
	if deleteFiles {
		op = "remove from library and delete its files"
	}
	if dry {
		before, _ := json.Marshal(s)
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Remove %s %s from %s", c.app.noun, c.display(r), c.app.name),
			Changes: []sdk.Change{{Target: fmt.Sprintf("%s %s", c.app.noun, c.display(r)), Op: op, Before: before}}}}, nil
	}
	q := url.Values{"deleteFiles": {strconv.FormatBool(deleteFiles)}, "addImportListExclusion": {"false"}, "addImportExclusion": {"false"}}
	if err := c.do(ctx, http.MethodDelete, "/"+c.app.item+"/"+strconv.Itoa(id), q, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"removed": id, "title": s["title"], "filesDeleted": deleteFiles})
}

func (c *conn) search(ctx context.Context, dry bool, id int) (sdk.Result, error) {
	body := map[string]any{"name": c.app.missingCmd}
	target, summary := "every missing monitored "+c.app.noun, "Search the indexers for everything missing"
	if id > 0 {
		r, err := c.item(ctx, id)
		if err != nil {
			return sdk.Result{}, err
		}
		t := c.display(r)
		target, summary = fmt.Sprintf("%s %v", c.app.noun, t), fmt.Sprintf("Search the indexers for %v", t)
		body["name"] = c.app.searchCmd
		if c.app.searchList {
			body[c.app.searchParam] = []int{id}
		} else {
			body[c.app.searchParam] = id
		}
	}
	if dry {
		return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{{Target: target, Op: "search"}}}}, nil
	}
	var cmd map[string]any
	if err := c.do(ctx, http.MethodPost, "/command", nil, body, &cmd); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"command": body["name"], "commandId": cmd["id"], "status": str(cmd, "status"), "target": target})
}

func (c *conn) history(ctx context.Context, limit int) (sdk.Result, error) {
	q := c.includes()
	q.Set("page", "1")
	q.Set("pageSize", strconv.Itoa(limit))
	q.Set("sortKey", "date")
	q.Set("sortDirection", "descending")
	var pg struct {
		TotalRecords int              `json:"totalRecords"`
		Records      []map[string]any `json:"records"`
	}
	if err := c.do(ctx, http.MethodGet, "/history", q, nil, &pg); err != nil {
		return sdk.Result{}, err
	}
	items := []map[string]any{}
	for _, r := range pg.Records {
		e := map[string]any{"date": str(r, "date"), "event": str(r, "eventType")}
		if s := str(r, "sourceTitle"); s != "" {
			e["title"] = s
		}
		if qn := str(obj(obj(r, "quality"), "quality"), "name"); qn != "" {
			e["quality"] = qn
		}
		if n := c.itemName(r); n != "" {
			e["item"] = n
		}
		if p := c.part(r); p != "" {
			e["part"] = p
		}
		// Only a few data fields: others hold download URLs with indexer keys.
		d := obj(r, "data")
		for _, k := range []string{"indexer", "downloadClient", "downloadClientName", "message", "reason", "query"} {
			if v := str(d, k); v != "" {
				e[k] = v
			}
		}
		if s, ok := r["successful"]; ok {
			e["successful"] = s
		}
		items = append(items, e)
	}
	return sdk.JSON(map[string]any{"total": pg.TotalRecords, "items": items})
}

func (c *conn) indexers(ctx context.Context) (sdk.Result, error) {
	var list []map[string]any
	if err := c.do(ctx, http.MethodGet, "/indexer", nil, nil, &list); err != nil {
		return sdk.Result{}, err
	}
	var status []map[string]any
	if err := c.do(ctx, http.MethodGet, "/indexerstatus", nil, nil, &status); err != nil {
		return sdk.Result{}, err
	}
	st := map[int]map[string]any{}
	for _, s := range status {
		st[int(num(s, "indexerId"))] = s
	}
	out := []map[string]any{}
	failing := 0
	for _, r := range list {
		id := int(num(r, "id"))
		// Settings (the "fields" list) hold API keys and passwords; leave them out.
		e := map[string]any{"id": id, "name": str(r, "name"), "implementation": str(r, "implementationName", "implementation"),
			"protocol": str(r, "protocol"), "priority": r["priority"]}
		if v, ok := r["enable"]; ok {
			e["enabled"] = v
		} else {
			e["enabled"] = r["enableRss"] == true || r["enableAutomaticSearch"] == true || r["enableInteractiveSearch"] == true
		}
		if p := str(r, "privacy"); p != "" {
			e["privacy"] = p
		}
		if s, ok := st[id]; ok {
			if d := str(s, "disabledTill"); d != "" {
				e["disabledTill"] = d
			}
			if d := str(s, "mostRecentFailure"); d != "" {
				e["lastFailure"] = d
				failing++
			}
		}
		out = append(out, e)
	}
	return sdk.JSON(map[string]any{"indexers": out, "failing": failing})
}

func (c *conn) testIndexers(ctx context.Context, id int) (sdk.Result, error) {
	type failure struct {
		Property string `json:"property,omitempty"`
		Message  string `json:"message"`
	}
	failures := func(err error) []failure {
		var e *apiError
		if errors.As(err, &e) {
			var out []failure
			for _, m := range strings.Split(e.msg, "; ") {
				out = append(out, failure{Message: m})
			}
			return out
		}
		return []failure{{Message: err.Error()}}
	}
	if id > 0 {
		var ix map[string]any
		if err := c.do(ctx, http.MethodGet, "/indexer/"+strconv.Itoa(id), nil, nil, &ix); err != nil {
			if isStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no indexer %d", id)
			}
			return sdk.Result{}, err
		}
		err := c.do(ctx, http.MethodPost, "/indexer/test", nil, ix, nil)
		if err != nil && (isStatus(err, http.StatusUnauthorized) || isStatus(err, http.StatusForbidden)) {
			return sdk.Result{}, err
		}
		e := map[string]any{"id": id, "name": str(ix, "name"), "ok": err == nil}
		if err != nil {
			e["failures"] = failures(err)
		}
		return sdk.JSON([]map[string]any{e})
	}
	var names = map[int]string{}
	var list []map[string]any
	if err := c.do(ctx, http.MethodGet, "/indexer", nil, nil, &list); err != nil {
		return sdk.Result{}, err
	}
	for _, r := range list {
		names[int(num(r, "id"))] = str(r, "name")
	}
	var results []struct {
		ID       int  `json:"id"`
		IsValid  bool `json:"isValid"`
		Failures []struct {
			PropertyName string `json:"propertyName"`
			ErrorMessage string `json:"errorMessage"`
		} `json:"validationFailures"`
	}
	// testall answers 400 when any indexer fails, with the same body.
	res, err := c.send(ctx, http.MethodPost, "/indexer/testall", nil, nil)
	if err != nil {
		return sdk.Result{}, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode >= 300 && res.StatusCode != http.StatusBadRequest {
		return sdk.Result{}, &apiError{status: res.StatusCode, msg: c.message(res, raw)}
	}
	if err := json.Unmarshal(raw, &results); err != nil {
		return sdk.Result{}, fmt.Errorf("unexpected answer from %s: %w", c.app.name, err)
	}
	out := []map[string]any{}
	for _, r := range results {
		e := map[string]any{"id": r.ID, "name": names[r.ID], "ok": r.IsValid}
		if len(r.Failures) > 0 {
			var fs []failure
			for _, f := range r.Failures {
				fs = append(fs, failure{Property: f.PropertyName, Message: f.ErrorMessage})
			}
			e["failures"] = fs
		}
		out = append(out, e)
	}
	return sdk.JSON(out)
}
