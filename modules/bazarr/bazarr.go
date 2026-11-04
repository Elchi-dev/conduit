// Package bazarr works with a Bazarr subtitle manager through its API key:
// status and health, episodes and movies missing subtitles, recent
// subtitle history, throttled providers, and starting a search for missing
// subtitles or resetting throttled providers.
package bazarr

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
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Bazarr server.
type Config struct {
	URL                string `json:"url"`    // e.g. http://nas.lan:6767 (with its URL base, if any)
	APIKey             string `json:"apiKey"` // secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Bazarr module.
func New() *Module { return &Module{} }

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// searchTasks are Bazarr's scheduler jobs that search for missing
// subtitles, by what they cover.
var searchTasks = map[string]string{
	"series": "wanted_search_missing_subtitles_series",
	"movies": "wanted_search_missing_subtitles_movies",
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	page := `"limit":{"type":"integer","minimum":1,"maximum":200,"default":25}`
	kind := `"kind":{"type":"string","enum":["series","movies"],"description":"Episodes of series, or movies"}`
	return sdk.Manifest{
		ID: "bazarr", Name: "Bazarr", Version: "0.1.0", Category: "Media", Icon: "film",
		Description: "Bazarr subtitles: what's missing, what was downloaded, throttled providers; search for missing subtitles.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"Bazarr's address, e.g. http://nas.lan:6767 (with its URL base if it has one, e.g. /bazarr)"},
			"apiKey":{"type":"string","x-secret":true,"description":"The API key (Settings, General, Security)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed certificate"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "status", Title: "Status", Description: "Bazarr's version, the Sonarr and Radarr versions it talks to, counts of what's missing and throttled providers, and health issues.", Risk: sdk.RiskRead},
			{Name: "wanted", Title: "Missing subtitles", Description: "Episodes or movies missing subtitles in the languages their profile asks for, with the languages missing.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["kind"],"properties":{` + kind + `,` + page + `}}`)},
			{Name: "history", Title: "Subtitle history", Description: "Recent subtitle downloads, upgrades and manual changes for episodes or movies: language, provider and score.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["kind"],"properties":{` + kind + `,` + page + `}}`)},
			{Name: "providers", Title: "Throttled providers", Description: "Subtitle providers Bazarr has paused after errors, with the reason and when it tries again.", Risk: sdk.RiskRead},
			{Name: "tasks", Title: "Tasks", Description: "Bazarr's scheduled tasks: interval, next run and whether each runs now.", Risk: sdk.RiskRead},
			{Name: "search_missing", Title: "Search for missing subtitles", Description: "Starts Bazarr's search for every missing subtitle of series or movies now. It downloads the subtitles it finds.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["kind"],"properties":{` + kind + `}}`)},
			{Name: "reset_providers", Title: "Reset throttled providers", Description: "Lets Bazarr use every throttled provider again right away.", Risk: sdk.RiskWrite, DryRun: true},
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
		return errors.New("the address is like http://nas.lan:6767")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
		if c.Fingerprint != "" || c.InsecureSkipVerify {
			tc, err := tlspin.Config(c.Fingerprint, c.InsecureSkipVerify)
			if err != nil {
				return err
			}
			tr := sdk.Transport(h)
			tr.TLSClientConfig = tc
			client = &http.Client{Timeout: 30 * time.Second, Transport: tr}
		}
	}
	ref := c.APIKey
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/api", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-API-KEY", strings.TrimSpace(k))
		return nil
	})
	// The key travels in X-API-KEY, which Go would forward to another host.
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, method, path, q, nil, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Bazarr refused the API key")
	case rest.IsStatus(err, http.StatusNotFound):
		return errors.New("no Bazarr API at this address (check the URL base)")
	}
	return err
}

// form posts form fields, as Bazarr's API expects for its actions.
func (c *conn) form(ctx context.Context, path string, v url.Values) error {
	res, err := c.api.Send(ctx, http.MethodPost, path, nil, strings.NewReader(v.Encode()), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Bazarr refused the API key")
	case err != nil:
		return err
	}
	res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("Bazarr answered %s", res.Status)
	}
	return nil
}

type sysStatus struct {
	Bazarr string `json:"bazarr_version"`
	Sonarr string `json:"sonarr_version"`
	Radarr string `json:"radarr_version"`
	Start  any    `json:"start_time"`
}

type badges struct {
	Episodes  int `json:"episodes"`
	Movies    int `json:"movies"`
	Providers int `json:"providers"`
	Status    int `json:"status"`
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var s struct {
		Data sysStatus `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/system/status", nil, &s); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if s.Data.Bazarr == "" {
		return sdk.Health{Status: "down", Message: "unexpected answer: is this Bazarr?"}
	}
	msg := "Bazarr " + s.Data.Bazarr
	var b badges
	if c.do(ctx, http.MethodGet, "/badges", nil, &b) == nil {
		msg += fmt.Sprintf(" · %d episodes and %d movies missing subtitles", b.Episodes, b.Movies)
		if b.Providers > 0 {
			msg += fmt.Sprintf(", %d providers throttled", b.Providers)
		}
		if b.Status > 0 {
			return sdk.Health{Status: "degraded", Message: msg + fmt.Sprintf(", %d health issues", b.Status)}
		}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type language struct {
	Name   string `json:"name"`
	Code2  string `json:"code2"`
	Forced bool   `json:"forced"`
	HI     bool   `json:"hi"`
}

func langs(ls []language) []string {
	out := []string{}
	for _, l := range ls {
		s := l.Code2
		if s == "" {
			s = l.Name
		}
		if l.Forced {
			s += " (forced)"
		}
		if l.HI {
			s += " (hearing impaired)"
		}
		out = append(out, s)
	}
	return out
}

type input struct {
	Kind  string `json:"kind"`
	Limit int    `json:"limit"`
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
	case "wanted", "history", "search_missing":
		if _, ok := searchTasks[p.Kind]; !ok {
			return sdk.Result{}, errors.New("kind is series or movies")
		}
	}
	limit := p.Limit
	if limit <= 0 || limit > 200 {
		limit = 25
	}
	page := url.Values{"start": {"0"}, "length": {strconv.Itoa(limit)}}
	switch call.Action {
	case "status":
		var s struct {
			Data sysStatus `json:"data"`
		}
		if err := c.do(ctx, http.MethodGet, "/system/status", nil, &s); err != nil {
			return sdk.Result{}, err
		}
		var b badges
		if err := c.do(ctx, http.MethodGet, "/badges", nil, &b); err != nil {
			return sdk.Result{}, err
		}
		var h struct {
			Data []struct {
				Object string `json:"object"`
				Issue  string `json:"issue"`
			} `json:"data"`
		}
		issues := []string{}
		if c.do(ctx, http.MethodGet, "/system/health", nil, &h) == nil {
			for _, i := range h.Data {
				issues = append(issues, rest.Redact(strings.TrimSpace(i.Object+": "+i.Issue)))
			}
		}
		out := map[string]any{"version": s.Data.Bazarr, "missingEpisodes": b.Episodes, "missingMovies": b.Movies, "throttledProviders": b.Providers, "healthIssues": issues}
		if s.Data.Sonarr != "" {
			out["sonarr"] = s.Data.Sonarr
		}
		if s.Data.Radarr != "" {
			out["radarr"] = s.Data.Radarr
		}
		return sdk.JSON(out)

	case "wanted":
		var res struct {
			Data []struct {
				SeriesTitle  string     `json:"seriesTitle"`
				Episode      string     `json:"episode_number"`
				EpisodeTitle string     `json:"episodeTitle"`
				Title        string     `json:"title"`
				Missing      []language `json:"missing_subtitles"`
				SeriesID     int        `json:"sonarrSeriesId"`
				EpisodeID    int        `json:"sonarrEpisodeId"`
				RadarrID     int        `json:"radarrId"`
			} `json:"data"`
			Total int `json:"total"`
		}
		path := "/episodes/wanted"
		if p.Kind == "movies" {
			path = "/movies/wanted"
		}
		if err := c.do(ctx, http.MethodGet, path, page, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range res.Data {
			row := map[string]any{"missing": langs(d.Missing)}
			if p.Kind == "movies" {
				row["title"], row["radarrId"] = d.Title, d.RadarrID
			} else {
				row["series"], row["episode"], row["title"], row["sonarrEpisodeId"] = d.SeriesTitle, d.Episode, d.EpisodeTitle, d.EpisodeID
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"total": res.Total, "items": out})

	case "history":
		var res struct {
			Data []struct {
				SeriesTitle  string    `json:"seriesTitle"`
				Episode      string    `json:"episode_number"`
				EpisodeTitle string    `json:"episodeTitle"`
				Title        string    `json:"title"`
				Timestamp    string    `json:"timestamp"`
				Description  string    `json:"description"`
				Language     *language `json:"language"`
				Provider     string    `json:"provider"`
				Score        any       `json:"score"`
				Action       int       `json:"action"`
			} `json:"data"`
			Total int `json:"total"`
		}
		path := "/episodes/history"
		if p.Kind == "movies" {
			path = "/movies/history"
		}
		if err := c.do(ctx, http.MethodGet, path, page, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range res.Data {
			row := map[string]any{"when": d.Timestamp, "action": actionName(d.Action), "provider": d.Provider}
			if d.Description != "" {
				row["description"] = rest.Redact(d.Description)
			}
			if d.Language != nil {
				row["language"] = langs([]language{*d.Language})[0]
			}
			if d.Score != nil && d.Score != "" {
				row["score"] = d.Score
			}
			if p.Kind == "movies" {
				row["title"] = d.Title
			} else {
				row["series"], row["episode"], row["title"] = d.SeriesTitle, d.Episode, d.EpisodeTitle
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"total": res.Total, "items": out})

	case "providers":
		ps, err := c.providers(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(ps)

	case "tasks":
		ts, err := c.tasks(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range ts {
			out = append(out, map[string]any{"id": t.JobID, "name": t.Name, "interval": t.Interval, "nextRun": t.NextRunIn, "running": t.Running})
		}
		return sdk.JSON(out)

	case "search_missing":
		job := searchTasks[p.Kind]
		ts, err := c.tasks(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		var found *task
		for i := range ts {
			if ts[i].JobID == job {
				found = &ts[i]
			}
		}
		if found == nil {
			return sdk.Result{}, fmt.Errorf("this Bazarr has no search for missing %s subtitles (is %s set up in Bazarr?)", p.Kind, map[string]string{"series": "Sonarr", "movies": "Radarr"}[p.Kind])
		}
		if found.Running {
			return sdk.JSON(map[string]any{"task": found.Name, "running": true, "note": "nothing to change"})
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Run " + found.Name + " now", Changes: []sdk.Change{{Target: "Bazarr task " + found.Name, Op: "run"}}}}, nil
		}
		if err := c.form(ctx, "/system/tasks", url.Values{"taskid": {job}}); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"task": found.Name, "started": true})

	case "reset_providers":
		ps, err := c.providers(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		if len(ps) == 0 {
			return sdk.JSON(map[string]any{"throttled": 0, "note": "nothing to change"})
		}
		if call.DryRun {
			var changes []sdk.Change
			for _, p := range ps {
				b, _ := json.Marshal(p["status"])
				changes = append(changes, sdk.Change{Target: "provider " + fmt.Sprint(p["name"]), Op: "reset", Before: b})
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Reset %d throttled providers", len(ps)), Changes: changes}}, nil
		}
		if err := c.form(ctx, "/providers", url.Values{"action": {"reset"}}); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"reset": len(ps)})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// actionName is Bazarr's history action code in words.
func actionName(a int) string {
	switch a {
	case 0:
		return "deleted"
	case 1:
		return "downloaded"
	case 2:
		return "manually downloaded"
	case 3:
		return "upgraded"
	case 4:
		return "uploaded"
	case 5:
		return "synced"
	case 6:
		return "translated"
	}
	return strconv.Itoa(a)
}

type task struct {
	JobID     string `json:"job_id"`
	Name      string `json:"name"`
	Interval  string `json:"interval"`
	NextRunIn string `json:"next_run_in"`
	Running   bool   `json:"job_running"`
}

func (c *conn) tasks(ctx context.Context) ([]task, error) {
	var res struct {
		Data []task `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, "/system/tasks", nil, &res)
	return res.Data, err
}

func (c *conn) providers(ctx context.Context) ([]map[string]any, error) {
	var res struct {
		Data []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Retry  string `json:"retry"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/providers", nil, &res); err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, p := range res.Data {
		out = append(out, map[string]any{"name": p.Name, "status": rest.Redact(p.Status), "retry": p.Retry})
	}
	return out, nil
}
