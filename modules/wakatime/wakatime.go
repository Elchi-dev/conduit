// Package wakatime reads coding activity from WakaTime, or from a server
// with a WakaTime-compatible API such as Wakapi: daily summaries, stats over
// a range (languages, projects, editors, best day) and projects.
package wakatime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one WakaTime (or Wakapi) account.
type Config struct {
	URL                string `json:"url"` // default https://wakatime.com/api/v1; Wakapi: https://wakapi.example.com
	Key                string `json:"key"` // secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

const defaultBase = "https://wakatime.com/api/v1"

type conn struct {
	api *rest.Client
	now func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://wakatime.com/api/v1 when no address is set (tests).
	Base string
	// Now replaces the clock (tests).
	Now func() time.Time
}

// New returns the WakaTime module.
func New() *Module { return &Module{} }

var (
	pathRe    = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	dateRe    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	statRange = map[string]bool{"last_7_days": true, "last_30_days": true, "last_6_months": true, "last_year": true, "all_time": true}
)

const (
	maxDays = 366
	maxText = 200
	top     = 10
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "wakatime", Name: "WakaTime", Version: "0.1.0", Category: "Development", Icon: "activity",
		Description: "Coding activity from WakaTime or Wakapi: daily summaries, stats by language, project and editor, and projects.",
		Presets:     []string{"developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"url":{"type":"string","default":"https://wakatime.com/api/v1","description":"WakaTime, or a Wakapi server's address, e.g. https://wakapi.example.com (its WakaTime-compatible API is used)"},
			"key":{"type":"string","x-secret":true,"description":"Your API key (WakaTime: Settings, API Key; Wakapi: Settings, API Key)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "summaries", Title: "Daily summaries", Description: "Time coded each day between two dates (the last 7 days by default), with the top projects and languages, and the total.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"start":{"type":"string","format":"date","description":"YYYY-MM-DD, 6 days ago by default"},"end":{"type":"string","format":"date","description":"YYYY-MM-DD, today by default"},"project":{"type":"string","description":"Only this project"}}}`)},
			{Name: "stats", Title: "Stats", Description: "Total and daily average over a range, with languages, projects, editors, operating systems and the best day.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"range":{"type":"string","enum":["last_7_days","last_30_days","last_6_months","last_year","all_time"],"default":"last_7_days"}}}`)},
			{Name: "projects", Title: "Projects", Description: "Projects with when they were last worked on.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string","description":"Only projects whose name contains this"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if strings.TrimSpace(c.URL) == "" {
		c.URL = defaultBase
		if m.Base != "" {
			c.URL = m.Base
		}
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://wakatime.com/api/v1 or https://wakapi.example.com")
	}
	if !strings.HasPrefix(c.Key, "secret://") {
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
	path := strings.TrimRight(u.Path, "/")
	if path == "" {
		// A bare address: WakaTime's API, or Wakapi's WakaTime-compatible one.
		path = "/api/compat/wakatime/v1"
		if h := strings.ToLower(u.Hostname()); h == "wakatime.com" || h == "api.wakatime.com" {
			path = "/api/v1"
		}
	}
	ref := c.Key
	api := rest.New(u.Scheme+"://"+u.Host+path, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(k))))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := c.api.Do(ctx, http.MethodGet, path, q, nil, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("the server refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API key isn't allowed to read this (WakaTime's free plan keeps two weeks of history)")
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var u struct {
		Data struct {
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := c.get(ctx, "/users/current", nil, &u); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no WakaTime-compatible API at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in"
	if u.Data.Username != "" {
		msg += " as " + u.Data.Username
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type item struct {
	Name         string  `json:"name"`
	TotalSeconds float64 `json:"total_seconds"`
	Percent      float64 `json:"percent"`
	Text         string  `json:"text"`
}

func items(in []item, n int) []map[string]any {
	out := []map[string]any{}
	for _, x := range in {
		if len(out) >= n {
			break
		}
		row := map[string]any{"name": x.Name, "seconds": int64(x.TotalSeconds), "time": x.Text}
		if x.Percent > 0 {
			row["percent"] = x.Percent
		}
		out = append(out, row)
	}
	return out
}

func parseDate(s string) (time.Time, error) {
	if !dateRe.MatchString(s) {
		return time.Time{}, fmt.Errorf("%q isn't a date like 2026-11-04", s)
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q isn't a date", s)
	}
	return t, nil
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Start   string `json:"start"`
		End     string `json:"end"`
		Project string `json:"project"`
		Range   string `json:"range"`
		Query   string `json:"query"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "summaries":
		return c.summaries(ctx, p.Start, p.End, strings.TrimSpace(p.Project))
	case "stats":
		r := p.Range
		if r == "" {
			r = "last_7_days"
		}
		if !statRange[r] {
			return sdk.Result{}, errors.New("range is last_7_days, last_30_days, last_6_months, last_year or all_time")
		}
		return c.stats(ctx, r)
	case "projects":
		q := strings.TrimSpace(p.Query)
		if len([]rune(q)) > maxText {
			return sdk.Result{}, fmt.Errorf("the query is at most %d characters", maxText)
		}
		var d struct {
			Data []struct {
				Name          string `json:"name"`
				LastHeartbeat string `json:"last_heartbeat_at"`
				CreatedAt     string `json:"created_at"`
				// Repository details aren't decoded: they can hold private URLs.
			} `json:"data"`
		}
		if err := c.get(ctx, "/users/current/projects", nil, &d); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, x := range d.Data {
			if q != "" && !strings.Contains(strings.ToLower(x.Name), strings.ToLower(q)) {
				continue
			}
			row := map[string]any{"name": x.Name}
			if x.LastHeartbeat != "" {
				row["lastActive"] = x.LastHeartbeat
			}
			if x.CreatedAt != "" {
				row["created"] = x.CreatedAt
			}
			out = append(out, row)
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) summaries(ctx context.Context, start, end, project string) (sdk.Result, error) {
	today := c.now()
	e := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	if end != "" {
		t, err := parseDate(end)
		if err != nil {
			return sdk.Result{}, err
		}
		e = t
	}
	s := e.AddDate(0, 0, -6)
	if start != "" {
		t, err := parseDate(start)
		if err != nil {
			return sdk.Result{}, err
		}
		s = t
	}
	if s.After(e) {
		return sdk.Result{}, errors.New("the start is after the end")
	}
	if e.Sub(s) > maxDays*24*time.Hour {
		return sdk.Result{}, fmt.Errorf("at most %d days at once", maxDays)
	}
	if len([]rune(project)) > maxText {
		return sdk.Result{}, fmt.Errorf("the project is at most %d characters", maxText)
	}
	q := url.Values{"start": {s.Format("2006-01-02")}, "end": {e.Format("2006-01-02")}}
	if project != "" {
		q.Set("project", project)
	}
	var d struct {
		Data []struct {
			GrandTotal struct {
				TotalSeconds float64 `json:"total_seconds"`
				Text         string  `json:"text"`
			} `json:"grand_total"`
			Range struct {
				Date string `json:"date"`
			} `json:"range"`
			Projects  []item `json:"projects"`
			Languages []item `json:"languages"`
		} `json:"data"`
		Cumulative struct {
			Seconds float64 `json:"seconds"`
			Text    string  `json:"text"`
		} `json:"cumulative_total"`
	}
	if err := c.get(ctx, "/users/current/summaries", q, &d); err != nil {
		return sdk.Result{}, err
	}
	days := []map[string]any{}
	var total float64
	for _, x := range d.Data {
		total += x.GrandTotal.TotalSeconds
		days = append(days, map[string]any{"date": x.Range.Date, "seconds": int64(x.GrandTotal.TotalSeconds), "time": x.GrandTotal.Text,
			"projects": items(x.Projects, 5), "languages": items(x.Languages, 5)})
	}
	res := map[string]any{"start": q.Get("start"), "end": q.Get("end"), "days": days, "totalSeconds": int64(total)}
	if d.Cumulative.Text != "" {
		res["total"] = d.Cumulative.Text
	}
	if project != "" {
		res["project"] = project
	}
	return sdk.JSON(res)
}

func (c *conn) stats(ctx context.Context, r string) (sdk.Result, error) {
	var d struct {
		Data struct {
			TotalSeconds     float64 `json:"total_seconds"`
			Total            string  `json:"human_readable_total"`
			DailyAverage     float64 `json:"daily_average"`
			DailyAverageText string  `json:"human_readable_daily_average"`
			Languages        []item  `json:"languages"`
			Projects         []item  `json:"projects"`
			Editors          []item  `json:"editors"`
			OperatingSystems []item  `json:"operating_systems"`
			BestDay          *struct {
				Date         string  `json:"date"`
				Text         string  `json:"text"`
				TotalSeconds float64 `json:"total_seconds"`
			} `json:"best_day"`
			Start      string `json:"start"`
			End        string `json:"end"`
			IsUpToDate *bool  `json:"is_up_to_date"`
			Status     string `json:"status"`
		} `json:"data"`
	}
	if err := c.get(ctx, "/users/current/stats/"+url.PathEscape(r), nil, &d); err != nil {
		return sdk.Result{}, err
	}
	x := d.Data
	out := map[string]any{"range": r, "totalSeconds": int64(x.TotalSeconds), "total": x.Total, "dailyAverageSeconds": int64(x.DailyAverage), "dailyAverage": x.DailyAverageText,
		"languages": items(x.Languages, top), "projects": items(x.Projects, top), "editors": items(x.Editors, top), "operatingSystems": items(x.OperatingSystems, top)}
	if x.Start != "" {
		out["start"], out["end"] = x.Start, x.End
	}
	if x.BestDay != nil && x.BestDay.Date != "" {
		out["bestDay"] = map[string]any{"date": x.BestDay.Date, "time": x.BestDay.Text, "seconds": int64(x.BestDay.TotalSeconds)}
	}
	if x.IsUpToDate != nil && !*x.IsUpToDate {
		out["note"] = "WakaTime is still calculating these stats; try again in a few minutes"
	}
	return sdk.JSON(out)
}
