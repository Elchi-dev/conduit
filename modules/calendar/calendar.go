// Package calendar reads and writes calendars over CalDAV (iCloud, Fastmail,
// Nextcloud, Radicale, ...) and reads any ICS feed (including Google's and
// Outlook's private calendar addresses).
package calendar

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"

	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one calendar account's settings.
type Config struct {
	// Mode is "caldav" or "ics".
	Mode     string `json:"mode"`
	URL      string `json:"url"`      // CalDAV server URL
	Username string `json:"username"` // CalDAV
	Password string `json:"password"` // secret:// reference (CalDAV)
	Feed     string `json:"feed"`     // secret:// reference to a private ICS address
	Timezone string `json:"timezone"`
}

type account struct {
	cfg  Config
	host sdk.Host
	loc  *time.Location

	mu        sync.Mutex
	client    *caldav.Client
	calendars []caldav.Calendar
}

// Module implements sdk.Module.
type Module struct {
	mu       sync.Mutex
	accounts map[string]*account
	http     *http.Client
}

// New returns the calendar module.
func New() *Module {
	return &Module{accounts: map[string]*account{}, http: &http.Client{Timeout: 30 * time.Second}}
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID: "calendar", Name: "Calendar", Version: "0.1.0", Category: "Communication", Icon: "calendar",
		Description: "Your agenda from any CalDAV calendar or private ICS address, and new events.",
		Presets:     []string{"developer", "gamer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","properties":{
			"mode":{"type":"string","enum":["caldav","ics"],"default":"caldav","description":"CalDAV can read and write (iCloud, Fastmail, Nextcloud). ICS is read-only and works with Google and Outlook's private calendar address."},
			"url":{"type":"string","description":"CalDAV server, e.g. https://caldav.icloud.com or https://cloud.example.com/remote.php/dav"},
			"username":{"type":"string"},
			"password":{"type":"string","x-secret":true,"description":"Vault reference to an app password"},
			"feed":{"type":"string","x-secret":true,"title":"Private ICS address","description":"Vault reference to the secret iCal address (for ICS mode)"},
			"timezone":{"type":"string","description":"e.g. Europe/Zurich. Defaults to this computer's zone."}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "agenda", Title: "Agenda", Description: "Upcoming events.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","default":7,"maximum":90}}}`)},
			{Name: "today", Title: "Today", Risk: sdk.RiskRead},
			{Name: "calendars", Title: "Calendars", Risk: sdk.RiskRead},
			{Name: "create_event", Title: "Add an event", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["title","start"],"properties":{
					"title":{"type":"string"},
					"start":{"type":"string","description":"2026-11-05T14:00 (local time) or 2026-11-05 for all day"},
					"end":{"type":"string","description":"Defaults to one hour after start"},
					"location":{"type":"string"},"description":{"type":"string","x-multiline":true},
					"calendar":{"type":"string","description":"Calendar name; defaults to the first"}}}`)},
			{Name: "delete_event", Title: "Delete an event", Risk: sdk.RiskDestructive,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Event id from the agenda"}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if cfg.Mode == "" {
		cfg.Mode = "caldav"
	}
	switch cfg.Mode {
	case "caldav":
		if cfg.URL == "" || cfg.Username == "" || cfg.Password == "" {
			return errors.New("CalDAV needs a server URL, username and password")
		}
	case "ics":
		if cfg.Feed == "" {
			return errors.New("ICS mode needs the private calendar address")
		}
	default:
		return fmt.Errorf("unknown mode %q", cfg.Mode)
	}
	loc := time.Local
	if cfg.Timezone != "" {
		l, err := time.LoadLocation(cfg.Timezone)
		if err != nil {
			return fmt.Errorf("unknown time zone %q", cfg.Timezone)
		}
		loc = l
	}
	m.mu.Lock()
	m.accounts[id] = &account{cfg: cfg, host: h, loc: loc}
	m.mu.Unlock()
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error {
	m.mu.Lock()
	delete(m.accounts, id)
	m.mu.Unlock()
	return nil
}

func (m *Module) account(id string) (*account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a := m.accounts[id]; a != nil {
		return a, nil
	}
	return nil, errors.New("calendar is not configured")
}

func (m *Module) caldav(ctx context.Context, a *account) (*caldav.Client, []caldav.Calendar, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client != nil {
		return a.client, a.calendars, nil
	}
	pw, err := a.host.Secret(ctx, a.cfg.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("password: %w", err)
	}
	c, err := caldav.NewClient(webdav.HTTPClientWithBasicAuth(m.http, a.cfg.Username, pw), a.cfg.URL)
	if err != nil {
		return nil, nil, err
	}
	principal, err := c.FindCurrentUserPrincipal(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("sign-in or discovery failed: %w", err)
	}
	home, err := c.FindCalendarHomeSet(ctx, principal)
	if err != nil {
		return nil, nil, err
	}
	cals, err := c.FindCalendars(ctx, home)
	if err != nil {
		return nil, nil, err
	}
	var events []caldav.Calendar
	for _, cal := range cals {
		if len(cal.SupportedComponentSet) == 0 || contains(cal.SupportedComponentSet, ical.CompEvent) {
			events = append(events, cal)
		}
	}
	a.client, a.calendars = c, events
	return c, events, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	a, err := m.account(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	evs, err := m.events(ctx, a, startOfDay(time.Now().In(a.loc)), 1)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d events today", len(evs))}
}

// Event is one occurrence in the agenda.
type Event struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Start    string `json:"start"`
	End      string `json:"end"`
	AllDay   bool   `json:"allDay"`
	Location string `json:"location,omitempty"`
	Calendar string `json:"calendar,omitempty"`
}

func startOfDay(t time.Time) time.Time {
	y, mo, d := t.Date()
	return time.Date(y, mo, d, 0, 0, 0, 0, t.Location())
}

func (m *Module) events(ctx context.Context, a *account, from time.Time, days int) ([]Event, error) {
	to := from.AddDate(0, 0, days)
	var out []Event
	if a.cfg.Mode == "ics" {
		feed, err := a.host.Secret(ctx, a.cfg.Feed)
		if err != nil {
			return nil, fmt.Errorf("calendar address: %w", err)
		}
		feed = strings.Replace(feed, "webcal://", "https://", 1)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed, nil)
		if err != nil {
			return nil, err
		}
		res, err := m.http.Do(req)
		if err != nil {
			return nil, rest.TransportError(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("calendar feed answered %s", res.Status)
		}
		cal, err := ical.NewDecoder(io.LimitReader(res.Body, 20<<20)).Decode()
		if err != nil {
			return nil, fmt.Errorf("calendar feed: %w", err)
		}
		out = expand(cal, "", "", a.loc, from, to)
	} else {
		c, cals, err := m.caldav(ctx, a)
		if err != nil {
			return nil, err
		}
		for _, cal := range cals {
			objs, err := c.QueryCalendar(ctx, cal.Path, &caldav.CalendarQuery{
				CompRequest: caldav.CalendarCompRequest{Name: ical.CompCalendar, AllProps: true, AllComps: true},
				CompFilter:  caldav.CompFilter{Name: ical.CompCalendar, Comps: []caldav.CompFilter{{Name: ical.CompEvent, Start: from.UTC(), End: to.UTC()}}},
			})
			if err != nil {
				return nil, fmt.Errorf("%s: %w", cal.Name, err)
			}
			for _, o := range objs {
				out = append(out, expand(o.Data, o.Path, cal.Name, a.loc, from, to)...)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

// expand turns a calendar's events into occurrences between from and to,
// following recurrence rules.
func expand(cal *ical.Calendar, path, calName string, loc *time.Location, from, to time.Time) []Event {
	var out []Event
	if cal == nil {
		return out
	}
	for _, comp := range cal.Children {
		if comp.Name != ical.CompEvent {
			continue
		}
		ev := ical.Event{Component: comp}
		start, err := ev.DateTimeStart(loc)
		if err != nil {
			continue
		}
		end, err := ev.DateTimeEnd(loc)
		if err != nil || end.IsZero() {
			end = start.Add(time.Hour)
		}
		allDay := comp.Props.Get(ical.PropDateTimeStart) != nil && comp.Props.Get(ical.PropDateTimeStart).ValueType() == ical.ValueDate
		dur := end.Sub(start)
		title, _ := comp.Props.Text(ical.PropSummary)
		where, _ := comp.Props.Text(ical.PropLocation)
		id := path
		if id == "" {
			id, _ = comp.Props.Text(ical.PropUID)
		}
		add := func(s time.Time) {
			e := s.Add(dur)
			if e.Before(from) || !s.Before(to) {
				return
			}
			f := "2006-01-02T15:04:05Z07:00"
			if allDay {
				f = "2006-01-02"
			}
			out = append(out, Event{ID: id, Title: title, Start: s.In(loc).Format(f), End: e.In(loc).Format(f), AllDay: allDay, Location: where, Calendar: calName})
		}
		set, err := comp.RecurrenceSet(loc)
		if err != nil || set == nil {
			add(start)
			continue
		}
		for _, s := range set.Between(from.Add(-dur), to, true) {
			add(s)
		}
	}
	return out
}

func parseWhen(s string, loc *time.Location) (time.Time, bool, error) {
	for _, f := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05", "2006-01-02 15:04"} {
		if t, err := time.ParseInLocation(f, s, loc); err == nil {
			return t, false, nil
		}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.In(loc), false, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, loc); err == nil {
		return t, true, nil
	}
	return time.Time{}, false, fmt.Errorf("can't read the time %q; use 2026-11-05T14:00 or 2026-11-05", s)
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, c sdk.Call) (sdk.Result, error) {
	a, err := m.account(c.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	switch c.Action {
	case "agenda", "today":
		var in struct {
			Days int `json:"days"`
		}
		_ = sdk.Decode(c, &in)
		if c.Action == "today" {
			in.Days = 1
		}
		if in.Days <= 0 || in.Days > 90 {
			in.Days = 7
		}
		evs, err := m.events(ctx, a, startOfDay(time.Now().In(a.loc)), in.Days)
		if err != nil {
			return sdk.Result{}, err
		}
		if evs == nil {
			evs = []Event{}
		}
		return sdk.JSON(evs)

	case "calendars":
		if a.cfg.Mode == "ics" {
			return sdk.JSON([]map[string]string{{"name": "ICS feed", "access": "read-only"}})
		}
		_, cals, err := m.caldav(ctx, a)
		if err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]string{}
		for _, cal := range cals {
			out = append(out, map[string]string{"name": cal.Name, "description": cal.Description})
		}
		return sdk.JSON(out)

	case "create_event":
		if a.cfg.Mode != "caldav" {
			return sdk.Result{}, errors.New("ICS feeds are read-only; connect over CalDAV to add events")
		}
		var in struct {
			Title       string `json:"title"`
			Start       string `json:"start"`
			End         string `json:"end"`
			Location    string `json:"location"`
			Description string `json:"description"`
			Calendar    string `json:"calendar"`
		}
		if err := sdk.Decode(c, &in); err != nil {
			return sdk.Result{}, err
		}
		start, allDay, err := parseWhen(in.Start, a.loc)
		if err != nil {
			return sdk.Result{}, err
		}
		end := start.Add(time.Hour)
		if allDay {
			end = start.AddDate(0, 0, 1)
		}
		if in.End != "" {
			if end, _, err = parseWhen(in.End, a.loc); err != nil {
				return sdk.Result{}, err
			}
		}
		if !end.After(start) {
			return sdk.Result{}, errors.New("the end must be after the start")
		}
		cl, cals, err := m.caldav(ctx, a)
		if err != nil {
			return sdk.Result{}, err
		}
		if len(cals) == 0 {
			return sdk.Result{}, errors.New("no calendars found on the server")
		}
		target := cals[0]
		for _, cal := range cals {
			if strings.EqualFold(cal.Name, in.Calendar) {
				target = cal
			}
		}
		if c.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add %q to %s", in.Title, target.Name), Changes: []sdk.Change{{Target: target.Name, Op: "create",
				After: mustJSON(map[string]any{"title": in.Title, "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "location": in.Location})}}}}, nil
		}
		uid := randomUID()
		ev := ical.NewEvent()
		ev.Props.SetText(ical.PropUID, uid)
		ev.Props.SetDateTime(ical.PropDateTimeStamp, time.Now().UTC())
		ev.Props.SetText(ical.PropSummary, in.Title)
		if allDay {
			ev.Props.SetDate(ical.PropDateTimeStart, start)
			ev.Props.SetDate(ical.PropDateTimeEnd, end)
		} else {
			ev.Props.SetDateTime(ical.PropDateTimeStart, start.UTC())
			ev.Props.SetDateTime(ical.PropDateTimeEnd, end.UTC())
		}
		if in.Location != "" {
			ev.Props.SetText(ical.PropLocation, in.Location)
		}
		if in.Description != "" {
			ev.Props.SetText(ical.PropDescription, in.Description)
		}
		cal := ical.NewCalendar()
		cal.Props.SetText(ical.PropProductID, "-//Conduit//EN")
		cal.Props.SetText(ical.PropVersion, "2.0")
		cal.Children = append(cal.Children, ev.Component)
		path := strings.TrimSuffix(target.Path, "/") + "/" + uid + ".ics"
		if _, err := cl.PutCalendarObject(ctx, path, cal); err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"id": path, "title": in.Title, "calendar": target.Name, "start": start.Format(time.RFC3339)})
		r.Undo = sdk.UndoWith("delete_event", map[string]string{"id": path}, "Remove "+in.Title)
		return r, err

	case "delete_event":
		if a.cfg.Mode != "caldav" {
			return sdk.Result{}, errors.New("ICS feeds are read-only")
		}
		var in struct {
			ID string `json:"id"`
		}
		if err := sdk.Decode(c, &in); err != nil || !strings.HasSuffix(in.ID, ".ics") {
			return sdk.Result{}, errors.New("id must be an event id from the agenda")
		}
		cl, cals, err := m.caldav(ctx, a)
		if err != nil {
			return sdk.Result{}, err
		}
		inside := false
		for _, cal := range cals {
			if strings.HasPrefix(in.ID, cal.Path) {
				inside = true
			}
		}
		if !inside {
			return sdk.Result{}, errors.New("that event is not in one of your calendars")
		}
		if err := cl.RemoveAll(ctx, in.ID); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]string{"deleted": in.ID})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(c.Action)
}

func randomUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) + "@conduit"
}

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
