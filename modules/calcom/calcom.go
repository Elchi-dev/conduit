// Package calcom works with Cal.com (the hosted service or a self-hosted
// API v2) through an API key: event types, bookings, open slots, and
// cancelling or rescheduling a booking.
//
// Cancelling and rescheduling email the attendees and change their plans,
// so both are destructive with a preview; a reschedule's undo moves the
// booking back to its old time. Attendee names and emails, and booking
// titles (Cal.com puts the attendees' names in them), appear only in
// bookings, which is sensitive; previews and other answers count attendees
// instead, and meeting links are never returned.
package calcom

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
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Cal.com account.
type Config struct {
	URL                string `json:"url"` // default https://api.cal.com; self-hosted: the API v2 address
	Key                string `json:"key"` // secret:// API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

// API versions Cal.com's v2 endpoints expect in cal-api-version.
const (
	bookingsVersion   = "2024-08-13"
	eventTypesVersion = "2024-06-14"
	slotsVersion      = "2024-09-04"
)

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Cal.com module.
func New() *Module { return &Module{} }

func (m *Module) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

var (
	pathRe  = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)
	keyRe   = regexp.MustCompile(`^cal_[A-Za-z0-9_]{16,128}$`)
	uidRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{6,64}$`)
	idRe    = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
	tzRe    = regexp.MustCompile(`^([A-Za-z_]+(/[A-Za-z0-9_+-]+){0,2}|UTC)$`)
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
)

var bookingStatuses = map[string]bool{"upcoming": true, "recurring": true, "past": true, "cancelled": true, "unconfirmed": true}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	booking := `"booking":{"type":"string","description":"The booking's uid (see bookings)"}`
	return sdk.Manifest{
		ID: "calcom", Name: "Cal.com", Version: "0.1.0", Category: "Productivity", Icon: "calendar",
		Description: "Cal.com scheduling: event types, bookings and open slots; cancel or reschedule bookings with a preview.",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["key"],"properties":{
			"url":{"type":"string","default":"https://api.cal.com","description":"Cal.com's API, or your self-hosted API v2 address, e.g. https://cal-api.example.com"},
			"key":{"type":"string","x-secret":true,"description":"An API key (Settings, Developer, API keys)"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server certificate, for a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "event_types", Title: "Event types", Description: "The account's event types: title, slug, length and whether they're hidden.", Risk: sdk.RiskRead},
			{Name: "bookings", Title: "Bookings", Description: "Bookings with their title, time, status, event type and attendees (name, email, time zone).", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"status":{"type":"string","enum":["","upcoming","recurring","past","cancelled","unconfirmed"],"default":"upcoming"},"eventType":{"type":"string","description":"Only this event type's id"},"limit":{"type":"integer","default":20,"minimum":1,"maximum":100},"skip":{"type":"integer","minimum":0}}}`)},
			{Name: "availability", Title: "Open slots", Description: "Free slots of an event type between two dates (up to 31 days), in a time zone.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["eventType"],"properties":{"eventType":{"type":"string","description":"Event type id (see event_types)"},"start":{"type":"string","description":"First day, YYYY-MM-DD (default today)"},"end":{"type":"string","description":"Last day, YYYY-MM-DD (default a week on)"},"timeZone":{"type":"string","default":"UTC","description":"Like Europe/Berlin"}}}`)},
			{Name: "cancel_booking", Title: "Cancel a booking", Description: "Cancels a booking; Cal.com tells the attendees. Can't be undone. The preview shows the booking and how many attendees it reaches.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["booking"],"properties":{` + booking + `,"reason":{"type":"string","maxLength":500,"description":"Shown to the attendees"}}}`)},
			{Name: "reschedule_booking", Title: "Reschedule a booking", Description: "Moves a booking to a new start time; Cal.com tells the attendees. Undo moves it back.", Risk: sdk.RiskDestructive, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["booking","start"],"properties":{` + booking + `,"start":{"type":"string","description":"New start, like 2026-11-10T14:00:00Z"},"reason":{"type":"string","maxLength":500,"description":"Shown to the attendees"}}}`)},
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
		c.URL = "https://api.cal.com"
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !pathRe.MatchString(u.Path) {
		return errors.New("the address is like https://api.cal.com or https://cal-api.example.com")
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
	ref := c.Key
	base := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/v2")
	api := rest.New(u.Scheme+"://"+u.Host+base+"/v2", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		k = strings.TrimSpace(k)
		if !keyRe.MatchString(k) {
			return errors.New("the stored key doesn't look like a Cal.com API key (cal_…)")
		}
		r.Header.Set("Authorization", "Bearer "+k)
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func scrub(s string) string {
	s = emailRe.ReplaceAllString(rest.Redact(s), "[email]")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func friendly(err error) error {
	var e *rest.Error
	switch {
	case err == nil:
		return nil
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Cal.com refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the API key's user isn't allowed to do this in Cal.com")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Cal.com is limiting requests; try again in a moment")
	case errors.As(err, &e):
		return &rest.Error{Status: e.Status, Message: "Cal.com: " + scrub(e.Message)}
	}
	return err
}

// do calls one endpoint with its API version and decodes the data field.
func (c *conn) do(ctx context.Context, method, path, version string, q url.Values, body, out any) error {
	var env struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	hdr := http.Header{}
	if version != "" {
		hdr.Set("cal-api-version", version)
	}
	cl := *c.api
	cl.Header = hdr
	if _, err := cl.Do(ctx, method, path, q, body, &env); err != nil {
		return friendly(err)
	}
	if env.Status != "" && env.Status != "success" {
		return errors.New("Cal.com answered with an error")
	}
	if out != nil && len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, out); err != nil {
			return errors.New("unexpected answer from Cal.com")
		}
	}
	return nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		Username string `json:"username"`
		TimeZone string `json:"timeZone"`
	}
	if err := c.do(ctx, http.MethodGet, "/me", "", nil, nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Cal.com API v2 at this address"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: "connected as " + me.Username}
}

type input struct {
	Status    string `json:"status"`
	EventType ident  `json:"eventType"`
	Limit     int    `json:"limit"`
	Skip      int    `json:"skip"`
	Start     string `json:"start"`
	End       string `json:"end"`
	TimeZone  string `json:"timeZone"`
	Booking   string `json:"booking"`
	Reason    string `json:"reason"`
}

// ident is an id given as a string or a number.
type ident string

func (i *ident) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*i = ident(strings.TrimSpace(s))
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return errors.New("an id is a number")
	}
	*i = ident(n.String())
	return nil
}

type booking struct {
	ID                 int64  `json:"id"`
	UID                string `json:"uid"`
	Title              string `json:"title"`
	Status             string `json:"status"`
	Start              string `json:"start"`
	End                string `json:"end"`
	Duration           int    `json:"duration"`
	EventTypeID        int64  `json:"eventTypeId"`
	CancellationReason string `json:"cancellationReason"`
	CreatedAt          string `json:"createdAt"`
	Attendees          []struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		TimeZone string `json:"timeZone"`
		Absent   bool   `json:"absent"`
	} `json:"attendees"`
	Hosts []struct {
		Name string `json:"name"`
	} `json:"hosts"`
	// Meeting URLs and locations aren't decoded: a link to a call lets
	// anyone join it.
}

func bookingOut(b booking, personal bool) map[string]any {
	out := map[string]any{"uid": b.UID, "id": b.ID, "title": b.Title, "status": b.Status, "start": b.Start, "end": b.End, "durationMinutes": b.Duration, "attendeeCount": len(b.Attendees)}
	if b.EventTypeID != 0 {
		out["eventType"] = b.EventTypeID
	}
	if b.CancellationReason != "" && personal {
		out["cancellationReason"] = b.CancellationReason
	}
	if personal {
		as := []map[string]any{}
		for _, a := range b.Attendees {
			row := map[string]any{"name": a.Name, "email": a.Email, "timeZone": a.TimeZone}
			if a.Absent {
				row["absent"] = true
			}
			as = append(as, row)
		}
		out["attendees"] = as
		hs := []string{}
		for _, h := range b.Hosts {
			hs = append(hs, h.Name)
		}
		out["hosts"] = hs
	}
	return out
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
	case "event_types":
		var ts []struct {
			ID              int64  `json:"id"`
			Title           string `json:"title"`
			Slug            string `json:"slug"`
			LengthInMinutes int    `json:"lengthInMinutes"`
			Hidden          bool   `json:"hidden"`
			Description     string `json:"description"`
		}
		if err := c.do(ctx, http.MethodGet, "/event-types", eventTypesVersion, nil, nil, &ts); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, t := range ts {
			out = append(out, map[string]any{"id": t.ID, "title": t.Title, "slug": t.Slug, "lengthMinutes": t.LengthInMinutes, "hidden": t.Hidden})
		}
		return sdk.JSON(map[string]any{"items": out})
	case "bookings":
		return c.bookings(ctx, p)
	case "availability":
		return m.availability(ctx, c, p)
	case "cancel_booking", "reschedule_booking":
		return m.change(ctx, c, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) bookings(ctx context.Context, p input) (sdk.Result, error) {
	st := p.Status
	if st == "" {
		st = "upcoming"
	}
	if !bookingStatuses[st] {
		return sdk.Result{}, fmt.Errorf("status %q isn't upcoming, recurring, past, cancelled or unconfirmed", p.Status)
	}
	n := p.Limit
	if n <= 0 || n > 100 {
		n = 20
	}
	if p.Skip < 0 {
		return sdk.Result{}, errors.New("skip is zero or more")
	}
	q := url.Values{"status": {st}, "take": {strconv.Itoa(n)}, "skip": {strconv.Itoa(p.Skip)}}
	if st == "past" || st == "cancelled" {
		q.Set("sortStart", "desc")
	} else {
		q.Set("sortStart", "asc")
	}
	if e := string(p.EventType); e != "" {
		if !idRe.MatchString(e) {
			return sdk.Result{}, errors.New("the event type is its numeric id (see event_types)")
		}
		q.Set("eventTypeId", e)
	}
	var bs []booking
	if err := c.do(ctx, http.MethodGet, "/bookings", bookingsVersion, q, nil, &bs); err != nil {
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	for _, b := range bs {
		out = append(out, bookingOut(b, true))
	}
	return sdk.JSON(map[string]any{"items": out, "skip": p.Skip, "limit": n})
}

func (m *Module) availability(ctx context.Context, c *conn, p input) (sdk.Result, error) {
	e := string(p.EventType)
	if !idRe.MatchString(e) {
		return sdk.Result{}, errors.New("the event type is its numeric id (see event_types)")
	}
	tz := strings.TrimSpace(p.TimeZone)
	if tz == "" {
		tz = "UTC"
	}
	if !tzRe.MatchString(tz) || len(tz) > 64 {
		return sdk.Result{}, errors.New("the time zone is like Europe/Berlin or UTC")
	}
	day := func(s string, def time.Time) (time.Time, error) {
		if s == "" {
			return def, nil
		}
		return time.Parse("2006-01-02", s)
	}
	today := m.now().UTC().Truncate(24 * time.Hour)
	start, err := day(p.Start, today)
	if err != nil {
		return sdk.Result{}, errors.New("start is a date like 2026-11-10")
	}
	end, err := day(p.End, start.AddDate(0, 0, 7))
	if err != nil {
		return sdk.Result{}, errors.New("end is a date like 2026-11-17")
	}
	if end.Before(start) || end.Sub(start) > 31*24*time.Hour {
		return sdk.Result{}, errors.New("end is on or after start, and at most 31 days later")
	}
	q := url.Values{"eventTypeId": {e}, "start": {start.Format("2006-01-02")}, "end": {end.Format("2006-01-02")}, "timeZone": {tz}}
	var slots map[string][]struct {
		Start string `json:"start"`
	}
	if err := c.do(ctx, http.MethodGet, "/slots", slotsVersion, q, nil, &slots); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no event type %s", e)
		}
		return sdk.Result{}, err
	}
	days := []map[string]any{}
	total := 0
	for d := start; !d.After(end); d = d.AddDate(0, 0, 1) {
		k := d.Format("2006-01-02")
		if len(slots[k]) == 0 {
			continue
		}
		starts := []string{}
		for _, s := range slots[k] {
			starts = append(starts, s.Start)
		}
		total += len(starts)
		days = append(days, map[string]any{"date": k, "slots": starts})
	}
	return sdk.JSON(map[string]any{"eventType": e, "timeZone": tz, "days": days, "total": total})
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (m *Module) change(ctx context.Context, c *conn, call sdk.Call, p input) (sdk.Result, error) {
	uid := strings.TrimSpace(p.Booking)
	if !uidRe.MatchString(uid) {
		return sdk.Result{}, errors.New("the booking is its uid (see bookings)")
	}
	reason := strings.TrimSpace(p.Reason)
	if utf8.RuneCountInString(reason) > 500 || strings.ContainsRune(reason, 0) {
		return sdk.Result{}, errors.New("the reason is at most 500 characters")
	}
	reschedule := call.Action == "reschedule_booking"
	var to time.Time
	if reschedule {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(p.Start))
		if err != nil {
			return sdk.Result{}, errors.New("start is a time like 2026-11-10T14:00:00Z")
		}
		if !t.After(m.now()) {
			return sdk.Result{}, errors.New("the new start is in the past")
		}
		to = t.UTC()
	}
	var b booking
	if err := c.do(ctx, http.MethodGet, "/bookings/"+url.PathEscape(uid), bookingsVersion, nil, nil, &b); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no booking %s", uid)
		}
		return sdk.Result{}, err
	}
	if b.UID == "" {
		return sdk.Result{}, fmt.Errorf("there's no booking %s", uid)
	}
	if b.Status == "cancelled" || b.Status == "rejected" {
		if !reschedule {
			return sdk.JSON(map[string]any{"booking": uid, "status": b.Status, "note": "nothing to change: it's " + b.Status + " already"})
		}
		return sdk.Result{}, fmt.Errorf("booking %s is %s; it can't be rescheduled", uid, b.Status)
	}
	before := map[string]any{"eventType": b.EventTypeID, "start": b.Start, "end": b.End, "status": b.Status, "attendees": len(b.Attendees)}
	people := fmt.Sprintf("%d attendees are told", len(b.Attendees))
	if len(b.Attendees) == 1 {
		people = "1 attendee is told"
	}
	if !reschedule {
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Cancel booking %s on %s (%s); this can't be undone", uid, b.Start, people),
				Changes: []sdk.Change{{Target: "booking " + uid, Op: "cancel", Before: mustJSON(before), After: mustJSON(map[string]any{"status": "cancelled", "reason": reason})}}}}, nil
		}
		body := map[string]any{}
		if reason != "" {
			body["cancellationReason"] = reason
		}
		var r booking
		if err := c.do(ctx, http.MethodPost, "/bookings/"+url.PathEscape(uid)+"/cancel", bookingsVersion, nil, body, &r); err != nil {
			return sdk.Result{}, err
		}
		status := r.Status
		if status == "" {
			status = "cancelled"
		}
		return sdk.JSON(map[string]any{"booking": uid, "status": status})
	}
	if from, err := time.Parse(time.RFC3339, b.Start); err == nil && from.Equal(to) {
		return sdk.JSON(map[string]any{"booking": uid, "start": b.Start, "note": "nothing to change: it starts then already"})
	}
	start := to.Format(time.RFC3339)
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Move booking %s from %s to %s (%s)", uid, b.Start, start, people),
			Changes: []sdk.Change{{Target: "booking " + uid, Op: "update", Before: mustJSON(before), After: mustJSON(map[string]any{"start": start})}}}}, nil
	}
	body := map[string]any{"start": start}
	if reason != "" {
		body["reschedulingReason"] = reason
	}
	var r booking
	if err := c.do(ctx, http.MethodPost, "/bookings/"+url.PathEscape(uid)+"/reschedule", bookingsVersion, nil, body, &r); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"booking": r.UID, "previousBooking": uid, "start": r.Start, "end": r.End, "status": r.Status})
	// The reschedule makes a new booking; the undo moves that one back.
	if uidRe.MatchString(r.UID) {
		if old, perr := time.Parse(time.RFC3339, b.Start); perr == nil && old.After(m.now()) {
			res.Undo = sdk.UndoWith("reschedule_booking", map[string]string{"booking": r.UID, "start": old.UTC().Format(time.RFC3339)}, "Move the booking back to "+b.Start)
		}
	}
	return res, err
}
