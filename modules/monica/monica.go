// Package monica works with a Monica personal CRM (monicahq.com or a
// self-hosted Monica 4) through its REST API and a personal access token:
// contacts, upcoming reminders and birthdays, and notes on a contact.
//
// Everything Monica holds is about people, so every action is sensitive:
// Conduit keeps inputs and outputs out of the audit log, approvals and
// events.
package monica

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
	"unicode"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/modules/internal/tlspin"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Monica account.
type Config struct {
	URL                string `json:"url"`   // e.g. https://app.monicahq.com
	Token              string `json:"token"` // secret:// personal access token
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api    *rest.Client
	origin string
	now    func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Now replaces the clock (tests).
	Now func() time.Time
}

// New returns the Monica module.
func New() *Module { return &Module{} }

const (
	maxNote  = 10000
	maxQuery = 200
	// maxPages bounds how many pages of 100 upcoming reads.
	maxPages = 10
)

var pathRe = regexp.MustCompile(`^[A-Za-z0-9/._~-]*$`)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	contact := `"contact":{"type":"integer","minimum":1,"description":"Contact id (see contacts)"}`
	return sdk.Manifest{
		ID: "monica", Name: "Monica", Version: "0.1.0", Category: "Productivity", Icon: "contacts",
		Description: "Your Monica personal CRM: find contacts, see upcoming reminders and birthdays, and add notes to a contact. Kept out of logs.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"Monica's address: https://app.monicahq.com or your own"},
			"token":{"type":"string","x-secret":true,"description":"A personal access token from Settings → API. It acts as you"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of the server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "contacts", Title: "Contacts", Description: "Contacts matching a name, nickname or email, or all of them by name, with birthdays. Private, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string","maxLength":200},"limit":{"type":"integer","minimum":1,"maximum":100,"default":30}}}`)},
			{Name: "contact", Title: "Contact", Description: "One contact with their birthday, description and newest notes. Private, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["contact"],"properties":{` + contact + `,"notes":{"type":"integer","minimum":0,"maximum":50,"default":5}}}`)},
			{Name: "upcoming", Title: "Upcoming reminders and birthdays", Description: "Reminders and birthdays in the next days, soonest first. Private, so it's kept out of logs.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{"days":{"type":"integer","minimum":1,"maximum":366,"default":30}}}`)},
			{Name: "add_note", Title: "Add a note", Description: "Adds a note to a contact (they aren't sent anything). Undo deletes it.", Risk: sdk.RiskWrite, Sensitive: true, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["contact","body"],"properties":{` + contact + `,"body":{"type":"string","maxLength":10000},"favorite":{"type":"boolean","default":false}}}`)},
			{Name: "delete_note", Title: "Delete a note", Description: "Deletes one note. Monica can't bring it back. The preview quotes the note.", Risk: sdk.RiskDestructive, Sensitive: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["note"],"properties":{"note":{"type":"integer","minimum":1,"description":"Note id (see contact)"}}}`)},
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
		return errors.New("the address is like https://app.monicahq.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the access token in the vault and enter its secret:// reference")
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
	origin := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api")
	api := rest.New(origin+"/api", func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	api.HTTP = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, origin: origin, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Monica refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Monica refused the request: %v", err)
	}
	return err
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		Data struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/me", nil, nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Health{Status: "down", Message: "no Monica API at this address (Monica 5 has no API yet)"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	if me.Data.ID == 0 {
		return sdk.Health{Status: "down", Message: "unexpected answer from Monica"}
	}
	return sdk.Health{Status: "ok", Message: "signed in"}
}

type contact struct {
	ID           int    `json:"id"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	Nickname     string `json:"nickname"`
	CompleteName string `json:"complete_name"`
	Description  string `json:"description"`
	IsStarred    bool   `json:"is_starred"`
	IsPartial    bool   `json:"is_partial"`
	IsDead       bool   `json:"is_dead"`
	Information  struct {
		Dates struct {
			Birthdate struct {
				Date          *string `json:"date"`
				IsYearUnknown bool    `json:"is_year_unknown"`
				IsAgeBased    bool    `json:"is_age_based"`
			} `json:"birthdate"`
		} `json:"dates"`
	} `json:"information"`
}

func (k contact) name() string {
	if n := strings.TrimSpace(k.CompleteName); n != "" {
		return n
	}
	return strings.TrimSpace(k.FirstName + " " + k.LastName)
}

// birthday returns the month and day, and the year when it's known.
func (k contact) birthday() (month time.Month, day, year int, ok bool) {
	b := k.Information.Dates.Birthdate
	if b.Date == nil || len(*b.Date) < 10 {
		return 0, 0, 0, false
	}
	t, err := time.Parse("2006-01-02", (*b.Date)[:10])
	if err != nil {
		return 0, 0, 0, false
	}
	if !b.IsYearUnknown && !b.IsAgeBased {
		year = t.Year()
	}
	return t.Month(), t.Day(), year, true
}

func (k contact) summary() map[string]any {
	out := map[string]any{"id": k.ID, "name": k.name()}
	if k.Nickname != "" {
		out["nickname"] = k.Nickname
	}
	if mo, d, y, ok := k.birthday(); ok {
		if y > 0 {
			out["birthday"] = fmt.Sprintf("%04d-%02d-%02d", y, mo, d)
		} else {
			out["birthday"] = fmt.Sprintf("--%02d-%02d", mo, d)
		}
	}
	if k.IsStarred {
		out["starred"] = true
	}
	if k.IsDead {
		out["deceased"] = true
	}
	return out
}

type page struct {
	Meta struct {
		CurrentPage int `json:"current_page"`
		LastPage    int `json:"last_page"`
		Total       int `json:"total"`
	} `json:"meta"`
}

type note struct {
	ID          int    `json:"id"`
	Body        string `json:"body"`
	IsFavorited bool   `json:"is_favorited"`
	CreatedAt   string `json:"created_at"`
	Contact     *struct {
		ID           int    `json:"id"`
		CompleteName string `json:"complete_name"`
	} `json:"contact"`
}

type input struct {
	Query    string `json:"query"`
	Limit    int    `json:"limit"`
	Contact  int    `json:"contact"`
	Notes    *int   `json:"notes"`
	Days     int    `json:"days"`
	Body     string `json:"body"`
	Favorite bool   `json:"favorite"`
	Note     int    `json:"note"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func plain(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r' {
			return false
		}
	}
	return true
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
	case "contacts":
		q := strings.TrimSpace(p.Query)
		if len([]rune(q)) > maxQuery || !plain(q) {
			return sdk.Result{}, errors.New("the query is too long")
		}
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 30
		}
		v := url.Values{"limit": {strconv.Itoa(limit)}, "sort": {"first_name"}}
		if q != "" {
			v.Set("query", q)
		}
		var res struct {
			page
			Data []contact `json:"data"`
		}
		if err := c.do(ctx, http.MethodGet, "/contacts", v, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, k := range res.Data {
			if !k.IsPartial {
				out = append(out, k.summary())
			}
		}
		return sdk.JSON(map[string]any{"contacts": out, "total": res.Meta.Total})

	case "contact":
		k, err := c.contact(ctx, p.Contact)
		if err != nil {
			return sdk.Result{}, err
		}
		out := k.summary()
		if k.Description != "" {
			out["description"] = k.Description
		}
		out["open"] = c.origin + "/people/h:" + strconv.Itoa(k.ID)
		n := 5
		if p.Notes != nil {
			n = *p.Notes
		}
		if n < 0 || n > 50 {
			return sdk.Result{}, errors.New("notes is 0 to 50")
		}
		if n > 0 {
			var res struct {
				Data []note `json:"data"`
			}
			if err := c.do(ctx, http.MethodGet, "/contacts/"+strconv.Itoa(k.ID)+"/notes", url.Values{"limit": {strconv.Itoa(n)}, "sort": {"-created_at"}}, nil, &res); err != nil {
				return sdk.Result{}, err
			}
			notes := []map[string]any{}
			for _, x := range res.Data {
				r := map[string]any{"id": x.ID, "body": x.Body, "created": x.CreatedAt}
				if x.IsFavorited {
					r["favorite"] = true
				}
				notes = append(notes, r)
			}
			out["notes"] = notes
		}
		return sdk.JSON(out)

	case "upcoming":
		days := p.Days
		if days == 0 {
			days = 30
		}
		if days < 1 || days > 366 {
			return sdk.Result{}, errors.New("days is 1 to 366")
		}
		return c.upcoming(ctx, days)

	case "add_note":
		body := strings.TrimSpace(p.Body)
		if body == "" || len([]rune(body)) > maxNote || !plain(body) {
			return sdk.Result{}, fmt.Errorf("the note is 1 to %d characters", maxNote)
		}
		k, err := c.contact(ctx, p.Contact)
		if err != nil {
			return sdk.Result{}, err
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Add a note to " + k.name(),
				Changes: []sdk.Change{{Target: "contact " + k.name(), Op: "create", After: mustJSON(map[string]any{"body": body, "favorite": p.Favorite})}}}}, nil
		}
		var res struct {
			Data note `json:"data"`
		}
		if err := c.do(ctx, http.MethodPost, "/notes", nil, map[string]any{"body": body, "contact_id": k.ID, "is_favorited": p.Favorite}, &res); err != nil {
			return sdk.Result{}, err
		}
		r, err := sdk.JSON(map[string]any{"note": res.Data.ID, "contact": k.ID, "name": k.name()})
		if res.Data.ID > 0 {
			// The token holds the note's number alone, so the audit log
			// keeps it although delete_note is sensitive.
			r.Undo = sdk.UndoWith("delete_note", map[string]any{"note": res.Data.ID}, "Delete the note on "+k.name())
		}
		return r, err

	case "delete_note":
		if p.Note <= 0 {
			return sdk.Result{}, errors.New("the note is a note id (see contact)")
		}
		var res struct {
			Data note `json:"data"`
		}
		if err := c.do(ctx, http.MethodGet, "/notes/"+strconv.Itoa(p.Note), nil, nil, &res); err != nil {
			if rest.IsStatus(err, http.StatusNotFound) {
				return sdk.Result{}, fmt.Errorf("there's no note %d", p.Note)
			}
			return sdk.Result{}, err
		}
		who := "a contact"
		if res.Data.Contact != nil && res.Data.Contact.CompleteName != "" {
			who = res.Data.Contact.CompleteName
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Delete a note on " + who,
				Changes: []sdk.Change{{Target: "note " + strconv.Itoa(p.Note), Op: "delete", Before: mustJSON(map[string]any{"body": res.Data.Body, "created": res.Data.CreatedAt})}}}}, nil
		}
		if err := c.do(ctx, http.MethodDelete, "/notes/"+strconv.Itoa(p.Note), nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": p.Note, "contact": who})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) contact(ctx context.Context, id int) (contact, error) {
	if id <= 0 {
		return contact{}, errors.New("the contact is a contact id (see contacts)")
	}
	var res struct {
		Data contact `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/contacts/"+strconv.Itoa(id), nil, nil, &res); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return contact{}, fmt.Errorf("there's no contact %d", id)
		}
		return contact{}, err
	}
	if res.Data.ID == 0 {
		return contact{}, fmt.Errorf("there's no contact %d", id)
	}
	return res.Data, nil
}

type reminder struct {
	ID              int    `json:"id"`
	Title           string `json:"title"`
	FrequencyType   string `json:"frequency_type"`
	FrequencyNumber int    `json:"frequency_number"`
	InitialDate     string `json:"initial_date"`
	Contact         *struct {
		ID           int    `json:"id"`
		CompleteName string `json:"complete_name"`
	} `json:"contact"`
}

// next is the first time on or after from that a reminder comes up, or
// false when it doesn't any more.
func (r reminder) next(from time.Time) (time.Time, bool) {
	if len(r.InitialDate) < 10 {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02", r.InitialDate[:10])
	if err != nil {
		return time.Time{}, false
	}
	n := r.FrequencyNumber
	if n < 1 {
		n = 1
	}
	step := func(t time.Time, k int) time.Time {
		switch r.FrequencyType {
		case "week":
			return t.AddDate(0, 0, 7*n*k)
		case "month":
			return t.AddDate(0, n*k, 0)
		case "year":
			return t.AddDate(n*k, 0, 0)
		}
		return t
	}
	if !t.Before(from) {
		return t, true
	}
	if r.FrequencyType != "week" && r.FrequencyType != "month" && r.FrequencyType != "year" {
		return time.Time{}, false // one_time, in the past
	}
	// Jump close, then step (AddDate from the start, so month ends don't drift).
	k := 0
	switch r.FrequencyType {
	case "week":
		k = int(from.Sub(t).Hours()/24) / (7 * n)
	case "month":
		k = ((from.Year()-t.Year())*12 + int(from.Month()-t.Month())) / n
	case "year":
		k = (from.Year() - t.Year()) / n
	}
	if k > 0 {
		k--
	}
	for i := 0; i < 1000; i, k = i+1, k+1 {
		if x := step(t, k); !x.Before(from) {
			return x, true
		}
	}
	return time.Time{}, false
}

// nextBirthday is the next month/day on or after from (29 February is
// kept on the 28th in other years).
func nextBirthday(mo time.Month, d int, from time.Time) time.Time {
	for y := from.Year(); ; y++ {
		day := d
		if mo == time.February && d == 29 && !leap(y) {
			day = 28
		}
		t := time.Date(y, mo, day, 0, 0, 0, 0, time.UTC)
		if !t.Before(from) {
			return t
		}
	}
}

func leap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }

func (c *conn) upcoming(ctx context.Context, days int) (sdk.Result, error) {
	n := c.now()
	from := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC)
	until := from.AddDate(0, 0, days)
	type event struct {
		when time.Time
		row  map[string]any
	}
	var events []event
	birthdays := map[string]bool{} // contact id + date
	partial := false

	for pg := 1; pg <= maxPages; pg++ {
		var res struct {
			page
			Data []contact `json:"data"`
		}
		if err := c.do(ctx, http.MethodGet, "/contacts", url.Values{"limit": {"100"}, "page": {strconv.Itoa(pg)}}, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		for _, k := range res.Data {
			mo, d, y, ok := k.birthday()
			if !ok || k.IsDead {
				continue
			}
			t := nextBirthday(mo, d, from)
			if t.After(until) {
				continue
			}
			row := map[string]any{"date": t.Format("2006-01-02"), "kind": "birthday", "contact": k.ID, "name": k.name()}
			if y > 0 {
				row["turns"] = t.Year() - y
			}
			birthdays[strconv.Itoa(k.ID)+" "+t.Format("2006-01-02")] = true
			events = append(events, event{t, row})
		}
		if res.Meta.LastPage <= pg {
			break
		}
		if pg == maxPages {
			partial = true
		}
	}
	for pg := 1; pg <= maxPages; pg++ {
		var res struct {
			page
			Data []reminder `json:"data"`
		}
		if err := c.do(ctx, http.MethodGet, "/reminders", url.Values{"limit": {"100"}, "page": {strconv.Itoa(pg)}}, nil, &res); err != nil {
			return sdk.Result{}, err
		}
		for _, r := range res.Data {
			t, ok := r.next(from)
			if !ok || t.After(until) {
				continue
			}
			row := map[string]any{"date": t.Format("2006-01-02"), "kind": "reminder", "title": r.Title}
			if r.Contact != nil {
				// Monica's own birthday reminders duplicate the birthday.
				if birthdays[strconv.Itoa(r.Contact.ID)+" "+t.Format("2006-01-02")] {
					continue
				}
				row["contact"], row["name"] = r.Contact.ID, r.Contact.CompleteName
			}
			events = append(events, event{t, row})
		}
		if res.Meta.LastPage <= pg {
			break
		}
		if pg == maxPages {
			partial = true
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].when.Before(events[j].when) })
	out := []map[string]any{}
	for _, e := range events {
		out = append(out, e.row)
	}
	res := map[string]any{"days": days, "upcoming": out}
	if partial {
		res["note"] = fmt.Sprintf("only the first %d contacts and reminders were read", maxPages*100)
	}
	return sdk.JSON(res)
}
