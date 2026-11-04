// Package uptimerobot works with UptimeRobot through its API v2 with an API
// key: monitors with status and uptime ratios, recent downtime, pausing and
// resuming one monitor, creating a simple HTTP monitor and deleting one.
package uptimerobot

import (
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
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one UptimeRobot account.
type Config struct {
	APIKey string `json:"apiKey"` // secret:// main or read-only API key
}

type conn struct {
	api  *rest.Client
	host sdk.Host
	ref  string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.uptimerobot.com/v2 (tests).
	Base string
}

// New returns the UptimeRobot module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.uptimerobot.com/v2"

var (
	searchRe = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,100}$`)
	nameRe   = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,100}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	id := `"id":{"type":"integer","minimum":1,"description":"Monitor ID (see monitors)"}`
	return sdk.Manifest{
		ID: "uptimerobot", Name: "UptimeRobot", Version: "0.1.0", Category: "Monitoring", Icon: "pulse",
		Description: "UptimeRobot: monitors with status and 1/7/30-day uptime, recent downtime, pause or resume one monitor, create an HTTP monitor, delete a monitor.",
		Presets:     []string{"developer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"apiKey":{"type":"string","x-secret":true,"description":"Main API key (My Settings, API Settings), or the read-only key to only read"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "monitors", Title: "Monitors", Description: "Monitors with type, interval, status (up, down, paused) and uptime over 1, 7 and 30 days.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"search":{"type":"string","description":"Only monitors whose name or shown address (scheme, host and first path segment) contains this"},"status":{"type":"string","enum":["up","down","paused"]}}}`)},
			{Name: "monitor", Title: "Monitor", Description: "One monitor with uptime and its latest events (down, up, paused, started) with reasons.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
			{Name: "recent_downs", Title: "Recent downtime", Description: "The latest down events across monitors (or of one), newest first, with how long they lasted and why.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + id + `,"limit":{"type":"integer","minimum":1,"maximum":100,"default":20}}}`)},
			{Name: "pause_monitor", Title: "Pause a monitor", Description: "Pauses one monitor: it stops checking and alerting until resumed. Pausing every monitor isn't offered. Undo resumes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
			{Name: "resume_monitor", Title: "Resume a monitor", Description: "Resumes a paused monitor. Undo pauses it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{` + id + `}}`)},
			{Name: "create_monitor", Title: "Create an HTTP monitor", Description: "Creates an HTTP(S) monitor of a URL with a check interval (no alert contacts; add them in UptimeRobot). Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["name","url"],"properties":{"name":{"type":"string","maxLength":100},"url":{"type":"string","description":"http:// or https:// address to check"},"interval":{"type":"integer","minimum":60,"maximum":86400,"default":300,"description":"Seconds between checks (the free plan's minimum is 300)"}}}`)},
			{Name: "delete_monitor", Title: "Delete a monitor", Description: "Deletes a monitor with its uptime history and logs, for good. The preview shows what goes.", Risk: sdk.RiskDestructive, DryRun: true,
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
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	// The key goes in the form body (UptimeRobot v2 takes it nowhere else).
	api := rest.New(base, nil)
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api, host: h, ref: c.APIKey})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

var errKey = errors.New("UptimeRobot refused the API key")

// call posts one API method with a form and decodes the answer.
func (c *conn) call(ctx context.Context, method string, form url.Values, out any) error {
	key, err := c.host.Secret(ctx, c.ref)
	if err != nil {
		return err
	}
	if form == nil {
		form = url.Values{}
	}
	form.Set("api_key", strings.TrimSpace(key))
	form.Set("format", "json")
	res, err := c.api.Send(ctx, http.MethodPost, "/"+method, nil, strings.NewReader(form.Encode()),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}, "Cache-Control": {"no-cache"}})
	if err != nil {
		switch {
		case rest.IsStatus(err, http.StatusUnauthorized), rest.IsStatus(err, http.StatusForbidden):
			return errKey
		case rest.IsStatus(err, http.StatusTooManyRequests):
			return errors.New("UptimeRobot's rate limit was hit; try again in a minute")
		}
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("unexpected answer from UptimeRobot: %s", res.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	var env struct {
		Stat  string `json:"stat"`
		Error *struct {
			Type    string `json:"type"`
			Param   string `json:"parameter_name"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return errors.New("unexpected answer from UptimeRobot")
	}
	if env.Stat != "ok" {
		// The error echoes the passed value (the key, for api_key), so only
		// the parameter name and message are passed on.
		if env.Error != nil && (env.Error.Param == "api_key" || strings.Contains(strings.ToLower(env.Error.Message), "api_key")) {
			return errKey
		}
		if env.Error != nil && env.Error.Type == "not_authorized" {
			return errors.New("UptimeRobot refused: this API key may only read (use the main API key to change monitors)")
		}
		msg := "UptimeRobot refused the request"
		if env.Error != nil && env.Error.Message != "" {
			msg += ": " + clip(rest.Redact(env.Error.Message), 200)
		}
		return errors.New(msg)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return errors.New("unexpected answer from UptimeRobot")
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
	var a struct {
		Account struct {
			Up     int `json:"up_monitors"`
			Down   int `json:"down_monitors"`
			Paused int `json:"paused_monitors"`
		} `json:"account"`
	}
	if err := c.call(ctx, "getAccountDetails", nil, &a); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("%d up · %d down · %d paused", a.Account.Up, a.Account.Down, a.Account.Paused)
	if a.Account.Down > 0 {
		return sdk.Health{Status: "degraded", Message: msg}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type logEntry struct {
	Type     int   `json:"type"`
	Datetime int64 `json:"datetime"`
	Duration int64 `json:"duration"`
	Reason   *struct {
		Code   any    `json:"code"`
		Detail string `json:"detail"`
	} `json:"reason"`
}

type monitor struct {
	ID          int64      `json:"id"`
	Name        string     `json:"friendly_name"`
	URL         string     `json:"url"`
	Type        int        `json:"type"`
	Interval    int        `json:"interval"`
	Status      int        `json:"status"`
	Created     int64      `json:"create_datetime"`
	UptimeRatio string     `json:"custom_uptime_ratio"`
	Logs        []logEntry `json:"logs"`
}

type monitorsAnswer struct {
	Pagination struct {
		Offset int `json:"offset"`
		Limit  int `json:"limit"`
		Total  int `json:"total"`
	} `json:"pagination"`
	Monitors []monitor `json:"monitors"`
}

var statusNames = map[int]string{0: "paused", 1: "not checked yet", 2: "up", 8: "seems down", 9: "down"}
var typeNames = map[int]string{1: "http", 2: "keyword", 3: "ping", 4: "port", 5: "heartbeat"}
var logNames = map[int]string{1: "down", 2: "up", 98: "started", 99: "paused"}

func name(m map[int]string, v int) string {
	if s, ok := m[v]; ok {
		return s
	}
	return strconv.Itoa(v)
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func ts(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

// shownURL is a monitored address cut to scheme://host and its first path
// segment (rest.ShortURL: a token in the path, the query or the user part
// would end up in the audit log), and nothing for heartbeat monitors, whose
// URL is the secret push address.
func shownURL(mo monitor) string {
	if mo.Type == 5 {
		return ""
	}
	return clip(rest.ShortURL(mo.URL), 300)
}

func monitorOut(mo monitor) map[string]any {
	out := map[string]any{"id": mo.ID, "name": clip(mo.Name, 200), "type": name(typeNames, mo.Type), "status": name(statusNames, mo.Status), "intervalSeconds": mo.Interval}
	if u := shownURL(mo); u != "" {
		out["url"] = u
	}
	if r := strings.Split(mo.UptimeRatio, "-"); len(r) == 3 {
		up := map[string]float64{}
		for i, k := range []string{"1d", "7d", "30d"} {
			if f, err := strconv.ParseFloat(r[i], 64); err == nil {
				up[k] = f
			}
		}
		out["uptime"] = up
	}
	if mo.Created > 0 {
		out["created"] = ts(mo.Created)
	}
	return out
}

func logOut(l logEntry) map[string]any {
	out := map[string]any{"event": name(logNames, l.Type), "at": ts(l.Datetime), "durationSeconds": l.Duration}
	if l.Reason != nil {
		code := ""
		if l.Reason.Code != nil {
			code = clip(fmt.Sprint(l.Reason.Code), 20)
		}
		out["reason"] = strings.TrimSpace(code + " " + clip(rest.Redact(l.Reason.Detail), 200))
	}
	return out
}

type input struct {
	ID       int64  `json:"id"`
	Search   string `json:"search"`
	Status   string `json:"status"`
	Limit    int    `json:"limit"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Interval int    `json:"interval"`
}

func monitorID(id int64) (string, error) {
	if id < 1 || id > 1e12 {
		return "", errors.New("the monitor is its ID, a number (see monitors)")
	}
	return strconv.FormatInt(id, 10), nil
}

func (c *conn) get(ctx context.Context, id int64, logs int) (monitor, error) {
	sid, err := monitorID(id)
	if err != nil {
		return monitor{}, err
	}
	f := url.Values{"monitors": {sid}, "custom_uptime_ratios": {"1-7-30"}}
	if logs > 0 {
		f.Set("logs", "1")
		f.Set("logs_limit", strconv.Itoa(logs))
	}
	var a monitorsAnswer
	if err := c.call(ctx, "getMonitors", f, &a); err != nil {
		return monitor{}, err
	}
	for _, mo := range a.Monitors {
		if mo.ID == id {
			return mo, nil
		}
	}
	return monitor{}, fmt.Errorf("there's no monitor %d", id)
}

// list pages through getMonitors (50 a page, up to 500 monitors).
func (c *conn) list(ctx context.Context, f url.Values) ([]monitor, int, error) {
	var all []monitor
	total := 0
	for off := 0; off < 500; off += 50 {
		f.Set("offset", strconv.Itoa(off))
		f.Set("limit", "50")
		var a monitorsAnswer
		if err := c.call(ctx, "getMonitors", f, &a); err != nil {
			return nil, 0, err
		}
		all = append(all, a.Monitors...)
		total = a.Pagination.Total
		if len(a.Monitors) < 50 || len(all) >= total {
			break
		}
	}
	return all, total, nil
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func checkURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(s) > 2048 || strings.ContainsAny(s, " \t\r\n") {
		return "", errors.New("the url is an http:// or https:// address")
	}
	if u.User != nil {
		return "", errors.New("leave credentials out of the url (they'd be stored in UptimeRobot and shown in the audit log)")
	}
	return s, nil
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
	case "monitors":
		f := url.Values{"custom_uptime_ratios": {"1-7-30"}}
		// The search runs here, on names and the shown address: UptimeRobot's
		// own search matches the whole URL, which would let a caller guess a
		// token in it one character at a time.
		search := strings.ToLower(strings.TrimSpace(p.Search))
		if search != "" && !searchRe.MatchString(search) {
			return sdk.Result{}, errors.New("the search is up to 100 characters")
		}
		switch p.Status {
		case "":
		case "up":
			f.Set("statuses", "2")
		case "down":
			f.Set("statuses", "8-9")
		case "paused":
			f.Set("statuses", "0")
		default:
			return sdk.Result{}, errors.New("the status is up, down or paused")
		}
		ms, total, err := c.list(ctx, f)
		if err != nil {
			return sdk.Result{}, err
		}
		list := []map[string]any{}
		for _, mo := range ms {
			if search != "" && !strings.Contains(strings.ToLower(mo.Name), search) && !strings.Contains(strings.ToLower(shownURL(mo)), search) {
				continue
			}
			list = append(list, monitorOut(mo))
		}
		if search != "" {
			total = len(list)
		}
		out := map[string]any{"total": total, "monitors": list}
		if total > len(list) {
			out["note"] = fmt.Sprintf("showing the first %d", len(list))
		}
		return sdk.JSON(out)

	case "monitor":
		mo, err := c.get(ctx, p.ID, 10)
		if err != nil {
			return sdk.Result{}, err
		}
		out := monitorOut(mo)
		events := []map[string]any{}
		for _, l := range mo.Logs {
			events = append(events, logOut(l))
		}
		out["events"] = events
		return sdk.JSON(out)

	case "recent_downs":
		limit := p.Limit
		if limit == 0 {
			limit = 20
		}
		if limit < 1 || limit > 100 {
			return sdk.Result{}, errors.New("the limit is between 1 and 100")
		}
		f := url.Values{"logs": {"1"}, "logs_limit": {strconv.Itoa(limit)}, "log_types": {"1"}}
		if p.ID != 0 {
			sid, err := monitorID(p.ID)
			if err != nil {
				return sdk.Result{}, err
			}
			f.Set("monitors", sid)
		}
		ms, _, err := c.list(ctx, f)
		if err != nil {
			return sdk.Result{}, err
		}
		type down struct {
			at  int64
			row map[string]any
		}
		var downs []down
		for _, mo := range ms {
			first := true
			for _, l := range mo.Logs {
				if l.Type != 1 {
					continue
				}
				row := logOut(l)
				delete(row, "event")
				row["monitor"], row["name"] = mo.ID, clip(mo.Name, 200)
				// Logs come newest first: the latest down of a monitor that's down now is still going on.
				if first && mo.Status >= 8 {
					row["ongoing"] = true
				}
				first = false
				downs = append(downs, down{l.Datetime, row})
			}
		}
		sort.SliceStable(downs, func(i, j int) bool { return downs[i].at > downs[j].at })
		list := []map[string]any{}
		for i, d := range downs {
			if i == limit {
				break
			}
			list = append(list, d.row)
		}
		return sdk.JSON(map[string]any{"downs": list})

	case "pause_monitor", "resume_monitor":
		pausing := call.Action == "pause_monitor"
		mo, err := c.get(ctx, p.ID, 0)
		if err != nil {
			return sdk.Result{}, err
		}
		paused := mo.Status == 0
		if paused == pausing {
			state := "isn't paused"
			if paused {
				state = "is already paused"
			}
			return sdk.JSON(map[string]any{"id": mo.ID, "name": clip(mo.Name, 200), "note": "the monitor " + state})
		}
		verb, back, backDesc, status := "Pause", "resume_monitor", "Resume monitor %s", "0"
		if !pausing {
			verb, back, backDesc, status = "Resume", "pause_monitor", "Pause monitor %s again", "1"
		}
		label := clip(mo.Name, 100)
		if call.DryRun {
			sum := fmt.Sprintf("%s monitor %s (%d)", verb, label, mo.ID)
			if pausing {
				sum += "; it stops checking and alerting until resumed"
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "monitor " + label, Op: strings.ToLower(verb),
				Before: mustJSON(map[string]any{"status": name(statusNames, mo.Status)}), After: mustJSON(map[string]any{"status": map[bool]string{true: "paused", false: "checking"}[pausing]})}}}}, nil
		}
		if err := c.call(ctx, "editMonitor", url.Values{"id": {strconv.FormatInt(mo.ID, 10)}, "status": {status}}, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"id": mo.ID, "name": clip(mo.Name, 200), "paused": pausing})
		res.Undo = sdk.UndoWith(back, map[string]any{"id": mo.ID}, fmt.Sprintf(backDesc, label))
		return res, err

	case "create_monitor":
		nm := strings.TrimSpace(p.Name)
		if !nameRe.MatchString(nm) {
			return sdk.Result{}, errors.New("the name is 1 to 100 characters")
		}
		u, err := checkURL(p.URL)
		if err != nil {
			return sdk.Result{}, err
		}
		interval := p.Interval
		if interval == 0 {
			interval = 300
		}
		if interval < 60 || interval > 86400 {
			return sdk.Result{}, errors.New("the interval is 60 to 86400 seconds")
		}
		after := map[string]any{"name": nm, "url": shownURL(monitor{URL: u, Type: 1}), "type": "http", "intervalSeconds": interval}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Create an HTTP monitor %s of %s every %d seconds", nm, after["url"], interval),
				Changes: []sdk.Change{{Target: "monitor " + nm, Op: "create", After: mustJSON(after)}}}}, nil
		}
		var a struct {
			Monitor struct {
				ID int64 `json:"id"`
			} `json:"monitor"`
		}
		if err := c.call(ctx, "newMonitor", url.Values{"type": {"1"}, "friendly_name": {nm}, "url": {u}, "interval": {strconv.Itoa(interval)}}, &a); err != nil {
			return sdk.Result{}, err
		}
		if a.Monitor.ID < 1 {
			return sdk.Result{}, errors.New("unexpected answer from UptimeRobot: no monitor ID")
		}
		after["id"] = a.Monitor.ID
		res, err := sdk.JSON(after)
		res.Undo = sdk.UndoWith("delete_monitor", map[string]any{"id": a.Monitor.ID}, "Delete monitor "+clip(nm, 100))
		return res, err

	case "delete_monitor":
		mo, err := c.get(ctx, p.ID, 0)
		if err != nil {
			return sdk.Result{}, err
		}
		before := monitorOut(mo)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete monitor %s (%d) with its uptime history, for good", clip(mo.Name, 100), mo.ID),
				Changes: []sdk.Change{{Target: "monitor " + clip(mo.Name, 100), Op: "delete", Before: mustJSON(before)}}}}, nil
		}
		if err := c.call(ctx, "deleteMonitor", url.Values{"id": {strconv.FormatInt(mo.ID, 10)}}, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": before})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
