// Package healthchecks works with Healthchecks.io (or a self-hosted
// Healthchecks server) through its Management API v3 with a project API
// key: checks with status and last ping, status changes (flips), pausing and
// resuming a check, pinging one, creating a check and deleting one.
package healthchecks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Config is one Healthchecks project.
type Config struct {
	Address            string `json:"address"` // https://healthchecks.io or a self-hosted server
	APIKey             string `json:"apiKey"`  // secret:// project API key
	Fingerprint        string `json:"fingerprint"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type conn struct {
	api  *rest.Client
	http *http.Client // for pings, which carry no API key
	host string
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Healthchecks module.
func New() *Module { return &Module{} }

const defaultAddress = "https://healthchecks.io"

var (
	uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	tagRe      = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,64}$`)
	nameRe     = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,100}$`)
	scheduleRe = regexp.MustCompile(`^[0-9A-Za-z*/,@ -]{1,100}$`)
	tzRe       = regexp.MustCompile(`^(UTC|[A-Za-z][A-Za-z_]+(/[A-Za-z0-9_+-]+){1,2})$`)
	prefixRe   = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)*$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	check := `"check":{"type":"string","description":"Check UUID (see checks)"}`
	return sdk.Manifest{
		ID: "healthchecks", Name: "Healthchecks", Version: "0.1.0", Category: "Monitoring", Icon: "pulse",
		Description: "Healthchecks.io or self-hosted Healthchecks: cron and heartbeat checks with status and last ping, status changes, pause or resume one check, ping, create and delete checks.",
		Presets:     []string{"developer", "homelab", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["apiKey"],"properties":{
			"address":{"type":"string","default":"https://healthchecks.io","description":"https://healthchecks.io, or your server, e.g. https://hc.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"The project's API key (project Settings, API Access); the read-only key only lists checks"},
			"fingerprint":{"type":"string","description":"SHA-256 fingerprint of a self-hosted server's certificate, to trust a self-signed one"},
			"insecureSkipVerify":{"type":"boolean","default":false,"description":"Skip certificate checks (not recommended; use the fingerprint)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "checks", Title: "Checks", Description: "Checks with status (up, down, grace, paused, new, started), last and next expected ping, period or schedule, grace and tags.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"tags":{"type":"array","items":{"type":"string"},"maxItems":10,"description":"Only checks with all these tags"}}}`)},
			{Name: "check", Title: "Check", Description: "One check's status, timing, description and integrations count.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["check"],"properties":{` + check + `}}`)},
			{Name: "flips", Title: "Status changes", Description: "When a check went down and came back up over the last days, newest first.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["check"],"properties":{` + check + `,"days":{"type":"integer","minimum":1,"maximum":90,"default":7}}}`)},
			{Name: "pause_check", Title: "Pause a check", Description: "Pauses one check: no alerts until its next ping (or until resumed, when the check needs a manual resume). Undo resumes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["check"],"properties":{` + check + `}}`)},
			{Name: "resume_check", Title: "Resume a check", Description: "Resumes a paused check (its status becomes new until the next ping). Undo pauses it again.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["check"],"properties":{` + check + `}}`)},
			{Name: "ping_check", Title: "Ping a check", Description: "Sends a ping as the job would: success marks the check up (which can hide a real outage, so this is destructive), fail marks it down and alerts, start starts the run timer, log only records. The preview shows the status now.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["check"],"properties":{` + check + `,"signal":{"type":"string","enum":["success","fail","start","log"],"default":"success"},"message":{"type":"string","maxLength":1000,"description":"Text recorded with the ping"}}}`)},
			{Name: "create_check", Title: "Create a check", Description: "Creates a check expecting a ping every timeout seconds, or on a cron schedule, with a grace time. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["name"],"properties":{"name":{"type":"string","maxLength":100},"timeout":{"type":"integer","minimum":60,"maximum":31536000,"description":"Expected period in seconds (default a day), instead of a schedule"},"schedule":{"type":"string","description":"Cron expression, e.g. 0 3 * * *, instead of a timeout"},"tz":{"type":"string","description":"Time zone of the schedule, e.g. Europe/Berlin (default UTC)"},"grace":{"type":"integer","minimum":60,"maximum":31536000,"default":3600,"description":"Seconds to wait past the expected time before alerting"},"tags":{"type":"array","items":{"type":"string"},"maxItems":10},"description":{"type":"string","maxLength":1000},"allIntegrations":{"type":"boolean","description":"Notify every integration of the project"}}}`)},
			{Name: "delete_check", Title: "Delete a check", Description: "Deletes a check with its ping history, for good; the job's pings stop being received. The preview shows what goes.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["check"],"properties":{` + check + `}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	addr := strings.TrimSpace(c.Address)
	if addr == "" {
		addr = defaultAddress
	}
	u, err := url.Parse(addr)
	prefix := ""
	if err == nil {
		prefix = strings.TrimRight(u.Path, "/")
	}
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !prefixRe.MatchString(prefix) || strings.Contains(prefix, "/..") {
		return errors.New("the address is https://healthchecks.io or your server, like https://hc.example.com")
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
		client = sdk.HTTPClient(h, 30*time.Second)
		client.Transport.(*http.Transport).TLSClientConfig = tc
	}
	client = rest.SameHostOnly(client)
	ref := c.APIKey
	api := rest.New(u.Scheme+"://"+u.Host+prefix+"/api/v3", func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-Api-Key", strings.TrimSpace(k))
		return nil
	})
	// X-Api-Key is a custom header, which Go would forward on a redirect.
	api.HTTP = client
	m.set.Put(id, &conn{api: api, http: client, host: u.Host})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Healthchecks refused the API key (a read-only key can only list checks)")
	case rest.IsStatus(err, http.StatusForbidden):
		return fmt.Errorf("Healthchecks refused: %s belongs to another project", what)
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Healthchecks' rate limit was hit; try again in a minute")
	}
	return err
}

type check struct {
	Name         string  `json:"name"`
	Slug         string  `json:"slug"`
	Tags         string  `json:"tags"`
	Desc         string  `json:"desc"`
	Grace        int64   `json:"grace"`
	Timeout      *int64  `json:"timeout"`
	Schedule     string  `json:"schedule"`
	TZ           string  `json:"tz"`
	NPings       int64   `json:"n_pings"`
	Status       string  `json:"status"`
	Started      bool    `json:"started"`
	LastPing     *string `json:"last_ping"`
	NextPing     *string `json:"next_ping"`
	ManualResume bool    `json:"manual_resume"`
	UUID         string  `json:"uuid"`
	UniqueKey    string  `json:"unique_key"` // read-only keys
	PingURL      string  `json:"ping_url"`
	Channels     string  `json:"channels"`
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func checkOut(c check) map[string]any {
	out := map[string]any{"name": clip(c.Name, 200), "status": c.Status, "graceSeconds": c.Grace, "pings": c.NPings}
	if uuidRe.MatchString(c.UUID) {
		out["check"] = c.UUID
	} else if c.UniqueKey != "" {
		out["key"] = clip(c.UniqueKey, 64)
	}
	if c.Slug != "" {
		out["slug"] = clip(c.Slug, 100)
	}
	if t := strings.Fields(c.Tags); len(t) > 0 {
		out["tags"] = t
	}
	if c.Schedule != "" {
		out["schedule"], out["tz"] = clip(c.Schedule, 100), clip(c.TZ, 64)
	} else if c.Timeout != nil {
		out["periodSeconds"] = *c.Timeout
	}
	if v := str(c.LastPing); v != "" {
		out["lastPing"] = v
	}
	if v := str(c.NextPing); v != "" {
		out["nextPing"] = v
	}
	if c.Started {
		out["started"] = true
	}
	if c.ManualResume {
		out["manualResume"] = true
	}
	return out
}

func checkID(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !uuidRe.MatchString(s) {
		return "", errors.New("the check is its UUID (see checks)")
	}
	return s, nil
}

func (c *conn) get(ctx context.Context, raw string) (check, error) {
	id, err := checkID(raw)
	if err != nil {
		return check{}, err
	}
	var ch check
	if _, err := c.api.Do(ctx, http.MethodGet, "/checks/"+id, nil, nil, &ch); err != nil {
		return check{}, friendly(err, "check "+id)
	}
	if ch.UUID != id {
		return check{}, errors.New("Healthchecks answered without the check's UUID: actions on a check need the full API key, not the read-only one")
	}
	return ch, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var a struct {
		Checks []check `json:"checks"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/checks/", nil, nil, &a); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "Healthchecks refused the API key"}
		}
		return sdk.Health{Status: "down", Message: friendly(err, "API here").Error()}
	}
	down := 0
	for _, ch := range a.Checks {
		if ch.Status == "down" {
			down++
		}
	}
	msg := fmt.Sprintf("%d checks · %d down", len(a.Checks), down)
	if down > 0 {
		return sdk.Health{Status: "degraded", Message: msg}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Check           string   `json:"check"`
	Tags            []string `json:"tags"`
	Days            int      `json:"days"`
	Signal          string   `json:"signal"`
	Message         string   `json:"message"`
	Name            string   `json:"name"`
	Timeout         int64    `json:"timeout"`
	Schedule        string   `json:"schedule"`
	TZ              string   `json:"tz"`
	Grace           int64    `json:"grace"`
	Description     string   `json:"description"`
	AllIntegrations bool     `json:"allIntegrations"`
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func tags(in []string) ([]string, error) {
	if len(in) > 10 {
		return nil, errors.New("give at most 10 tags")
	}
	var out []string
	for _, t := range in {
		t = strings.TrimSpace(t)
		if !tagRe.MatchString(t) {
			return nil, fmt.Errorf("the tag %q is letters, digits and _ . : @ -", t)
		}
		out = append(out, t)
	}
	return out, nil
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
	case "checks":
		tg, err := tags(p.Tags)
		if err != nil {
			return sdk.Result{}, err
		}
		var a struct {
			Checks []check `json:"checks"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/checks/", url.Values{"tag": tg}, nil, &a); err != nil {
			return sdk.Result{}, friendly(err, "checks")
		}
		list := []map[string]any{}
		by := map[string]int{}
		for i, ch := range a.Checks {
			by[ch.Status]++
			if i < 500 {
				list = append(list, checkOut(ch))
			}
		}
		out := map[string]any{"checks": list, "byStatus": by}
		if len(a.Checks) > len(list) {
			out["note"] = fmt.Sprintf("showing the first %d of %d", len(list), len(a.Checks))
		}
		if len(a.Checks) > 0 && a.Checks[0].UUID == "" {
			out["note"] = "the read-only key shows no check UUIDs, so only listing works"
		}
		return sdk.JSON(out)

	case "check":
		ch, err := c.get(ctx, p.Check)
		if err != nil {
			return sdk.Result{}, err
		}
		out := checkOut(ch)
		if d := clip(ch.Desc, 1000); d != "" {
			out["description"] = d
		}
		n := 0
		if ch.Channels != "" {
			n = len(strings.Split(ch.Channels, ","))
		}
		out["integrations"] = n
		return sdk.JSON(out)

	case "flips":
		id, err := checkID(p.Check)
		if err != nil {
			return sdk.Result{}, err
		}
		days := p.Days
		if days == 0 {
			days = 7
		}
		if days < 1 || days > 90 {
			return sdk.Result{}, errors.New("days is between 1 and 90")
		}
		var fl []struct {
			Timestamp string `json:"timestamp"`
			Up        int    `json:"up"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/checks/"+id+"/flips/", url.Values{"seconds": {strconv.Itoa(days * 86400)}}, nil, &fl); err != nil {
			return sdk.Result{}, friendly(err, "check "+id)
		}
		list := []map[string]any{}
		// The API lists them oldest first.
		for i := len(fl) - 1; i >= 0 && len(list) < 100; i-- {
			st := "down"
			if fl[i].Up == 1 {
				st = "up"
			}
			list = append(list, map[string]any{"at": clip(fl[i].Timestamp, 40), "to": st})
		}
		return sdk.JSON(map[string]any{"check": id, "days": days, "flips": list})

	case "pause_check", "resume_check":
		pausing := call.Action == "pause_check"
		ch, err := c.get(ctx, p.Check)
		if err != nil {
			return sdk.Result{}, err
		}
		paused := ch.Status == "paused"
		label := clip(ch.Name, 100)
		if paused == pausing {
			state := "isn't paused"
			if paused {
				state = "is already paused"
			}
			return sdk.JSON(map[string]any{"check": ch.UUID, "name": label, "note": "the check " + state})
		}
		verb, back, backDesc := "Pause", "resume_check", "Resume check %s"
		if !pausing {
			verb, back, backDesc = "Resume", "pause_check", "Pause check %s again"
		}
		if call.DryRun {
			sum := fmt.Sprintf("%s check %s", verb, label)
			after := "new"
			if pausing {
				after = "paused"
				sum += "; no alerts until its next ping"
				if ch.ManualResume {
					sum = fmt.Sprintf("Pause check %s; no alerts until it's resumed (it needs a manual resume)", label)
				}
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: sum, Changes: []sdk.Change{{Target: "check " + label, Op: strings.ToLower(verb),
				Before: mustJSON(map[string]any{"status": ch.Status}), After: mustJSON(map[string]any{"status": after})}}}}, nil
		}
		var after check
		if _, err := c.api.Do(ctx, http.MethodPost, "/checks/"+ch.UUID+"/"+strings.ToLower(verb), nil, map[string]any{}, &after); err != nil {
			if !pausing && rest.IsStatus(err, http.StatusConflict) {
				return sdk.Result{}, errors.New("Healthchecks refused: the check isn't paused")
			}
			return sdk.Result{}, friendly(err, "check "+ch.UUID)
		}
		res, err := sdk.JSON(map[string]any{"check": ch.UUID, "name": label, "status": after.Status})
		res.Undo = sdk.UndoWith(back, map[string]any{"check": ch.UUID}, fmt.Sprintf(backDesc, label))
		return res, err

	case "ping_check":
		suffix := map[string]string{"": "", "success": "", "fail": "/fail", "start": "/start", "log": "/log"}
		sfx, ok := suffix[p.Signal]
		if !ok {
			return sdk.Result{}, errors.New("the signal is success, fail, start or log")
		}
		sig := p.Signal
		if sig == "" {
			sig = "success"
		}
		msg := p.Message
		if len(msg) > 1000 {
			return sdk.Result{}, errors.New("the message is at most 1000 characters")
		}
		ch, err := c.get(ctx, p.Check)
		if err != nil {
			return sdk.Result{}, err
		}
		pu, err := url.Parse(ch.PingURL)
		if err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" || pu.User != nil || pu.RawQuery != "" || !strings.HasSuffix(pu.Path, "/"+ch.UUID) {
			return sdk.Result{}, errors.New("Healthchecks gave no usable ping address for this check")
		}
		label := clip(ch.Name, 100)
		if call.DryRun {
			sum := map[string]string{
				"success": "Ping check %s as succeeded; it becomes up (now %s), which hides an outage if the job really failed",
				"fail":    "Ping check %s as failed; it becomes down (now %s) and its integrations alert",
				"start":   "Signal check %s as started (now %s); it goes down if no success follows in time",
				"log":     "Record a log ping on check %s (now %s); the status doesn't change",
			}[sig]
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf(sum, label, ch.Status), Changes: []sdk.Change{{Target: "check " + label, Op: "ping",
				Before: mustJSON(map[string]any{"status": ch.Status}), After: mustJSON(map[string]any{"signal": sig, "message": clip(msg, 200)})}}}}, nil
		}
		ping := rest.New(pu.Scheme+"://"+pu.Host+pu.Path, nil)
		ping.HTTP = c.http
		res, err := ping.Send(ctx, http.MethodPost, sfx, nil, strings.NewReader(msg), http.Header{"Content-Type": {"text/plain; charset=utf-8"}})
		if err != nil {
			return sdk.Result{}, fmt.Errorf("the ping failed: %w", err)
		}
		io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		res.Body.Close()
		if res.StatusCode >= 300 {
			return sdk.Result{}, fmt.Errorf("the ping failed: %s", res.Status)
		}
		return sdk.JSON(map[string]any{"check": ch.UUID, "name": label, "signal": sig, "before": ch.Status})

	case "create_check":
		nm := strings.TrimSpace(p.Name)
		if !nameRe.MatchString(nm) {
			return sdk.Result{}, errors.New("the name is 1 to 100 characters")
		}
		body := map[string]any{"name": nm}
		shown := map[string]any{"name": nm}
		sched, tz := strings.TrimSpace(p.Schedule), strings.TrimSpace(p.TZ)
		switch {
		case sched != "" && p.Timeout != 0:
			return sdk.Result{}, errors.New("give a timeout or a schedule, not both")
		case sched != "":
			if !scheduleRe.MatchString(sched) || len(strings.Fields(sched)) > 6 {
				return sdk.Result{}, errors.New("the schedule is a cron expression, like 0 3 * * *")
			}
			if tz == "" {
				tz = "UTC"
			}
			if len(tz) > 64 || !tzRe.MatchString(tz) {
				return sdk.Result{}, errors.New("the time zone is a name like Europe/Berlin or UTC")
			}
			body["schedule"], body["tz"] = sched, tz
			shown["schedule"], shown["tz"] = sched, tz
		default:
			if tz != "" {
				return sdk.Result{}, errors.New("a time zone goes with a schedule")
			}
			t := p.Timeout
			if t == 0 {
				t = 86400
			}
			if t < 60 || t > 31536000 {
				return sdk.Result{}, errors.New("the timeout is 60 to 31536000 seconds")
			}
			body["timeout"] = t
			shown["periodSeconds"] = t
		}
		g := p.Grace
		if g == 0 {
			g = 3600
		}
		if g < 60 || g > 31536000 {
			return sdk.Result{}, errors.New("the grace is 60 to 31536000 seconds")
		}
		body["grace"], shown["graceSeconds"] = g, g
		tg, err := tags(p.Tags)
		if err != nil {
			return sdk.Result{}, err
		}
		if len(tg) > 0 {
			body["tags"], shown["tags"] = strings.Join(tg, " "), tg
		}
		if d := strings.TrimSpace(p.Description); d != "" {
			if len(d) > 1000 {
				return sdk.Result{}, errors.New("the description is at most 1000 characters")
			}
			body["desc"], shown["description"] = d, clip(d, 200)
		}
		if p.AllIntegrations {
			body["channels"], shown["integrations"] = "*", "all"
		}
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: "Create check " + nm, Changes: []sdk.Change{{Target: "check " + nm, Op: "create", After: mustJSON(shown)}}}}, nil
		}
		var ch check
		if _, err := c.api.Do(ctx, http.MethodPost, "/checks/", nil, body, &ch); err != nil {
			return sdk.Result{}, friendly(err, "project")
		}
		if !uuidRe.MatchString(ch.UUID) {
			return sdk.Result{}, errors.New("unexpected answer from Healthchecks: no check UUID")
		}
		res, err := sdk.JSON(checkOut(ch))
		res.Undo = sdk.UndoWith("delete_check", map[string]any{"check": ch.UUID}, "Delete check "+clip(nm, 100))
		return res, err

	case "delete_check":
		ch, err := c.get(ctx, p.Check)
		if err != nil {
			return sdk.Result{}, err
		}
		before := checkOut(ch)
		label := clip(ch.Name, 100)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete check %s (%s, %d pings recorded) for good; its job's pings will be refused", label, ch.Status, ch.NPings),
				Changes: []sdk.Change{{Target: "check " + label, Op: "delete", Before: mustJSON(before)}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodDelete, "/checks/"+ch.UUID, nil, nil, nil); err != nil {
			return sdk.Result{}, friendly(err, "check "+ch.UUID)
		}
		return sdk.JSON(map[string]any{"deleted": before})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
