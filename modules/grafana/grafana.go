// Package grafana works with a Grafana server through a service account
// token: dashboards, alert rules and their state, firing alerts, silences
// and annotations.
package grafana

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

// Config is one Grafana server.
type Config struct {
	URL   string `json:"url"`   // e.g. https://grafana.example.com
	Token string `json:"token"` // secret:// service account token
}

type conn struct {
	api    *rest.Client
	origin string // scheme://host, for links
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	now  func() time.Time
}

// New returns the Grafana module.
func New() *Module { return &Module{now: time.Now} }

// Grafana uids are letters, digits, - and _ (at most 40); silence ids are
// UUIDs.
var (
	uidRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)
	silenceRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

const amPath = "/api/alertmanager/grafana/api/v2"

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	matchers := `"matchers":{"type":"array","minItems":1,"maxItems":20,"description":"Label matchers; an alert is silenced when all match","items":{"type":"object","required":["name","value"],"properties":{"name":{"type":"string"},"value":{"type":"string"},"isRegex":{"type":"boolean","default":false},"isEqual":{"type":"boolean","default":true}}}}`
	return sdk.Manifest{
		ID: "grafana", Name: "Grafana", Version: "0.1.0", Category: "Monitoring", Icon: "chart",
		Description: "Grafana dashboards, alert rules and their state, firing alerts, silences and annotations.",
		Presets:     []string{"homelab", "developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","token"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://grafana.example.com"},
			"token":{"type":"string","x-secret":true,"description":"Service account token (Administration, Service accounts). Viewer reads; Editor creates silences and annotations"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "dashboards", Title: "Dashboards", Description: "Search dashboards by title or tag.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"query":{"type":"string"},"tag":{"type":"string"},"limit":{"type":"integer","default":50,"maximum":200}}}`)},
			{Name: "alert_rules", Title: "Alert rules", Description: "Grafana-managed alert rules with their state (firing, pending, normal), health and active alerts.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"state":{"type":"string","enum":["firing","pending","inactive"],"description":"Only rules in this state"}}}`)},
			{Name: "alerts", Title: "Firing alerts", Description: "Alerts that are firing now and aren't silenced.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"includeSilenced":{"type":"boolean","default":false}}}`)},
			{Name: "silences", Title: "Silences", Description: "Active and pending silences (expired ones too when asked).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"includeExpired":{"type":"boolean","default":false}}}`)},
			{Name: "create_silence", Title: "Silence alerts", Description: "Mutes matching alerts for a while. Undo expires the silence.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["matchers","comment"],"properties":{` + matchers + `,"durationMinutes":{"type":"integer","minimum":1,"maximum":43200,"default":120},"comment":{"type":"string"}}}`)},
			{Name: "expire_silence", Title: "Expire a silence", Description: "Ends a silence now. Undo creates it again for the time it had left.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"Silence id"}}}`)},
			{Name: "annotate", Title: "Add an annotation", Description: "Marks an event (a deploy, an outage) on the graphs, everywhere or on one dashboard. Undo deletes it.", Risk: sdk.RiskWrite, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["text"],"properties":{"text":{"type":"string"},"tags":{"type":"array","items":{"type":"string"},"maxItems":20},"dashboardUID":{"type":"string"},"panelId":{"type":"integer","minimum":1},"time":{"type":"integer","description":"Start, Unix milliseconds (default now)"},"timeEnd":{"type":"integer","description":"End, Unix milliseconds, for a region"}}}`)},
			{Name: "delete_annotation", Title: "Delete an annotation", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1}}}`)},
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
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is like https://grafana.example.com")
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the service account token in the vault and enter its secret:// reference")
	}
	tok := c.Token
	origin := u.Scheme + "://" + u.Host
	api := rest.New(origin+strings.TrimRight(u.Path, "/"), func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, tok)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second) // through the instance's network, if any
	}
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api, origin: origin})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var org struct {
		Name string `json:"name"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/api/org", nil, nil, &org); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "Grafana refused the token"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	var hl struct {
		Database string `json:"database"`
		Version  string `json:"version"`
	}
	_, _ = c.api.Do(ctx, http.MethodGet, "/api/health", nil, nil, &hl)
	msg := "organization " + org.Name
	if hl.Version != "" {
		msg += " · Grafana " + hl.Version
	}
	if hl.Database != "" && hl.Database != "ok" {
		return sdk.Health{Status: "degraded", Message: msg + " · database " + hl.Database}
	}
	return sdk.Health{Status: "ok", Message: msg}
}

// Matcher is one silence matcher.
type Matcher struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	IsRegex bool   `json:"isRegex"`
	IsEqual *bool  `json:"isEqual,omitempty"`
}

type silence struct {
	ID        string                 `json:"id"`
	Status    struct{ State string } `json:"status"`
	Matchers  []Matcher              `json:"matchers"`
	StartsAt  string                 `json:"startsAt"`
	EndsAt    string                 `json:"endsAt"`
	CreatedBy string                 `json:"createdBy"`
	Comment   string                 `json:"comment"`
}

func (s silence) summary() map[string]any {
	return map[string]any{"id": s.ID, "state": s.Status.State, "matchers": s.Matchers, "startsAt": s.StartsAt, "endsAt": s.EndsAt, "createdBy": s.CreatedBy, "comment": s.Comment}
}

func describe(ms []Matcher) string {
	parts := make([]string, 0, len(ms))
	for _, x := range ms {
		op := "="
		eq := x.IsEqual == nil || *x.IsEqual
		switch {
		case x.IsRegex && eq:
			op = "=~"
		case x.IsRegex:
			op = "!~"
		case !eq:
			op = "!="
		}
		parts = append(parts, x.Name+op+strconv.Quote(x.Value))
	}
	return strings.Join(parts, ", ")
}

type input struct {
	Query           string          `json:"query"`
	Tag             string          `json:"tag"`
	Limit           int             `json:"limit"`
	State           string          `json:"state"`
	IncludeSilenced bool            `json:"includeSilenced"`
	IncludeExpired  bool            `json:"includeExpired"`
	Matchers        []Matcher       `json:"matchers"`
	DurationMinutes int             `json:"durationMinutes"`
	Comment         string          `json:"comment"`
	ID              json.RawMessage `json:"id"`
	Text            string          `json:"text"`
	Tags            []string        `json:"tags"`
	DashboardUID    string          `json:"dashboardUID"`
	PanelID         int64           `json:"panelId"`
	Time            int64           `json:"time"`
	TimeEnd         int64           `json:"timeEnd"`
}

func (p input) stringID() (string, error) {
	var s string
	if json.Unmarshal(p.ID, &s) != nil || !silenceRe.MatchString(s) {
		return "", errors.New("enter the silence id")
	}
	return s, nil
}

func (p input) intID() (int64, error) {
	var n int64
	if json.Unmarshal(p.ID, &n) != nil || n <= 0 {
		return 0, errors.New("enter the annotation id")
	}
	return n, nil
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
	case "dashboards":
		limit := p.Limit
		if limit <= 0 || limit > 200 {
			limit = 50
		}
		q := url.Values{"type": {"dash-db"}, "limit": {strconv.Itoa(limit)}}
		if s := strings.TrimSpace(p.Query); s != "" {
			q.Set("query", s)
		}
		if s := strings.TrimSpace(p.Tag); s != "" {
			q.Set("tag", s)
		}
		var hits []struct {
			UID         string   `json:"uid"`
			Title       string   `json:"title"`
			URL         string   `json:"url"`
			FolderTitle string   `json:"folderTitle"`
			Tags        []string `json:"tags"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/api/search", q, nil, &hits); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, d := range hits {
			link := d.URL
			if strings.HasPrefix(link, "/") {
				link = c.origin + link
			}
			out = append(out, map[string]any{"uid": d.UID, "title": d.Title, "folder": d.FolderTitle, "tags": d.Tags, "url": link})
		}
		return sdk.JSON(out)

	case "alert_rules":
		if p.State != "" && p.State != "firing" && p.State != "pending" && p.State != "inactive" {
			return sdk.Result{}, errors.New("the state is firing, pending or inactive")
		}
		var r struct {
			Data struct {
				Groups []struct {
					Name  string `json:"name"`
					File  string `json:"file"`
					Rules []struct {
						UID            string            `json:"uid"`
						Name           string            `json:"name"`
						State          string            `json:"state"`
						Health         string            `json:"health"`
						LastError      string            `json:"lastError"`
						Labels         map[string]string `json:"labels"`
						LastEvaluation string            `json:"lastEvaluation"`
						Alerts         []json.RawMessage `json:"alerts"`
					} `json:"rules"`
				} `json:"groups"`
			} `json:"data"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/api/prometheus/grafana/api/v1/rules", nil, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, g := range r.Data.Groups {
			for _, x := range g.Rules {
				if p.State != "" && x.State != p.State {
					continue
				}
				row := map[string]any{"folder": g.File, "group": g.Name, "name": x.Name, "state": x.State, "health": x.Health, "labels": x.Labels, "activeAlerts": len(x.Alerts), "lastEvaluation": x.LastEvaluation}
				if x.UID != "" {
					row["uid"] = x.UID
				}
				if x.LastError != "" {
					row["lastError"] = x.LastError
				}
				out = append(out, row)
			}
		}
		return sdk.JSON(out)

	case "alerts":
		q := url.Values{"active": {"true"}, "silenced": {strconv.FormatBool(p.IncludeSilenced)}, "inhibited": {"false"}}
		var list []struct {
			Labels       map[string]string `json:"labels"`
			Annotations  map[string]string `json:"annotations"`
			StartsAt     string            `json:"startsAt"`
			GeneratorURL string            `json:"generatorURL"`
			Fingerprint  string            `json:"fingerprint"`
			Status       struct {
				State      string   `json:"state"`
				SilencedBy []string `json:"silencedBy"`
			} `json:"status"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, amPath+"/alerts", q, nil, &list); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, a := range list {
			row := map[string]any{"name": a.Labels["alertname"], "state": a.Status.State, "since": a.StartsAt, "labels": a.Labels, "fingerprint": a.Fingerprint, "link": a.GeneratorURL}
			if s := a.Annotations["summary"]; s != "" {
				row["summary"] = s
			}
			if len(a.Status.SilencedBy) > 0 {
				row["silencedBy"] = a.Status.SilencedBy
			}
			out = append(out, row)
		}
		sort.SliceStable(out, func(i, j int) bool { return fmt.Sprint(out[i]["since"]) > fmt.Sprint(out[j]["since"]) })
		return sdk.JSON(out)

	case "silences":
		var list []silence
		if _, err := c.api.Do(ctx, http.MethodGet, amPath+"/silences", nil, nil, &list); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, s := range list {
			if s.Status.State == "expired" && !p.IncludeExpired {
				continue
			}
			out = append(out, s.summary())
		}
		return sdk.JSON(out)

	case "create_silence":
		if len(p.Matchers) == 0 || len(p.Matchers) > 20 {
			return sdk.Result{}, errors.New("add 1 to 20 matchers")
		}
		for i, x := range p.Matchers {
			if strings.TrimSpace(x.Name) == "" {
				return sdk.Result{}, errors.New("every matcher needs a label name")
			}
			if x.IsEqual == nil {
				t := true
				p.Matchers[i].IsEqual = &t
			}
			if x.IsRegex {
				if _, err := regexp.Compile(x.Value); err != nil {
					return sdk.Result{}, fmt.Errorf("matcher %s: %v", x.Name, err)
				}
			}
		}
		if strings.TrimSpace(p.Comment) == "" {
			return sdk.Result{}, errors.New("say why in the comment")
		}
		mins := p.DurationMinutes
		if mins == 0 {
			mins = 120
		}
		if mins < 1 || mins > 43200 {
			return sdk.Result{}, errors.New("the duration is 1 minute to 30 days")
		}
		start := m.clock().UTC()
		end := start.Add(time.Duration(mins) * time.Minute)
		body := map[string]any{"matchers": p.Matchers, "startsAt": start.Format(time.RFC3339), "endsAt": end.Format(time.RFC3339), "createdBy": "Conduit", "comment": p.Comment}
		if call.DryRun {
			after, _ := json.Marshal(body)
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Silence alerts matching %s for %s", describe(p.Matchers), time.Duration(mins)*time.Minute),
				Changes: []sdk.Change{{Target: "silence " + describe(p.Matchers), Op: "create", After: after}}}}, nil
		}
		var r struct {
			SilenceID string `json:"silenceID"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, amPath+"/silences", nil, body, &r); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"id": r.SilenceID, "endsAt": body["endsAt"]})
		res.Undo = sdk.UndoWith("expire_silence", map[string]any{"id": r.SilenceID}, "Expire the silence")
		return res, err

	case "expire_silence":
		sid, err := p.stringID()
		if err != nil {
			return sdk.Result{}, err
		}
		var s silence
		if _, err := c.api.Do(ctx, http.MethodGet, amPath+"/silence/"+sid, nil, nil, &s); err != nil {
			return sdk.Result{}, err
		}
		if s.Status.State == "expired" {
			return sdk.Result{}, fmt.Errorf("silence %s has already expired", sid)
		}
		if call.DryRun {
			before, _ := json.Marshal(s.summary())
			return sdk.Result{Plan: &sdk.Plan{Summary: "Expire the silence on " + describe(s.Matchers) + " (" + s.Comment + ")",
				Changes: []sdk.Change{{Target: "silence " + sid, Op: "expire", Before: before}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodDelete, amPath+"/silence/"+sid, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"expired": sid})
		if end, perr := time.Parse(time.RFC3339, s.EndsAt); perr == nil {
			if left := end.Sub(m.clock()); left > time.Minute {
				mins := int(math.Ceil(left.Minutes()))
				if mins > 43200 {
					mins = 43200
				}
				res.Undo = sdk.UndoWith("create_silence", map[string]any{"matchers": s.Matchers, "comment": s.Comment, "durationMinutes": mins},
					"Silence "+describe(s.Matchers)+" again")
			}
		}
		return res, err

	case "annotate":
		text := strings.TrimSpace(p.Text)
		if text == "" {
			return sdk.Result{}, errors.New("write the annotation's text")
		}
		if len(p.Tags) > 20 {
			return sdk.Result{}, errors.New("at most 20 tags")
		}
		body := map[string]any{"text": text}
		if len(p.Tags) > 0 {
			body["tags"] = p.Tags
		}
		target := "every dashboard"
		if p.DashboardUID != "" {
			if !uidRe.MatchString(p.DashboardUID) {
				return sdk.Result{}, errors.New("the dashboard uid is letters, digits, - and _")
			}
			body["dashboardUID"] = p.DashboardUID
			target = "dashboard " + p.DashboardUID
			if p.PanelID > 0 {
				body["panelId"] = p.PanelID
				target += fmt.Sprintf(" panel %d", p.PanelID)
			}
		} else if p.PanelID > 0 {
			return sdk.Result{}, errors.New("a panel needs its dashboard's uid")
		}
		start := p.Time
		if start <= 0 {
			start = m.clock().UnixMilli()
		}
		body["time"] = start
		if p.TimeEnd != 0 {
			if p.TimeEnd < start {
				return sdk.Result{}, errors.New("the end is before the start")
			}
			body["timeEnd"] = p.TimeEnd
		}
		if call.DryRun {
			after, _ := json.Marshal(body)
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Annotate %s: %q", target, text),
				Changes: []sdk.Change{{Target: target, Op: "create", After: after}}}}, nil
		}
		var r struct {
			ID int64 `json:"id"`
		}
		if _, err := c.api.Do(ctx, http.MethodPost, "/api/annotations", nil, body, &r); err != nil {
			return sdk.Result{}, err
		}
		res, err := sdk.JSON(map[string]any{"id": r.ID, "time": start})
		res.Undo = sdk.UndoWith("delete_annotation", map[string]any{"id": r.ID}, "Delete the annotation")
		return res, err

	case "delete_annotation":
		aid, err := p.intID()
		if err != nil {
			return sdk.Result{}, err
		}
		path := "/api/annotations/" + strconv.FormatInt(aid, 10)
		if call.DryRun {
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete annotation %d", aid),
				Changes: []sdk.Change{{Target: fmt.Sprintf("annotation %d", aid), Op: "delete"}}}}, nil
		}
		if _, err := c.api.Do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"deleted": aid})
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (m *Module) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}
