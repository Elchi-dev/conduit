// Package statuspage works with Atlassian Statuspage through its API and an
// API key: pages, components and their status, incidents, posting and
// updating incidents, and setting a component's status. Everything it
// changes is public on the status page, so every change is destructive and
// subscribers are only notified when the input asks for it.
package statuspage

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

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Statuspage account.
type Config struct {
	Token string `json:"token"` // secret:// API key
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.statuspage.io/v1 (tests).
	Base string
}

// New returns the Statuspage module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.statuspage.io/v1"

var idRe = regexp.MustCompile(`^[A-Za-z0-9]{1,40}$`)

// componentStatuses and incidentStatuses are Statuspage's values.
var (
	componentStatuses = []string{"operational", "degraded_performance", "partial_outage", "major_outage", "under_maintenance"}
	incidentStatuses  = []string{"investigating", "identified", "monitoring", "resolved"}
	impacts           = []string{"none", "minor", "major", "critical"}
)

func oneOf(s string, list []string) bool {
	for _, v := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	page := `"page":{"type":"string","description":"Page id (see pages)"}`
	notify := `"notify":{"type":"boolean","default":false,"description":"Notify the page's subscribers (email, SMS, webhooks and others). Off unless set"}`
	comps := `"components":{"type":"object","additionalProperties":{"type":"string","enum":["operational","degraded_performance","partial_outage","major_outage","under_maintenance"]},"description":"Component id to the status it shows, e.g. {\"8kbf7d35c070\":\"major_outage\"}"}`
	body := `"body":{"type":"string","maxLength":5000,"description":"The public message, plain text"}`
	return sdk.Manifest{
		ID: "statuspage", Name: "Statuspage", Version: "0.1.0", Category: "Monitoring", Icon: "pulse",
		Description: "Atlassian Statuspage: pages, components and their status, incidents; post and update incidents and set component status (public, so destructive; subscribers are notified only when asked).",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An API key (your avatar, API info, Create key)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "pages", Title: "Pages", Description: "Status pages with their public address.", Risk: sdk.RiskRead},
			{Name: "components", Title: "Components", Description: "A page's components with their status (operational, degraded_performance, partial_outage, major_outage, under_maintenance) and group.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["page"],"properties":{` + page + `}}`)},
			{Name: "incidents", Title: "Incidents", Description: "A page's incidents, newest first: name, status, impact, affected components and the latest update. Unresolved only if asked.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["page"],"properties":{` + page + `,"unresolved":{"type":"boolean"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "create_incident", Title: "Post an incident", Description: "Posts an incident on the public status page, optionally setting component statuses. Public at once, so destructive; subscribers are notified only with notify. The preview shows the exact text.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["page","name"],"properties":{` + page + `,"name":{"type":"string","maxLength":255,"description":"The incident's public title"},"status":{"type":"string","enum":["investigating","identified","monitoring","resolved"],"default":"investigating"},"impact":{"type":"string","enum":["none","minor","major","critical"]},` + body + `,` + comps + `,` + notify + `}}`)},
			{Name: "update_incident", Title: "Update an incident", Description: "Posts an update on an incident: a new status, a public message and component statuses. Public at once, so destructive; subscribers are notified only with notify.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["page","incident"],"properties":{` + page + `,"incident":{"type":"string","description":"Incident id (see incidents)"},"status":{"type":"string","enum":["investigating","identified","monitoring","resolved"]},"impact":{"type":"string","enum":["none","minor","major","critical"]},` + body + `,` + comps + `,` + notify + `}}`)},
			{Name: "set_component_status", Title: "Set a component's status", Description: "Shows a component in a new status on the public page, without an incident (destructive: public at once). Undo sets the status it had.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["page","component","status"],"properties":{` + page + `,"component":{"type":"string","description":"Component id (see components)"},"status":{"type":"string","enum":["operational","degraded_performance","partial_outage","major_outage","under_maintenance"]}}}`)},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.Token, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("Authorization", "OAuth "+strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	api.HTTP = rest.SameHostOnly(client)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Statuspage refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Statuspage refused: the key's user can't do this on this page")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Statuspage's rate limit was hit; try again in a minute")
	}
	return err
}

type page struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Subdomain   string `json:"subdomain"`
	Domain      string `json:"domain"`
	Description string `json:"page_description"`
}

func (p page) address() string {
	if p.Domain != "" {
		return "https://" + clip(p.Domain, 253)
	}
	if p.Subdomain != "" {
		return "https://" + clip(p.Subdomain, 63) + ".statuspage.io"
	}
	return ""
}

type component struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	GroupID string `json:"group_id"`
	Group   bool   `json:"group"`
	Desc    string `json:"description"`
}

type incident struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Status     string      `json:"status"`
	Impact     string      `json:"impact"`
	Shortlink  string      `json:"shortlink"`
	CreatedAt  string      `json:"created_at"`
	UpdatedAt  string      `json:"updated_at"`
	ResolvedAt *string     `json:"resolved_at"`
	Components []component `json:"components"`
	Updates    []struct {
		Status    string `json:"status"`
		Body      string `json:"body"`
		CreatedAt string `json:"created_at"`
	} `json:"incident_updates"`
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// publicText checks text that goes on the public page: plain text without
// markup, so what the preview shows is exactly what's posted.
func publicText(s string, max int, multiline bool, what string) (string, error) {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > max {
		return "", fmt.Errorf("%s is up to %d characters", what, max)
	}
	for _, r := range s {
		if r == '<' || r == '>' {
			return "", fmt.Errorf("%s is plain text: no < or > (Statuspage may show it as HTML)", what)
		}
		if (r < 0x20 && !(multiline && (r == '\n' || r == '\t'))) || r == 0x7f {
			return "", fmt.Errorf("%s has a control character", what)
		}
	}
	return s, nil
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var ps []page
	if _, err := c.api.Do(ctx, http.MethodGet, "/pages", nil, nil, &ps); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "Statuspage API here").Error()}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d page(s)", len(ps))}
}

type input struct {
	Page       string            `json:"page"`
	Incident   string            `json:"incident"`
	Component  string            `json:"component"`
	Unresolved bool              `json:"unresolved"`
	Limit      int               `json:"limit"`
	Name       string            `json:"name"`
	Status     string            `json:"status"`
	Impact     string            `json:"impact"`
	Body       string            `json:"body"`
	Components map[string]string `json:"components"`
	Notify     bool              `json:"notify"`
}

func checkID(s, what string) (string, error) {
	s = strings.TrimSpace(s)
	if !idRe.MatchString(s) {
		return "", fmt.Errorf("the %s is its id (see %ss)", what, what)
	}
	return s, nil
}

// checkComponents validates a component-to-status map before any request.
func checkComponents(in map[string]string) (map[string]string, error) {
	if len(in) > 50 {
		return nil, errors.New("up to 50 components at once")
	}
	out := map[string]string{}
	for id, st := range in {
		id = strings.TrimSpace(id)
		if !idRe.MatchString(id) {
			return nil, errors.New("components maps component ids (see components) to a status")
		}
		if !oneOf(st, componentStatuses) {
			return nil, fmt.Errorf("a component status is one of %s", strings.Join(componentStatuses, ", "))
		}
		out[id] = st
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
	if call.Action == "pages" {
		var ps []page
		if _, err := c.api.Do(ctx, http.MethodGet, "/pages", nil, nil, &ps); err != nil {
			return sdk.Result{}, friendly(err, "page")
		}
		out := []map[string]any{}
		for _, x := range ps {
			out = append(out, map[string]any{"id": x.ID, "name": clip(x.Name, 200), "address": x.address()})
		}
		return sdk.JSON(out)
	}
	switch call.Action {
	case "components", "incidents", "create_incident", "update_incident", "set_component_status":
	default:
		return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
	}
	pg, err := checkID(p.Page, "page")
	if err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "components":
		cs, err := c.components(ctx, pg)
		if err != nil {
			return sdk.Result{}, err
		}
		groups := map[string]string{}
		for _, x := range cs {
			if x.Group {
				groups[x.ID] = x.Name
			}
		}
		out := []map[string]any{}
		for _, x := range cs {
			row := map[string]any{"id": x.ID, "name": clip(x.Name, 200), "status": x.Status}
			if x.Group {
				row["isGroup"] = true
			}
			if g := groups[x.GroupID]; g != "" {
				row["group"] = clip(g, 200)
			}
			out = append(out, row)
		}
		return sdk.JSON(out)

	case "incidents":
		limit := p.Limit
		if limit == 0 {
			limit = 25
		}
		if limit < 1 || limit > 100 {
			return sdk.Result{}, errors.New("the limit is between 1 and 100")
		}
		path := "/pages/" + url.PathEscape(pg) + "/incidents"
		if p.Unresolved {
			path += "/unresolved"
		}
		var is []incident
		if _, err := c.api.Do(ctx, http.MethodGet, path, url.Values{"limit": {strconv.Itoa(limit)}, "page": {"1"}}, nil, &is); err != nil {
			return sdk.Result{}, friendly(err, "page "+pg)
		}
		out := []map[string]any{}
		for _, x := range is {
			if len(out) == limit {
				break
			}
			out = append(out, incidentOut(x))
		}
		return sdk.JSON(out)

	case "create_incident":
		return c.createIncident(ctx, call, pg, p)
	case "update_incident":
		return c.updateIncident(ctx, call, pg, p)
	case "set_component_status":
		return c.setComponent(ctx, call, pg, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func incidentOut(x incident) map[string]any {
	row := map[string]any{"id": x.ID, "name": clip(x.Name, 255), "status": x.Status, "impact": x.Impact, "created": x.CreatedAt, "updated": x.UpdatedAt}
	if x.Shortlink != "" {
		row["link"] = clip(rest.ShortURL(x.Shortlink), 200)
	}
	if x.ResolvedAt != nil && *x.ResolvedAt != "" {
		row["resolved"] = *x.ResolvedAt
	}
	comps := []map[string]string{}
	for _, c := range x.Components {
		comps = append(comps, map[string]string{"id": c.ID, "name": clip(c.Name, 200), "status": c.Status})
	}
	row["components"] = comps
	if len(x.Updates) > 0 {
		u := x.Updates[0]
		row["latestUpdate"] = map[string]string{"status": u.Status, "body": clip(u.Body, 1000), "at": u.CreatedAt}
	}
	return row
}

func (c *conn) page(ctx context.Context, id string) (page, error) {
	var p page
	if _, err := c.api.Do(ctx, http.MethodGet, "/pages/"+url.PathEscape(id), nil, nil, &p); err != nil {
		return page{}, friendly(err, "page "+id)
	}
	if p.ID != id {
		return page{}, errors.New("Statuspage answered with another page")
	}
	return p, nil
}

func (c *conn) components(ctx context.Context, pg string) ([]component, error) {
	var cs []component
	if _, err := c.api.Do(ctx, http.MethodGet, "/pages/"+url.PathEscape(pg)+"/components", url.Values{"per_page": {"100"}}, nil, &cs); err != nil {
		return nil, friendly(err, "page "+pg)
	}
	return cs, nil
}

// componentChanges resolves the asked statuses against the page's
// components: names for the preview, and only those that differ.
func (c *conn) componentChanges(ctx context.Context, pg string, want map[string]string) (map[string]string, []string, error) {
	if len(want) == 0 {
		return map[string]string{}, nil, nil
	}
	cs, err := c.components(ctx, pg)
	if err != nil {
		return nil, nil, err
	}
	by := map[string]component{}
	for _, x := range cs {
		by[x.ID] = x
	}
	changed := map[string]string{}
	var lines []string
	for id, st := range want {
		x, ok := by[id]
		if !ok {
			return nil, nil, fmt.Errorf("there's no component %s on this page", id)
		}
		if x.Group {
			return nil, nil, fmt.Errorf("%s is a group; set the status of the components in it", clip(x.Name, 100))
		}
		if x.Status != st {
			changed[id] = st
			lines = append(lines, fmt.Sprintf("%s: %s → %s", clip(x.Name, 100), x.Status, st))
		}
	}
	sort.Strings(lines)
	return changed, lines, nil
}

func notifyNote(on bool) string {
	if on {
		return "the page's subscribers are notified (notify is on)"
	}
	return "subscribers are not notified (notify is off)"
}

func (c *conn) createIncident(ctx context.Context, call sdk.Call, pg string, p input) (sdk.Result, error) {
	name, err := publicText(p.Name, 255, false, "the name")
	if err != nil {
		return sdk.Result{}, err
	}
	if name == "" {
		return sdk.Result{}, errors.New("an incident needs a name")
	}
	body, err := publicText(p.Body, 5000, true, "the body")
	if err != nil {
		return sdk.Result{}, err
	}
	status := p.Status
	if status == "" {
		status = "investigating"
	}
	if !oneOf(status, incidentStatuses) {
		return sdk.Result{}, fmt.Errorf("the status is one of %s", strings.Join(incidentStatuses, ", "))
	}
	if p.Impact != "" && !oneOf(p.Impact, impacts) {
		return sdk.Result{}, fmt.Errorf("the impact is one of %s", strings.Join(impacts, ", "))
	}
	want, err := checkComponents(p.Components)
	if err != nil {
		return sdk.Result{}, err
	}
	pgx, err := c.page(ctx, pg)
	if err != nil {
		return sdk.Result{}, err
	}
	_, lines, err := c.componentChanges(ctx, pg, want)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		where := clip(pgx.Name, 100)
		if a := pgx.address(); a != "" {
			where += " (" + a + ")"
		}
		after := map[string]any{"name": name, "status": status, "body": body, "deliverNotifications": p.Notify}
		if p.Impact != "" {
			after["impact"] = p.Impact
		}
		if len(lines) > 0 {
			after["components"] = lines
		}
		return sdk.Result{Plan: &sdk.Plan{
			Summary: fmt.Sprintf("Post the incident %q (%s) publicly on %s; %s", name, status, where, notifyNote(p.Notify)),
			Changes: []sdk.Change{{Target: "status page " + clip(pgx.Name, 100), Op: "create", After: mustJSON(after)}}}}, nil
	}
	inc := map[string]any{"name": name, "status": status, "body": body, "deliver_notifications": p.Notify}
	if p.Impact != "" {
		inc["impact_override"] = p.Impact
	}
	if len(want) > 0 {
		ids := []string{}
		for id := range want {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		inc["component_ids"], inc["components"] = ids, want
	}
	var out incident
	if _, err := c.api.Do(ctx, http.MethodPost, "/pages/"+url.PathEscape(pg)+"/incidents", nil, map[string]any{"incident": inc}, &out); err != nil {
		return sdk.Result{}, friendly(err, "page "+pg)
	}
	res := incidentOut(out)
	res["notified"] = p.Notify
	return sdk.JSON(res)
}

func (c *conn) updateIncident(ctx context.Context, call sdk.Call, pg string, p input) (sdk.Result, error) {
	id, err := checkID(p.Incident, "incident")
	if err != nil {
		return sdk.Result{}, err
	}
	body, err := publicText(p.Body, 5000, true, "the body")
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Status != "" && !oneOf(p.Status, incidentStatuses) {
		return sdk.Result{}, fmt.Errorf("the status is one of %s", strings.Join(incidentStatuses, ", "))
	}
	if p.Impact != "" && !oneOf(p.Impact, impacts) {
		return sdk.Result{}, fmt.Errorf("the impact is one of %s", strings.Join(impacts, ", "))
	}
	want, err := checkComponents(p.Components)
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Status == "" && p.Impact == "" && body == "" && len(want) == 0 {
		return sdk.Result{}, errors.New("give a status, an impact, a body or component statuses")
	}
	var cur incident
	if _, err := c.api.Do(ctx, http.MethodGet, "/pages/"+url.PathEscape(pg)+"/incidents/"+url.PathEscape(id), nil, nil, &cur); err != nil {
		return sdk.Result{}, friendly(err, "incident "+id)
	}
	if cur.ID != id {
		return sdk.Result{}, errors.New("Statuspage answered with another incident")
	}
	changed, lines, err := c.componentChanges(ctx, pg, want)
	if err != nil {
		return sdk.Result{}, err
	}
	newStatus := p.Status != "" && p.Status != cur.Status
	newImpact := p.Impact != "" && p.Impact != cur.Impact
	if !newStatus && !newImpact && body == "" && len(changed) == 0 {
		return sdk.JSON(map[string]any{"id": cur.ID, "name": clip(cur.Name, 255), "status": cur.Status, "note": "nothing to change"})
	}
	inc := map[string]any{"deliver_notifications": p.Notify}
	if p.Status != "" {
		inc["status"] = p.Status
	}
	if newImpact {
		inc["impact_override"] = p.Impact
	}
	if body != "" {
		inc["body"] = body
	}
	if len(changed) > 0 {
		ids := []string{}
		for id := range changed {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		inc["component_ids"], inc["components"] = ids, changed
	}
	if call.DryRun {
		pgx, err := c.page(ctx, pg)
		if err != nil {
			return sdk.Result{}, err
		}
		where := clip(pgx.Name, 100)
		if a := pgx.address(); a != "" {
			where += " (" + a + ")"
		}
		before := map[string]any{"status": cur.Status, "impact": cur.Impact}
		after := map[string]any{"status": cur.Status, "impact": cur.Impact, "deliverNotifications": p.Notify}
		if p.Status != "" {
			after["status"] = p.Status
		}
		if newImpact {
			after["impact"] = p.Impact
		}
		if body != "" {
			after["body"] = body
		}
		if len(lines) > 0 {
			after["components"] = lines
		}
		return sdk.Result{Plan: &sdk.Plan{
			Summary: fmt.Sprintf("Post an update on the incident %q publicly on %s; %s", clip(cur.Name, 100), where, notifyNote(p.Notify)),
			Changes: []sdk.Change{{Target: "incident " + cur.ID, Op: "update", Before: mustJSON(before), After: mustJSON(after)}}}}, nil
	}
	var out incident
	if _, err := c.api.Do(ctx, http.MethodPatch, "/pages/"+url.PathEscape(pg)+"/incidents/"+url.PathEscape(id), nil, map[string]any{"incident": inc}, &out); err != nil {
		return sdk.Result{}, friendly(err, "incident "+id)
	}
	res := incidentOut(out)
	res["notified"] = p.Notify
	return sdk.JSON(res)
}

func (c *conn) setComponent(ctx context.Context, call sdk.Call, pg string, p input) (sdk.Result, error) {
	id, err := checkID(p.Component, "component")
	if err != nil {
		return sdk.Result{}, err
	}
	if !oneOf(p.Status, componentStatuses) {
		return sdk.Result{}, fmt.Errorf("the status is one of %s", strings.Join(componentStatuses, ", "))
	}
	path := "/pages/" + url.PathEscape(pg) + "/components/" + url.PathEscape(id)
	var cur component
	if _, err := c.api.Do(ctx, http.MethodGet, path, nil, nil, &cur); err != nil {
		return sdk.Result{}, friendly(err, "component "+id)
	}
	if cur.ID != id {
		return sdk.Result{}, errors.New("Statuspage answered with another component")
	}
	if cur.Group {
		return sdk.Result{}, fmt.Errorf("%s is a group; set the status of the components in it", clip(cur.Name, 100))
	}
	name := clip(cur.Name, 100)
	if cur.Status == p.Status {
		return sdk.JSON(map[string]any{"id": cur.ID, "name": name, "status": cur.Status, "note": "nothing to change"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{
			Summary: fmt.Sprintf("Show %s as %s on the public status page (no incident is posted and no notification is asked for)", name, p.Status),
			Changes: []sdk.Change{{Target: "component " + name, Op: "update", Before: mustJSON(map[string]string{"status": cur.Status}), After: mustJSON(map[string]string{"status": p.Status})}}}}, nil
	}
	var out component
	if _, err := c.api.Do(ctx, http.MethodPatch, path, nil, map[string]any{"component": map[string]string{"status": p.Status}}, &out); err != nil {
		return sdk.Result{}, friendly(err, "component "+id)
	}
	if out.ID != "" && out.Status != p.Status {
		return sdk.Result{}, fmt.Errorf("Statuspage kept %s as %s", name, out.Status)
	}
	res, err := sdk.JSON(map[string]any{"id": cur.ID, "name": name, "status": p.Status, "was": cur.Status})
	res.Undo = sdk.UndoWith("set_component_status", map[string]string{"page": pg, "component": cur.ID, "status": cur.Status}, "Show "+name+" as "+cur.Status+" again")
	return res, err
}
