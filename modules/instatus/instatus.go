// Package instatus works with Instatus status pages through their API and
// an API key: pages, components, incidents, and posting and updating
// incidents. Incidents are public on the status page, so posting is
// destructive and subscribers are only notified when the input asks for it.
package instatus

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

// Config is one Instatus account.
type Config struct {
	Token string `json:"token"` // secret:// API key
}

type conn struct {
	api *rest.Client
	now func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.instatus.com (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the Instatus module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.instatus.com"

var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

var (
	componentStatuses = []string{"OPERATIONAL", "DEGRADEDPERFORMANCE", "PARTIALOUTAGE", "MAJOROUTAGE", "UNDERMAINTENANCE"}
	incidentStatuses  = []string{"INVESTIGATING", "IDENTIFIED", "MONITORING", "RESOLVED"}
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
	notify := `"notify":{"type":"boolean","default":false,"description":"Notify the page's subscribers. Off unless set"}`
	comps := `"components":{"type":"object","additionalProperties":{"type":"string","enum":["OPERATIONAL","DEGRADEDPERFORMANCE","PARTIALOUTAGE","MAJOROUTAGE","UNDERMAINTENANCE"]},"description":"Affected component id to the status it shows"}`
	msg := `"message":{"type":"string","maxLength":5000,"description":"The public message, plain text"}`
	status := `"status":{"type":"string","enum":["INVESTIGATING","IDENTIFIED","MONITORING","RESOLVED"]}`
	return sdk.Manifest{
		ID: "instatus", Name: "Instatus", Version: "0.1.0", Category: "Monitoring", Icon: "pulse",
		Description: "Instatus status pages: pages, components, incidents; post and update incidents (public, so destructive; subscribers are notified only when asked).",
		Presets:     []string{"team", "developer"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"An API key (User settings, Developer settings)"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "pages", Title: "Pages", Description: "Status pages with their public address and overall status.", Risk: sdk.RiskRead},
			{Name: "components", Title: "Components", Description: "A page's components with their status and group.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["page"],"properties":{` + page + `}}`)},
			{Name: "incidents", Title: "Incidents", Description: "A page's incidents, newest first: name, status, when it started and was resolved, affected components and the latest update.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["page"],"properties":{` + page + `,"unresolved":{"type":"boolean"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25}}}`)},
			{Name: "create_incident", Title: "Post an incident", Description: "Posts an incident on the public status page with the affected components' statuses. Public at once, so destructive; subscribers are notified only with notify. The preview shows the exact text.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["page","name","message","components"],"properties":{` + page + `,"name":{"type":"string","maxLength":255,"description":"The incident's public title"},` + status + `,` + msg + `,` + comps + `,` + notify + `}}`)},
			{Name: "update_incident", Title: "Update an incident", Description: "Posts an update on an incident: a public message, a new status and component statuses. Public at once, so destructive; subscribers are notified only with notify.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["page","incident"],"properties":{` + page + `,"incident":{"type":"string","description":"Incident id (see incidents)"},` + status + `,` + msg + `,` + comps + `,` + notify + `}}`)},
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
		r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
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

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Instatus refused the API key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Instatus refused: the key can't do this on this page")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Instatus's rate limit was hit; try again in a minute")
	}
	return err
}

type page struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Subdomain string  `json:"subdomain"`
	Custom    *string `json:"customDomain"`
	Status    string  `json:"status"`
}

func (p page) address() string {
	if p.Custom != nil && *p.Custom != "" {
		return "https://" + clip(*p.Custom, 253)
	}
	if p.Subdomain != "" {
		return "https://" + clip(p.Subdomain, 63) + ".instatus.com"
	}
	return ""
}

type component struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Group  *struct {
		Name string `json:"name"`
	} `json:"group"`
}

type incident struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Status     string      `json:"status"`
	Started    string      `json:"started"`
	Resolved   *string     `json:"resolved"`
	Components []component `json:"components"`
	Updates    []struct {
		Message   string `json:"message"`
		Status    string `json:"status"`
		CreatedAt string `json:"createdAt"`
		Started   string `json:"started"`
	} `json:"updates"`
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
			return "", fmt.Errorf("%s is plain text: no < or >", what)
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
	if _, err := c.api.Do(ctx, http.MethodGet, "/v2/pages", nil, nil, &ps); err != nil {
		return sdk.Health{Status: "down", Message: friendly(err, "Instatus API here").Error()}
	}
	issues := 0
	for _, p := range ps {
		if p.Status != "" && p.Status != "UP" {
			issues++
		}
	}
	if issues > 0 {
		return sdk.Health{Status: "degraded", Message: fmt.Sprintf("%d page(s), %d with issues or maintenance", len(ps), issues)}
	}
	return sdk.Health{Status: "ok", Message: fmt.Sprintf("%d page(s)", len(ps))}
}

type input struct {
	Page       string            `json:"page"`
	Incident   string            `json:"incident"`
	Unresolved bool              `json:"unresolved"`
	Limit      int               `json:"limit"`
	Name       string            `json:"name"`
	Status     string            `json:"status"`
	Message    string            `json:"message"`
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

func pagePath(pg string) string { return "/v1/" + url.PathEscape(pg) }

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
	case "pages":
		var ps []page
		if _, err := c.api.Do(ctx, http.MethodGet, "/v2/pages", nil, nil, &ps); err != nil {
			return sdk.Result{}, friendly(err, "page")
		}
		out := []map[string]any{}
		for _, x := range ps {
			out = append(out, map[string]any{"id": x.ID, "name": clip(x.Name, 200), "address": x.address(), "status": x.Status})
		}
		return sdk.JSON(out)
	case "components", "incidents", "create_incident", "update_incident":
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
		out := []map[string]any{}
		for _, x := range cs {
			row := map[string]any{"id": x.ID, "name": clip(x.Name, 200), "status": x.Status}
			if x.Group != nil && x.Group.Name != "" {
				row["group"] = clip(x.Group.Name, 200)
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
		var is []incident
		if _, err := c.api.Do(ctx, http.MethodGet, pagePath(pg)+"/incidents", url.Values{"page": {"1"}, "per_page": {strconv.Itoa(limit)}}, nil, &is); err != nil {
			return sdk.Result{}, friendly(err, "page "+pg)
		}
		out := []map[string]any{}
		for _, x := range is {
			if len(out) == limit {
				break
			}
			if p.Unresolved && x.Status == "RESOLVED" {
				continue
			}
			out = append(out, incidentOut(x))
		}
		return sdk.JSON(out)

	case "create_incident":
		return c.createIncident(ctx, call, pg, p)
	}
	return c.updateIncident(ctx, call, pg, p)
}

func incidentOut(x incident) map[string]any {
	row := map[string]any{"id": x.ID, "name": clip(x.Name, 255), "status": x.Status, "started": x.Started}
	if x.Resolved != nil && *x.Resolved != "" {
		row["resolved"] = *x.Resolved
	}
	comps := []map[string]string{}
	for _, c := range x.Components {
		comps = append(comps, map[string]string{"id": c.ID, "name": clip(c.Name, 200), "status": c.Status})
	}
	row["components"] = comps
	if n := len(x.Updates); n > 0 {
		// Instatus lists updates oldest first.
		u := x.Updates[n-1]
		at := u.CreatedAt
		if at == "" {
			at = u.Started
		}
		row["latestUpdate"] = map[string]string{"status": u.Status, "message": clip(u.Message, 1000), "at": at}
	}
	return row
}

func (c *conn) components(ctx context.Context, pg string) ([]component, error) {
	var cs []component
	if _, err := c.api.Do(ctx, http.MethodGet, pagePath(pg)+"/components", nil, nil, &cs); err != nil {
		return nil, friendly(err, "page "+pg)
	}
	return cs, nil
}

func (c *conn) pageInfo(ctx context.Context, pg string) string {
	var ps []page
	if _, err := c.api.Do(ctx, http.MethodGet, "/v2/pages", nil, nil, &ps); err == nil {
		for _, p := range ps {
			if p.ID == pg {
				s := clip(p.Name, 100)
				if a := p.address(); a != "" {
					s += " (" + a + ")"
				}
				return s
			}
		}
	}
	return "page " + pg
}

func notifyNote(on bool) string {
	if on {
		return "the page's subscribers are notified (notify is on)"
	}
	return "subscribers are not notified (notify is off)"
}

// statuses builds the affected components list for a post: every id in
// keep with the asked status, else the status it has now. It also returns
// preview lines for the components whose status changes.
func statuses(cs []component, keep []string, want map[string]string) ([]string, []map[string]string, []string, error) {
	by := map[string]component{}
	for _, x := range cs {
		by[x.ID] = x
	}
	ids := map[string]bool{}
	for _, id := range keep {
		ids[id] = true
	}
	for id := range want {
		if _, ok := by[id]; !ok {
			return nil, nil, nil, fmt.Errorf("there's no component %s on this page", id)
		}
		ids[id] = true
	}
	list := []string{}
	for id := range ids {
		list = append(list, id)
	}
	sort.Strings(list)
	sts := []map[string]string{}
	var lines []string
	for _, id := range list {
		st, ok := want[id]
		if !ok {
			st = by[id].Status
		}
		sts = append(sts, map[string]string{"id": id, "status": st})
		if cur := by[id].Status; cur != st {
			lines = append(lines, fmt.Sprintf("%s: %s → %s", clip(by[id].Name, 100), cur, st))
		}
	}
	return list, sts, lines, nil
}

func (c *conn) createIncident(ctx context.Context, call sdk.Call, pg string, p input) (sdk.Result, error) {
	name, err := publicText(p.Name, 255, false, "the name")
	if err != nil {
		return sdk.Result{}, err
	}
	msg, err := publicText(p.Message, 5000, true, "the message")
	if err != nil {
		return sdk.Result{}, err
	}
	if name == "" || msg == "" {
		return sdk.Result{}, errors.New("an incident needs a name and a message")
	}
	status := p.Status
	if status == "" {
		status = "INVESTIGATING"
	}
	if !oneOf(status, incidentStatuses) {
		return sdk.Result{}, fmt.Errorf("the status is one of %s", strings.Join(incidentStatuses, ", "))
	}
	want, err := checkComponents(p.Components)
	if err != nil {
		return sdk.Result{}, err
	}
	if len(want) == 0 {
		return sdk.Result{}, errors.New("name the affected components and their status (see components)")
	}
	cs, err := c.components(ctx, pg)
	if err != nil {
		return sdk.Result{}, err
	}
	ids, sts, lines, err := statuses(cs, nil, want)
	if err != nil {
		return sdk.Result{}, err
	}
	if call.DryRun {
		after := map[string]any{"name": name, "status": status, "message": msg, "components": lines, "notify": p.Notify}
		return sdk.Result{Plan: &sdk.Plan{
			Summary: fmt.Sprintf("Post the incident %q (%s) publicly on %s; %s", name, status, c.pageInfo(ctx, pg), notifyNote(p.Notify)),
			Changes: []sdk.Change{{Target: "status page " + pg, Op: "create", After: mustJSON(after)}}}}, nil
	}
	body := map[string]any{"name": name, "message": msg, "status": status, "components": ids, "statuses": sts, "notify": p.Notify,
		"started": c.now().UTC().Format(time.RFC3339)}
	var out incident
	if _, err := c.api.Do(ctx, http.MethodPost, pagePath(pg)+"/incidents", nil, body, &out); err != nil {
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
	msg, err := publicText(p.Message, 5000, true, "the message")
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Status != "" && !oneOf(p.Status, incidentStatuses) {
		return sdk.Result{}, fmt.Errorf("the status is one of %s", strings.Join(incidentStatuses, ", "))
	}
	want, err := checkComponents(p.Components)
	if err != nil {
		return sdk.Result{}, err
	}
	if p.Status == "" && msg == "" && len(want) == 0 {
		return sdk.Result{}, errors.New("give a message, a status or component statuses")
	}
	var cur incident
	if _, err := c.api.Do(ctx, http.MethodGet, pagePath(pg)+"/incidents/"+url.PathEscape(id), nil, nil, &cur); err != nil {
		return sdk.Result{}, friendly(err, "incident "+id)
	}
	if cur.ID != id {
		return sdk.Result{}, errors.New("Instatus answered with another incident")
	}
	cs, err := c.components(ctx, pg)
	if err != nil {
		return sdk.Result{}, err
	}
	keep := []string{}
	for _, x := range cur.Components {
		keep = append(keep, x.ID)
	}
	ids, sts, lines, err := statuses(cs, keep, want)
	if err != nil {
		return sdk.Result{}, err
	}
	status := p.Status
	if status == "" {
		status = cur.Status
	}
	if status == cur.Status && msg == "" && len(lines) == 0 {
		return sdk.JSON(map[string]any{"id": cur.ID, "name": clip(cur.Name, 255), "status": cur.Status, "note": "nothing to change"})
	}
	if msg == "" {
		return sdk.Result{}, errors.New("Instatus posts every update with a public message: add one")
	}
	if call.DryRun {
		after := map[string]any{"status": status, "message": msg, "notify": p.Notify}
		if len(lines) > 0 {
			after["components"] = lines
		}
		return sdk.Result{Plan: &sdk.Plan{
			Summary: fmt.Sprintf("Post an update on the incident %q publicly on %s; %s", clip(cur.Name, 100), c.pageInfo(ctx, pg), notifyNote(p.Notify)),
			Changes: []sdk.Change{{Target: "incident " + cur.ID, Op: "update", Before: mustJSON(map[string]string{"status": cur.Status}), After: mustJSON(after)}}}}, nil
	}
	body := map[string]any{"message": msg, "status": status, "components": ids, "statuses": sts, "notify": p.Notify,
		"started": c.now().UTC().Format(time.RFC3339)}
	if _, err := c.api.Do(ctx, http.MethodPost, pagePath(pg)+"/incidents/"+url.PathEscape(id)+"/incident-updates", nil, body, nil); err != nil {
		return sdk.Result{}, friendly(err, "incident "+id)
	}
	return sdk.JSON(map[string]any{"id": cur.ID, "name": clip(cur.Name, 255), "status": status, "message": msg, "notified": p.Notify})
}
