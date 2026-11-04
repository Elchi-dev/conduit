// Package hubspot works with a HubSpot account through a private app's
// access token: contacts, companies, deals (with their pipeline stages),
// tickets and the notes on a record; it can add or delete a note and move a
// deal to another stage.
//
// Contacts and notes carry personal data (names, emails, phones, free text
// about people), and so do tickets (a ticket from the inbox takes the
// customer's email subject), so those actions are sensitive; companies and
// deals return business fields only. Error text from HubSpot is scrubbed
// of emails and phone numbers before it's passed on.
package hubspot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one HubSpot account.
type Config struct {
	Token string `json:"token"` // secret:// private app access token
}

const defaultBase = "https://api.hubapi.com"

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.hubapi.com (tests).
	Base string
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// New returns the HubSpot module.
func New() *Module { return &Module{} }

func (m *Module) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

var (
	tokenRe  = regexp.MustCompile(`^pat-[a-z0-9]{2,8}-[0-9A-Fa-f-]{20,64}$`)
	idRe     = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	cursorRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,200}$`)
	stageRe  = regexp.MustCompile(`^[A-Za-z0-9 _.-]{1,100}$`)
	tagRe    = regexp.MustCompile(`<[^>]*>`)
	emailRe  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	phoneRe  = regexp.MustCompile(`\+?[0-9][0-9 ().-]{6,}[0-9]`)
)

// noteTypes are HubSpot's defined association types from a note to a record.
var noteTypes = map[string]int{"contact": 202, "company": 190, "deal": 214, "ticket": 228}

var plural = map[string]string{"contact": "contacts", "company": "companies", "deal": "deals", "ticket": "tickets"}

var singular = map[string]string{"contacts": "contact", "companies": "company", "deals": "deal", "tickets": "ticket"}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	page := `"limit":{"type":"integer","default":20,"minimum":1,"maximum":100},"after":{"type":"string","description":"after of the previous page"}`
	search := `"search":{"type":"string","description":"Words to look for; the most recently changed records when empty"}`
	record := `"type":{"type":"string","enum":["contact","company","deal","ticket"]},"id":{"type":"string","description":"The record's id"}`
	return sdk.Manifest{
		ID: "hubspot", Name: "HubSpot", Version: "0.1.0", Category: "Productivity", Icon: "contacts",
		Description: "HubSpot CRM: contacts, companies, deals and their stages, tickets and notes; add notes and move deals with a preview.",
		Presets:     []string{"team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["token"],"properties":{
			"token":{"type":"string","x-secret":true,"description":"A private app's access token (Settings, Integrations, Private Apps), with only the CRM scopes you need"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "contacts", Title: "Contacts", Description: "Finds contacts by name, email or phone, or lists the latest: name, email, phone, company, lifecycle stage.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + search + `,` + page + `}}`)},
			{Name: "companies", Title: "Companies", Description: "Companies: name, domain, industry, city, country, size and lifecycle stage.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + search + `,` + page + `}}`)},
			{Name: "deals", Title: "Deals", Description: "Deals: name, amount, pipeline and stage (by label), close date and owner id.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{` + search + `,` + page + `}}`)},
			{Name: "tickets", Title: "Tickets", Description: "Support tickets: subject, pipeline and stage, priority, created and changed dates. Not the ticket's content.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","properties":{` + search + `,` + page + `}}`)},
			{Name: "notes", Title: "Notes on a record", Description: "The notes on a contact, company, deal or ticket, newest first, as plain text.", Risk: sdk.RiskRead, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["type","id"],"properties":{` + record + `,"limit":{"type":"integer","default":20,"minimum":1,"maximum":100}}}`)},
			{Name: "add_note", Title: "Add a note", Description: "Adds a note to a contact, company, deal or ticket. Undo deletes it.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true, Sensitive: true,
				Input: sdk.Schema(`{"type":"object","required":["type","id","text"],"properties":{` + record + `,"text":{"type":"string","maxLength":10000}}}`)},
			{Name: "delete_note", Title: "Delete a note", Description: "Deletes a note. The preview shows when it was written and what it's on.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["note"],"properties":{"note":{"type":"string","description":"Note id (see notes)"}}}`)},
			{Name: "set_deal_stage", Title: "Move a deal", Description: "Moves a deal to another stage of its pipeline (by stage id or label). Undo moves it back.", Risk: sdk.RiskWrite, DryRun: true, Reversible: true,
				Input: sdk.Schema(`{"type":"object","required":["deal","stage"],"properties":{"deal":{"type":"string","description":"Deal id (see deals)"},"stage":{"type":"string","description":"Stage id or label, like closedwon or Contract sent"}}}`)},
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
		return errors.New("store the access token in the vault and enter its secret:// reference")
	}
	base := defaultBase
	if m.Base != "" {
		base = strings.TrimRight(m.Base, "/")
	}
	hc := m.HTTP
	if hc == nil {
		hc = sdk.HTTPClient(h, 30*time.Second)
	}
	ref := c.Token
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		t = strings.TrimSpace(t)
		if !tokenRe.MatchString(t) {
			return errors.New("the stored token doesn't look like a HubSpot private app token (pat-…)")
		}
		r.Header.Set("Authorization", "Bearer "+t)
		return nil
	})
	api.HTTP = rest.SameHostOnly(hc)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// scrub keeps credentials, emails and phone numbers out of error text.
func scrub(s string) string {
	s = rest.Redact(s)
	s = emailRe.ReplaceAllString(s, "[email]")
	s = phoneRe.ReplaceAllString(s, "[number]")
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
		return errors.New("HubSpot refused the access token")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("the private app is missing a scope for this in HubSpot")
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("HubSpot is limiting requests; try again in a moment")
	case errors.As(err, &e):
		return &rest.Error{Status: e.Status, Message: "HubSpot: " + scrub(e.Message)}
	}
	return err
}

func (c *conn) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.api.Do(ctx, method, path, q, body, out)
	return friendly(err)
}

type object struct {
	ID         string            `json:"id"`
	Properties map[string]string `json:"properties"`
	CreatedAt  string            `json:"createdAt"`
	UpdatedAt  string            `json:"updatedAt"`
}

type list struct {
	Total   *int     `json:"total"`
	Results []object `json:"results"`
	Paging  *struct {
		Next *struct {
			After string `json:"after"`
		} `json:"next"`
	} `json:"paging"`
}

func (l list) after() string {
	if l.Paging != nil && l.Paging.Next != nil {
		return l.Paging.Next.After
	}
	return ""
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var a struct {
		PortalID        int64  `json:"portalId"`
		AccountType     string `json:"accountType"`
		CompanyCurrency string `json:"companyCurrency"`
	}
	if err := c.do(ctx, http.MethodGet, "/account-info/v3/details", nil, nil, &a); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := fmt.Sprintf("connected to account %d", a.PortalID)
	if a.AccountType != "" {
		msg += " (" + strings.ToLower(a.AccountType) + ")"
	}
	return sdk.Health{Status: "ok", Message: msg}
}

type input struct {
	Search string `json:"search"`
	Limit  int    `json:"limit"`
	After  string `json:"after"`
	Type   string `json:"type"`
	ID     ident  `json:"id"`
	Text   string `json:"text"`
	Note   ident  `json:"note"`
	Deal   ident  `json:"deal"`
	Stage  string `json:"stage"`
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

var properties = map[string][]string{
	"contacts":  {"firstname", "lastname", "email", "phone", "company", "jobtitle", "lifecyclestage", "lastmodifieddate"},
	"companies": {"name", "domain", "industry", "city", "country", "numberofemployees", "lifecyclestage", "hs_lastmodifieddate"},
	"deals":     {"dealname", "amount", "deal_currency_code", "pipeline", "dealstage", "closedate", "hubspot_owner_id", "hs_lastmodifieddate"},
	"tickets":   {"subject", "hs_pipeline", "hs_pipeline_stage", "hs_ticket_priority", "hs_ticket_category", "createdate", "hs_lastmodifieddate"},
}

func modifiedProp(kind string) string {
	if kind == "contacts" {
		return "lastmodifieddate"
	}
	return "hs_lastmodifieddate"
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
	case "contacts", "companies", "deals", "tickets":
		return c.records(ctx, call.Action, p)
	case "notes":
		return c.notes(ctx, p)
	case "add_note":
		return m.addNote(ctx, c, call, p)
	case "delete_note":
		return c.deleteNote(ctx, call, p)
	case "set_deal_stage":
		return c.setDealStage(ctx, call, p)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func limit(n int) int {
	if n <= 0 || n > 100 {
		return 20
	}
	return n
}

func (c *conn) records(ctx context.Context, kind string, p input) (sdk.Result, error) {
	search := strings.TrimSpace(p.Search)
	if utf8.RuneCountInString(search) > 100 || strings.ContainsAny(search, "\x00\r\n") {
		return sdk.Result{}, errors.New("search is a few words, at most 100 characters")
	}
	if p.After != "" && !cursorRe.MatchString(p.After) {
		return sdk.Result{}, errors.New("after is the value from the previous page")
	}
	n := limit(p.Limit)
	var l list
	if search != "" {
		body := map[string]any{"query": search, "limit": n, "properties": properties[kind],
			"sorts": []map[string]string{{"propertyName": modifiedProp(kind), "direction": "DESCENDING"}}}
		if p.After != "" {
			body["after"] = p.After
		}
		if err := c.do(ctx, http.MethodPost, "/crm/v3/objects/"+kind+"/search", nil, body, &l); err != nil {
			return sdk.Result{}, err
		}
	} else {
		q := url.Values{"limit": {strconv.Itoa(n)}, "properties": {strings.Join(properties[kind], ",")}, "archived": {"false"}}
		if p.After != "" {
			q.Set("after", p.After)
		}
		if err := c.do(ctx, http.MethodGet, "/crm/v3/objects/"+kind, q, nil, &l); err != nil {
			return sdk.Result{}, err
		}
	}
	var stages map[string]stageInfo
	var pipes map[string]string
	if kind == "deals" || kind == "tickets" {
		stages, pipes = c.pipelines(ctx, kind)
	}
	out := []map[string]any{}
	for _, o := range l.Results {
		out = append(out, recordOut(kind, o, stages, pipes))
	}
	res := map[string]any{"items": out}
	if a := l.after(); a != "" {
		res["after"] = a
	}
	if l.Total != nil {
		res["total"] = *l.Total
	}
	return sdk.JSON(res)
}

type stageInfo struct {
	Label    string
	Pipeline string
	Closed   bool
}

type pipeline struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Stages []struct {
		ID       string `json:"id"`
		Label    string `json:"label"`
		Metadata struct {
			IsClosed    string `json:"isClosed"`
			Probability string `json:"probability"`
		} `json:"metadata"`
	} `json:"stages"`
}

func (c *conn) pipelineList(ctx context.Context, kind string) ([]pipeline, error) {
	var r struct {
		Results []pipeline `json:"results"`
	}
	err := c.do(ctx, http.MethodGet, "/crm/v3/pipelines/"+kind, nil, nil, &r)
	return r.Results, err
}

// pipelines maps stage and pipeline ids to labels (best effort).
func (c *conn) pipelines(ctx context.Context, kind string) (map[string]stageInfo, map[string]string) {
	stages, pipes := map[string]stageInfo{}, map[string]string{}
	ps, err := c.pipelineList(ctx, kind)
	if err != nil {
		return stages, pipes
	}
	for _, p := range ps {
		pipes[p.ID] = p.Label
		for _, s := range p.Stages {
			stages[s.ID] = stageInfo{Label: s.Label, Pipeline: p.ID, Closed: s.Metadata.IsClosed == "true"}
		}
	}
	return stages, pipes
}

func labelOr(m map[string]string, id string) string {
	if l := m[id]; l != "" {
		return l
	}
	return id
}

func recordOut(kind string, o object, stages map[string]stageInfo, pipes map[string]string) map[string]any {
	pr := o.Properties
	out := map[string]any{"id": o.ID, "updated": o.UpdatedAt}
	switch kind {
	case "contacts":
		out["name"] = strings.TrimSpace(pr["firstname"] + " " + pr["lastname"])
		out["email"], out["phone"], out["company"], out["jobTitle"], out["lifecycleStage"] = pr["email"], pr["phone"], pr["company"], pr["jobtitle"], pr["lifecyclestage"]
	case "companies":
		out["name"], out["domain"], out["industry"], out["city"], out["country"], out["lifecycleStage"] = pr["name"], pr["domain"], pr["industry"], pr["city"], pr["country"], pr["lifecyclestage"]
		if n := pr["numberofemployees"]; n != "" {
			out["employees"] = n
		}
	case "deals":
		out["name"], out["amount"], out["currency"], out["closeDate"] = pr["dealname"], pr["amount"], pr["deal_currency_code"], pr["closedate"]
		out["pipeline"] = labelOr(pipes, pr["pipeline"])
		out["stageId"] = pr["dealstage"]
		if s, ok := stages[pr["dealstage"]]; ok {
			out["stage"] = s.Label
			out["closed"] = s.Closed
		}
		if pr["hubspot_owner_id"] != "" {
			out["owner"] = pr["hubspot_owner_id"]
		}
	case "tickets":
		out["subject"], out["priority"], out["category"], out["created"] = pr["subject"], pr["hs_ticket_priority"], pr["hs_ticket_category"], pr["createdate"]
		out["pipeline"] = labelOr(pipes, pr["hs_pipeline"])
		out["stageId"] = pr["hs_pipeline_stage"]
		if s, ok := stages[pr["hs_pipeline_stage"]]; ok {
			out["stage"] = s.Label
			out["closed"] = s.Closed
		}
	}
	return out
}

func checkRecord(p input) (string, string, error) {
	if _, ok := noteTypes[p.Type]; !ok {
		return "", "", errors.New("the type is contact, company, deal or ticket")
	}
	if !idRe.MatchString(string(p.ID)) {
		return "", "", fmt.Errorf("the id is the %s's numeric id", p.Type)
	}
	return p.Type, string(p.ID), nil
}

// text turns a note's HTML body into plain text.
func text(body string) string {
	body = strings.NewReplacer("<br>", "\n", "<br/>", "\n", "<br />", "\n", "</p>", "\n").Replace(body)
	return strings.TrimSpace(html.UnescapeString(tagRe.ReplaceAllString(body, "")))
}

func (c *conn) notes(ctx context.Context, p input) (sdk.Result, error) {
	kind, id, err := checkRecord(p)
	if err != nil {
		return sdk.Result{}, err
	}
	var assoc struct {
		Results []struct {
			ToObjectID json.Number `json:"toObjectId"`
		} `json:"results"`
	}
	if err := c.do(ctx, http.MethodGet, "/crm/v4/objects/"+plural[kind]+"/"+url.PathEscape(id)+"/associations/notes", url.Values{"limit": {"100"}}, nil, &assoc); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no %s %s", kind, id)
		}
		return sdk.Result{}, err
	}
	out := []map[string]any{}
	if len(assoc.Results) == 0 {
		return sdk.JSON(map[string]any{"items": out})
	}
	inputs := []map[string]string{}
	for _, a := range assoc.Results {
		inputs = append(inputs, map[string]string{"id": a.ToObjectID.String()})
	}
	var l list
	if err := c.do(ctx, http.MethodPost, "/crm/v3/objects/notes/batch/read", nil, map[string]any{"properties": []string{"hs_note_body", "hs_timestamp", "hubspot_owner_id"}, "inputs": inputs}, &l); err != nil {
		return sdk.Result{}, err
	}
	// Newest first.
	rs := l.Results
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j].Properties["hs_timestamp"] > rs[j-1].Properties["hs_timestamp"]; j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
	n := limit(p.Limit)
	for i, o := range rs {
		if i >= n {
			break
		}
		row := map[string]any{"id": o.ID, "time": o.Properties["hs_timestamp"], "text": text(o.Properties["hs_note_body"])}
		if ow := o.Properties["hubspot_owner_id"]; ow != "" {
			row["owner"] = ow
		}
		out = append(out, row)
	}
	return sdk.JSON(map[string]any{"items": out, "total": len(rs)})
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (m *Module) addNote(ctx context.Context, c *conn, call sdk.Call, p input) (sdk.Result, error) {
	kind, id, err := checkRecord(p)
	if err != nil {
		return sdk.Result{}, err
	}
	t := strings.TrimSpace(p.Text)
	if t == "" || utf8.RuneCountInString(t) > 10000 || !utf8.ValidString(t) {
		return sdk.Result{}, errors.New("the note is 1 to 10,000 characters")
	}
	// Check the record exists, so the note can't land nowhere.
	var rec object
	if err := c.do(ctx, http.MethodGet, "/crm/v3/objects/"+plural[kind]+"/"+url.PathEscape(id), nil, nil, &rec); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no %s %s", kind, id)
		}
		return sdk.Result{}, err
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Add a note of %d characters to %s %s", utf8.RuneCountInString(t), kind, id),
			Changes: []sdk.Change{{Target: kind + " " + id, Op: "create", After: mustJSON(map[string]string{"note": t})}}}}, nil
	}
	body := map[string]any{
		"properties": map[string]string{"hs_timestamp": m.now().UTC().Format(time.RFC3339), "hs_note_body": html.EscapeString(t)},
		"associations": []map[string]any{{"to": map[string]string{"id": id},
			"types": []map[string]any{{"associationCategory": "HUBSPOT_DEFINED", "associationTypeId": noteTypes[kind]}}}},
	}
	var n object
	if err := c.do(ctx, http.MethodPost, "/crm/v3/objects/notes", nil, body, &n); err != nil {
		return sdk.Result{}, err
	}
	if !idRe.MatchString(n.ID) {
		return sdk.Result{}, errors.New("HubSpot didn't return the new note's id")
	}
	res, err := sdk.JSON(map[string]any{"note": n.ID, "on": kind + " " + id, "created": n.CreatedAt})
	res.Undo = sdk.UndoWith("delete_note", map[string]string{"note": n.ID}, "Delete note "+n.ID)
	return res, err
}

func (c *conn) deleteNote(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	id := string(p.Note)
	if !idRe.MatchString(id) {
		return sdk.Result{}, errors.New("the note is its numeric id (see notes)")
	}
	var n struct {
		object
		Associations map[string]struct {
			Results []struct {
				ID string `json:"id"`
			} `json:"results"`
		} `json:"associations"`
	}
	q := url.Values{"properties": {"hs_timestamp"}, "associations": {"contacts,companies,deals,tickets"}}
	if err := c.do(ctx, http.MethodGet, "/crm/v3/objects/notes/"+url.PathEscape(id), q, nil, &n); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no note %s (it may be deleted already)", id)
		}
		return sdk.Result{}, err
	}
	on := []string{}
	for _, kind := range []string{"contacts", "companies", "deals", "tickets"} {
		for _, r := range n.Associations[kind].Results {
			on = append(on, singular[kind]+" "+r.ID)
		}
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Delete note %s written %s", id, n.Properties["hs_timestamp"]),
			Changes: []sdk.Change{{Target: "note " + id, Op: "delete", Before: mustJSON(map[string]any{"time": n.Properties["hs_timestamp"], "on": on})}}}}, nil
	}
	if err := c.do(ctx, http.MethodDelete, "/crm/v3/objects/notes/"+url.PathEscape(id), nil, nil, nil); err != nil {
		return sdk.Result{}, err
	}
	return sdk.JSON(map[string]any{"note": id, "deleted": true})
}

func (c *conn) setDealStage(ctx context.Context, call sdk.Call, p input) (sdk.Result, error) {
	id := string(p.Deal)
	if !idRe.MatchString(id) {
		return sdk.Result{}, errors.New("the deal is its numeric id (see deals)")
	}
	want := strings.TrimSpace(p.Stage)
	if !stageRe.MatchString(want) {
		return sdk.Result{}, errors.New("the stage is its id or label, like closedwon or Contract sent")
	}
	var d object
	q := url.Values{"properties": {"dealname,dealstage,pipeline,amount,deal_currency_code"}}
	if err := c.do(ctx, http.MethodGet, "/crm/v3/objects/deals/"+url.PathEscape(id), q, nil, &d); err != nil {
		if rest.IsStatus(err, http.StatusNotFound) {
			return sdk.Result{}, fmt.Errorf("there's no deal %s", id)
		}
		return sdk.Result{}, err
	}
	ps, err := c.pipelineList(ctx, "deals")
	if err != nil {
		return sdk.Result{}, err
	}
	pipeID := d.Properties["pipeline"]
	var pipe *pipeline
	for i := range ps {
		if ps[i].ID == pipeID {
			pipe = &ps[i]
		}
	}
	if pipe == nil {
		return sdk.Result{}, fmt.Errorf("deal %s's pipeline isn't one HubSpot lists", id)
	}
	// A stage id wins over a label: the undo names the old stage by its id,
	// and another stage may be labelled like it. Two stages with the same
	// label (ignoring case) are ambiguous.
	var to, toLabel, fromLabel string
	labels := []string{}
	byLabel := 0
	for _, s := range pipe.Stages {
		labels = append(labels, s.Label)
		if s.ID == d.Properties["dealstage"] {
			fromLabel = s.Label
		}
	}
	for _, s := range pipe.Stages {
		if s.ID == want {
			to, toLabel, byLabel = s.ID, s.Label, 0
			break
		}
		if strings.EqualFold(s.Label, want) {
			if byLabel == 0 {
				to, toLabel = s.ID, s.Label
			}
			byLabel++
		}
	}
	if byLabel > 1 {
		return sdk.Result{}, fmt.Errorf("pipeline %s has %d stages labelled %q; give the stage's id", pipe.Label, byLabel, want)
	}
	if to == "" {
		return sdk.Result{}, fmt.Errorf("%q isn't a stage of pipeline %s; its stages are %s", want, pipe.Label, strings.Join(labels, ", "))
	}
	name := d.Properties["dealname"]
	from := d.Properties["dealstage"]
	if from == to {
		return sdk.JSON(map[string]any{"deal": id, "name": name, "stage": toLabel, "note": "nothing to change"})
	}
	if call.DryRun {
		return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Move deal %s from %s to %s", name, labelOr(map[string]string{from: fromLabel}, from), toLabel),
			Changes: []sdk.Change{{Target: "deal " + id, Op: "update", Before: mustJSON(map[string]string{"stage": fromLabel, "stageId": from}), After: mustJSON(map[string]string{"stage": toLabel, "stageId": to})}}}}, nil
	}
	var after object
	if err := c.do(ctx, http.MethodPatch, "/crm/v3/objects/deals/"+url.PathEscape(id), nil, map[string]any{"properties": map[string]string{"dealstage": to}}, &after); err != nil {
		return sdk.Result{}, err
	}
	res, err := sdk.JSON(map[string]any{"deal": id, "name": name, "stage": toLabel, "stageId": to, "previousStage": fromLabel})
	if from != "" {
		res.Undo = sdk.UndoWith("set_deal_stage", map[string]string{"deal": id, "stage": from}, "Move deal "+name+" back to "+labelOr(map[string]string{from: fromLabel}, from))
	}
	return res, err
}
