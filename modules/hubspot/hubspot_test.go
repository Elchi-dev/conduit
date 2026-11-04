package hubspot

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const goodToken = "pat-xx9-11111111-22223333-4444-555555555555"

type fakeHubSpot struct {
	mu       sync.Mutex
	seen     []string
	stage    string
	notes    map[string]string
	lastNote map[string]any
}

func (f *fakeHubSpot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+goodToken {
		w.WriteHeader(401)
		io.WriteString(w, `{"status":"error","message":"Authentication credentials not found.","category":"INVALID_AUTHENTICATION"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	enc := json.NewEncoder(w)
	switch r.Method + " " + r.URL.Path {
	case "GET /account-info/v3/details":
		io.WriteString(w, `{"portalId":4242,"accountType":"STANDARD","timeZone":"Europe/Berlin","companyCurrency":"EUR"}`)
	case "GET /crm/v3/objects/contacts", "POST /crm/v3/objects/contacts/search":
		io.WriteString(w, `{"total":1,"results":[{"id":"51","properties":{"firstname":"Jane","lastname":"Doe","email":"jane@example.org","phone":"+4915112345678","company":"Acme","lifecyclestage":"customer"},"updatedAt":"2026-11-01T00:00:00Z"}],"paging":{"next":{"after":"52"}}}`)
	case "GET /crm/v3/objects/companies":
		io.WriteString(w, `{"results":[{"id":"7","properties":{"name":"Acme","domain":"acme.example","industry":"RETAIL","city":"Berlin","country":"Germany","numberofemployees":"40"}}]}`)
	case "GET /crm/v3/objects/deals", "POST /crm/v3/objects/deals/search":
		enc.Encode(map[string]any{"results": []any{map[string]any{"id": "900", "properties": map[string]string{"dealname": "Acme renewal", "amount": "12000", "deal_currency_code": "EUR", "pipeline": "default", "dealstage": f.stage, "hubspot_owner_id": "77"}}}})
	case "GET /crm/v3/objects/tickets":
		io.WriteString(w, `{"results":[{"id":"30","properties":{"subject":"Login broken","hs_pipeline":"0","hs_pipeline_stage":"1","hs_ticket_priority":"HIGH","content":"LEAKME customer text"}}]}`)
	case "GET /crm/v3/pipelines/deals":
		io.WriteString(w, `{"results":[{"id":"default","label":"Sales","stages":[{"id":"appointmentscheduled","label":"Appointment scheduled","metadata":{"isClosed":"false"}},{"id":"contractsent","label":"Contract sent","metadata":{"isClosed":"false"}},{"id":"closedwon","label":"Closed won","metadata":{"isClosed":"true"}}]}]}`)
	case "GET /crm/v3/pipelines/tickets":
		io.WriteString(w, `{"results":[{"id":"0","label":"Support","stages":[{"id":"1","label":"New","metadata":{"isClosed":"false"}}]}]}`)
	case "GET /crm/v3/objects/deals/900":
		enc.Encode(map[string]any{"id": "900", "properties": map[string]string{"dealname": "Acme renewal", "pipeline": "default", "dealstage": f.stage}})
	case "PATCH /crm/v3/objects/deals/900":
		var b struct {
			Properties map[string]string `json:"properties"`
		}
		json.Unmarshal(body, &b)
		f.stage = b.Properties["dealstage"]
		io.WriteString(w, `{"id":"900"}`)
	case "GET /crm/v3/objects/contacts/51":
		io.WriteString(w, `{"id":"51","properties":{}}`)
	case "GET /crm/v4/objects/contacts/51/associations/notes":
		ids := []any{}
		for id := range f.notes {
			ids = append(ids, map[string]any{"toObjectId": json.Number(id)})
		}
		enc.Encode(map[string]any{"results": ids})
	case "POST /crm/v3/objects/notes/batch/read":
		rs := []any{}
		for id, b := range f.notes {
			rs = append(rs, map[string]any{"id": id, "properties": map[string]string{"hs_note_body": b, "hs_timestamp": "2026-11-0" + id[len(id)-1:] + "T00:00:00Z"}})
		}
		enc.Encode(map[string]any{"results": rs})
	case "POST /crm/v3/objects/notes":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.lastNote = b
		f.notes["503"] = b["properties"].(map[string]any)["hs_note_body"].(string)
		io.WriteString(w, `{"id":"503","createdAt":"2026-11-04T12:00:00Z"}`)
	case "GET /crm/v3/objects/notes/503", "GET /crm/v3/objects/notes/501":
		id := r.URL.Path[len(r.URL.Path)-3:]
		if _, ok := f.notes[id]; !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"status":"error","message":"Object not found"}`)
			return
		}
		enc.Encode(map[string]any{"id": id, "properties": map[string]string{"hs_timestamp": "2026-11-04T12:00:00Z", "hs_note_body": "LEAKME"},
			"associations": map[string]any{"contacts": map[string]any{"results": []any{map[string]string{"id": "51", "type": "note_to_contact"}}}}})
	case "DELETE /crm/v3/objects/notes/503", "DELETE /crm/v3/objects/notes/501":
		delete(f.notes, r.URL.Path[len(r.URL.Path)-3:])
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"status":"error","message":"resource not found"}`)
	}
}

var secrets = map[string]string{"secret://hs": goodToken, "secret://bad": "pat-xx9-99999999-22223333-4444-555555555555", "secret://junk": "hunter2"}

func setup(t *testing.T, tok string) (*Module, *fakeHubSpot) {
	t.Helper()
	f := &fakeHubSpot{stage: "appointmentscheduled", notes: map[string]string{"501": "<p>Called &amp; agreed</p>"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	m.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) }
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(secrets), "h", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "h", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestHubSpotReads(t *testing.T) {
	m, f := setup(t, "secret://hs")
	if h := m.Health(context.Background(), "h"); h.Status != "ok" || h.Message != "connected to account 4242 (standard)" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"contacts", `{}`, `"email":"jane@example.org"`},
		{"contacts", `{"search":"jane"}`, `"after":"52"`},
		{"companies", `{}`, `"domain":"acme.example"`},
		{"deals", `{}`, `"stage":"Appointment scheduled"`},
		{"deals", `{"search":"acme"}`, `"pipeline":"Sales"`},
		{"tickets", `{}`, `"stage":"New"`},
		{"notes", `{"type":"contact","id":"51"}`, `"text":"Called \u0026 agreed"`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		out := string(r.Output)
		if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
			t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
		}
		if c.action != "contacts" && c.action != "notes" && (strings.Contains(out, "jane") || strings.Contains(out, "+49")) {
			t.Fatalf("%s returned personal data: %s", c.action, out)
		}
	}
	if !strings.Contains(strings.Join(f.seen, "\n"), `"query":"jane"`) {
		t.Fatal(f.seen)
	}
	for _, a := range m.Manifest().Actions {
		want := a.Name == "contacts" || a.Name == "notes" || a.Name == "add_note"
		if a.Sensitive != want {
			t.Fatalf("%s: sensitive %v", a.Name, a.Sensitive)
		}
		if strings.HasPrefix(a.Name, "delete") && a.Risk != sdk.RiskDestructive {
			t.Fatalf("%s is %s", a.Name, a.Risk)
		}
	}
}

func TestHubSpotNotesAndDeals(t *testing.T) {
	m, f := setup(t, "secret://hs")
	r, err := invoke(m, "add_note", `{"type":"contact","id":51,"text":"Prefers <email>"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Add a note of 15 characters to contact 51" || len(f.notes) != 1 {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "add_note", `{"type":"contact","id":"51","text":"Prefers <email>"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_note" || string(r.Undo.Input) != `{"note":"503"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if f.notes["503"] != "Prefers &lt;email&gt;" {
		t.Fatal(f.notes)
	}
	as := f.lastNote["associations"].([]any)[0].(map[string]any)["types"].([]any)[0].(map[string]any)
	if as["associationTypeId"] != float64(202) || f.lastNote["properties"].(map[string]any)["hs_timestamp"] != "2026-11-04T12:00:00Z" {
		t.Fatal(f.lastNote)
	}
	r, err = invoke(m, "delete_note", `{"note":"503"}`, true)
	plan, _ := json.Marshal(r.Plan)
	if err != nil || !strings.Contains(string(plan), "contact 51") || strings.Contains(string(plan), "LEAKME") || len(f.notes) != 2 {
		t.Fatalf("%s %v", plan, err)
	}
	if _, err := invoke(m, "delete_note", `{"note":"503"}`, false); err != nil || len(f.notes) != 1 {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_note", `{"note":"503"}`, false); err == nil || !strings.Contains(err.Error(), "no note 503") {
		t.Fatal(err)
	}

	r, err = invoke(m, "set_deal_stage", `{"deal":"900","stage":"contract sent"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Move deal Acme renewal from Appointment scheduled to Contract sent" || f.stage != "appointmentscheduled" {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "set_deal_stage", `{"deal":900,"stage":"contractsent"}`, false)
	if err != nil || f.stage != "contractsent" || r.Undo == nil || string(r.Undo.Input) != `{"deal":"900","stage":"appointmentscheduled"}` {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := invoke(m, "set_deal_stage", `{"deal":"900","stage":"Contract sent"}`, false); err != nil || r.Undo != nil || !strings.Contains(string(r.Output), "nothing to change") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "set_deal_stage", `{"deal":"900","stage":"lost forever"}`, false); err == nil || !strings.Contains(err.Error(), "its stages are") {
		t.Fatal(err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.stage != "appointmentscheduled" {
		t.Fatal(err)
	}
}

func TestHubSpotValidation(t *testing.T) {
	m, f := setup(t, "secret://hs")
	for _, c := range []struct{ action, in string }{
		{"contacts", `{"after":"../x"}`},
		{"contacts", `{"search":"a\nb"}`},
		{"deals", `{"search":"` + strings.Repeat("x", 101) + `"}`},
		{"notes", `{"type":"contact","id":"51/../../x"}`},
		{"notes", `{"type":"user","id":"51"}`},
		{"add_note", `{"type":"contact","id":"51","text":"  "}`},
		{"add_note", `{"type":"deal","id":"abc","text":"x"}`},
		{"delete_note", `{"note":"5 03"}`},
		{"delete_note", `{}`},
		{"set_deal_stage", `{"deal":"900","stage":"a/b"}`},
		{"set_deal_stage", `{"deal":"9?x=1","stage":"closedwon"}`},
		{"nope", `{}`},
	} {
		for _, dry := range []bool{false, true} {
			if _, err := invoke(m, c.action, c.in, dry); err == nil {
				t.Fatalf("%s accepted %s", c.action, c.in)
			}
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached HubSpot: %v", f.seen)
	}
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", json.RawMessage(`{"token":"`+goodToken+`"}`)); err == nil {
		t.Fatal("accepted a plain token")
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "h"); h.Status != "down" || h.Message != "HubSpot refused the access token" {
		t.Fatalf("%+v", h)
	}
	junk, fj := setup(t, "secret://junk")
	if _, err := invoke(junk, "deals", `{}`, false); err == nil || len(fj.seen) != 0 || strings.Contains(err.Error(), "hunter2") {
		t.Fatal(err)
	}
}

func TestHubSpotErrorsHidePersonalData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, `{"status":"error","message":"Property values were not valid: jane@example.org, +49 151 1234 5678"}`)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	if err := m.Configure(context.Background(), fakehost.New(secrets), "h", json.RawMessage(`{"token":"secret://hs"}`)); err != nil {
		t.Fatal(err)
	}
	_, err := invoke(m, "companies", `{}`, false)
	if err == nil || strings.Contains(err.Error(), "jane") || strings.Contains(err.Error(), "5678") || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("error: %v", err)
	}
}

func TestHubSpotRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := &Module{Base: srv.URL}
	if err := m.Configure(context.Background(), fakehost.New(secrets), "h", json.RawMessage(`{"token":"secret://hs"}`)); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "h"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}
