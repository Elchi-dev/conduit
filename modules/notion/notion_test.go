package notion

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const (
	pageID = "11111111-1111-1111-1111-111111111111"
	dbID   = "22222222-2222-2222-2222-222222222222"
	dsID   = "33333333-3333-3333-3333-333333333333"
	listID = "44444444-4444-4444-4444-444444444444"
	tblID  = "55555555-5555-5555-5555-555555555555"
	newID  = "66666666-6666-6666-6666-666666666666"
)

type fakeNotion struct {
	mu      sync.Mutex
	seen    []string
	trashed map[string]bool
	created map[string]any
}

func rt(s string, bold bool) string {
	return fmt.Sprintf(`[{"type":"text","plain_text":%q,"href":null,"annotations":{"bold":%v}}]`, s, bold)
}

func (f *fakeNotion) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer ntn_tok" {
		w.WriteHeader(401)
		io.WriteString(w, `{"object":"error","status":401,"code":"unauthorized","message":"API token is invalid."}`)
		return
	}
	if r.Header.Get("Notion-Version") != Version {
		w.WriteHeader(400)
		io.WriteString(w, `{"object":"error","message":"missing version"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	page := func(id, title string) string {
		return fmt.Sprintf(`{"object":"page","id":%q,"url":"https://www.notion.so/x-%s","in_trash":%v,"last_edited_time":"2026-11-01T10:00:00Z","properties":{"Name":{"type":"title","title":%s},"Status":{"type":"status","status":{"name":"Doing"}},"Tags":{"type":"multi_select","multi_select":[{"name":"a"},{"name":"b"}]},"Due":{"type":"date","date":{"start":"2026-11-05","end":null}}}}`,
			id, strings.ReplaceAll(id, "-", ""), f.trashed[id], rt(title, false))
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /users/me":
		io.WriteString(w, `{"object":"user","type":"bot","name":"Conduit","bot":{"workspace_name":"Elchi HQ"}}`)
	case "POST /search":
		var b map[string]any
		json.Unmarshal(body, &b)
		if fl, ok := b["filter"].(map[string]any); ok && fl["value"] == "data_source" {
			io.WriteString(w, `{"results":[{"object":"data_source","id":"`+dsID+`","title":`+rt("Tasks", false)+`,"parent":{"type":"database_id","database_id":"`+dbID+`"}}]}`)
			return
		}
		io.WriteString(w, `{"results":[`+page(pageID, "Plan")+`]}`)
	case "GET /pages/" + pageID:
		io.WriteString(w, page(pageID, "Plan"))
	case "GET /pages/" + newID:
		io.WriteString(w, page(newID, "New row"))
	case "PATCH /pages/" + pageID, "PATCH /pages/" + newID:
		var b struct {
			InTrash bool `json:"in_trash"`
		}
		json.Unmarshal(body, &b)
		f.trashed[strings.TrimPrefix(r.URL.Path, "/pages/")] = b.InTrash
		io.WriteString(w, `{"object":"page"}`)
	case "GET /blocks/" + pageID + "/children":
		if r.URL.Query().Get("start_cursor") == "" {
			io.WriteString(w, `{"results":[
				{"id":"a0000000-0000-0000-0000-000000000001","type":"heading_1","has_children":false,"heading_1":{"rich_text":`+rt("Goals", false)+`}},
				{"id":"a0000000-0000-0000-0000-000000000002","type":"paragraph","has_children":false,"paragraph":{"rich_text":`+rt("Ship it", true)+`}},
				{"id":"`+listID+`","type":"bulleted_list_item","has_children":true,"bulleted_list_item":{"rich_text":`+rt("Parent", false)+`}}
			],"has_more":true,"next_cursor":"c2"}`)
			return
		}
		io.WriteString(w, `{"results":[
			{"id":"a0000000-0000-0000-0000-000000000003","type":"to_do","has_children":false,"to_do":{"rich_text":`+rt("Done thing", false)+`,"checked":true}},
			{"id":"a0000000-0000-0000-0000-000000000004","type":"code","has_children":false,"code":{"rich_text":`+rt("go test ./...", false)+`,"language":"bash"}},
			{"id":"a0000000-0000-0000-0000-000000000005","type":"child_page","has_children":true,"child_page":{"title":"Sub"}},
			{"id":"`+tblID+`","type":"table","has_children":true,"table":{"table_width":2}},
			{"id":"a0000000-0000-0000-0000-000000000006","type":"image","has_children":false,"image":{"type":"file","file":{"url":"https://s3.example/signed?X-Amz-Signature=abc"},"caption":[]}}
		],"has_more":false,"next_cursor":null}`)
	case "GET /blocks/" + listID + "/children":
		io.WriteString(w, `{"results":[{"id":"a0000000-0000-0000-0000-000000000007","type":"bulleted_list_item","has_children":false,"bulleted_list_item":{"rich_text":`+rt("Child", false)+`}}],"has_more":false}`)
	case "GET /blocks/" + tblID + "/children":
		io.WriteString(w, `{"results":[{"id":"r1","type":"table_row","table_row":{"cells":[`+rt("k", false)+`,`+rt("v", false)+`]}},{"id":"r2","type":"table_row","table_row":{"cells":[`+rt("a|b", false)+`,`+rt("2", false)+`]}}],"has_more":false}`)
	case "GET /databases/" + dbID:
		io.WriteString(w, `{"object":"database","id":"`+dbID+`","title":`+rt("Tasks", false)+`,"url":"https://www.notion.so/db","data_sources":[{"id":"`+dsID+`","name":"Tasks"}]}`)
	case "GET /data_sources/" + dsID:
		io.WriteString(w, `{"object":"data_source","id":"`+dsID+`","properties":{"Name":{"id":"title","type":"title"},"Status":{"id":"s","type":"status"},"Tags":{"id":"t","type":"multi_select"},"Due":{"id":"d","type":"date"},"Points":{"id":"p","type":"number"},"Who":{"id":"w","type":"people"}}}`)
	case "POST /data_sources/" + dsID + "/query":
		var b map[string]any
		json.Unmarshal(body, &b)
		if b["start_cursor"] == nil {
			io.WriteString(w, `{"results":[`+page(pageID, "Plan")+`],"has_more":true,"next_cursor":"q2"}`)
			return
		}
		io.WriteString(w, `{"results":[`+page(newID, "Other")+`],"has_more":false,"next_cursor":null}`)
	case "POST /pages":
		var b map[string]any
		json.Unmarshal(body, &b)
		f.created = b
		io.WriteString(w, `{"object":"page","id":"`+newID+`","url":"https://www.notion.so/new"}`)
	case "PATCH /blocks/" + pageID + "/children":
		io.WriteString(w, `{"results":[{"id":"b0000000-0000-0000-0000-000000000001"},{"id":"b0000000-0000-0000-0000-000000000002"}]}`)
	case "GET /blocks/a0000000-0000-0000-0000-000000000005":
		io.WriteString(w, `{"id":"a0000000-0000-0000-0000-000000000005","type":"child_page","child_page":{"title":"Sub"}}`)
	case "GET /blocks/d0000000-0000-0000-0000-000000000001":
		io.WriteString(w, `{"id":"d0000000-0000-0000-0000-000000000001","type":"child_database","child_database":{"title":"Tasks"}}`)
	default:
		if strings.HasPrefix(r.URL.Path, "/blocks/b0000000") {
			if r.Method == "PATCH" {
				var b struct {
					InTrash bool `json:"in_trash"`
				}
				json.Unmarshal(body, &b)
				f.trashed[strings.TrimPrefix(r.URL.Path, "/blocks/")] = b.InTrash
			}
			io.WriteString(w, `{"id":"x","type":"paragraph","paragraph":{"rich_text":`+rt("added", false)+`}}`)
			return
		}
		w.WriteHeader(404)
		io.WriteString(w, `{"object":"error","status":404,"code":"object_not_found","message":"Could not find object."}`)
	}
}

func setup(t *testing.T, tok string) (*Module, *fakeNotion) {
	f := &fakeNotion{trashed: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: tok})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://n": "ntn_tok", "secret://bad": "nope"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestNotionReads(t *testing.T) {
	m, _ := setup(t, "secret://n")
	if h := m.Health(context.Background(), "n"); h.Status != "ok" || h.Message != "integration Conduit in Elchi HQ" {
		t.Fatalf("%+v", h)
	}
	for _, c := range []struct{ action, in, want string }{
		{"search", `{"query":"plan"}`, `"title":"Plan"`},
		{"search", `{"type":"database"}`, `"dataSource":"` + dsID + `"`},
		{"database", `{"database":"https://www.notion.so/team/Tasks-22222222222222222222222222222222?v=abc"}`, `"Points":"number"`},
		{"query_database", `{"database":"` + dbID + `","filter":{"property":"Status","status":{"equals":"Doing"}}}`, `"count":2`},
		{"query_database", `{"database":"` + dbID + `"}`, `"Tags":["a","b"]`},
	} {
		r, err := invoke(m, c.action, c.in, false)
		if err != nil || !strings.Contains(string(r.Output), c.want) {
			t.Fatalf("%s %s: %s %v", c.action, c.in, r.Output, err)
		}
	}
	r, err := invoke(m, "read_page", `{"page":"11111111111111111111111111111111"}`, false)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Markdown  string
		Truncated bool
		Title     string
	}
	json.Unmarshal(r.Output, &out)
	want := "# Goals\n**Ship it**\n- Parent\n  - Child\n- [x] Done thing\n```bash\ngo test ./...\n```\n[page: Sub] (a0000000-0000-0000-0000-000000000005)\n| k | v |\n| --- | --- |\n| a\\|b | 2 |\n[image: image]"
	if out.Markdown != want || out.Truncated || out.Title != "Plan" {
		t.Fatalf("got\n%s\nwant\n%s", out.Markdown, want)
	}
	if strings.Contains(string(r.Output), "X-Amz-Signature") {
		t.Fatal("returned a signed file link")
	}
	r, _ = invoke(m, "read_page", `{"page":"`+pageID+`","maxChars":10}`, false)
	if !strings.Contains(string(r.Output), `"truncated":true`) {
		t.Fatal(string(r.Output))
	}
	r, _ = invoke(m, "read_page", `{"page":"`+pageID+`","depth":1}`, false)
	if !strings.Contains(string(r.Output), `- Parent\n  …`) {
		t.Fatal(string(r.Output))
	}
	for _, a := range m.Manifest().Actions {
		if a.Name == "read_page" && !a.Sensitive {
			t.Fatal("read_page must be sensitive")
		}
	}
}

func TestNotionWrites(t *testing.T) {
	m, f := setup(t, "secret://n")

	in := `{"database":"` + dbID + `","title":"New row","properties":{"Status":"Todo","Tags":["x"],"Due":"2026-11-10","Points":3},"content":"# Notes\n- one"}`
	r, err := invoke(m, "create_page", in, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != `Create "New row" in Tasks` || f.created != nil {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "create_page", in, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "archive_page" {
		t.Fatalf("%+v %v", r, err)
	}
	got, _ := json.Marshal(f.created)
	for _, want := range []string{`"data_source_id":"` + dsID + `"`, `"Status":{"status":{"name":"Todo"}}`, `"Tags":{"multi_select":[{"name":"x"}]}`, `"Due":{"date":{"start":"2026-11-10"}}`, `"Points":{"number":3}`, `"type":"heading_1"`, `"Name":{"title":[{"text":{"content":"New row"},"type":"text"}]}`} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	r, err = invoke(m, r.Undo.Action, string(r.Undo.Input), false)
	if err != nil || !f.trashed[newID] || r.Undo == nil || r.Undo.Action != "unarchive_page" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.trashed[newID] {
		t.Fatal(err)
	}
	if _, err := invoke(m, "create_page", `{"database":"`+dbID+`","properties":{"Nope":"x"}}`, false); err == nil || !strings.Contains(err.Error(), `no property "Nope"`) {
		t.Fatal(err)
	}
	if _, err := invoke(m, "create_page", `{"database":"`+dbID+`","properties":{"Who":"x"}}`, false); err == nil || !strings.Contains(err.Error(), "can't set") {
		t.Fatal(err)
	}

	r, err = invoke(m, "append_blocks", `{"page":"`+pageID+`","content":"## Update\n- [ ] follow up\nplain line"}`, true)
	if err != nil || r.Plan == nil || len(r.Plan.Changes) != 3 || r.Plan.Summary != `Append 3 blocks to page "Plan"` {
		t.Fatalf("%+v %v", r.Plan, err)
	}
	r, err = invoke(m, "append_blocks", `{"page":"`+pageID+`","content":"## Update\n- [ ] follow up\nplain line"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "trash_blocks" || !strings.Contains(f.seen[len(f.seen)-1], `"to_do"`) {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = invoke(m, "trash_blocks", string(r.Undo.Input), true); err != nil || r.Plan == nil || len(r.Plan.Changes) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = invoke(m, "trash_blocks", `{"blocks":["b0000000-0000-0000-0000-000000000001","b0000000000000000000000000000002"]}`, false)
	if err != nil || !f.trashed["b0000000-0000-0000-0000-000000000002"] || r.Undo.Action != "restore_blocks" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || f.trashed["b0000000-0000-0000-0000-000000000001"] {
		t.Fatal(err)
	}
	if r, err := invoke(m, "archive_page", `{"page":"`+pageID+`"}`, true); err != nil || r.Plan == nil || f.trashed[pageID] {
		t.Fatal(err)
	}
}

func TestNotionValidation(t *testing.T) {
	m, f := setup(t, "secret://n")
	for _, c := range []struct{ action, in string }{
		{"read_page", `{"page":"../users/me"}`},
		{"read_page", `{"page":"https://evil.example/Page-11111111111111111111111111111111"}`},
		{"archive_page", `{"page":"1111"}`},
		{"query_database", `{"database":"` + dbID + `/../x"}`},
		{"query_database", `{"database":"` + dbID + `","filter":[1]}`},
		{"search", `{"type":"user"}`},
		{"append_blocks", `{"page":"` + pageID + `","content":"   "}`},
		{"append_blocks", `{"page":"` + pageID + `","content":"` + strings.Repeat(`x\n`, 101) + `"}`},
		{"trash_blocks", `{"blocks":[]}`},
		{"trash_blocks", `{"blocks":["nope"]}`},
		{"create_page", `{"database":"` + dbID + `"}`},
	} {
		if _, err := invoke(m, c.action, c.in, false); err == nil {
			t.Fatalf("%s accepted %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	raw, _ := json.Marshal(Config{Token: "ntn_plain"})
	if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
		t.Fatal("accepted a plain token")
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "n"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

func TestNotionRefusesCrossHostRedirect(t *testing.T) {
	var hit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	m.Base = srv.URL
	raw, _ := json.Marshal(Config{Token: "secret://n"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://n": "ntn_tok"}), "n", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "n"); h.Status != "down" || hit {
		t.Fatalf("followed the redirect: %+v", h)
	}
}

// A child_page or child_database block is a whole page or database, so
// trash_blocks (write) refuses it and points to archive_page.
func TestNotionTrashBlocksSparesPages(t *testing.T) {
	m, f := setup(t, "secret://n")
	for _, id := range []string{"a0000000-0000-0000-0000-000000000005", "d0000000000000000000000000000001"} {
		for _, dry := range []bool{true, false} {
			in := `{"blocks":["b0000000-0000-0000-0000-000000000001","` + id + `"]}`
			if _, err := invoke(m, "trash_blocks", in, dry); err == nil || !strings.Contains(err.Error(), "archive_page") {
				t.Fatalf("%s: %v", id, err)
			}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.trashed) != 0 {
		t.Fatalf("trashed %v", f.trashed)
	}
}
