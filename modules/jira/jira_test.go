package jira

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestJiraCloud(t *testing.T) {
	status := "To Do"
	var created map[string]any
	var deleted, comment string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic YUBleGFtcGxlLmNvbTp0b2s=" { // a@example.com:tok
			w.WriteHeader(401)
			io.WriteString(w, `{"errorMessages":["unauthorized"]}`)
			return
		}
		trans := func() string {
			if status == "To Do" {
				return `{"transitions":[{"id":"21","name":"Start","to":{"name":"In Progress"}}]}`
			}
			return `{"transitions":[{"id":"11","name":"Stop","to":{"name":"To Do"}},{"id":"31","name":"Finish","to":{"name":"Done"}}]}`
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /rest/api/3/myself":
			io.WriteString(w, `{"displayName":"Ada"}`)
		case "GET /rest/api/3/search/jql":
			if !strings.Contains(r.URL.Query().Get("jql"), "currentUser") {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"issues":[{"key":"OPS-1","fields":{"summary":"Disk full","status":{"name":"To Do"},"assignee":{"displayName":"Ada"},"issuetype":{"name":"Bug"}}}]}`)
		case "GET /rest/api/3/issue/OPS-1":
			io.WriteString(w, `{"key":"OPS-1","fields":{"summary":"Disk full","status":{"name":"`+status+`"},"description":{"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"Root is at 99%"}]}]}}}`)
		case "POST /rest/api/3/issue":
			json.NewDecoder(r.Body).Decode(&created)
			w.WriteHeader(201)
			io.WriteString(w, `{"id":"100","key":"OPS-2"}`)
		case "DELETE /rest/api/3/issue/OPS-2":
			deleted = "OPS-2"
			w.WriteHeader(204)
		case "POST /rest/api/3/issue/OPS-1/comment":
			w.WriteHeader(201)
			io.WriteString(w, `{"id":"5005"}`)
		case "DELETE /rest/api/3/issue/OPS-1/comment/5005":
			comment = "deleted"
			w.WriteHeader(204)
		case "GET /rest/api/3/issue/OPS-1/transitions":
			io.WriteString(w, trans())
		case "POST /rest/api/3/issue/OPS-1/transitions":
			var b struct{ Transition struct{ ID string } }
			json.NewDecoder(r.Body).Decode(&b)
			switch b.Transition.ID {
			case "21":
				status = "In Progress"
			case "11":
				status = "To Do"
			case "31":
				status = "Done"
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"errorMessages":["Issue does not exist"]}`)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	host := fakehost.New(map[string]string{"secret://jira": "tok"})
	m := New()
	cfg, _ := json.Marshal(Config{Site: srv.URL + "/", Email: "a@example.com", Token: "secret://jira"})
	if err := m.Configure(ctx, host, "j", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "j"); h.Status != "ok" {
		t.Fatalf("health %+v", h)
	}
	inv := func(action, in string) sdk.Result {
		t.Helper()
		r, err := m.Invoke(ctx, sdk.Call{Instance: "j", Action: action, Input: json.RawMessage(in)})
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		return r
	}
	r := inv("search", `{"jql":"assignee = currentUser()"}`)
	if !strings.Contains(string(r.Output), `"assignee":"Ada"`) {
		t.Fatalf("search %s", r.Output)
	}
	r = inv("issue", `{"key":"ops-1"}`)
	if !strings.Contains(string(r.Output), "Root is at 99%") {
		t.Fatalf("issue %s", r.Output)
	}
	r = inv("create", `{"project":"OPS","summary":"Rotate logs","description":"Weekly.\n\nKeep 4."}`)
	desc := created["fields"].(map[string]any)["description"].(map[string]any)
	if desc["type"] != "doc" || len(desc["content"].([]any)) != 2 {
		t.Fatalf("description %v", desc)
	}
	inv(r.Undo.Action, string(r.Undo.Input))
	if deleted != "OPS-2" {
		t.Fatal("undo create")
	}
	r = inv("comment", `{"key":"OPS-1","text":"On it"}`)
	inv(r.Undo.Action, string(r.Undo.Input))
	if comment != "deleted" {
		t.Fatal("undo comment")
	}
	r = inv("transition", `{"key":"OPS-1","to":"in progress"}`)
	if status != "In Progress" || r.Undo == nil {
		t.Fatalf("transition %s %+v", status, r.Undo)
	}
	inv(r.Undo.Action, string(r.Undo.Input))
	if status != "To Do" {
		t.Fatalf("undo transition: %s", status)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "j", Action: "transition", Input: json.RawMessage(`{"key":"OPS-1","to":"Done"}`)}); err == nil || !strings.Contains(err.Error(), "In Progress") {
		t.Fatalf("impossible move: %v", err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "j", Action: "issue", Input: json.RawMessage(`{"key":"../../admin"}`)}); err == nil {
		t.Fatal("bad key accepted")
	}
	if err := m.Configure(ctx, host, "x", json.RawMessage(`{"site":"https://x.atlassian.net"}`)); err == nil {
		t.Fatal("no credentials accepted")
	}
}

func TestJiraDataCenter(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pat" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/rest/api/2/search":
			io.WriteString(w, `{"issues":[]}`)
		case "/rest/api/2/issue/OPS-1/comment":
			json.NewDecoder(r.Body).Decode(&body)
			io.WriteString(w, `{"id":"1"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	cfg, _ := json.Marshal(Config{Site: srv.URL, PAT: "secret://pat"})
	if err := m.Configure(ctx, fakehost.New(map[string]string{"secret://pat": "pat"}), "d", cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: "search", Input: json.RawMessage(`{"jql":"project = OPS"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "d", Action: "comment", Input: json.RawMessage(`{"key":"OPS-1","text":"plain"}`)}); err != nil || body["body"] != "plain" {
		t.Fatalf("v2 comment %v %v", err, body)
	}
}
