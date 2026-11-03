package gitlab

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

func TestGitLab(t *testing.T) {
	var state string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "glpat" {
			w.WriteHeader(401)
			io.WriteString(w, `{"message":"401 Unauthorized"}`)
			return
		}
		switch r.Method + " " + r.URL.EscapedPath() {
		case "GET /api/v4/user":
			io.WriteString(w, `{"username":"kim"}`)
		case "GET /api/v4/merge_requests":
			io.WriteString(w, `[{"iid":4,"title":"Add cache","state":"opened","author":{"username":"lee"},"references":{"full":"infra/web!4"}}]`)
		case "GET /api/v4/projects/infra%2Fweb/pipelines":
			io.WriteString(w, `[{"id":51,"ref":"main","status":"failed","source":"push"}]`)
		case "POST /api/v4/projects/infra%2Fweb/issues":
			io.WriteString(w, `{"iid":9,"title":"Disk","state":"opened"}`)
		case "PUT /api/v4/projects/infra%2Fweb/issues/9":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			state = b["state_event"]
			io.WriteString(w, `{"iid":9,"title":"Disk","state":"closed"}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"404 Not Found"}`)
		}
	}))
	defer srv.Close()
	m := New()
	ctx := context.Background()
	cfg, _ := json.Marshal(Config{Token: "secret://gl", URL: srv.URL})
	if err := m.Configure(ctx, fakehost.New(map[string]string{"secret://gl": "glpat"}), "gl", cfg); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(ctx, "gl"); h.Status != "ok" {
		t.Fatalf("health %+v", h)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "gl", Action: "merge_requests"})
	if err != nil {
		t.Fatal(err)
	}
	var mrs []Item
	json.Unmarshal(r.Output, &mrs)
	if len(mrs) != 1 || mrs[0].Project != "infra/web" {
		t.Fatalf("mrs %+v", mrs)
	}
	r, err = m.Invoke(ctx, sdk.Call{Instance: "gl", Action: "pipelines", Input: json.RawMessage(`{"project":"infra/web"}`)})
	if err != nil {
		t.Fatal(err)
	}
	var ps []Pipeline
	json.Unmarshal(r.Output, &ps)
	if len(ps) != 1 || ps[0].Status != "failed" {
		t.Fatalf("pipelines %+v", ps)
	}
	r, err = m.Invoke(ctx, sdk.Call{Instance: "gl", Action: "create_issue", Input: json.RawMessage(`{"project":"infra/web","title":"Disk"}`)})
	if err != nil || r.Undo == nil {
		t.Fatalf("create %v %+v", err, r)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "gl", Action: r.Undo.Action, Input: r.Undo.Input}); err != nil || state != "close" {
		t.Fatalf("undo %v %s", err, state)
	}
}
