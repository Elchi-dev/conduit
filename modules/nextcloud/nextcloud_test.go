package nextcloud

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

func TestNextcloud(t *testing.T) {
	shares := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, pw, _ := r.BasicAuth(); u != "alex" || pw != "app-pw" || r.Header.Get("OCS-APIRequest") != "true" {
			w.WriteHeader(401)
			return
		}
		ok := func(data string) {
			io.WriteString(w, `{"ocs":{"meta":{"status":"ok","statuscode":200},"data":`+data+`}}`)
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /ocs/v2.php/cloud/user":
			ok(`{"displayname":"Alex"}`)
		case "GET /ocs/v2.php/apps/serverinfo/api/v1/info":
			ok(`{"nextcloud":{"system":{"version":"30.0.1","freespace":1000},"storage":{"num_users":3,"num_files":42}},"activeUsers":{"last5minutes":1,"last1hour":2,"last24hours":3}}`)
		case "GET /ocs/v2.php/apps/notifications/api/v2/notifications":
			ok(`[{"notification_id":7,"app":"updatenotification","subject":"Update available","datetime":"2026-11-03T10:00:00+00:00"}]`)
		case "GET /ocs/v2.php/cloud/users/alex":
			ok(`{"quota":{"used":500,"total":1500,"quota":2000,"relative":25}}`)
		case "POST /ocs/v2.php/apps/files_sharing/api/v1/shares":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["shareType"] != 3.0 || b["permissions"] != 1.0 {
				w.WriteHeader(400)
				return
			}
			shares["12"] = true
			ok(`{"id":12,"url":"https://cloud.example.com/s/abc"}`)
		case "DELETE /ocs/v2.php/apps/files_sharing/api/v1/shares/12":
			delete(shares, "12")
			ok(`[]`)
		default:
			io.WriteString(w, `{"ocs":{"meta":{"status":"failure","statuscode":404,"message":"Not found"},"data":[]}}`)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	m := New()
	h := fakehost.New(map[string]string{"secret://nc": "app-pw"})
	cfg, _ := json.Marshal(Config{URL: srv.URL, User: "alex", AppPassword: "secret://nc"})
	if err := m.Configure(ctx, h, "n", cfg); err != nil {
		t.Fatal(err)
	}
	if hl := m.Health(ctx, "n"); hl.Status != "ok" {
		t.Fatalf("health %+v", hl)
	}
	run := func(action, in string) (sdk.Result, error) {
		return m.Invoke(ctx, sdk.Call{Instance: "n", Action: action, Input: json.RawMessage(in)})
	}
	r, err := run("server", "")
	if err != nil || !strings.Contains(string(r.Output), `"version":"30.0.1"`) {
		t.Fatalf("server %s %v", r.Output, err)
	}
	if r, err = run("usage", ""); err != nil || !strings.Contains(string(r.Output), `"percent":25`) {
		t.Fatalf("usage %s %v", r.Output, err)
	}
	if r, err = run("notifications", ""); err != nil || !strings.Contains(string(r.Output), "Update available") {
		t.Fatalf("notifications %s %v", r.Output, err)
	}
	r, err = run("share", `{"path":"Documents/report.pdf","expires":"2026-12-01"}`)
	if err != nil || !shares["12"] || r.Undo == nil {
		t.Fatalf("share %v", err)
	}
	if _, err := run(r.Undo.Action, string(r.Undo.Input)); err != nil || shares["12"] {
		t.Fatalf("unshare %v", err)
	}
	if _, err := run("unshare", `{"id":"12/../../x"}`); err == nil {
		t.Fatal("bad share id accepted")
	}
	if _, err := run("usage", `{"user":"../admin"}`); err == nil {
		t.Fatal("bad user accepted")
	}
	if _, err := run("share", `{"path":"/a/../../etc"}`); err == nil {
		t.Fatal("dot-dot path accepted")
	}
	if _, err := run("missing", ""); err == nil {
		t.Fatal("unknown action")
	}
}
