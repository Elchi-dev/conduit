package immich

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

type fakeImmich struct {
	mu      sync.Mutex
	seen    []string
	started string
}

func (f *fakeImmich) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/server/version" {
		io.WriteString(w, `{"major":1,"minor":132,"patch":3}`)
		return
	}
	key := r.Header.Get("x-api-key")
	if key != "admin" && key != "user" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Invalid API key","error":"Unauthorized","statusCode":401}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.Path+" "+string(body))
	admin := key == "admin"
	if !admin && (strings.HasPrefix(r.URL.Path, "/api/admin/") || r.URL.Path == "/api/server/statistics" || strings.HasPrefix(r.URL.Path, "/api/jobs")) {
		w.WriteHeader(403)
		io.WriteString(w, `{"message":"Forbidden"}`)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/users/me":
		io.WriteString(w, `{"id":"u1","name":"Elchi","isAdmin":`+map[bool]string{true: "true", false: "false"}[admin]+`}`)
	case "GET /api/server/statistics":
		io.WriteString(w, `{"photos":1200,"videos":40,"usage":52000000000,"usageByUser":[{"userId":"u1","userName":"Elchi","photos":1000,"videos":30,"usage":50000000000,"quotaSizeInBytes":null},{"userId":"u2","userName":"Sam","photos":200,"videos":10,"usage":2000000000,"quotaSizeInBytes":10000000000}]}`)
	case "GET /api/server/storage":
		io.WriteString(w, `{"diskSize":"1.8 TiB","diskUse":"400 GiB","diskAvailable":"1.4 TiB","diskUsagePercentage":21.5}`)
	case "GET /api/admin/users":
		io.WriteString(w, `[{"id":"u1","name":"Elchi","email":"e@example.com","isAdmin":true,"status":"active"},{"id":"u2","name":"Sam","email":"s@example.com","isAdmin":false,"status":"active"}]`)
	case "GET /api/jobs":
		io.WriteString(w, `{"thumbnailGeneration":{"jobCounts":{"active":1,"waiting":5,"failed":0},"queueStatus":{"isActive":true,"isPaused":false}},"smartSearch":{"jobCounts":{"failed":2},"queueStatus":{}}}`)
	case "PUT /api/jobs/smartSearch":
		f.started = string(body)
		io.WriteString(w, `{"jobCounts":{"waiting":40},"queueStatus":{"isActive":true}}`)
	case "POST /api/search/metadata":
		io.WriteString(w, `{"assets":{"total":1240,"items":[{"id":"a1","type":"IMAGE","originalFileName":"IMG_0001.HEIC","localDateTime":"2026-11-01T10:00:00.000Z","isFavorite":true,"owner":{"name":"Elchi"},"exifInfo":{"make":"Apple","model":"iPhone 16","city":"Lisbon","country":"Portugal","fileSizeInByte":2500000,"latitude":38.7}}]}}`)
	case "GET /api/albums":
		io.WriteString(w, `[{"id":"al1","albumName":"Holiday","assetCount":88,"shared":true,"owner":{"name":"Elchi"}}]`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

func setup(t *testing.T, ref string) (*Module, *fakeImmich) {
	f := &fakeImmich{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL + "/api/", APIKey: ref})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://admin": "admin", "secret://user": "user", "secret://bad": "x"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "i", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestImmich(t *testing.T) {
	m, f := setup(t, "secret://admin")
	if h := m.Health(context.Background(), "i"); h.Status != "ok" || h.Message != "signed in as Elchi (admin) · Immich v1.132.3" {
		t.Fatalf("%+v", h)
	}
	for action, want := range map[string]string{
		"server":        `"photos":1200`,
		"storage":       `"usedPercent":21.5`,
		"users":         `"admins":1`,
		"jobs":          `"job":"smartSearch"`,
		"recent_assets": `"place":"Lisbon, Portugal"`,
		"albums":        `"name":"Holiday"`,
	} {
		r, err := invoke(m, action, `{}`, false)
		if err != nil || !strings.Contains(string(r.Output), want) {
			t.Fatalf("%s: %s %v", action, r.Output, err)
		}
		if strings.Contains(string(r.Output), "@example.com") || strings.Contains(string(r.Output), "38.7") {
			t.Fatalf("%s leaked email or coordinates: %s", action, r.Output)
		}
	}
	r, _ := invoke(m, "users", `{}`, false)
	if !strings.Contains(string(r.Output), `"quotaGB":10`) || !strings.Contains(string(r.Output), `"total":2`) {
		t.Fatal(string(r.Output))
	}

	r, err := invoke(m, "start_job_force", `{"job":"smartSearch"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Start the smartSearch job for every asset" || f.started != "" {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	if r, err = invoke(m, "start_job", `{"job":"smartSearch"}`, false); err != nil || !strings.Contains(string(r.Output), `"waiting":40`) {
		t.Fatal(err)
	}
	if f.started != `{"command":"start","force":false}` {
		t.Fatal(f.started)
	}
}

func TestImmichNonAdmin(t *testing.T) {
	m, _ := setup(t, "secret://user")
	if r, err := invoke(m, "server", `{}`, false); err != nil || !strings.Contains(string(r.Output), "administrator") || !strings.Contains(string(r.Output), "v1.132.3") {
		t.Fatalf("%s %v", r.Output, err)
	}
	if _, err := invoke(m, "users", `{}`, false); err == nil || !strings.Contains(err.Error(), "administrator") {
		t.Fatal(err)
	}
}

func TestImmichValidation(t *testing.T) {
	m, f := setup(t, "secret://admin")
	for _, job := range []string{"", "../admin/users", "smartSearch/../x", "SMARTSEARCH", "backgroundTask"} {
		in, _ := json.Marshal(map[string]any{"job": job})
		if _, err := invoke(m, "start_job", string(in), false); err == nil {
			t.Fatalf("accepted %q", job)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://photos", APIKey: "plain"}, {URL: "ftp://photos", APIKey: "secret://admin"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, "secret://bad")
	if h := bad.Health(context.Background(), "i"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}

// A redirect to another host must not carry the x-api-key there.
func TestImmichRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("x-api-key") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, APIKey: "secret://k"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://k": "admin"}), "i", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "i"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
}

// force redoes every asset (and wipes faces and people for the face jobs),
// so start_job (write) refuses it; start_job_force is destructive.
func TestImmichForceIsDestructive(t *testing.T) {
	m, f := setup(t, "secret://admin")
	risk := map[string]sdk.Risk{}
	for _, a := range m.Manifest().Actions {
		risk[a.Name] = a.Risk
	}
	if risk["start_job"] != sdk.RiskWrite || risk["start_job_force"] != sdk.RiskDestructive {
		t.Fatalf("%v", risk)
	}
	for _, dry := range []bool{true, false} {
		if _, err := invoke(m, "start_job", `{"job":"facialRecognition","force":true}`, dry); err == nil || !strings.Contains(err.Error(), "start_job_force") {
			t.Fatal(err)
		}
	}
	if f.started != "" {
		t.Fatal(f.started)
	}
	r, err := invoke(m, "start_job_force", `{"job":"faceDetection"}`, true)
	if err != nil || !strings.Contains(r.Plan.Summary, "discarding the existing faces and people") {
		t.Fatalf("%+v %v", r.Plan, err)
	}
}
