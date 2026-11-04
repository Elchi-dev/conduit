package ocis

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

const space = "1284d238-aa92-42ce-bdc4-0b0000009157$4c510ada-c86b-4815-8820-42cdf82c3d51"

type fakeOCIS struct {
	mu   sync.Mutex
	seen []string
	huge bool
}

const drives = `{"value":[
 {"id":"` + space + `","name":"Alice Hansen","driveType":"personal","driveAlias":"personal/alice","lastModifiedDateTime":"2026-11-01T00:00:00Z",
  "quota":{"remaining":9,"total":10,"used":1,"state":"normal"},"owner":{"user":{"id":"LEAKME","displayName":"LEAKME"}},"root":{"webDavUrl":"x"}},
 {"id":"a$b","name":"Marketing","driveType":"project","quota":{"total":0,"used":5,"state":"normal"},"root":{"deleted":{"state":"trashed"}}}]}`

func (f *fakeOCIS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	u, p, basic := r.BasicAuth()
	if auth != "Bearer oidc-good" && !(basic && u == "alice" && p == "app-good") {
		w.WriteHeader(401)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.EscapedPath()+" "+r.Header.Get("Depth"))
	switch {
	case r.Method == "GET" && r.URL.Path == "/o/graph/v1.0/me":
		io.WriteString(w, `{"id":"x","displayName":"Alice","mail":"LEAKME@example.com"}`)
	case r.Method == "GET" && (r.URL.Path == "/o/graph/v1.0/me/drives" || r.URL.Path == "/o/graph/v1.0/drives"):
		io.WriteString(w, drives)
	case r.Method == "GET" && r.URL.Path == "/o/graph/v1.0/drives/a$b":
		io.WriteString(w, `{"id":"a$b","driveType":"project","quota":{"total":100,"used":50,"remaining":50,"state":"nearing"}}`)
	case r.Method == "PROPFIND" && r.URL.EscapedPath() == "/o/dav/spaces/"+space+"/My%20Docs/":
		if r.Header.Get("Depth") != "1" || !strings.Contains(string(body), "propfind") {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(207)
		if f.huge {
			io.WriteString(w, `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">`+strings.Repeat("<d:response><d:href>/x</d:href></d:response>", 2000)+`</d:multistatus>`)
			return
		}
		io.WriteString(w, `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
 <d:response><d:href>/o/dav/spaces/`+space+`/My%20Docs/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><oc:size>5</oc:size></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
 <d:response><d:href>/o/dav/spaces/`+space+`/My%20Docs/Old/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><oc:size>0</oc:size><d:getlastmodified>Sun, 01 Nov 2026 10:00:00 GMT</d:getlastmodified></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
 <d:response><d:href>/o/dav/spaces/`+space+`/My%20Docs/a%20b.pdf</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>5</d:getcontentlength><d:getcontenttype>application/pdf</d:getcontenttype><oc:fileid>fid1</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  <d:propstat><d:prop><oc:size/></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat></d:response>
</d:multistatus>`)
	case r.Method == "PROPFIND" && r.URL.EscapedPath() == "/o/dav/spaces/a$b%21c/":
		// A share space: oCIS escapes its "$" and "!" in hrefs.
		w.WriteHeader(207)
		io.WriteString(w, `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">
 <d:response><d:href>/o/dav/spaces/a%24b%21c/</d:href></d:response>
 <d:response><d:href>/o/dav/spaces/a%24b%21c/x.txt</d:href></d:response>
 <d:response><d:href>https://other.example/o/dav/spaces/a%24b%21c/LEAKME.txt</d:href></d:response>
 <d:response><d:href>/o/dav/spaces/a%24b%21cd/LEAKME2.txt</d:href></d:response>
</d:multistatus>`)
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T, cfg Config) (*Module, *fakeOCIS) {
	f := &fakeOCIS{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	cfg.URL = srv.URL + "/o"
	raw, _ := json.Marshal(cfg)
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://oidc": "oidc-good", "secret://app": "app-good", "secret://bad": "bad-LEAKME"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "o", Action: action, Input: json.RawMessage(in)})
}

func TestOCIS(t *testing.T) {
	for _, cfg := range []Config{{Token: "secret://oidc"}, {User: "alice", Token: "secret://app"}} {
		m, f := setup(t, cfg)
		if h := m.Health(context.Background(), "o"); h.Status != "ok" || h.Message != "signed in as Alice; 2 spaces" {
			t.Fatalf("%+v", h)
		}
		for _, c := range []struct{ action, in, want string }{
			{"drives", `{}`, `"percent":10`},
			{"drives", `{"type":"project"}`, `"disabled":true`},
			{"drives", `{"all":true}`, `"alias":"personal/alice"`},
			{"quota", `{}`, `"remainingBytes":9`},
			{"quota", `{"drive":"a$b"}`, `"state":"nearing"`},
			{"list", `{"drive":"` + space + `","path":"/My Docs"}`, `"path":"/My Docs/a b.pdf"`},
			{"list", `{"drive":"` + space + `","path":"/My Docs/"}`, `"modified":"2026-11-01T10:00:00Z"`},
		} {
			r, err := invoke(m, c.action, c.in)
			out := string(r.Output)
			if err != nil || !strings.Contains(out, c.want) || strings.Contains(out, "LEAKME") {
				t.Fatalf("%s %s: %s %v", c.action, c.in, out, err)
			}
		}
		r, _ := invoke(m, "list", `{"drive":"`+space+`","path":"/My Docs","limit":1}`)
		var out struct {
			Entries []map[string]any `json:"entries"`
			More    bool             `json:"more"`
		}
		json.Unmarshal(r.Output, &out)
		if len(out.Entries) != 1 || !out.More || out.Entries[0]["type"] != "folder" {
			t.Fatalf("%s", r.Output)
		}
		if out.Entries[0]["path"] != "/My Docs/Old" {
			t.Fatalf("listed the folder itself: %s", r.Output)
		}
		f.huge = true
		old := maxPropfind
		maxPropfind = 1 << 10
		if _, err := invoke(m, "list", `{"drive":"`+space+`","path":"/My Docs"}`); err == nil || !strings.Contains(err.Error(), "larger") {
			t.Fatal(err)
		}
		maxPropfind = old
		f.huge = false
		r, err := invoke(m, "list", `{"drive":"a$b!c"}`)
		if err != nil || !strings.Contains(string(r.Output), `"path":"/x.txt"`) || strings.Contains(string(r.Output), "LEAKME") {
			t.Fatalf("share space: %s %v", r.Output, err)
		}
	}
}

func TestOCISValidation(t *testing.T) {
	m, f := setup(t, Config{Token: "secret://oidc"})
	for _, c := range []struct{ action, in string }{
		{"list", `{}`},
		{"list", `{"drive":"../x"}`},
		{"list", `{"drive":"a/b"}`},
		{"list", `{"drive":"a$b","path":"/x/../.."}`},
		{"list", `{"drive":"a$b","path":"x"}`},
		{"quota", `{"drive":"a?b"}`},
		{"drives", `{"type":"x y"}`},
	} {
		if _, err := invoke(m, c.action, c.in); err == nil {
			t.Fatalf("accepted %s %s", c.action, c.in)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("invalid input reached the server: %v", f.seen)
	}
	for _, c := range []Config{{URL: "https://o.example.com", Token: "plain"}, {URL: "o.example.com", Token: "secret://x"},
		{URL: "https://u:p@o.example.com", Token: "secret://x"}, {URL: "https://o.example.com/?a", Token: "secret://x"}, {URL: "https://o.example.com", User: "a b", Token: "secret://x"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad, _ := setup(t, Config{Token: "secret://bad"})
	if h := bad.Health(context.Background(), "o"); h.Status != "down" || !strings.HasPrefix(h.Message, "oCIS refused the token") || strings.Contains(h.Message, "LEAKME") {
		t.Fatalf("%+v", h)
	}
}

func TestOCISRefusesCrossHostRedirect(t *testing.T) {
	var leaked string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	m := New()
	raw, _ := json.Marshal(Config{URL: srv.URL, Token: "secret://t"})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://t": "oidc-good"}), "o", raw); err != nil {
		t.Fatal(err)
	}
	if h := m.Health(context.Background(), "o"); h.Status != "down" || leaked != "" {
		t.Fatalf("followed the redirect: %+v %q", h, leaked)
	}
	if _, err := invoke(m, "list", `{"drive":"a$b"}`); err == nil || leaked != "" {
		t.Fatalf("PROPFIND followed the redirect: %v %q", err, leaked)
	}
}
