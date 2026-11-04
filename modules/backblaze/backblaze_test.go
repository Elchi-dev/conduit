package backblaze

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

const bucketID = "4a48fe8875c6214145260818"

type fakeB2 struct {
	mu     sync.Mutex
	url    string
	tokens int
	token  string
	files  []file // newest first per name
	next   int
	calls  []string
}

func (f *fakeB2) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fail := func(status int, code, msg string) {
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"status":%d,"code":%q,"message":%q}`, status, code, msg)
	}
	if r.URL.Path == "/b2api/v3/b2_authorize_account" {
		if u, p, _ := r.BasicAuth(); u != "0012345abcdef0000000001" || p != "K001key" {
			fail(401, "unauthorized", "bad key")
			return
		}
		f.tokens++
		f.token = fmt.Sprintf("tok%d", f.tokens)
		fmt.Fprintf(w, `{"accountId":"12345abcdef","authorizationToken":%q,"apiInfo":{"storageApi":{"apiUrl":%q,"capabilities":["listBuckets","listFiles","readFiles","deleteFiles","writeFiles"],"bucketId":null}}}`, f.token, f.url)
		return
	}
	if r.Header.Get("Authorization") != f.token {
		fail(401, "expired_auth_token", "Authorization token has expired")
		return
	}
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	op := strings.TrimPrefix(r.URL.Path, "/b2api/v3/")
	f.calls = append(f.calls, op)
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch op {
	case "b2_list_buckets":
		all := []map[string]any{{"bucketId": bucketID, "bucketName": "family-photos", "bucketType": "allPrivate", "lifecycleRules": []any{map[string]any{}}}}
		if n, _ := in["bucketName"].(string); n != "" && n != "family-photos" {
			all = nil
		}
		reply(map[string]any{"buckets": all})
	case "b2_list_file_names", "b2_list_file_versions":
		if in["bucketId"] != bucketID {
			fail(400, "bad_request", "bucket")
			return
		}
		start, _ := in["startFileName"].(string)
		out := []file{}
		seen := map[string]bool{}
		for _, x := range f.files {
			if x.FileName < start {
				continue
			}
			if op == "b2_list_file_names" {
				if seen[x.FileName] {
					continue
				}
				seen[x.FileName] = true
				if x.Action == "hide" {
					continue
				}
			}
			out = append(out, x)
		}
		reply(map[string]any{"files": out, "nextFileName": nil})
	case "b2_get_file_info":
		for _, x := range f.files {
			if x.FileID == in["fileId"] {
				reply(x)
				return
			}
		}
		fail(404, "not_found", "no such file")
	case "b2_hide_file":
		f.next++
		m := file{FileName: in["fileName"].(string), FileID: fmt.Sprintf("4_z_hide_marker_%02d", f.next), Action: "hide", Uploaded: 1_800_000_000_000}
		f.files = append([]file{m}, f.files...)
		f.sort()
		reply(m)
	case "b2_delete_file_version":
		for i, x := range f.files {
			if x.FileID == in["fileId"] && x.FileName == in["fileName"] {
				f.files = append(f.files[:i], f.files[i+1:]...)
				reply(map[string]any{"fileId": x.FileID, "fileName": x.FileName})
				return
			}
		}
		fail(400, "file_not_present", "no such version")
	default:
		fail(404, "not_found", op)
	}
}

func (f *fakeB2) sort() {
	sort.SliceStable(f.files, func(i, j int) bool { return f.files[i].FileName < f.files[j].FileName })
}

func setup(t *testing.T) (*Module, *fakeB2) {
	t.Helper()
	f := &fakeB2{files: []file{
		{FileName: "a.txt", FileID: "4_z_a_version_2", Action: "upload", Size: 100, Uploaded: 1_700_000_000_000},
		{FileName: "a.txt", FileID: "4_z_a_version_1", Action: "upload", Size: 50, Uploaded: 1_690_000_000_000},
		{FileName: "photos/cat.jpg", FileID: "4_z_cat_version_1", Action: "upload", Size: 1000, Uploaded: 1_700_000_000_000},
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.url = srv.URL
	m := New()
	m.HTTP = srv.Client()
	raw, _ := json.Marshal(Config{KeyID: "0012345abcdef0000000001", Key: "secret://b2", API: srv.URL})
	if err := m.Configure(context.Background(), fakehost.New(map[string]string{"secret://b2": "K001key", "secret://bad": "x"}), "b2", raw); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func invoke(m *Module, action, in string, dry bool) (sdk.Result, error) {
	return m.Invoke(context.Background(), sdk.Call{Instance: "b2", Action: action, Input: json.RawMessage(in), DryRun: dry})
}

func TestBackblaze(t *testing.T) {
	m, f := setup(t)
	if h := m.Health(context.Background(), "b2"); h.Status != "ok" || h.Message != "account 12345abcdef" {
		t.Fatalf("%+v", h)
	}
	if r, err := invoke(m, "buckets", `{}`, false); err != nil || !strings.Contains(string(r.Output), `"name":"family-photos"`) || !strings.Contains(string(r.Output), `"lifecycleRules":1`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err := invoke(m, "files", `{"bucket":"family-photos","versions":true}`, false)
	if err != nil || strings.Count(string(r.Output), `"fileId"`) != 3 || !strings.Contains(string(r.Output), `"uploaded":"2023-11-14T22:13:20Z"`) {
		t.Fatalf("%s %v", r.Output, err)
	}
	r, err = invoke(m, "usage", `{}`, false)
	if err != nil || !strings.Contains(string(r.Output), `"files":2`) || !strings.Contains(string(r.Output), `"bytes":1150`) || !strings.Contains(string(r.Output), `"currentBytes":1100`) {
		t.Fatalf("%s %v", r.Output, err)
	}

	// An expired token is renewed once, transparently.
	f.token = "rotated"
	if _, err := invoke(m, "buckets", `{}`, false); err != nil || f.tokens != 2 {
		t.Fatalf("reauth: %v %d", err, f.tokens)
	}

	r, err = invoke(m, "hide_file", `{"bucket":"family-photos","fileName":"photos/cat.jpg"}`, true)
	if err != nil || r.Plan == nil || r.Plan.Summary != "Hide family-photos/photos/cat.jpg (its versions stay)" || len(f.files) != 3 {
		t.Fatalf("plan %+v %v", r.Plan, err)
	}
	r, err = invoke(m, "hide_file", `{"bucket":"family-photos","fileName":"photos/cat.jpg"}`, false)
	if err != nil || r.Undo == nil || r.Undo.Action != "delete_file_version" || len(f.files) != 4 {
		t.Fatalf("%+v %v", r, err)
	}
	if lst, _ := invoke(m, "files", `{"bucket":"family-photos","recursive":true}`, false); strings.Contains(string(lst.Output), "cat.jpg") {
		t.Fatalf("still listed: %s", lst.Output)
	}
	p, err := invoke(m, "delete_file_version", string(r.Undo.Input), true)
	if err != nil || p.Plan == nil || !strings.Contains(p.Plan.Summary, "hide marker") {
		t.Fatalf("undo plan %+v %v", p.Plan, err)
	}
	if _, err := invoke(m, r.Undo.Action, string(r.Undo.Input), false); err != nil || len(f.files) != 3 {
		t.Fatalf("undo: %v %d", err, len(f.files))
	}

	if _, err := invoke(m, "delete_file_version", `{"fileName":"photos/cat.jpg","fileId":"4_z_a_version_1"}`, false); err == nil || !strings.Contains(err.Error(), "belongs to a.txt") {
		t.Fatal(err)
	}
	if _, err := invoke(m, "delete_file_version", `{"fileName":"a.txt","fileId":"4_z_a_version_1"}`, false); err != nil || len(f.files) != 2 {
		t.Fatal(err)
	}
}

func TestBackblazeValidation(t *testing.T) {
	m, f := setup(t)
	for _, in := range []string{
		`{"bucket":"../x"}`, `{"bucket":"ab"}`, `{"bucket":"a b c d e"}`,
	} {
		if _, err := invoke(m, "files", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	for _, in := range []string{
		`{"fileName":"a.txt","fileId":"../../b2_delete_bucket"}`, `{"fileName":"","fileId":"4_z_a_version_1"}`,
		`{"fileName":"a\nb","fileId":"4_z_a_version_1"}`, `{"fileName":"/a.txt","fileId":"4_z_a_version_1"}`,
	} {
		if _, err := invoke(m, "delete_file_version", in, false); err == nil {
			t.Fatalf("accepted %s", in)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("invalid input reached the API: %v", f.calls)
	}
	for _, c := range []Config{{KeyID: "0012345abcdef0000000001", Key: "K001plain"}, {KeyID: "../x", Key: "secret://b2"}, {KeyID: "0012345abcdef0000000001", Key: "secret://b2", API: "ftp://x"}} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), fakehost.New(nil), "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	bad := New()
	bad.HTTP = m.HTTP
	raw, _ := json.Marshal(Config{KeyID: "0012345abcdef0000000001", Key: "secret://bad", API: f.url})
	_ = bad.Configure(context.Background(), fakehost.New(map[string]string{"secret://bad": "x"}), "b2", raw)
	if h := bad.Health(context.Background(), "b2"); h.Status != "down" || !strings.Contains(h.Message, "refused") {
		t.Fatalf("%+v", h)
	}
}
