package s3

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/internal/fakehost"
	"github.com/elchi-dev/conduit/modules/aws"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

var fixed = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

type fakeS3 struct {
	mu      sync.Mutex
	objects map[string]int64 // "bucket/key" -> size
	seen    []string
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	again, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), nil)
	aws.Sign(again, nil, aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "s3cr3t"}, "us-east-1", "s3", fixed)
	if again.Header.Get("Authorization") != r.Header.Get("Authorization") {
		w.WriteHeader(403)
		io.WriteString(w, `<Error><Code>SignatureDoesNotMatch</Code><Message>bad signature</Message></Error>`)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.EscapedPath())
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	switch {
	case r.URL.Path == "/":
		io.WriteString(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>backups</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate></Bucket><Bucket><Name>media</Name><CreationDate>2026-02-01T00:00:00Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>`)
	case len(parts) == 1 && r.Method == http.MethodGet:
		prefix := r.URL.Query().Get("prefix")
		max := 1000
		fmt.Sscan(r.URL.Query().Get("max-keys"), &max)
		start := 0
		fmt.Sscan(r.URL.Query().Get("continuation-token"), &start)
		var keys []string
		for k := range f.objects {
			if strings.HasPrefix(k, parts[0]+"/"+prefix) {
				keys = append(keys, strings.TrimPrefix(k, parts[0]+"/"))
			}
		}
		sortStrings(keys)
		end := start + max
		if end > len(keys) {
			end = len(keys)
		}
		var b strings.Builder
		b.WriteString("<ListBucketResult>")
		for _, k := range keys[start:end] {
			fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>%d</Size><LastModified>2026-11-01T00:00:00Z</LastModified></Contents>", k, f.objects[parts[0]+"/"+k])
		}
		if end < len(keys) {
			fmt.Fprintf(&b, "<IsTruncated>true</IsTruncated><NextContinuationToken>%d</NextContinuationToken>", end)
		}
		b.WriteString("</ListBucketResult>")
		io.WriteString(w, b.String())
	case len(parts) == 2:
		size, ok := f.objects[parts[0]+"/"+parts[1]]
		if !ok {
			w.WriteHeader(404)
			return
		}
		switch r.Method {
		case http.MethodHead:
			w.Header().Set("Content-Length", fmt.Sprint(size))
			w.Header().Set("Content-Type", "application/x-tar")
			w.Header().Set("ETag", `"abc"`)
		case http.MethodDelete:
			delete(f.objects, parts[0]+"/"+parts[1])
			w.WriteHeader(204)
		}
	default:
		w.WriteHeader(400)
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func setup(t *testing.T, secret string) (*Module, *fakeS3) {
	t.Helper()
	f := &fakeS3{objects: map[string]int64{"backups/a.tar": 100, "backups/b c.tar": 50, "backups/old/x.tar": 7}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New()
	m.now = func() time.Time { return fixed }
	h := fakehost.New(map[string]string{"secret://s3": "s3cr3t", "secret://bad": "nope"})
	cfg, _ := json.Marshal(Config{Endpoint: srv.URL, AccessKeyID: "AKIDEXAMPLE", SecretKey: secret})
	if err := m.Configure(context.Background(), h, "s", cfg); err != nil {
		t.Fatal(err)
	}
	return m, f
}

func call(t *testing.T, m *Module, action string, in any, dry bool) (map[string]any, sdk.Result, error) {
	t.Helper()
	raw, _ := json.Marshal(in)
	res, err := m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: action, Input: raw, DryRun: dry})
	var out map[string]any
	if err == nil && res.Output != nil {
		_ = json.Unmarshal(res.Output, &out)
	}
	return out, res, err
}

func TestS3(t *testing.T) {
	m, f := setup(t, "secret://s3")
	if h := m.Health(context.Background(), "s"); h.Status != "ok" || h.Message != "2 buckets" {
		t.Fatalf("health %+v", h)
	}
	res, err := m.Invoke(context.Background(), sdk.Call{Instance: "s", Action: "buckets", Input: json.RawMessage(`{}`)})
	if err != nil || !strings.Contains(string(res.Output), `"media"`) {
		t.Fatalf("buckets %s %v", res.Output, err)
	}
	out, _, err := call(t, m, "objects", map[string]any{"bucket": "backups", "prefix": "old/"}, false)
	if err != nil || len(out["objects"].([]any)) != 1 {
		t.Fatalf("objects %v %v", out, err)
	}
	out, _, err = call(t, m, "info", map[string]any{"bucket": "backups", "key": "b c.tar"}, false)
	if err != nil || out["size"].(float64) != 50 || out["etag"] != "abc" {
		t.Fatalf("info %v %v", out, err)
	}
	out, _, err = call(t, m, "usage", map[string]any{"bucket": "backups"}, false)
	if err != nil || out["objects"].(float64) != 3 || out["bytes"].(float64) != 157 || out["complete"] != true {
		t.Fatalf("usage %v %v", out, err)
	}
	out, _, err = call(t, m, "link", map[string]any{"bucket": "backups", "key": "a.tar", "hours": 2}, false)
	if err != nil || !strings.Contains(out["url"].(string), "X-Amz-Expires=7200") || !strings.Contains(out["url"].(string), "X-Amz-Signature=") {
		t.Fatalf("link %v %v", out, err)
	}
	if _, _, err := call(t, m, "link", map[string]any{"bucket": "backups", "key": "a.tar", "hours": 200}, false); err == nil {
		t.Fatal("link over 7 days accepted")
	}
	_, res, err = call(t, m, "delete", map[string]any{"bucket": "backups", "key": "a.tar"}, true)
	if err != nil || res.Plan == nil || res.Plan.Changes[0].Target != "backups/a.tar" || f.objects["backups/a.tar"] != 100 {
		t.Fatalf("dry run %+v %v", res.Plan, err)
	}
	if _, _, err := call(t, m, "delete", map[string]any{"bucket": "backups", "key": "a.tar"}, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.objects["backups/a.tar"]; ok {
		t.Fatal("not deleted")
	}
	if _, _, err := call(t, m, "delete", map[string]any{"bucket": "backups", "key": "a.tar"}, false); err == nil {
		t.Fatal("deleting a missing object succeeded")
	}
	joined := strings.Join(f.seen, "\n")
	if !strings.Contains(joined, "HEAD /backups/b%20c.tar") {
		t.Fatalf("key not escaped: %s", joined)
	}
}

func TestS3UsagePages(t *testing.T) {
	m, f := setup(t, "secret://s3")
	for i := 0; i < 2500; i++ {
		f.objects[fmt.Sprintf("media/f%04d", i)] = 2
	}
	out, _, err := call(t, m, "usage", map[string]any{"bucket": "media"}, false)
	if err != nil || out["objects"].(float64) != 2500 || out["bytes"].(float64) != 5000 {
		t.Fatalf("usage %v %v", out, err)
	}
}

func TestS3Validation(t *testing.T) {
	m, _ := setup(t, "secret://s3")
	for _, in := range []map[string]any{
		{"bucket": "../etc", "key": "x"},
		{"bucket": "Backups", "key": "x"},
		{"bucket": "backups", "key": "../x"},
		{"bucket": "backups", "key": "a/./b"},
		{"bucket": "backups", "key": "a\nb"},
		{"bucket": "backups", "key": ""},
	} {
		if _, _, err := call(t, m, "info", in, false); err == nil {
			t.Fatalf("accepted %v", in)
		}
	}
	h := fakehost.New(nil)
	for _, c := range []Config{
		{Endpoint: "https://s3.example.com", AccessKeyID: "AKID", SecretKey: "plain"},
		{Endpoint: "http://s3.example.com", AccessKeyID: "AKID", SecretKey: "secret://s3"},
		{Endpoint: "https://s3.example.com/path", AccessKeyID: "AKID", SecretKey: "secret://s3"},
		{Endpoint: "ftp://s3.example.com", AccessKeyID: "AKID", SecretKey: "secret://s3"},
		{Endpoint: "https://s3.example.com", AccessKeyID: "", SecretKey: "secret://s3"},
		{Endpoint: "https://s3.example.com", AccessKeyID: "AKID", SecretKey: "secret://s3", Region: "US East"},
	} {
		raw, _ := json.Marshal(c)
		if err := New().Configure(context.Background(), h, "x", raw); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

func TestS3WrongKey(t *testing.T) {
	m, _ := setup(t, "secret://bad")
	if h := m.Health(context.Background(), "s"); h.Status != "down" || !strings.Contains(h.Message, "SignatureDoesNotMatch") {
		t.Fatalf("health %+v", h)
	}
}

// The example from the AWS documentation on query-string authentication.
func TestPresignAWSExample(t *testing.T) {
	u, _ := url.Parse("https://examplebucket.s3.amazonaws.com/test.txt")
	got := Presign(u, aws.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		"us-east-1", 24*time.Hour, time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC))
	if !strings.HasSuffix(got, "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404") {
		t.Fatalf("got %s", got)
	}
}

func TestVirtualHost(t *testing.T) {
	base, _ := url.Parse("https://s3.amazonaws.com")
	c := &conn{cfg: Config{VirtualHost: true}, base: base}
	if u := c.objectURL("bkt", "a b/c"); u.Host != "bkt.s3.amazonaws.com" || u.EscapedPath() != "/a%20b/c" {
		t.Fatalf("%s %s", u.Host, u.EscapedPath())
	}
}
