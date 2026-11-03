package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

type fixture struct {
	u      *Updater
	priv   ed25519.PrivateKey
	binary []byte
	srv    *httptest.Server
	feed   []byte
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	exe := filepath.Join(dir, "bin", "conduitd")
	_ = os.MkdirAll(filepath.Dir(exe), 0o755)
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &fixture{priv: priv, binary: []byte("new binary v1.1.0")}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/feed.json":
			_, _ = w.Write(f.feed)
		case "/conduitd":
			_, _ = w.Write(f.binary)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	f.u = &Updater{Feed: f.srv.URL + "/feed.json", Channel: "stable", DataDir: dir, Exe: exe, HTTP: f.srv.Client(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Current: "1.0.0", Key: base64.StdEncoding.EncodeToString(pub)}
	return f
}

func (f *fixture) publish(t *testing.T, p Payload, key ed25519.PrivateKey) {
	t.Helper()
	raw, _ := json.Marshal(p)
	m := Manifest{Version: p.Version, Releases: map[string]Signed{p.Platform: {
		Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))}}}
	f.feed, _ = json.Marshal(m)
}

func (f *fixture) release(version string) Payload {
	sum := sha256.Sum256(f.binary)
	return Payload{Component: "daemon", Channel: "stable", Platform: Platform(), Version: version, URL: f.srv.URL + "/conduitd", SHA256: hex.EncodeToString(sum[:])}
}

func read(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplyConfirm(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.publish(t, f.release("1.0.0"), f.priv)
	if p, err := f.u.Check(ctx); err != nil || p != nil {
		t.Fatalf("same version must not be offered: %v %v", p, err)
	}
	f.publish(t, f.release("1.1.0"), f.priv)
	p, err := f.u.Check(ctx)
	if err != nil || p == nil || p.Version != "1.1.0" {
		t.Fatalf("check: %v %v", p, err)
	}
	if _, err := f.u.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if read(t, f.u.Exe) != string(f.binary) || read(t, f.u.Exe+".old") != "old binary" {
		t.Fatal("binary not swapped")
	}
	// The new version starts and stays up.
	f.u.Current = "1.1.0"
	rolled, confirm := f.u.Probation()
	if rolled {
		t.Fatal("first start must not roll back")
	}
	confirm()
	if _, err := os.Stat(f.u.Exe + ".old"); !os.IsNotExist(err) {
		t.Fatal("old binary should be removed after confirmation")
	}
	if f.u.Status().Last.Result != "confirmed" {
		t.Fatalf("outcome %+v", f.u.Status().Last)
	}
}

func TestRollbackAfterFailedStarts(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.publish(t, f.release("1.1.0"), f.priv)
	if _, err := f.u.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < MaxAttempts; i++ {
		if rolled, _ := f.u.Probation(); rolled {
			t.Fatalf("rolled back too early at start %d", i)
		}
	}
	rolled, _ := f.u.Probation()
	if !rolled {
		t.Fatal("should roll back")
	}
	if read(t, f.u.Exe) != "old binary" || read(t, f.u.Exe+".failed") != string(f.binary) {
		t.Fatal("previous binary not restored")
	}
	if f.u.Status().Last.Result != "rolled_back" {
		t.Fatalf("outcome %+v", f.u.Status().Last)
	}
	if rolled, _ := f.u.Probation(); rolled {
		t.Fatal("no marker left: nothing to roll back")
	}
}

func TestRejectsBadReleases(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	f.publish(t, f.release("1.1.0"), other)
	if _, err := f.u.Check(ctx); err == nil {
		t.Fatal("a release signed with another key must be refused")
	}
	bad := f.release("1.1.0")
	bad.SHA256 = hex.EncodeToString(make([]byte, 32))
	f.publish(t, bad, f.priv)
	if _, err := f.u.Apply(ctx); err == nil {
		t.Fatal("a checksum mismatch must be refused")
	}
	if read(t, f.u.Exe) != "old binary" {
		t.Fatal("binary must be untouched after a failed update")
	}
	f.u.Current = "dev"
	f.publish(t, f.release("9.0.0"), f.priv)
	if _, err := f.u.Apply(ctx); err == nil {
		t.Fatal("dev builds must not update")
	}
	f.u.Current = "1.0.0"
	f.u.Managed = true
	if _, err := f.u.Apply(ctx); err == nil {
		t.Fatal("desktop-managed daemons must not replace themselves")
	}
}

func TestNewer(t *testing.T) {
	for _, c := range [][2]string{{"1.0.1", "1.0.0"}, {"1.10.0", "1.9.9"}, {"1.0.0", "1.0.0-beta"}, {"v2.0.0", "1.99.0"}} {
		if !Newer(c[0], c[1]) || Newer(c[1], c[0]) {
			t.Errorf("%s > %s", c[0], c[1])
		}
	}
	if Newer("1.0.0", "dev") || Newer("dev", "1.0.0") {
		t.Error("dev compares as not newer")
	}
}
