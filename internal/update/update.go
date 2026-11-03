// Package update keeps a standalone conduitd current: it checks a signed
// release feed, replaces its own binary, and rolls back if the new version
// keeps failing to start.
//
// Trust: every release is a payload signed with Conduit's release key
// (ed25519). The public key is compiled into the binary, so neither the feed
// host (GitHub, a hub) nor the network can push a binary the key didn't
// sign. The payload names the download URL and its SHA-256.
//
// When the desktop app runs the daemon (CONDUIT_MANAGED=desktop), the app
// updates both together and this package only reports.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/internal/version"
)

// ReleaseKey is the base64 ed25519 public key releases are signed with.
// Override at link time for forks:
//
//	-ldflags "-X github.com/elchi-dev/conduit/internal/update.ReleaseKey=…"
var ReleaseKey = "cNW7YRR4O9dHz9WcIFMhaopG5Ky06OPh09axTD/Uj+c="

// DefaultFeed is where official releases are listed.
const DefaultFeed = "https://github.com/Elchi-dev/conduit/releases/latest/download/conduitd-release.json"

// Payload is what the release key signs (the same shape the hub's update
// feed serves, see docs/protocol/hub.md).
type Payload struct {
	Component string `json:"component"`
	Channel   string `json:"channel"`
	Platform  string `json:"platform"`
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Notes     string `json:"notes,omitempty"`
}

// Signed is a payload with its signature, both base64.
type Signed struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Manifest is the file published with each release: one signed payload per
// platform.
type Manifest struct {
	Version  string            `json:"version"`
	Releases map[string]Signed `json:"releases"`
}

// Status is what the settings page and API show.
type Status struct {
	Current   string     `json:"current"`
	Platform  string     `json:"platform"`
	Managed   bool       `json:"managed"` // the desktop app updates this daemon
	Feed      string     `json:"feed"`
	Available *Payload   `json:"available,omitempty"`
	CheckedAt *time.Time `json:"checkedAt,omitempty"`
	LastError string     `json:"lastError,omitempty"`
	// Last is the outcome of the most recent update, if any.
	Last *Outcome `json:"last,omitempty"`
}

// Outcome records an applied, confirmed or rolled-back update.
type Outcome struct {
	From   string    `json:"from"`
	To     string    `json:"to"`
	Result string    `json:"result"` // applied, confirmed, rolled_back
	At     time.Time `json:"at"`
	Detail string    `json:"detail,omitempty"`
}

// Updater checks and applies updates for the running binary.
type Updater struct {
	Feed    string
	Channel string
	DataDir string
	Exe     string // path of the running binary
	Managed bool
	HTTP    *http.Client
	Log     *slog.Logger
	// Current is the running version (version.Version; tests override it).
	Current string
	// Key overrides ReleaseKey (tests).
	Key string

	mu     sync.Mutex
	status Status
}

// New returns an updater for this process.
func New(dataDir string, log *slog.Logger) *Updater {
	exe, _ := os.Executable()
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	feed := os.Getenv("CONDUIT_UPDATE_FEED")
	if feed == "" {
		feed = DefaultFeed
	}
	ch := os.Getenv("CONDUIT_UPDATE_CHANNEL")
	if ch == "" {
		ch = "stable"
	}
	u := &Updater{Feed: feed, Channel: ch, DataDir: dataDir, Exe: exe, Managed: os.Getenv("CONDUIT_MANAGED") != "", Current: version.Version,
		HTTP: &http.Client{Timeout: 5 * time.Minute}, Log: log}
	u.status = Status{Current: version.Version, Platform: Platform(), Managed: u.Managed, Feed: feed}
	u.status.Last = u.readOutcome()
	return u
}

// Platform is this build's platform name, e.g. linux-amd64.
func Platform() string { return runtime.GOOS + "-" + runtime.GOARCH }

// Status returns the last known state.
func (u *Updater) Status() Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.status
}

func (u *Updater) key() (ed25519.PublicKey, error) {
	k := u.Key
	if k == "" {
		k = ReleaseKey
	}
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("this build has no valid release key")
	}
	return ed25519.PublicKey(b), nil
}

// Verify checks a signed payload against the release key and this platform.
func (u *Updater) Verify(s Signed) (Payload, error) {
	var p Payload
	key, err := u.key()
	if err != nil {
		return p, err
	}
	raw, err1 := base64.StdEncoding.DecodeString(s.Payload)
	sig, err2 := base64.StdEncoding.DecodeString(s.Signature)
	if err1 != nil || err2 != nil || !ed25519.Verify(key, raw, sig) {
		return p, errors.New("the release isn't signed with Conduit's release key")
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if p.Component != "daemon" || p.Platform != Platform() {
		return p, fmt.Errorf("the release is for %s %s, not daemon %s", p.Component, p.Platform, Platform())
	}
	// A signed beta build must not be served to stable installs.
	if u.Channel != "" && p.Channel != u.Channel {
		return p, fmt.Errorf("the release is on the %q channel, not %q", p.Channel, u.Channel)
	}
	if !strings.HasPrefix(p.URL, "https://") || len(p.SHA256) != 64 {
		return p, errors.New("the release has no https download or checksum")
	}
	return p, nil
}

// fetchSigned reads the feed: a release manifest (one entry per platform) or
// a hub answer (a single signed payload).
func (u *Updater) fetchSigned(ctx context.Context) (*Signed, error) {
	url := u.Feed
	if strings.HasPrefix(url, "hub:") {
		url = strings.TrimRight(strings.TrimPrefix(url, "hub:"), "/") + "/v1/updates/daemon/" + u.Channel + "/" + Platform() + "?current=" + u.Current
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := u.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("couldn't reach the update feed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent || res.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the update feed answered %s", res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if json.Unmarshal(body, &m) == nil && m.Releases != nil {
		s, ok := m.Releases[Platform()]
		if !ok {
			return nil, nil
		}
		return &s, nil
	}
	var s Signed
	if err := json.Unmarshal(body, &s); err != nil || s.Payload == "" {
		return nil, errors.New("the update feed's answer isn't a release")
	}
	return &s, nil
}

// Check asks the feed for a newer release.
func (u *Updater) Check(ctx context.Context) (*Payload, error) {
	now := time.Now().UTC()
	s, err := u.fetchSigned(ctx)
	var p *Payload
	if err == nil && s != nil {
		var got Payload
		if got, err = u.Verify(*s); err == nil && Newer(got.Version, u.Current) {
			p = &got
		}
	}
	u.mu.Lock()
	u.status.CheckedAt = &now
	u.status.Available = p
	u.status.LastError = ""
	if err != nil {
		u.status.LastError = err.Error()
	}
	u.mu.Unlock()
	return p, err
}

// Apply downloads, verifies and installs the available release, keeping the
// current binary beside it for rollback. The caller restarts the process
// (Restart) once the API has answered.
func (u *Updater) Apply(ctx context.Context) (Payload, error) {
	if u.Managed {
		return Payload{}, errors.New("the Conduit app updates this daemon; use Check for updates in the app")
	}
	if !semver.MatchString(u.Current) {
		return Payload{}, errors.New("this is a development build; it doesn't update itself")
	}
	p, err := u.Check(ctx)
	if err != nil {
		return Payload{}, err
	}
	if p == nil {
		return Payload{}, errors.New("already up to date")
	}
	dir := filepath.Dir(u.Exe)
	tmp, err := os.CreateTemp(dir, ".conduitd-update-*")
	if err != nil {
		return *p, fmt.Errorf("can't write next to %s (install where the daemon can replace itself, or update it with your package manager): %w", u.Exe, err)
	}
	defer os.Remove(tmp.Name())
	if err := u.download(ctx, *p, tmp); err != nil {
		tmp.Close()
		return *p, err
	}
	if err := tmp.Close(); err != nil {
		return *p, err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return *p, err
	}
	old := u.Exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(u.Exe, old); err != nil {
		return *p, err
	}
	if err := os.Rename(tmp.Name(), u.Exe); err != nil {
		_ = os.Rename(old, u.Exe)
		return *p, err
	}
	if err := u.writeMarker(marker{From: u.Current, To: p.Version, At: time.Now().UTC()}); err != nil {
		u.Log.Warn("update: couldn't write the rollback marker", "err", err)
	}
	u.saveOutcome(Outcome{From: u.Current, To: p.Version, Result: "applied", At: time.Now().UTC()})
	u.Log.Info("update installed; restarting", "from", u.Current, "to", p.Version)
	return *p, nil
}

func (u *Updater) download(ctx context.Context, p Payload, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return err
	}
	res, err := u.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("download answered %s", res.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(res.Body, 512<<20)); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, p.SHA256) {
		return fmt.Errorf("the download's checksum doesn't match the signed release (got %s)", got)
	}
	return nil
}

// --- rollback ----------------------------------------------------------------

// marker exists between installing an update and the new version proving it
// runs. Each start while it exists counts an attempt.
type marker struct {
	From     string    `json:"from"`
	To       string    `json:"to"`
	At       time.Time `json:"at"`
	Attempts int       `json:"attempts"`
}

func (u *Updater) markerPath() string  { return filepath.Join(u.DataDir, "update-pending.json") }
func (u *Updater) outcomePath() string { return filepath.Join(u.DataDir, "update-last.json") }

func (u *Updater) writeMarker(m marker) error {
	b, _ := json.Marshal(m)
	return os.WriteFile(u.markerPath(), b, 0o600)
}

func (u *Updater) saveOutcome(o Outcome) {
	b, _ := json.Marshal(o)
	_ = os.WriteFile(u.outcomePath(), b, 0o600)
	u.mu.Lock()
	u.status.Last = &o
	u.mu.Unlock()
}

func (u *Updater) readOutcome() *Outcome {
	b, err := os.ReadFile(u.outcomePath())
	if err != nil {
		return nil
	}
	var o Outcome
	if json.Unmarshal(b, &o) != nil {
		return nil
	}
	return &o
}

// MaxAttempts is how many starts a new version gets before rolling back.
const MaxAttempts = 3

// Probation runs at start. If an update is pending and this is its
// MaxAttempts-th start without being confirmed, it restores the previous
// binary and reports rolledBack: the caller must Restart. Otherwise it
// returns a confirm function to call once the daemon has served for a while.
func (u *Updater) Probation() (rolledBack bool, confirm func()) {
	b, err := os.ReadFile(u.markerPath())
	if err != nil {
		return false, func() {}
	}
	var m marker
	if json.Unmarshal(b, &m) != nil {
		_ = os.Remove(u.markerPath())
		return false, func() {}
	}
	m.Attempts++
	if m.Attempts >= MaxAttempts {
		old := u.Exe + ".old"
		if _, err := os.Stat(old); err == nil {
			bad := u.Exe + ".failed"
			_ = os.Remove(bad)
			if os.Rename(u.Exe, bad) == nil && os.Rename(old, u.Exe) == nil {
				_ = os.Remove(u.markerPath())
				u.saveOutcome(Outcome{From: m.From, To: m.To, Result: "rolled_back", At: time.Now().UTC(),
					Detail: fmt.Sprintf("%s didn't stay up after %d starts; restored %s", m.To, m.Attempts-1, m.From)})
				u.Log.Error("update: new version kept failing; rolled back", "to", m.From)
				return true, func() {}
			}
		}
		_ = os.Remove(u.markerPath())
		return false, func() {}
	}
	_ = u.writeMarker(m)
	return false, func() {
		_ = os.Remove(u.markerPath())
		_ = os.Remove(u.Exe + ".old")
		u.saveOutcome(Outcome{From: m.From, To: m.To, Result: "confirmed", At: time.Now().UTC()})
		u.Log.Info("update confirmed", "version", m.To)
	}
}

// --- versions ----------------------------------------------------------------

var semver = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?`)

// Newer reports whether a is a later version than b. Anything that isn't a
// semantic version (such as "dev") compares as not newer, so development
// builds never update.
func Newer(a, b string) bool {
	pa, pb := semver.FindStringSubmatch(a), semver.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x > y
		}
	}
	switch {
	case pa[4] == pb[4]:
		return false
	case pa[4] == "":
		return true
	case pb[4] == "":
		return false
	}
	return pa[4] > pb[4]
}
