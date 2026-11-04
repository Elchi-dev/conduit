package mail

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// state is what an instance remembers between restarts: certificate pins
// taken on first use and how far the new-mail watcher has read. It is a small
// JSON file in the module's data folder; it holds no secrets.
type state struct {
	path string
	mu   sync.Mutex
	data stateData
}

type stateData struct {
	// Pins maps an endpoint ("imap", "smtp") to the SHA-256 fingerprint of
	// the certificate trusted on first use.
	Pins     map[string]pin `json:"pins,omitempty"`
	LastUID  uint32         `json:"lastUid,omitempty"`
	Validity uint32         `json:"uidValidity,omitempty"`
	Unread   *uint32        `json:"unread,omitempty"`
}

type pin struct {
	Fingerprint string `json:"fingerprint"`
	Since       string `json:"since"`
	Subject     string `json:"subject,omitempty"`
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

func openState(dir, instance string) *state {
	s := &state{data: stateData{Pins: map[string]pin{}}}
	if dir == "" {
		return s // memory only
	}
	s.path = filepath.Join(dir, unsafeName.ReplaceAllString(instance, "_")+".json")
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, &s.data)
	}
	if s.data.Pins == nil {
		s.data.Pins = map[string]pin{}
	}
	return s
}

// update changes the state under its lock and writes it out.
func (s *state) update(f func(d *stateData)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(&s.data)
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *state) get() stateData {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.data
	d.Pins = map[string]pin{}
	for k, v := range s.data.Pins {
		d.Pins[k] = v
	}
	return d
}

// defaultDir is where module state lives when the daemon doesn't say: the
// same folder the daemon uses by default for its data.
func defaultDir(module string) string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "conduit", "modules", module)
}
