package games

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Session is one recorded stretch of play.
type Session struct {
	GameID   string    `json:"gameId"`
	Title    string    `json:"title"`
	Launcher string    `json:"launcher"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Seconds  int64     `json:"seconds"`
}

// openSession is a game running now, kept on disk so a restart of the
// daemon can pick it up again (or close it where it was last seen).
type openSession struct {
	GameID   string    `json:"gameId"`
	Title    string    `json:"title"`
	Launcher string    `json:"launcher"`
	Start    time.Time `json:"start"`
	LastSeen time.Time `json:"lastSeen"`
	PIDs     []int32   `json:"pids"`
}

// CustomGame is a game the person added by hand.
type CustomGame struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Executable   string    `json:"executable,omitempty"`
	Args         []string  `json:"args,omitempty"`
	WorkingDir   string    `json:"workingDir,omitempty"`
	URI          string    `json:"uri,omitempty"`
	CoverURL     string    `json:"coverUrl,omitempty"`
	ProcessNames []string  `json:"processNames,omitempty"`
	InstallPath  string    `json:"installPath,omitempty"`
	Added        time.Time `json:"added"`
}

type storeData struct {
	Version  int           `json:"version"`
	Custom   []CustomGame  `json:"custom"`
	Sessions []Session     `json:"sessions"`
	Open     []openSession `json:"open,omitempty"`
}

// maxSessions bounds the history (years of daily play).
const maxSessions = 50000

// store keeps the module's data in one JSON file in its data folder, or in
// memory when there is no folder (tests, or a daemon without a data dir).
type store struct {
	mu   sync.Mutex
	path string
	d    storeData
}

func openStore(dir string) (*store, error) {
	s := &store{d: storeData{Version: 1}}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s.path = filepath.Join(dir, "games.json")
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.d); err != nil {
		// Keep the unreadable file for a person to look at; start fresh.
		_ = os.Rename(s.path, s.path+".broken")
		s.d = storeData{Version: 1}
	}
	return s, nil
}

// save writes the file atomically. The caller holds s.mu.
func (s *store) save() error {
	if s.path == "" {
		return nil
	}
	if n := len(s.d.Sessions); n > maxSessions {
		s.d.Sessions = append([]Session(nil), s.d.Sessions[n-maxSessions:]...)
	}
	b, err := json.Marshal(s.d)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *store) sessions() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Session(nil), s.d.Sessions...)
}

func (s *store) custom() []CustomGame {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]CustomGame(nil), s.d.Custom...)
}
