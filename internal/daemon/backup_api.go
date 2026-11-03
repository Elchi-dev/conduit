package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elchi-dev/conduit/internal/backup"
	"github.com/elchi-dev/conduit/internal/version"
)

// Backups: download one now (a person with the passphrase), or have the
// daemon write one every day to a folder (a NAS mount, a synced folder),
// with the passphrase kept in the vault.

// BackupSchedule is the scheduled-backup setting.
type BackupSchedule struct {
	Enabled    bool   `json:"enabled"`
	Folder     string `json:"folder"`     // where backups go; default <data>/backups
	Passphrase string `json:"passphrase"` // secret:// reference in the vault
	Keep       int    `json:"keep"`       // newest backups to keep, default 7
	Hour       int    `json:"hour"`       // local hour of day, default 3
	LastRun    string `json:"lastRun,omitempty"`
	LastFile   string `json:"lastFile,omitempty"`
	LastError  string `json:"lastError,omitempty"`
}

const backupSetting = "backup.schedule"

var backupMu sync.Mutex // one backup at a time

func (s *Server) backupRoutes() []route {
	return []route{
		{"POST /api/v1/backup", s.need("admin:*:*", s.downloadBackup)},
		{"GET /api/v1/backup/schedule", s.need("admin:*:*", s.getBackupSchedule)},
		{"PUT /api/v1/backup/schedule", s.need("admin:*:*", s.putBackupSchedule)},
		{"POST /api/v1/backup/run", s.need("admin:*:*", s.runBackupNow)},
	}
}

func (s *Server) dataDir() string {
	var f string
	_ = s.DB.QueryRow(`PRAGMA database_list`).Scan(new(int), new(string), &f)
	return filepath.Dir(f)
}

// downloadBackup streams an encrypted backup. A backup holds every secret
// (still under the vault passphrase) and all settings, so only signed-in
// people can take one.
func (s *Server) downloadBackup(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := readJSON(r, &req); err != nil || len(req.Passphrase) < backup.MinPassphrase {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("choose a backup passphrase of at least %d characters", backup.MinPassphrase))
		return
	}
	if !backupMu.TryLock() {
		writeErr(w, http.StatusConflict, "a backup is already running")
		return
	}
	defer backupMu.Unlock()
	s.auditConfig(r, "backup_downloaded", "", nil)
	name := "conduit-backup-" + time.Now().Format("2006-01-02-1504") + ".cdb"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	if err := backup.Write(r.Context(), w, s.DB, s.dataDir(), req.Passphrase, version.Version); err != nil {
		s.Log.Error("backup failed", "err", err)
	}
}

func (s *Server) backupSchedule(ctx context.Context) BackupSchedule {
	c := BackupSchedule{Keep: 7, Hour: 3}
	var raw string
	if s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, backupSetting).Scan(&raw) == nil {
		_ = json.Unmarshal([]byte(raw), &c)
	}
	return c
}

func (s *Server) saveBackupSchedule(ctx context.Context, c BackupSchedule) error {
	b, _ := json.Marshal(c)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, backupSetting, string(b))
	return err
}

func (s *Server) getBackupSchedule(w http.ResponseWriter, r *http.Request) {
	c := s.backupSchedule(r.Context())
	if c.Folder == "" {
		c.Folder = filepath.Join(s.dataDir(), "backups")
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) putBackupSchedule(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	var c BackupSchedule
	if err := readJSON(r, &c); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if c.Enabled && !strings.HasPrefix(c.Passphrase, "secret://") {
		writeErr(w, http.StatusBadRequest, "store the backup passphrase in the vault and enter its secret:// reference")
		return
	}
	if err := s.mayUse(r.Context(), principalActor(r), strings.TrimPrefix(c.Passphrase, "secret://")); c.Passphrase != "" && err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	if c.Folder != "" && !filepath.IsAbs(c.Folder) {
		writeErr(w, http.StatusBadRequest, "the folder must be a full path, like /mnt/nas/conduit")
		return
	}
	if c.Keep <= 0 {
		c.Keep = 7
	}
	if c.Keep > 365 || c.Hour < 0 || c.Hour > 23 {
		writeErr(w, http.StatusBadRequest, "keep 1 to 365 backups, at an hour from 0 to 23")
		return
	}
	old := s.backupSchedule(r.Context())
	c.LastRun, c.LastFile, c.LastError = old.LastRun, old.LastFile, old.LastError
	if err := s.saveBackupSchedule(r.Context(), c); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditConfig(r, "backup_schedule_changed", "", map[string]any{"enabled": c.Enabled, "folder": c.Folder, "keep": c.Keep, "hour": c.Hour})
	s.getBackupSchedule(w, r)
}

func (s *Server) runBackupNow(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	file, err := s.scheduledBackup(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"file": file})
}

// scheduledBackup writes one backup to the configured folder and prunes old
// ones. It records the outcome in the setting.
func (s *Server) scheduledBackup(ctx context.Context) (string, error) {
	c := s.backupSchedule(ctx)
	file, err := s.writeScheduled(ctx, c)
	c.LastRun = time.Now().UTC().Format(time.RFC3339)
	c.LastFile, c.LastError = file, ""
	if err != nil {
		c.LastError = err.Error()
	}
	_ = s.saveBackupSchedule(ctx, c)
	if err != nil {
		s.Log.Warn("scheduled backup failed", "err", err)
	}
	return file, err
}

func (s *Server) writeScheduled(ctx context.Context, c BackupSchedule) (string, error) {
	if !strings.HasPrefix(c.Passphrase, "secret://") {
		return "", errors.New("set the backup passphrase (a vault reference) first")
	}
	pass, err := s.Vault.Resolve(ctx, c.Passphrase)
	if err != nil {
		return "", fmt.Errorf("the backup passphrase: %w", err)
	}
	dir := c.Folder
	if dir == "" {
		dir = filepath.Join(s.dataDir(), "backups")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if !backupMu.TryLock() {
		return "", errors.New("a backup is already running")
	}
	defer backupMu.Unlock()
	name := filepath.Join(dir, "conduit-backup-"+time.Now().Format("2006-01-02-150405")+".cdb")
	f, err := os.OpenFile(name+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	err = backup.Write(ctx, f, s.DB, s.dataDir(), pass, version.Version)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name + ".tmp")
		return "", err
	}
	if err := os.Rename(name+".tmp", name); err != nil {
		return "", err
	}
	// Keep the newest c.Keep.
	matches, _ := filepath.Glob(filepath.Join(dir, "conduit-backup-*.cdb"))
	sort.Strings(matches)
	for len(matches) > c.Keep {
		_ = os.Remove(matches[0])
		matches = matches[1:]
	}
	return name, nil
}

// runBackups checks every 10 minutes whether today's backup is due.
func runBackups(ctx context.Context, s *Server) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c := s.backupSchedule(ctx)
		if !c.Enabled {
			continue
		}
		now := time.Now()
		last, _ := time.Parse(time.RFC3339, c.LastRun)
		if now.Hour() >= c.Hour && last.Local().Format("2006-01-02") != now.Format("2006-01-02") {
			_, _ = s.scheduledBackup(ctx)
		}
	}
}
