// Package daemon wires the Conduit daemon together: storage, the module
// registry, the permission engine and the HTTP surface.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/elchi-dev/conduit/internal/version"
)

// Config holds daemon settings.
type Config struct {
	Listen  string
	DataDir string
}

// DefaultConfig listens on loopback only; remote access goes through the hub
// relay or an explicit -listen.
func DefaultConfig() Config {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return Config{Listen: "127.0.0.1:7600", DataDir: filepath.Join(dir, "conduit")}
}

// Run starts the daemon and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("conduitd listening", "addr", cfg.Listen, "version", version.Version)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shut); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// Routes returns the daemon's HTTP handler.
func Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/v1/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, version.Get())
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
