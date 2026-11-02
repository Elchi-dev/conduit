// Package hub implements the Conduit hub server.
package hub

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/elchi-dev/conduit/internal/version"
)

// Config holds hub settings. Mail provider settings (Resend key or SMTP) are
// per-operator and added in the accounts phase.
type Config struct {
	Listen      string
	DatabaseURL string
}

// DefaultConfig returns settings suitable for a local test hub.
func DefaultConfig() Config {
	return Config{Listen: ":7700", DatabaseURL: "hub.db"}
}

// Run starts the hub and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	srv := &http.Server{Addr: cfg.Listen, Handler: Routes(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("conduit-hub listening", "addr", cfg.Listen, "version", version.Version)
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

// Routes returns the hub's HTTP handler.
func Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(version.Get())
	})
	return mux
}
