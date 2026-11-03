// Package daemon wires the Conduit daemon together: storage, the module
// engine, accounts and keys, and the HTTP surface.
package daemon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/elchi-dev/conduit/internal/ai"
	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/automation"
	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/internal/ui"
	"github.com/elchi-dev/conduit/internal/vault"
	"github.com/elchi-dev/conduit/internal/version"
	"github.com/elchi-dev/conduit/modules/notify"
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

// App is a running daemon's parts, exposed so modules and tests can be
// registered before serving.
type App struct {
	Store       *core.Store
	Engine      *core.Engine
	Auth        *auth.Service
	Vault       *vault.Vault
	Notify      *notify.Module
	Automations *automation.Service
	Server      *Server
}

// Open prepares a daemon in dataDir without serving it.
func Open(ctx context.Context, dataDir string, log *slog.Logger) (*App, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	store, err := core.OpenStore(ctx, filepath.Join(dataDir, "conduit.db"))
	if err != nil {
		return nil, err
	}
	engine := core.NewEngine(store, log)
	authSvc := auth.New(store)
	sum := sha256.Sum256([]byte(dataDir))
	v := vault.New(store, vault.OSKeychain{Account: hex.EncodeToString(sum[:8])})
	engine.SetSecrets(v)
	autos := automation.New(engine)
	providers := ai.NewProviders(store, v)
	assistant := &ai.Agent{DB: store.DB, Providers: providers}
	bridge := &ai.Bridge{DB: store.DB, Engine: engine, Secrets: v}
	app := &App{Store: store, Engine: engine, Auth: authSvc, Vault: v, Automations: autos,
		Server: &Server{Engine: engine, Auth: authSvc, Vault: v, Automations: autos, Providers: providers, Assistant: assistant, Bridge: bridge, Log: log, UI: ui.Handler()}}
	if v.UnlockFromKeychain(ctx) {
		log.Info("vault unlocked from the system keychain")
	}

	n, err := authSvc.UserCount(ctx)
	if err != nil {
		store.Close()
		return nil, err
	}
	if n == 0 {
		tok := randomHex(16)
		app.Server.SetupToken = tok
		path := filepath.Join(dataDir, "setup-token")
		if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
			log.Warn("could not write setup token file", "err", err)
		}
		log.Info("first start: create the owner account with this setup token", "token", tok, "file", path)
	} else {
		_ = os.Remove(filepath.Join(dataDir, "setup-token"))
	}
	return app, nil
}

// Close releases the daemon's resources.
func (a *App) Close() {
	a.Engine.Close()
	a.Store.Close()
}

// Run starts the daemon and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	app, err := Open(ctx, cfg.DataDir, log)
	if err != nil {
		return err
	}
	defer app.Close()
	if err := registerBuiltins(app); err != nil {
		return err
	}
	externals := app.Engine.LoadExternalDir(ctx, filepath.Join(cfg.DataDir, "modules"))
	defer func() {
		for _, x := range externals {
			_ = x.Stop()
		}
	}()
	if err := app.Engine.Start(ctx); err != nil {
		return err
	}
	if err := ensureSingletons(ctx, app); err != nil {
		return err
	}
	go app.Server.Bridge.MountAll(ctx)
	if err := app.Automations.Start(ctx); err != nil {
		return err
	}
	go housekeeping(ctx, app)
	go forwardAlerts(ctx, app)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.Server.Handler(),
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

// registerBuiltins adds the compiled-in modules.
func registerBuiltins(app *App) error {
	for _, m := range builtins(app) {
		if err := app.Engine.Register(m); err != nil {
			return err
		}
	}
	return nil
}

// ensureSingletons creates the one instance of modules that have exactly
// one per daemon (the vault, this computer).
func ensureSingletons(ctx context.Context, app *App) error {
	for id, name := range singletons {
		if _, ok := app.Engine.Instance(id); ok {
			continue
		}
		if _, err := app.Engine.SaveInstance(ctx, core.Instance{ID: id, Module: id, Name: name, Enabled: true}); err != nil {
			return err
		}
	}
	return nil
}

func housekeeping(ctx context.Context, app *App) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = app.Auth.PruneUsage(ctx)
		}
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func constantEq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
