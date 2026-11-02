// Command conduitd is the Conduit daemon: it hosts modules, enforces the
// permission policy, serves the app UI and exposes the daemon API and MCP.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/elchi-dev/conduit/internal/daemon"
)

func main() {
	cfg := daemon.DefaultConfig()
	flag.StringVar(&cfg.Listen, "listen", cfg.Listen, "address to listen on")
	flag.StringVar(&cfg.DataDir, "data", cfg.DataDir, "data directory")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := daemon.Run(ctx, cfg, log); err != nil {
		log.Error("daemon stopped", "err", err)
		os.Exit(1)
	}
}
