// Command conduit-hub is the Conduit hub: accounts, device pairing, the
// end-to-end encrypted relay, sync, the module registry and the update feed.
//
// The hub is optional. Anyone can run one; daemons work local-only without it.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/elchi-dev/conduit/internal/hub"
)

func main() {
	cfg := hub.DefaultConfig()
	flag.StringVar(&cfg.Listen, "listen", cfg.Listen, "address to listen on")
	flag.StringVar(&cfg.DatabaseURL, "db", cfg.DatabaseURL, "database URL (postgres:// or sqlite path)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := hub.Run(ctx, cfg, log); err != nil {
		log.Error("hub stopped", "err", err)
		os.Exit(1)
	}
}
