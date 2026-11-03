// Command conduitd is the Conduit daemon: it hosts modules, enforces the
// permission policy, serves the app UI and exposes the daemon API and MCP.
//
//	conduitd                 run the daemon
//	conduitd mcp             bridge an MCP client (stdio) to a running daemon
//	conduitd update          install the newest signed release (-check to only look)
//	conduitd version         print the version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/elchi-dev/conduit/internal/ai"
	"github.com/elchi-dev/conduit/internal/daemon"
	"github.com/elchi-dev/conduit/internal/update"
	"github.com/elchi-dev/conduit/internal/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "mcp":
			fs := flag.NewFlagSet("mcp", flag.ExitOnError)
			url := fs.String("url", envOr("CONDUIT_URL", "http://127.0.0.1:7600"), "daemon address")
			_ = fs.Parse(os.Args[2:])
			if err := ai.ServeStdio(ctx, *url, os.Getenv("CONDUIT_API_KEY"), os.Stdin, os.Stdout, os.Stderr); err != nil {
				fmt.Fprintln(os.Stderr, "conduit mcp:", err)
				os.Exit(1)
			}
			return
		case "update":
			fs := flag.NewFlagSet("update", flag.ExitOnError)
			data := fs.String("data", daemon.DefaultConfig().DataDir, "data directory")
			only := fs.Bool("check", false, "only report whether an update exists")
			_ = fs.Parse(os.Args[2:])
			u := update.New(*data, slog.New(slog.NewTextHandler(os.Stderr, nil)))
			if *only {
				p, err := u.Check(ctx)
				switch {
				case err != nil:
					fmt.Fprintln(os.Stderr, "conduit update:", err)
					os.Exit(1)
				case p == nil:
					fmt.Println("conduitd", version.Version, "is up to date")
				default:
					fmt.Println("conduitd", p.Version, "is available (you have", version.Version+")")
				}
				return
			}
			p, err := u.Apply(ctx)
			if err != nil {
				fmt.Fprintln(os.Stderr, "conduit update:", err)
				os.Exit(1)
			}
			fmt.Println("installed conduitd", p.Version+"; restart the daemon to use it")
			return
		case "version":
			v := version.Get()
			fmt.Printf("conduitd %s (%s, %s) %s/%s\n", v.Version, v.Commit, v.Date, v.OS, v.Arch)
			return
		}
	}

	cfg := daemon.DefaultConfig()
	flag.StringVar(&cfg.Listen, "listen", cfg.Listen, "address to listen on")
	flag.StringVar(&cfg.DataDir, "data", cfg.DataDir, "data directory")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := daemon.Run(ctx, cfg, log); err != nil {
		log.Error("daemon stopped", "err", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
