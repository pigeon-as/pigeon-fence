//go:build linux

// pigeon-fence is a pluggable firewall manager daemon.
//
// Usage:
//
//	pigeon-fence --config=<path> [--once] [--log-level=info]
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pigeon-as/pigeon-fence/internal/config"
	"github.com/pigeon-as/pigeon-fence/internal/runner"
)

func main() {
	var (
		configPath = flag.String("config", "", "Path to HCL config file or directory (required)")
		once       = flag.Bool("once", false, "Reconcile all rules once and exit")
		logLevel   = flag.String("log-level", "", "Log level (debug, info, warn, error)")
		version    = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Println("pigeon-fence v0.1.0")
		return
	}

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "--config is required")
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "invalid log-level %q: %v\n", cfg.LogLevel, err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	r, err := runner.New(logger, cfg)
	if err != nil {
		logger.Error("create runner", "err", err)
		os.Exit(1)
	}
	if *once {
		if err := r.Once(); err != nil {
			logger.Error("reconcile", "err", err)
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("starting", "interval", cfg.Interval)
	if err := r.Run(ctx); err != nil {
		logger.Error("run", "err", err)
		os.Exit(1)
	}
}
