//go:build linux

// pigeon-fence is a pluggable firewall manager daemon.
//
// Usage:
//
//	pigeon-fence --config=<path> [--config=<path>...] [--once] [--log-level=info]
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pigeon-as/pigeon-fence/internal/config"
	"github.com/pigeon-as/pigeon-fence/internal/runner"
)

var version = "dev"

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// stringSlice implements flag.Value for repeated --config flags.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	var configPaths stringSlice
	flag.Var(&configPaths, "config", "Path to HCL config file or directory (repeatable, required)")
	var (
		once        = flag.Bool("once", false, "Reconcile all rules once and exit")
		logLevel    = flag.String("log-level", "", "Log level (debug, info, warn, error)")
		showVersion = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("pigeon-fence " + version)
		return
	}

	if len(configPaths) == 0 {
		fatal("--config is required")
	}

	cfg, err := config.Load(configPaths...)
	if err != nil {
		fatal("load config: %v", err)
	}

	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		fatal("invalid log-level %q: %v", cfg.LogLevel, err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	r, err := runner.New(logger, cfg)
	if err != nil {
		fatal("create runner: %v", err)
	}
	if *once {
		if err := r.Once(); err != nil {
			fatal("reconcile: %v", err)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("starting", "interval", cfg.Interval)
	if err := r.Run(ctx); err != nil {
		fatal("run: %v", err)
	}
}
