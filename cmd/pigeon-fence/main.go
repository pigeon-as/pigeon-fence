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
	"time"

	"github.com/coreos/go-systemd/v22/daemon"

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
		if err := cfg.LogLevel.UnmarshalText([]byte(*logLevel)); err != nil {
			fatal("invalid log-level %q: %v", *logLevel, err)
		}
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: cfg.LogLevel,
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

	// Notify systemd we're ready. No-op when NOTIFY_SOCKET is unset.
	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		logger.Warn("sd_notify ready", "err", err)
	}

	// If WatchdogSec= is set, heartbeat at 1/3 the interval.
	if interval, err := daemon.SdWatchdogEnabled(false); err == nil && interval > 0 {
		go heartbeat(ctx, interval/3, logger)
	}

	logger.Info("starting", "interval", cfg.Interval)
	if err := r.Run(ctx); err != nil {
		fatal("run: %v", err)
	}
}

// heartbeat pings systemd's watchdog on a fixed interval. Exits when ctx
// is cancelled.
func heartbeat(ctx context.Context, period time.Duration, log *slog.Logger) {
	tick := time.NewTicker(period)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if _, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); err != nil {
				log.Warn("sd_notify watchdog", "err", err)
			}
		}
	}
}
