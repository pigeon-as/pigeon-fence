//go:build linux

package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/pigeon-as/pigeon-fence/internal/config"
	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

type Runner struct {
	cfg         config.Config
	logger      *slog.Logger
	entries     []providerEntry
	dataSources []dataEntry
}

func New(logger *slog.Logger, cfg config.Config) (*Runner, error) {
	entries, dataSources, err := build(logger, cfg)
	if err != nil {
		return nil, err
	}

	return &Runner{
		cfg:         cfg,
		logger:      logger,
		entries:     entries,
		dataSources: dataSources,
	}, nil
}

func (r *Runner) Once() error {
	return r.reconcile(context.Background())
}

func (r *Runner) Run(ctx context.Context) error {
	if err := r.reconcile(ctx); err != nil {
		r.logger.Error("initial reconcile", "err", err)
	}

	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.reconcile(ctx); err != nil {
				r.logger.Error("reconcile", "err", err)
			}
		}
	}
}

func (r *Runner) reconcile(ctx context.Context) error {
	r.logger.Debug("reconcile tick")

	resolved := make(map[string][]string)
	failed := make(map[string]bool)
	var errs []error
	for _, ds := range r.dataSources {
		vals, err := ds.source.Resolve(ctx)
		if err != nil {
			r.logger.Error("resolve data source", "source", ds.key, "err", err)
			failed[ds.key] = true
			errs = append(errs, fmt.Errorf("data source %s: %w", ds.key, err))
			continue
		}
		resolved[ds.key] = vals
		r.logger.Debug("resolved data source", "source", ds.key, "count", len(vals))
	}

	for _, e := range r.entries {
		// If any rule for this provider references a failed data source,
		// skip the entire provider. This preserves the existing kernel
		// rules rather than reconciling a partial rule set that would
		// remove rules dependent on the failed source.
		if key, ok := rule.RefsFailedSource(e.rules, failed); ok {
			r.logger.Warn("skipping provider: data source unavailable",
				"provider", e.name, "source", key)
			errs = append(errs, fmt.Errorf("provider %s not reconciled: data source %s unavailable", e.name, key))
			continue
		}

		expanded, err := expandRules(e.rules, resolved, r.logger)
		if err != nil {
			r.logger.Error("expand rules", "provider", e.name, "err", err)
			errs = append(errs, err)
			continue
		}
		result, err := e.provider.Reconcile(ctx, expanded)
		if err != nil {
			r.logger.Error("reconcile failed", "provider", e.name, "err", err)
			errs = append(errs, err)
			continue
		}
		if result.InSync {
			r.logger.Debug("in sync", "provider", e.name)
		} else {
			r.logger.Info("reconciled", "provider", e.name, "reason", result.Reason)
		}
	}

	return errors.Join(errs...)
}

func expandRules(rules []rule.Rule, resolved map[string][]string, logger *slog.Logger) ([]rule.Rule, error) {
	var out []rule.Rule
	for _, r := range rules {
		expanded, skip, err := rule.Expand(r, resolved)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.Name, err)
		}
		if skip {
			logger.Warn("rule skipped: data refs resolved to empty", "rule", r.Name)
			continue
		}
		out = append(out, expanded)
	}
	return out, nil
}
