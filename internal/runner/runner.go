//go:build linux

package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
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

	ticker := time.NewTicker(r.cfg.IntervalDuration())
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
		expanded, err := expandRules(e.rules, resolved, failed, r.logger)
		if err != nil {
			r.logger.Error("expand rules", "provider", e.provider.Name(), "err", err)
			errs = append(errs, err)
			continue
		}
		result, err := e.provider.Reconcile(ctx, expanded)
		if err != nil {
			r.logger.Error("reconcile failed", "provider", e.provider.Name(), "err", err)
			errs = append(errs, err)
			continue
		}
		if result.InSync {
			r.logger.Debug("in sync", "provider", e.provider.Name())
		} else {
			r.logger.Info("reconciled", "provider", e.provider.Name(), "reason", result.Reason)
		}
	}

	return errors.Join(errs...)
}

func expandRules(rules []rule.Rule, resolved map[string][]string, failed map[string]bool, logger *slog.Logger) ([]rule.Rule, error) {
	var out []rule.Rule
	for _, r := range rules {
		if key, ok := refsFailedSource(r, failed); ok {
			logger.Warn("rule skipped: data source unavailable", "rule", r.Name, "source", key)
			continue
		}

		expanded := r
		var err error
		expanded.Source, err = rule.ExpandDataRefs(r.Source, resolved)
		if err != nil {
			return nil, fmt.Errorf("rule %q source: %w", r.Name, err)
		}
		expanded.Destination, err = rule.ExpandDataRefs(r.Destination, resolved)
		if err != nil {
			return nil, fmt.Errorf("rule %q destination: %w", r.Name, err)
		}

		if slices.ContainsFunc(r.Source, isDataRef) && len(expanded.Source) == 0 {
			logger.Warn("rule skipped: source data refs resolved to empty", "rule", r.Name)
			continue
		}
		if slices.ContainsFunc(r.Destination, isDataRef) && len(expanded.Destination) == 0 {
			logger.Warn("rule skipped: destination data refs resolved to empty", "rule", r.Name)
			continue
		}

		for _, s := range expanded.Source {
			if _, err := rule.ParseAddress(s); err != nil {
				return nil, fmt.Errorf("rule %q source: %w", r.Name, err)
			}
		}
		for _, d := range expanded.Destination {
			if _, err := rule.ParseAddress(d); err != nil {
				return nil, fmt.Errorf("rule %q destination: %w", r.Name, err)
			}
		}

		// Canonicalize order so hash drift detection is stable
		// regardless of data source return order.
		slices.Sort(expanded.Source)
		slices.Sort(expanded.Destination)

		out = append(out, expanded)
	}
	return out, nil
}

// isDataRef reports whether a value is a data.* reference.
func isDataRef(v string) bool { return strings.HasPrefix(v, "data.") }

// refsFailedSource reports whether a rule references a data source that failed
// to resolve. Returns the failed key and true if found.
func refsFailedSource(r rule.Rule, failed map[string]bool) (string, bool) {
	for _, v := range r.Source {
		if failed[v] {
			return v, true
		}
	}
	for _, v := range r.Destination {
		if failed[v] {
			return v, true
		}
	}
	return "", false
}
