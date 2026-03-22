package provider

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

// ReconcileResult reports what a provider did during reconciliation.
type ReconcileResult struct {
	InSync bool
	Reason string
}

// Provider manages firewall rules for a specific backend.
// Reconcile is called on each tick with the full set of desired rules.
// It must converge the backend to match. Rules persist across daemon
// restarts — no cleanup on shutdown.
type Provider interface {
	Name() string
	Reconcile(ctx context.Context, rules []rule.Rule) (*ReconcileResult, error)
}

// Retry calls fn up to maxAttempts times with exponential backoff
// (100ms, 200ms, 400ms…). Returns the last error if all attempts fail.
func Retry(ctx context.Context, logger *slog.Logger, opName string, maxAttempts int, fn func() error) error {
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			logger.Warn(fmt.Sprintf("%s retry", opName), "attempt", attempt+1, "err", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(100*(1<<(attempt-1))) * time.Millisecond):
			}
		}
		err = fn()
		if err == nil {
			return nil
		}
	}
	return err
}
