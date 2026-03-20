package provider

import (
	"context"

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
