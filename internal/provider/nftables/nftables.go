//go:build linux

package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/nftables"
	"github.com/pigeon-as/pigeon-fence/internal/provider"
	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

const (
	defaultTableName = "pigeon-fence"
	hashPrefix       = "pf:"
	flushRetries     = 3
)

type Config struct {
	Name   string
	Logger *slog.Logger
}

type Provider struct {
	name      string
	tableName string
	logger    *slog.Logger
}

func New(cfg Config) *Provider {
	return &Provider{
		name:      cfg.Name,
		tableName: defaultTableName,
		logger:    cfg.Logger,
	}
}

// ValidateRule checks nftables-specific rule constraints.
// Universal validation (protocol, port syntax, addresses) is handled
// by config.validate() and the runner's post-expansion checks.
func ValidateRule(_ rule.Rule) error {
	return nil
}

func (p *Provider) Name() string { return p.name }

func (p *Provider) Reconcile(ctx context.Context, rules []rule.Rule) (*provider.ReconcileResult, error) {
	// Split mixed-family rules.
	var effective []rule.Rule
	for _, r := range rules {
		split, err := rule.SplitByFamily(r)
		if err != nil {
			return nil, fmt.Errorf("split rule %q: %w", r.Name, err)
		}
		effective = append(effective, split...)
	}

	desiredHashes := make([]string, len(effective))
	for i, r := range effective {
		desiredHashes[i] = rule.HashRule(r)
	}

	// checkDrift reads from a separate Conn. The TOCTOU gap is harmless
	// because applyRules does a full replace (delete table + rebuild) atomically.
	conn := &nftables.Conn{}
	drifted, reason := p.checkDrift(conn, effective, desiredHashes)
	if !drifted {
		return &provider.ReconcileResult{InSync: true}, nil
	}

	// Apply with retry.
	err := provider.Retry(ctx, p.logger, "nftables flush", flushRetries, func() error {
		return p.applyRules(effective, desiredHashes)
	})
	if err != nil {
		return nil, fmt.Errorf("nftables reconcile failed after %d attempts: %w", flushRetries, err)
	}
	return &provider.ReconcileResult{InSync: false, Reason: reason}, nil
}

// applyRules atomically replaces all rules via a single nftables.Conn and
// a single Flush() call — delete old table, create new table with base chains
// and rules in one netlink transaction with zero gap.
//
// Own-table model (Calico/Felix pattern): pigeon-fence creates
// `table inet pigeon-fence` with its own base chains. Never touches
// other tables. Kernel dispatches via hook registration.
//
// Reads (ListTablesOfFamily) execute synchronously against the kernel.
// Writes (Del/Add) are batched and applied atomically on Flush().
func (p *Provider) applyRules(rules []rule.Rule, hashes []string) error {
	conn := &nftables.Conn{}
	if err := p.cleanupTable(conn); err != nil {
		return fmt.Errorf("cleanup table: %w", err)
	}

	if len(rules) == 0 {
		return conn.Flush()
	}

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   p.tableName,
	})

	// Group rules by direction → one base chain per direction.
	type chainRules struct {
		rules  []rule.Rule
		hashes []string
	}
	byDir := make(map[string]*chainRules)
	for i, r := range rules {
		chainName, err := mapDirection(r.Direction)
		if err != nil {
			return fmt.Errorf("rule %q: %w", r.Name, err)
		}
		cr := byDir[chainName]
		if cr == nil {
			cr = &chainRules{}
			byDir[chainName] = cr
		}
		cr.rules = append(cr.rules, r)
		cr.hashes = append(cr.hashes, hashes[i])
	}

	for chainName, cr := range byDir {
		hook, priority := chainHookPriority(chainName)
		policy := nftables.ChainPolicyDrop
		chain := conn.AddChain(&nftables.Chain{
			Name:     chainName,
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  hook,
			Priority: priority,
			Policy:   &policy,
		})

		for i, r := range cr.rules {
			exprs, err := buildExprs(r, conn, table)
			if err != nil {
				return fmt.Errorf("build rule %q: %w", r.Name, err)
			}
			conn.AddRule(&nftables.Rule{
				Table:    table,
				Chain:    chain,
				Exprs:    exprs,
				UserData: []byte(r.Name + "\x00" + hashPrefix + cr.hashes[i]),
			})
		}
	}

	return conn.Flush()
}

// chainHookPriority maps a chain name to its nftables hook and priority.
func chainHookPriority(chainName string) (*nftables.ChainHook, *nftables.ChainPriority) {
	switch chainName {
	case "output":
		return nftables.ChainHookOutput, nftables.ChainPriorityFilter
	case "forward":
		return nftables.ChainHookForward, nftables.ChainPriorityFilter
	default: // "input"
		return nftables.ChainHookInput, nftables.ChainPriorityFilter
	}
}

// checkDrift compares per-rule hashes from the kernel against desired hashes.
// Returns (true, reason) if rules need reapplication.
func (p *Provider) checkDrift(conn *nftables.Conn, rules []rule.Rule, desiredHashes []string) (bool, string) {
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		p.logger.Warn("drift check: failed to list tables", "err", err)
		return true, "failed to list tables"
	}

	var ourTable *nftables.Table
	for _, t := range tables {
		if t.Name == p.tableName {
			ourTable = t
			break
		}
	}
	if ourTable == nil {
		if len(desiredHashes) == 0 {
			return false, ""
		}
		return true, "table missing"
	}

	// Table exists but no rules desired — need cleanup.
	if len(desiredHashes) == 0 {
		return true, "table exists but no rules desired"
	}

	// Group desired hashes by direction for per-chain comparison.
	type chainHashes struct {
		hashes []string
	}
	expected := make(map[string]*chainHashes)
	for i, r := range rules {
		chainName, err := mapDirection(r.Direction)
		if err != nil {
			return true, fmt.Sprintf("invalid direction %q for rule at index %d", r.Direction, i)
		}
		ch := expected[chainName]
		if ch == nil {
			ch = &chainHashes{}
			expected[chainName] = ch
		}
		ch.hashes = append(ch.hashes, desiredHashes[i])
	}

	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		p.logger.Warn("drift check: failed to list chains", "err", err)
		return true, "failed to list chains"
	}

	// Count our chains and check each one.
	ourChainCount := 0
	for _, c := range chains {
		if c.Table.Name != p.tableName {
			continue
		}
		ourChainCount++
		ch, ok := expected[c.Name]
		if !ok {
			return true, fmt.Sprintf("unexpected chain %q in table", c.Name)
		}

		kernelRules, err := conn.GetRules(c.Table, c)
		if err != nil {
			p.logger.Warn("drift check: failed to read rules", "chain", c.Name, "err", err)
			return true, fmt.Sprintf("failed to read rules from %s", c.Name)
		}

		if len(kernelRules) != len(ch.hashes) {
			return true, fmt.Sprintf("%s: rule count: have %d, want %d", c.Name, len(kernelRules), len(ch.hashes))
		}

		for i, r := range kernelRules {
			parts := strings.SplitN(string(r.UserData), "\x00", 2)
			if len(parts) != 2 || strings.TrimPrefix(parts[1], hashPrefix) != ch.hashes[i] {
				return true, fmt.Sprintf("%s: rule %d hash mismatch", c.Name, i)
			}
		}
	}

	if ourChainCount != len(expected) {
		return true, fmt.Sprintf("chain count: have %d, want %d", ourChainCount, len(expected))
	}

	return false, ""
}

// cleanupTable deletes our table if it exists. DelTable removes all chains
// and rules within it. The deletion is batched and applied on Flush().
func (p *Provider) cleanupTable(conn *nftables.Conn) error {
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == p.tableName {
			conn.DelTable(t)
			return nil
		}
	}
	return nil
}

func mapDirection(dir string) (string, error) {
	switch dir {
	case "inbound":
		return "input", nil
	case "outbound":
		return "output", nil
	default:
		return "", fmt.Errorf("invalid direction %q", dir)
	}
}
