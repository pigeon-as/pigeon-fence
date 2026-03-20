//go:build linux

package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/pigeon-as/pigeon-fence/internal/provider"
	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

const (
	chainPrefix  = "pigeon-fence"
	hashPrefix   = "pf:"
	flushRetries = 3
)

type Config struct {
	Name   string
	Logger *slog.Logger
}

type Provider struct {
	name      string
	chainName string
	tableName string
	logger    *slog.Logger
}

func New(cfg Config) *Provider {
	return &Provider{
		name:      cfg.Name,
		chainName: chainPrefix,
		tableName: "filter",
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

	expectedJumps := make(map[string]bool)
	for _, r := range effective {
		chain, err := mapDirection(r.Direction)
		if err != nil {
			return nil, err
		}
		expectedJumps[chain] = true
	}

	// Pre-flight: verify the base chains we need actually exist.
	// pigeon-fence never creates base chains ("base skeleton untouched").
	if err := p.checkBaseChains(expectedJumps); err != nil {
		return nil, err
	}

	// checkDrift reads from a separate Conn. The TOCTOU gap is harmless
	// because applyRules does a full replace (cleanup + rebuild) atomically.
	conn := &nftables.Conn{}
	drifted, reason := p.checkDrift(conn, desiredHashes, expectedJumps)
	if !drifted {
		return &provider.ReconcileResult{InSync: true}, nil
	}

	// Apply with retry.
	var err error
	for attempt := 0; attempt < flushRetries; attempt++ {
		if attempt > 0 {
			p.logger.Warn("nftables flush retry", "attempt", attempt+1, "err", err)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(100*(1<<attempt)) * time.Millisecond):
			}
		}
		err = p.applyRules(effective, desiredHashes, expectedJumps)
		if err == nil {
			return &provider.ReconcileResult{InSync: false, Reason: reason}, nil
		}
	}
	return nil, fmt.Errorf("nftables reconcile failed after %d attempts: %w", flushRetries, err)
}

// applyRules atomically replaces all rules via a single nftables.Conn and
// a single Flush() call — cleanup, rebuild, and jump rules are one netlink
// transaction with zero gap between old and new rules.
//
// Reads (ListChainsOfTableFamily, GetRules) execute synchronously against the
// kernel. Writes (Add/Del/Flush) are batched and applied atomically on Flush().
// This read-then-write-then-flush pattern matches Calico/Felix.
func (p *Provider) applyRules(rules []rule.Rule, hashes []string, jumps map[string]bool) error {
	conn := &nftables.Conn{}
	if err := p.cleanupChains(conn); err != nil {
		return fmt.Errorf("cleanup chains: %w", err)
	}

	if len(rules) == 0 {
		return conn.Flush()
	}

	filterTable := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   p.tableName,
	})

	ourChain := conn.AddChain(&nftables.Chain{
		Name:  p.chainName,
		Table: filterTable,
	})

	for i, r := range rules {
		exprs, err := buildExprs(r, conn, filterTable)
		if err != nil {
			return fmt.Errorf("build rule %q: %w", r.Name, err)
		}
		conn.AddRule(&nftables.Rule{
			Table:    filterTable,
			Chain:    ourChain,
			Exprs:    exprs,
			UserData: []byte(r.Name + " " + hashPrefix + hashes[i]),
		})
	}

	for parentName := range jumps {
		baseChain := &nftables.Chain{Name: parentName, Table: filterTable}
		conn.AddRule(&nftables.Rule{
			Table: filterTable,
			Chain: baseChain,
			Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: p.chainName}},
		})
	}

	return conn.Flush()
}

// checkDrift compares per-rule hashes from the kernel against desired hashes.
// Returns (true, reason) if rules need reapplication.
func (p *Provider) checkDrift(conn *nftables.Conn, desiredHashes []string, expectedJumps map[string]bool) (bool, string) {
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		p.logger.Warn("drift check: failed to list chains", "err", err)
		return true, "failed to list chains"
	}

	var ourChain *nftables.Chain
	for _, c := range chains {
		if c.Table.Name == p.tableName && c.Name == p.chainName {
			ourChain = c
			break
		}
	}
	if ourChain == nil {
		if len(desiredHashes) == 0 {
			// No chain, no rules desired — also verify no stale jumps.
			if reason := p.checkStaleJumps(conn, chains, expectedJumps); reason != "" {
				return true, reason
			}
			return false, ""
		}
		return true, "chain missing"
	}

	// Chain exists but no rules desired — need cleanup.
	if len(desiredHashes) == 0 {
		return true, "chain exists but no rules desired"
	}

	rules, err := conn.GetRules(ourChain.Table, ourChain)
	if err != nil {
		p.logger.Warn("drift check: failed to read rules", "err", err)
		return true, "failed to read rules"
	}

	if len(rules) != len(desiredHashes) {
		return true, fmt.Sprintf("rule count: have %d, want %d", len(rules), len(desiredHashes))
	}

	for i, r := range rules {
		ud := string(r.UserData)
		hashIdx := strings.LastIndex(ud, hashPrefix)
		if hashIdx < 0 || ud[hashIdx+len(hashPrefix):] != desiredHashes[i] {
			return true, fmt.Sprintf("rule %d hash mismatch", i)
		}
	}

	for parentName := range expectedJumps {
		has, err := p.hasJumpRule(conn, ourChain.Table, parentName)
		if err != nil {
			return true, fmt.Sprintf("failed to check jump rule in %s: %v", parentName, err)
		}
		if !has {
			return true, fmt.Sprintf("jump rule missing in %s chain", parentName)
		}
	}

	// Check for stale jumps in chains we no longer expect.
	if reason := p.checkStaleJumps(conn, chains, expectedJumps); reason != "" {
		return true, reason
	}

	return false, ""
}

// checkStaleJumps detects jump rules to our chain in base chains we don't expect.
func (p *Provider) checkStaleJumps(conn *nftables.Conn, chains []*nftables.Chain, expectedJumps map[string]bool) string {
	for _, c := range chains {
		if c.Table.Name != p.tableName || strings.HasPrefix(c.Name, chainPrefix) || expectedJumps[c.Name] {
			continue
		}
		has, err := p.hasJumpRule(conn, c.Table, c.Name)
		if err != nil {
			p.logger.Warn("drift check: failed to check stale jump", "chain", c.Name, "err", err)
			return fmt.Sprintf("failed to check stale jump in %s: %v", c.Name, err)
		}
		if has {
			return fmt.Sprintf("stale jump rule in %s chain", c.Name)
		}
	}
	return ""
}

func (p *Provider) hasJumpRule(conn *nftables.Conn, table *nftables.Table, parentChainName string) (bool, error) {
	rules, err := conn.GetRules(table, &nftables.Chain{Name: parentChainName, Table: table})
	if err != nil {
		return false, fmt.Errorf("get rules for chain %q: %w", parentChainName, err)
	}
	for _, r := range rules {
		for _, e := range r.Exprs {
			if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictJump && v.Chain == p.chainName {
				return true, nil
			}
		}
	}
	return false, nil
}

// cleanupChains removes all chains with our prefix and their jump rules.
func (p *Provider) cleanupChains(conn *nftables.Conn) error {
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("list chains: %w", err)
	}

	var table *nftables.Table
	var ours []*nftables.Chain
	ourNames := make(map[string]bool)
	for _, c := range chains {
		if c.Table.Name != p.tableName {
			continue
		}
		table = c.Table
		if strings.HasPrefix(c.Name, chainPrefix) {
			ours = append(ours, c)
			ourNames[c.Name] = true
		}
	}

	if table == nil {
		return nil
	}

	// Remove jump rules from non-our chains.
	for _, c := range chains {
		if c.Table.Name != p.tableName || ourNames[c.Name] {
			continue
		}
		rules, err := conn.GetRules(c.Table, c)
		if err != nil {
			return fmt.Errorf("get rules for chain %q: %w", c.Name, err)
		}
		for _, r := range rules {
			for _, e := range r.Exprs {
				if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictJump && ourNames[v.Chain] {
					conn.DelRule(r)
					break
				}
			}
		}
	}

	for _, c := range ours {
		conn.FlushChain(c)
		conn.DelChain(c)
	}
	return nil
}

// checkBaseChains verifies that every base chain we need to jump into actually
// exists in the kernel. pigeon-fence never creates base chains — a pre-existing
// inet filter table with input/output chains is a prerequisite.
func (p *Provider) checkBaseChains(expectedJumps map[string]bool) error {
	if len(expectedJumps) == 0 {
		return nil
	}

	conn := &nftables.Conn{}
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("nftables: cannot list chains: %w "+
			"(is the nf_tables kernel module loaded?)", err)
	}

	existing := make(map[string]bool)
	for _, c := range chains {
		if c.Table.Name == p.tableName {
			existing[c.Name] = true
		}
	}

	var missing []string
	for name := range expectedJumps {
		if !existing[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("nftables: base chain(s) %v not found in inet %s table; "+
			"pigeon-fence requires a pre-existing base firewall skeleton "+
			"(nft add table inet filter; nft add chain inet filter input { type filter hook input priority 0 \\; policy accept \\; })",
			missing, p.tableName)
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
