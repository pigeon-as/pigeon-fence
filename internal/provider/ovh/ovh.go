package ovh

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	ovhsdk "github.com/ovh/go-ovh/ovh"
	"github.com/pigeon-as/pigeon-fence/internal/provider"
	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

const maxRules = 20

// credentials is the HCL body schema for the OVH provider block.
// All fields are optional — when empty, the go-ovh SDK falls back
// to OVH_* environment variables and ~/.ovh.conf.
type credentials struct {
	Endpoint          string `hcl:"endpoint,optional"`
	ApplicationKey    string `hcl:"application_key,optional"`
	ApplicationSecret string `hcl:"application_secret,optional"`
	ConsumerKey       string `hcl:"consumer_key,optional"`
}

type Config struct {
	Name   string
	Logger *slog.Logger
	Client *ovhsdk.Client
}

type Provider struct {
	name   string
	logger *slog.Logger
	client *ovhsdk.Client
}

// NewClient creates an OVH API client from a provider HCL body.
func NewClient(body hcl.Body) (*ovhsdk.Client, error) {
	var creds credentials
	diags := gohcl.DecodeBody(body, nil, &creds)
	if diags.HasErrors() {
		return nil, fmt.Errorf("decode credentials: %s", diags.Error())
	}
	return ovhsdk.NewClient(creds.Endpoint, creds.ApplicationKey, creds.ApplicationSecret, creds.ConsumerKey)
}

func New(cfg Config) *Provider {
	return &Provider{
		name:   cfg.Name,
		logger: cfg.Logger,
		client: cfg.Client,
	}
}

// ValidateRule checks OVH-specific rule constraints.
func (p *Provider) ValidateRule(r rule.Rule) error {
	if r.Direction != "inbound" {
		return fmt.Errorf("OVH firewall only supports inbound rules")
	}
	if r.IP == "" {
		return fmt.Errorf("ip is required")
	}
	if _, err := netip.ParseAddr(r.IP); err != nil {
		return fmt.Errorf("invalid ip %q: %w", r.IP, err)
	}
	if r.Protocol == "" {
		return fmt.Errorf("protocol is required")
	}
	if len(r.DstPort) > 1 {
		return fmt.Errorf("at most one dst_port per rule")
	}
	if len(r.SrcPort) > 1 {
		return fmt.Errorf("at most one src_port per rule")
	}
	for _, p := range r.DstPort {
		lo, hi, _ := rule.ParsePortOrRange(p)
		if lo != hi {
			return fmt.Errorf("dst_port %q: port ranges not supported by OVH API", p)
		}
	}
	for _, p := range r.SrcPort {
		lo, hi, _ := rule.ParsePortOrRange(p)
		if lo != hi {
			return fmt.Errorf("src_port %q: port ranges not supported by OVH API", p)
		}
	}
	if len(r.Source) > 1 {
		return fmt.Errorf("at most one source per rule")
	}
	if len(r.Destination) > 0 {
		return fmt.Errorf("destination is not supported (the ip field is the destination)")
	}
	if r.Interface != "" {
		return fmt.Errorf("interface is not supported")
	}
	return nil
}

func (p *Provider) Name() string { return p.name }

func (p *Provider) Reconcile(ctx context.Context, rules []rule.Rule) (*provider.ReconcileResult, error) {
	byIP, ips := groupByIP(rules)
	for _, ip := range ips {
		if len(byIP[ip]) > maxRules {
			return nil, fmt.Errorf("ip %s: at most %d rules, got %d", ip, maxRules, len(byIP[ip]))
		}
	}

	var dirty bool
	var reasons []string

	for _, ip := range ips {
		desired := byIP[ip]
		changed, reason, err := p.reconcileIP(ctx, ip, desired)
		if err != nil {
			return nil, fmt.Errorf("ip %s: %w", ip, err)
		}
		if changed {
			dirty = true
			reasons = append(reasons, fmt.Sprintf("%s: %s", ip, reason))
		}
	}

	if !dirty {
		return &provider.ReconcileResult{InSync: true}, nil
	}
	return &provider.ReconcileResult{InSync: false, Reason: strings.Join(reasons, "; ")}, nil
}

// groupByIP groups rules by their IP field, preserving declaration order.
func groupByIP(rules []rule.Rule) (map[string][]rule.Rule, []string) {
	m := make(map[string][]rule.Rule)
	var order []string
	for _, r := range rules {
		if _, exists := m[r.IP]; !exists {
			order = append(order, r.IP)
		}
		m[r.IP] = append(m[r.IP], r)
	}
	return m, order
}

// reconcileIP does per-sequence reconciliation for a single IP.
// Only deletes rules that don't match and creates rules that are missing or changed.
// Follows the same per-resource CRUD pattern as the Terraform OVH provider.
func (p *Provider) reconcileIP(ctx context.Context, ip string, desired []rule.Rule) (bool, string, error) {
	sequences, err := p.listRules(ctx, ip)
	if err != nil {
		return false, "", fmt.Errorf("list rules: %w", err)
	}

	// Build a map of existing sequence → firewallRule for O(1) lookup.
	existing := make(map[int]*firewallRule)
	for _, seq := range sequences {
		r, err := p.getRule(ctx, ip, seq)
		if err != nil {
			return false, "", fmt.Errorf("get rule %d: %w", seq, err)
		}
		existing[seq] = r
	}

	var changed int
	var reasons []string

	// Delete extra sequences (existing but not desired).
	for _, seq := range sequences {
		if seq >= len(desired) {
			if err := p.deleteRule(ctx, ip, seq); err != nil {
				return false, "", fmt.Errorf("delete rule %d: %w", seq, err)
			}
			changed++
			reasons = append(reasons, fmt.Sprintf("deleted extra seq %d", seq))
		}
	}

	// For each desired rule, check if existing matches. Delete+create if not.
	for i, r := range desired {
		cur, exists := existing[i]
		if exists && cur.State == "ok" && ruleMatches(r, cur) {
			continue
		}

		// Delete existing rule at this sequence if present.
		if exists {
			if err := p.deleteRule(ctx, ip, i); err != nil {
				return false, "", fmt.Errorf("delete rule %d: %w", i, err)
			}
		}

		opts, err := buildCreateOpts(r, i)
		if err != nil {
			return false, "", fmt.Errorf("build rule %q: %w", r.Name, err)
		}
		if err := p.createRule(ctx, ip, opts); err != nil {
			return false, "", fmt.Errorf("create rule %q (seq %d): %w", r.Name, i, err)
		}
		if err := p.waitRuleReady(ctx, ip, i); err != nil {
			return false, "", fmt.Errorf("rule %q (seq %d): %w", r.Name, i, err)
		}

		changed++
		if exists {
			reasons = append(reasons, fmt.Sprintf("replaced seq %d", i))
		} else {
			reasons = append(reasons, fmt.Sprintf("created seq %d", i))
		}
	}

	if changed == 0 {
		return false, "", nil
	}
	return true, strings.Join(reasons, ", "), nil
}

func ruleMatches(desired rule.Rule, current *firewallRule) bool {
	if mapAction(desired.Action) != current.Action {
		return false
	}
	if desired.Protocol != current.Protocol {
		return false
	}
	wantSource := "any"
	if len(desired.Source) == 1 {
		wantSource = desired.Source[0]
	}
	if !sourceMatches(wantSource, current.Source) {
		return false
	}
	if !portMatches(desired.DstPort, current.DestinationPort) {
		return false
	}
	if !portMatches(desired.SrcPort, current.SourcePort) {
		return false
	}
	return true
}
