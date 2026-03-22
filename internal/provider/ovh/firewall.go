package ovh

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/pigeon-as/pigeon-fence/internal/provider"
	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

// firewallRule represents an OVH firewall rule as returned by the GET API.
type firewallRule struct {
	Action          string `json:"action"`
	Protocol        string `json:"protocol"`
	Sequence        int    `json:"sequence"`
	Source          string `json:"source"`
	DestinationPort string `json:"destinationPort"`
	SourcePort      string `json:"sourcePort"`
	State           string `json:"state"`
}

// createRuleOpts is the JSON body for POST /ip/{ip}/firewall/{ip}/rule.
type createRuleOpts struct {
	Action          string `json:"action"`
	Protocol        string `json:"protocol"`
	Sequence        int    `json:"sequence"`
	Source          string `json:"source,omitempty"`
	DestinationPort *int   `json:"destinationPort,omitempty"`
	SourcePort      *int   `json:"sourcePort,omitempty"`
}

func firewallPath(ip string) string {
	e := url.PathEscape(ip)
	return fmt.Sprintf("/ip/%s/firewall/%s", e, e)
}

func (p *Provider) listRules(ctx context.Context, ip string) ([]int, error) {
	var sequences []int
	err := p.client.GetWithContext(ctx, firewallPath(ip)+"/rule", &sequences)
	if err != nil {
		return nil, err
	}
	sort.Ints(sequences)
	return sequences, nil
}

func (p *Provider) getRule(ctx context.Context, ip string, sequence int) (*firewallRule, error) {
	var r firewallRule
	err := p.client.GetWithContext(ctx, fmt.Sprintf("%s/rule/%d", firewallPath(ip), sequence), &r)
	return &r, err
}

func (p *Provider) createRule(ctx context.Context, ip string, opts createRuleOpts) error {
	return provider.Retry(ctx, p.logger.With("ip", ip, "seq", opts.Sequence), "OVH create rule", 3, func() error {
		return p.client.PostWithContext(ctx, firewallPath(ip)+"/rule", opts, nil)
	})
}

func (p *Provider) deleteRule(ctx context.Context, ip string, sequence int) error {
	return provider.Retry(ctx, p.logger.With("ip", ip, "seq", sequence), "OVH delete rule", 3, func() error {
		return p.client.DeleteWithContext(ctx, fmt.Sprintf("%s/rule/%d", firewallPath(ip), sequence), nil)
	})
}

// mapAction converts generic rule actions to OVH API values.
func mapAction(action string) string {
	switch action {
	case "allow":
		return "permit"
	case "deny":
		return "deny"
	default:
		return action
	}
}

// sourceMatches compares a desired source ("any" or IP/CIDR) with an OVH response source.
func sourceMatches(desired, got string) bool {
	if desired == "any" {
		return got == "any"
	}
	if got == "any" {
		return false
	}
	// Normalize both through netip for canonical comparison —
	// OVH may return "1.2.3.4/32" when we sent "1.2.3.4".
	dp, err := rule.ParseAddress(desired)
	if err != nil {
		return false
	}
	gp, err := rule.ParseAddress(got)
	if err != nil {
		return false
	}
	return dp == gp
}

// normalizeOVHPort converts an OVH API port string to a plain number.
// OVH returns ports as "eq 22" for single ports, "" or "any" for unset.
func normalizeOVHPort(s string) string {
	s = strings.TrimPrefix(s, "eq ")
	if s == "any" {
		return ""
	}
	return s
}

// portMatches compares a desired port slice (0 or 1 entries) with an OVH response port string.
func portMatches(desired []string, got string) bool {
	got = normalizeOVHPort(got)
	if len(desired) == 0 {
		return got == ""
	}
	return desired[0] == got
}

func buildCreateOpts(r rule.Rule, sequence int) (createRuleOpts, error) {
	opts := createRuleOpts{
		Action:   mapAction(r.Action),
		Protocol: r.Protocol,
		Sequence: sequence,
	}
	if len(r.Source) == 1 {
		opts.Source = r.Source[0]
	}
	if len(r.DstPort) == 1 {
		lo, _, err := rule.ParsePortOrRange(r.DstPort[0])
		if err != nil {
			return opts, fmt.Errorf("dst_port: %w", err)
		}
		v := int(lo)
		opts.DestinationPort = &v
	}
	if len(r.SrcPort) == 1 {
		lo, _, err := rule.ParsePortOrRange(r.SrcPort[0])
		if err != nil {
			return opts, fmt.Errorf("src_port: %w", err)
		}
		v := int(lo)
		opts.SourcePort = &v
	}
	return opts, nil
}

// waitRuleReady polls until a rule's state is "ok" (Terraform provider pattern).
func (p *Provider) waitRuleReady(ctx context.Context, ip string, sequence int) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for {
		r, err := p.getRule(ctx, ip, sequence)
		if err != nil {
			return fmt.Errorf("poll rule state: %w", err)
		}
		if r.State == "ok" {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out: rule in state %q, want %q: %w", r.State, "ok", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}
