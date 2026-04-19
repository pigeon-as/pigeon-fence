package rule

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// validActions defines the actions supported by all providers.
var validActions = map[string]bool{"accept": true, "drop": true, "reject": true}

// validProtocols defines the protocols supported by all providers.
var validProtocols = map[string]bool{"tcp": true, "udp": true, "icmp": true, "icmpv6": true}

// Rule represents a single firewall rule to be reconciled by a provider.
type Rule struct {
	Name              string   `hcl:"name,label"`
	Provider          string   `hcl:"provider"`
	Direction         string   `hcl:"direction"` // "inbound", "outbound", "forward"
	Source            []string `hcl:"source,optional"`
	Destination       []string `hcl:"destination,optional"`
	Protocol          string   `hcl:"protocol,optional"`
	SrcPort           []string `hcl:"src_port,optional"`
	DstPort           []string `hcl:"dst_port,optional"`
	Action            string   `hcl:"action"`
	InboundInterface  string   `hcl:"inbound_interface,optional"`
	OutboundInterface string   `hcl:"outbound_interface,optional"`
	Comment           string   `hcl:"comment,optional"`
}

func (r Rule) ProviderKey() string { return r.Provider }

// Validate checks rule semantics. Does not validate cross-rule concerns
// (duplicate names, provider refs) — those belong to the config layer.
// Static address literals are validated here; data.* references are
// re-checked by Expand after data source resolution.
func Validate(r Rule) error {
	if r.Direction == "" {
		return fmt.Errorf("direction is required")
	}
	if r.Direction != "inbound" && r.Direction != "outbound" && r.Direction != "forward" {
		return fmt.Errorf("direction must be \"inbound\", \"outbound\", or \"forward\"")
	}
	if r.Action == "" {
		return fmt.Errorf("action is required")
	}
	if !validActions[r.Action] {
		return fmt.Errorf("invalid action %q (must be accept, drop, or reject)", r.Action)
	}
	if r.Protocol != "" && !validProtocols[r.Protocol] {
		return fmt.Errorf("invalid protocol %q (must be tcp, udp, icmp, or icmpv6)", r.Protocol)
	}
	// Linux IFNAMSIZ is 16 (including null terminator), so max name is 15 chars.
	if len(r.InboundInterface) > 15 {
		return fmt.Errorf("inbound_interface name %q too long; maximum length is 15 characters", r.InboundInterface)
	}
	if len(r.OutboundInterface) > 15 {
		return fmt.Errorf("outbound_interface name %q too long; maximum length is 15 characters", r.OutboundInterface)
	}
	// Input chains only see inbound interfaces; output chains only see outbound.
	// Forward chains see both.
	switch r.Direction {
	case "inbound":
		if r.OutboundInterface != "" {
			return fmt.Errorf("inbound rules may not set outbound_interface")
		}
	case "outbound":
		if r.InboundInterface != "" {
			return fmt.Errorf("outbound rules may not set inbound_interface")
		}
	}
	// Ports only make sense for TCP/UDP — transport header offsets are
	// meaningless for ICMP/ICMPv6 and would match wrong header bytes.
	if (len(r.SrcPort) > 0 || len(r.DstPort) > 0) && r.Protocol != "tcp" && r.Protocol != "udp" {
		return fmt.Errorf("src_port/dst_port require protocol \"tcp\" or \"udp\"")
	}
	for _, p := range r.SrcPort {
		if _, _, err := ParsePortOrRange(p); err != nil {
			return fmt.Errorf("invalid src_port %q: %w", p, err)
		}
	}
	for _, p := range r.DstPort {
		if _, _, err := ParsePortOrRange(p); err != nil {
			return fmt.Errorf("invalid dst_port %q: %w", p, err)
		}
	}
	for _, s := range r.Source {
		if !IsDataRef(s) {
			if _, err := ParseAddress(s); err != nil {
				return fmt.Errorf("invalid source address %q: %w", s, err)
			}
		}
	}
	for _, d := range r.Destination {
		if !IsDataRef(d) {
			if _, err := ParseAddress(d); err != nil {
				return fmt.Errorf("invalid destination address %q: %w", d, err)
			}
		}
	}
	return nil
}

// HashRule returns a hex-encoded SHA-256 hash of a single rule.
// Used by providers for per-rule drift detection (Calico pattern).
func HashRule(r Rule) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\n",
		r.Name, r.Direction, r.InboundInterface, r.OutboundInterface, r.Protocol,
		strings.Join(r.SrcPort, ","), strings.Join(r.DstPort, ","),
		strings.Join(r.Source, ","), strings.Join(r.Destination, ","),
		r.Action, r.Comment)
	return hex.EncodeToString(h.Sum(nil))
}

// IsDataRef reports whether a value is a data.* reference.
func IsDataRef(v string) bool { return strings.HasPrefix(v, "data.") }

// ExpandDataRefs replaces data.* references in a string slice with resolved values.
func ExpandDataRefs(vals []string, resolved map[string][]string) ([]string, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	var out []string
	for _, v := range vals {
		if IsDataRef(v) {
			rs, ok := resolved[v]
			if !ok {
				return nil, fmt.Errorf("unknown data source reference: %s", v)
			}
			out = append(out, rs...)
		} else {
			out = append(out, v)
		}
	}
	return out, nil
}

// Expand returns the rule with Source/Destination data refs substituted.
// Returns skip=true when the original rule had data refs but all resolved to empty —
// the rule is unreachable and should be skipped, not applied as "match anything".
// Post-expansion addresses are re-validated and the slices are canonicalized
// (sorted) so hash drift detection is stable regardless of data source order.
func Expand(r Rule, resolved map[string][]string) (out Rule, skip bool, err error) {
	out = r
	out.Source, err = ExpandDataRefs(r.Source, resolved)
	if err != nil {
		return Rule{}, false, fmt.Errorf("source: %w", err)
	}
	out.Destination, err = ExpandDataRefs(r.Destination, resolved)
	if err != nil {
		return Rule{}, false, fmt.Errorf("destination: %w", err)
	}
	if slices.ContainsFunc(r.Source, IsDataRef) && len(out.Source) == 0 {
		return Rule{}, true, nil
	}
	if slices.ContainsFunc(r.Destination, IsDataRef) && len(out.Destination) == 0 {
		return Rule{}, true, nil
	}
	for _, s := range out.Source {
		if _, err := ParseAddress(s); err != nil {
			return Rule{}, false, fmt.Errorf("source: %w", err)
		}
	}
	for _, d := range out.Destination {
		if _, err := ParseAddress(d); err != nil {
			return Rule{}, false, fmt.Errorf("destination: %w", err)
		}
	}
	slices.Sort(out.Source)
	slices.Sort(out.Destination)
	return out, false, nil
}

// RefsFailedSource reports whether any rule in the set references a failed
// data source. Returns the failed key and true if found.
func RefsFailedSource(rules []Rule, failed map[string]bool) (string, bool) {
	for _, r := range rules {
		for _, v := range r.Source {
			if IsDataRef(v) && failed[v] {
				return v, true
			}
		}
		for _, v := range r.Destination {
			if IsDataRef(v) && failed[v] {
				return v, true
			}
		}
	}
	return "", false
}

// ParseAddress normalizes an IP or CIDR string to a prefix.
func ParseAddress(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address %q", s)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// ParsePortOrRange parses a port ("443") or range ("80-443") string.
func ParsePortOrRange(s string) (lo, hi uint16, err error) {
	if idx := strings.Index(s, "-"); idx >= 0 {
		lo, err = parsePort(s[:idx])
		if err != nil {
			return 0, 0, err
		}
		hi, err = parsePort(s[idx+1:])
		if err != nil {
			return 0, 0, err
		}
		if lo > hi {
			return 0, 0, fmt.Errorf("port range %d-%d: start must be <= end", lo, hi)
		}
		return lo, hi, nil
	}
	p, err := parsePort(s)
	return p, p, err
}

func parsePort(s string) (uint16, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%q is not a valid port", s)
	}
	if p == 0 {
		return 0, fmt.Errorf("port must be 1-65535")
	}
	return uint16(p), nil
}
