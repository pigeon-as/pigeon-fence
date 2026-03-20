package rule

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ValidActions defines the actions supported by all providers.
var ValidActions = map[string]bool{"allow": true, "deny": true}

// ValidProtocols defines the protocols supported by all providers.
var ValidProtocols = map[string]bool{"tcp": true, "udp": true, "icmp": true}

// Rule represents a single firewall rule to be reconciled by a provider.
type Rule struct {
	Name        string   `hcl:"name,label"`
	Provider    string   `hcl:"provider"`
	Direction   string   `hcl:"direction"` // "inbound", "outbound"
	IP          string   `hcl:"ip,optional"`
	Source      []string `hcl:"source,optional"`
	Destination []string `hcl:"destination,optional"`
	Protocol    string   `hcl:"protocol,optional"`
	SrcPort     []string `hcl:"src_port,optional"`
	DstPort     []string `hcl:"dst_port,optional"`
	Action      string   `hcl:"action"`
	Interface   string   `hcl:"interface,optional"`
	Comment     string   `hcl:"comment,optional"`
}

func (r Rule) ProviderKey() string { return r.Provider }

// HashRule returns a hex-encoded SHA-256 hash of a single rule.
// Used by providers for per-rule drift detection (Calico pattern).
func HashRule(r Rule) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\n",
		r.Name, r.Direction, r.IP, r.Interface, r.Protocol,
		strings.Join(r.SrcPort, ","), strings.Join(r.DstPort, ","),
		strings.Join(r.Source, ","), strings.Join(r.Destination, ","),
		r.Action, r.Comment)
	return hex.EncodeToString(h.Sum(nil))
}

// ExpandDataRefs replaces data.* references in a string slice with resolved values.
func ExpandDataRefs(vals []string, resolved map[string][]string) []string {
	if len(vals) == 0 {
		return nil
	}
	var out []string
	for _, v := range vals {
		if strings.HasPrefix(v, "data.") {
			if rs, ok := resolved[v]; ok {
				out = append(out, rs...)
			}
		} else {
			out = append(out, v)
		}
	}
	return out
}

// SplitByFamily splits a rule with mixed IPv4/IPv6 addresses into
// family-specific rules. Rules without addresses pass through unchanged.
func SplitByFamily(r Rule) ([]Rule, error) {
	if len(r.Source) == 0 && len(r.Destination) == 0 {
		return []Rule{r}, nil
	}

	srcV4, srcV6, err := partitionByFamily(r.Source)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	dstV4, dstV6, err := partitionByFamily(r.Destination)
	if err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}

	var rules []Rule
	if canMatch(r.Source, srcV4, r.Destination, dstV4) {
		v4 := r
		v4.Source = srcV4
		v4.Destination = dstV4
		rules = append(rules, v4)
	}
	if canMatch(r.Source, srcV6, r.Destination, dstV6) {
		v6 := r
		v6.Source = srcV6
		v6.Destination = dstV6
		rules = append(rules, v6)
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf("incompatible address families: source and destination have no overlapping IP family")
	}
	return rules, nil
}

// canMatch returns true if a rule for this family has valid constraints.
// A specified field (non-empty original) that lost all entries can't match.
func canMatch(origSrc, filteredSrc, origDst, filteredDst []string) bool {
	if len(origSrc) > 0 && len(filteredSrc) == 0 {
		return false
	}
	if len(origDst) > 0 && len(filteredDst) == 0 {
		return false
	}
	return len(filteredSrc) > 0 || len(filteredDst) > 0
}

func partitionByFamily(addrs []string) (v4, v6 []string, err error) {
	for _, a := range addrs {
		p, err := ParseAddress(a)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid address %q: %w", a, err)
		}
		if p.Addr().Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	return v4, v6, nil
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
