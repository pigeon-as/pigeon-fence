//go:build linux

package nftables

import (
	"fmt"

	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

// splitByFamily splits a rule with mixed IPv4/IPv6 addresses into family-specific
// rules. Required for nftables `inet` tables: a single rule can't match both
// families because the address offset differs between IPv4 and IPv6 headers.
// Rules without addresses pass through unchanged.
func splitByFamily(r rule.Rule) ([]rule.Rule, error) {
	if len(r.Source) == 0 && len(r.Destination) == 0 {
		return []rule.Rule{r}, nil
	}

	srcV4, srcV6, err := partitionByFamily(r.Source)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	dstV4, dstV6, err := partitionByFamily(r.Destination)
	if err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}

	var rules []rule.Rule
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
		p, err := rule.ParseAddress(a)
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
