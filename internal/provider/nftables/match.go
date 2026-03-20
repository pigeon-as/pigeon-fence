//go:build linux

package nftables

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

const (
	ifnamsiz = 16 // IFNAMSIZ: max Linux interface name length including \0

	// TCP/UDP transport header offsets (RFC 793 / RFC 768).
	thSrcPort uint32 = 0
	thDstPort uint32 = 2

	// IPv4 header address offsets (RFC 791).
	ipv4SrcAddr uint32 = 12
	ipv4DstAddr uint32 = 16

	// IPv6 header address offsets (RFC 8200).
	ipv6SrcAddr uint32 = 8
	ipv6DstAddr uint32 = 24
)

// matcher returns nftables expressions for one aspect of a rule.
type matcher func(r rule.Rule, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error)

// matchers defines the expression build order. Each matcher appends its
// expressions; the concatenated result forms a complete nftables rule.
var matchers = []matcher{
	matchFamily,
	matchInterface,
	matchProtocol,
	matchSrcPort,
	matchDstPort,
	matchSource,
	matchDestination,
	matchAction,
}

func buildExprs(r rule.Rule, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error) {
	var exprs []expr.Any
	for _, m := range matchers {
		e, err := m(r, conn, table)
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, e...)
	}
	return exprs, nil
}

// matchFamily gates on IPv4 or IPv6 when addresses are present (inet family correctness).
func matchFamily(r rule.Rule, _ *nftables.Conn, _ *nftables.Table) ([]expr.Any, error) {
	family, err := detectFamily(r)
	if err != nil {
		return nil, err
	}
	if family == 0 {
		return nil, nil
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
	}, nil
}

func detectFamily(r rule.Rule) (byte, error) {
	for _, s := range r.Source {
		p, err := rule.ParseAddress(s)
		if err != nil {
			return 0, fmt.Errorf("source address %q: %w", s, err)
		}
		if p.Addr().Is4() {
			return syscall.AF_INET, nil
		}
		return syscall.AF_INET6, nil
	}
	for _, d := range r.Destination {
		p, err := rule.ParseAddress(d)
		if err != nil {
			return 0, fmt.Errorf("destination address %q: %w", d, err)
		}
		if p.Addr().Is4() {
			return syscall.AF_INET, nil
		}
		return syscall.AF_INET6, nil
	}
	return 0, nil
}

func matchInterface(r rule.Rule, _ *nftables.Conn, _ *nftables.Table) ([]expr.Any, error) {
	if r.Interface == "" {
		return nil, nil
	}
	name := make([]byte, ifnamsiz)
	copy(name, r.Interface)
	key := expr.MetaKeyIIFNAME
	if r.Direction == "outbound" {
		key = expr.MetaKeyOIFNAME
	}
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name},
	}, nil
}

func matchProtocol(r rule.Rule, _ *nftables.Conn, _ *nftables.Table) ([]expr.Any, error) {
	if r.Protocol == "" {
		return nil, nil
	}
	var b byte
	switch strings.ToLower(r.Protocol) {
	case "tcp":
		b = syscall.IPPROTO_TCP
	case "udp":
		b = syscall.IPPROTO_UDP
	case "icmp":
		family, err := detectFamily(r)
		if err != nil {
			return nil, err
		}
		if family == syscall.AF_INET6 {
			b = syscall.IPPROTO_ICMPV6
		} else {
			b = syscall.IPPROTO_ICMP
		}
	default:
		return nil, fmt.Errorf("unknown protocol %q", r.Protocol)
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{b}},
	}, nil
}

func matchSrcPort(r rule.Rule, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error) {
	return portExprs(r.SrcPort, thSrcPort, conn, table)
}

func matchDstPort(r rule.Rule, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error) {
	return portExprs(r.DstPort, thDstPort, conn, table)
}

func matchSource(r rule.Rule, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error) {
	return addrExprs(r.Source, true, conn, table)
}

func matchDestination(r rule.Rule, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error) {
	return addrExprs(r.Destination, false, conn, table)
}

func matchAction(r rule.Rule, _ *nftables.Conn, _ *nftables.Table) ([]expr.Any, error) {
	switch r.Action {
	case "allow":
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}, nil
	case "deny":
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}, nil
	default:
		return nil, fmt.Errorf("unknown action %q", r.Action)
	}
}
