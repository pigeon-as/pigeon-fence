//go:build linux

package nftables

import (
	"fmt"
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

// buildExprs walks the rule fields in a fixed order and emits nftables
// expressions per concern. Each `match*` helper returns nil when the field
// is unset. Order matches the semantic chain: family → interface → proto →
// ports → addresses → verdict. Mirrors the imperative pattern in google/nftables
// tests; the cross-provider abstraction lives one level up in rule.Rule.
func buildExprs(r rule.Rule, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error) {
	var exprs []expr.Any

	family, err := matchFamily(r)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, family...)

	exprs = append(exprs, matchIface(r.InboundInterface, expr.MetaKeyIIFNAME)...)
	exprs = append(exprs, matchIface(r.OutboundInterface, expr.MetaKeyOIFNAME)...)

	proto, err := matchProtocol(r)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, proto...)

	srcPort, err := portExprs(r.SrcPort, thSrcPort, conn, table)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, srcPort...)

	dstPort, err := portExprs(r.DstPort, thDstPort, conn, table)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, dstPort...)

	src, err := addrExprs(r.Source, true, conn, table)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, src...)

	dst, err := addrExprs(r.Destination, false, conn, table)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, dst...)

	verdict, err := matchAction(r.Action)
	if err != nil {
		return nil, err
	}
	exprs = append(exprs, verdict...)

	return exprs, nil
}

// matchFamily gates on IPv4 or IPv6 when addresses are present (inet family correctness).
func matchFamily(r rule.Rule) ([]expr.Any, error) {
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

func matchIface(name string, key expr.MetaKey) []expr.Any {
	if name == "" {
		return nil
	}
	buf := make([]byte, ifnamsiz)
	copy(buf, name)
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: buf},
	}
}

func matchProtocol(r rule.Rule) ([]expr.Any, error) {
	if r.Protocol == "" {
		return nil, nil
	}
	var b byte
	switch r.Protocol {
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
			return nil, fmt.Errorf("protocol \"icmp\" is not valid for IPv6 addresses; use \"icmpv6\"")
		}
		b = syscall.IPPROTO_ICMP
	case "icmpv6":
		family, err := detectFamily(r)
		if err != nil {
			return nil, err
		}
		if family == syscall.AF_INET {
			return nil, fmt.Errorf("protocol \"icmpv6\" is not valid for IPv4 addresses; use \"icmp\"")
		}
		b = syscall.IPPROTO_ICMPV6
	default:
		return nil, fmt.Errorf("unknown protocol %q", r.Protocol)
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{b}},
	}, nil
}

func matchAction(action string) ([]expr.Any, error) {
	switch action {
	case "accept":
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}, nil
	case "drop":
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}, nil
	case "reject":
		return []expr.Any{&expr.Reject{}}, nil
	default:
		return nil, fmt.Errorf("unknown action %q", action)
	}
}
