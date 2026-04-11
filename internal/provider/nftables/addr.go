//go:build linux

package nftables

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

func addrExprs(addrs []string, isSrc bool, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error) {
	if len(addrs) == 0 {
		return nil, nil
	}

	prefixes := make([]netip.Prefix, len(addrs))
	for i, a := range addrs {
		p, err := rule.ParseAddress(a)
		if err != nil {
			return nil, err
		}
		prefixes[i] = p
	}

	isV4 := prefixes[0].Addr().Is4()
	var payloadOffset, addrLen uint32
	if isV4 {
		addrLen = 4
		payloadOffset = ipv4SrcAddr
		if !isSrc {
			payloadOffset = ipv4DstAddr
		}
	} else {
		addrLen = 16
		payloadOffset = ipv6SrcAddr
		if !isSrc {
			payloadOffset = ipv6DstAddr
		}
	}

	// Single host address: inline comparison.
	if len(prefixes) == 1 && prefixes[0].Bits() == int(addrLen)*8 {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: payloadOffset, Len: addrLen},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addrBytes(prefixes[0].Addr())},
		}, nil
	}

	// Single CIDR: inline bitwise + comparison.
	if len(prefixes) == 1 {
		return cidrExprs(prefixes[0], payloadOffset, addrLen)
	}

	// Multiple addresses/CIDRs: anonymous interval set.
	var keyType nftables.SetDatatype
	if isV4 {
		keyType = nftables.TypeIPAddr
	} else {
		keyType = nftables.TypeIP6Addr
	}

	set := &nftables.Set{
		Table:     table,
		Anonymous: true,
		Constant:  true,
		KeyType:   keyType,
		Interval:  true,
	}

	var elements []nftables.SetElement
	for _, p := range prefixes {
		elements = append(elements,
			nftables.SetElement{Key: prefixStart(p)},
			nftables.SetElement{Key: prefixEnd(p), IntervalEnd: true},
		)
	}

	if err := conn.AddSet(set, elements); err != nil {
		return nil, fmt.Errorf("add address set: %w", err)
	}

	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: payloadOffset, Len: addrLen},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
	}, nil
}

// cidrExprs builds inline bitwise+comparison expressions for a single CIDR prefix.
// The prefix is already masked by ParseAddress, so Addr() is the network address.
func cidrExprs(p netip.Prefix, offset, addrLen uint32) ([]expr.Any, error) {
	mask := net.CIDRMask(p.Bits(), int(addrLen)*8)
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: addrLen},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: addrLen, Mask: mask, Xor: make([]byte, addrLen)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addrBytes(p.Addr())},
	}, nil
}

func addrBytes(addr netip.Addr) []byte {
	if addr.Is4() {
		b := addr.As4()
		return b[:]
	}
	b := addr.As16()
	return b[:]
}

func prefixStart(p netip.Prefix) []byte {
	return addrBytes(p.Masked().Addr())
}

// prefixEnd returns the first address past the prefix (exclusive upper
// bound for nftables interval sets). Computed as broadcast | ~mask + 1.
// For /0 prefixes (entire address space), returns all-ones — nftables
// treats this as "end of range" when combined with IntervalEnd.
func prefixEnd(p netip.Prefix) []byte {
	start := addrBytes(p.Masked().Addr())
	mask := net.CIDRMask(p.Bits(), len(start)*8)
	end := make([]byte, len(start))
	for i := range end {
		end[i] = start[i] | ^mask[i] // broadcast
	}
	// +1 for exclusive upper bound. If this overflows (only happens
	// for /0 — broadcast is already all-ones), return all-zeros which
	// nftables interprets as wrapping to the end of the address space.
	for i := len(end) - 1; i >= 0; i-- {
		end[i]++
		if end[i] != 0 {
			break
		}
	}
	return end
}
