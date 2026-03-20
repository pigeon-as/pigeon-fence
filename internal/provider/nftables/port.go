//go:build linux

package nftables

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

func portExprs(ports []string, offset uint32, conn *nftables.Conn, table *nftables.Table) ([]expr.Any, error) {
	if len(ports) == 0 {
		return nil, nil
	}

	// Single port: inline comparison.
	if len(ports) == 1 {
		lo, hi, err := rule.ParsePortOrRange(ports[0])
		if err != nil {
			return nil, err
		}
		if lo == hi {
			return []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(lo)},
			}, nil
		}
		// Single range: inline >= lo, <= hi.
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2},
			&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(lo)},
			&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(hi)},
		}, nil
	}

	// Multiple ports/ranges: anonymous interval set.
	set := &nftables.Set{
		Table:     table,
		Anonymous: true,
		Constant:  true,
		KeyType:   nftables.TypeInetService,
		Interval:  true,
	}

	var elements []nftables.SetElement
	for _, p := range ports {
		lo, hi, err := rule.ParsePortOrRange(p)
		if err != nil {
			return nil, err
		}
		elements = append(elements,
			nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(lo)},
			nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(hi + 1), IntervalEnd: true},
		)
	}
	// Port 65535 causes hi+1 to overflow to 0. nftables interprets
	// a zero IntervalEnd as "unbounded above", which is correct.

	if err := conn.AddSet(set, elements); err != nil {
		return nil, fmt.Errorf("add port set: %w", err)
	}

	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
	}, nil
}
