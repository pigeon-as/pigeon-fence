//go:build linux

package nftables

import (
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// Base rules are prepended to every chain before user rules.
// They implement the VyOS global state-policy pattern:
//
//	ct state established,related accept  — all chains
//	ct state invalid drop                — all chains
//	iifname "lo" accept                  — input chain only
//
// Without these, policy-drop chains would drop return traffic for
// established connections — breaking every protocol.
const baseHashMarker = "__base"

type baseRule struct {
	exprs    []expr.Any
	userData []byte
}

// baseRules returns the automatic rules for a given chain name.
// These are added before user rules in every base chain.
func baseRules(chainName string) []baseRule {
	rules := []baseRule{
		{
			exprs:    ctStateAcceptExprs(),
			userData: []byte("__base:ct-accept\x00" + hashPrefix + baseHashMarker),
		},
		{
			exprs:    ctStateInvalidExprs(),
			userData: []byte("__base:ct-invalid\x00" + hashPrefix + baseHashMarker),
		},
	}
	if chainName == "input" {
		rules = append(rules, baseRule{
			exprs:    loAcceptExprs(),
			userData: []byte("__base:lo-accept\x00" + hashPrefix + baseHashMarker),
		})
	}
	return rules
}

// baseRuleCount returns how many base rules a chain has.
func baseRuleCount(chainName string) int {
	if chainName == "input" {
		return 3
	}
	return 2
}

// ctStateAcceptExprs: ct state established,related accept
func ctStateAcceptExprs() []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// ctStateInvalidExprs: ct state invalid drop
func ctStateInvalidExprs() []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitINVALID),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// loAcceptExprs: iifname "lo" accept
func loAcceptExprs() []expr.Any {
	lo := make([]byte, ifnamsiz)
	copy(lo, "lo")
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: lo},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}
