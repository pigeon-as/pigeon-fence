//go:build linux

package nftables

import (
	"net"
	"reflect"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

// requireExprs compares nftables expression slices using reflect.DeepEqual.
// All expr types have exported fields so DeepEqual works correctly
// (same approach used in google/nftables own tests).
func requireExprs(t *testing.T, want, got []expr.Any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("\nwant: %#v\ngot:  %#v", want, got)
	}
}

func ifname(s string) []byte {
	b := make([]byte, ifnamsiz)
	copy(b, s)
	return b
}

// --- Direction ---

func TestMapDirection(t *testing.T) {
	tests := []struct {
		input string
		want  string
		err   bool
	}{
		{"inbound", "input", false},
		{"outbound", "output", false},
		{"forward", "forward", false},
		{"bogus", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := mapDirection(tt.input)
			if tt.err {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestChainHookPriority(t *testing.T) {
	tests := []struct {
		chain    string
		wantHook *nftables.ChainHook
	}{
		{"input", nftables.ChainHookInput},
		{"output", nftables.ChainHookOutput},
		{"forward", nftables.ChainHookForward},
	}
	for _, tt := range tests {
		t.Run(tt.chain, func(t *testing.T) {
			hook, prio := chainHookPriority(tt.chain)
			if hook != tt.wantHook {
				t.Fatalf("hook: got %v, want %v", hook, tt.wantHook)
			}
			if prio != nftables.ChainPriorityFilter {
				t.Fatalf("priority: got %v, want ChainPriorityFilter", prio)
			}
		})
	}
}

// --- Family ---

func TestMatchFamily(t *testing.T) {
	tests := []struct {
		name string
		rule rule.Rule
		want []expr.Any
	}{
		{"ipv4 source", rule.Rule{Source: []string{"10.0.0.1"}}, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syscall.AF_INET}},
		}},
		{"ipv6 destination", rule.Rule{Destination: []string{"fd00::1"}}, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syscall.AF_INET6}},
		}},
		{"no addresses", rule.Rule{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchFamily(tt.rule, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			requireExprs(t, tt.want, got)
		})
	}
}

// --- Interface ---

func TestMatchInboundInterface(t *testing.T) {
	tests := []struct {
		name string
		rule rule.Rule
		want []expr.Any
	}{
		{"eth0", rule.Rule{InboundInterface: "eth0"}, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("eth0")},
		}},
		{"empty", rule.Rule{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchInboundInterface(tt.rule, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			requireExprs(t, tt.want, got)
		})
	}
}

func TestMatchOutboundInterface(t *testing.T) {
	tests := []struct {
		name string
		rule rule.Rule
		want []expr.Any
	}{
		{"eth0", rule.Rule{OutboundInterface: "eth0"}, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("eth0")},
		}},
		{"empty", rule.Rule{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchOutboundInterface(tt.rule, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			requireExprs(t, tt.want, got)
		})
	}
}

// --- Protocol ---

func TestMatchProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		want     []expr.Any
	}{
		{"tcp", "tcp", []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syscall.IPPROTO_TCP}},
		}},
		{"udp", "udp", []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syscall.IPPROTO_UDP}},
		}},
		{"icmp", "icmp", []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syscall.IPPROTO_ICMP}},
		}},
		{"empty", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchProtocol(rule.Rule{Protocol: tt.protocol}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			requireExprs(t, tt.want, got)
		})
	}

	t.Run("icmpv6 explicit", func(t *testing.T) {
		r := rule.Rule{Protocol: "icmpv6"}
		got, err := matchProtocol(r, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireExprs(t, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syscall.IPPROTO_ICMPV6}},
		}, got)
	})

	t.Run("icmp with ipv6 errors", func(t *testing.T) {
		r := rule.Rule{Protocol: "icmp", Source: []string{"fd00::1"}}
		_, err := matchProtocol(r, nil, nil)
		if err == nil {
			t.Fatal("expected error for icmp with IPv6 addresses")
		}
	})

	t.Run("icmpv6 with ipv4 errors", func(t *testing.T) {
		r := rule.Rule{Protocol: "icmpv6", Source: []string{"10.0.0.1"}}
		_, err := matchProtocol(r, nil, nil)
		if err == nil {
			t.Fatal("expected error for icmpv6 with IPv4 addresses")
		}
	})

	t.Run("icmp ipv4 stays ICMP", func(t *testing.T) {
		r := rule.Rule{Protocol: "icmp", Source: []string{"10.0.0.1"}}
		got, err := matchProtocol(r, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireExprs(t, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syscall.IPPROTO_ICMP}},
		}, got)
	})

	t.Run("unknown returns error", func(t *testing.T) {
		_, err := matchProtocol(rule.Rule{Protocol: "sctp"}, nil, nil)
		if err == nil {
			t.Fatal("expected error for unknown protocol")
		}
	})
}

// --- Action ---

func TestMatchAction(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   []expr.Any
	}{
		{"accept", "accept", []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}},
		{"drop", "drop", []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}},
		{"reject", "reject", []expr.Any{&expr.Reject{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchAction(rule.Rule{Action: tt.action}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			requireExprs(t, tt.want, got)
		})
	}

	t.Run("unknown returns error", func(t *testing.T) {
		_, err := matchAction(rule.Rule{Action: "bogus"}, nil, nil)
		if err == nil {
			t.Fatal("expected error for unknown action")
		}
	})
}

// --- Ports ---

func TestPortExprs(t *testing.T) {
	t.Run("single port", func(t *testing.T) {
		got, err := portExprs([]string{"22"}, thDstPort, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireExprs(t, []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: thDstPort, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(22)},
		}, got)
	})

	t.Run("port range", func(t *testing.T) {
		got, err := portExprs([]string{"80-443"}, thDstPort, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireExprs(t, []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: thDstPort, Len: 2},
			&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(80)},
			&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(443)},
		}, got)
	})

	t.Run("empty", func(t *testing.T) {
		got, err := portExprs(nil, thDstPort, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("got %v, want nil", got)
		}
	})
}

// --- Addresses ---

func TestAddrExprs(t *testing.T) {
	t.Run("ipv4 host src", func(t *testing.T) {
		got, err := addrExprs([]string{"10.0.0.1"}, true, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireExprs(t, []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: ipv4SrcAddr, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 0, 0, 1}},
		}, got)
	})

	t.Run("ipv4 host dst", func(t *testing.T) {
		got, err := addrExprs([]string{"10.0.0.1"}, false, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireExprs(t, []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: ipv4DstAddr, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 0, 0, 1}},
		}, got)
	})

	t.Run("ipv6 host src", func(t *testing.T) {
		got, err := addrExprs([]string{"fd00::1"}, true, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireExprs(t, []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: ipv6SrcAddr, Len: 16},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{
				0xfd, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 1,
			}},
		}, got)
	})

	t.Run("ipv4 cidr /8", func(t *testing.T) {
		got, err := addrExprs([]string{"10.0.0.0/8"}, true, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireExprs(t, []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: ipv4SrcAddr, Len: 4},
			&expr.Bitwise{
				SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: net.CIDRMask(8, 32),
				Xor:  make([]byte, 4),
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 0, 0, 0}},
		}, got)
	})

	t.Run("empty", func(t *testing.T) {
		got, err := addrExprs(nil, true, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("got %v, want nil", got)
		}
	})
}

// --- Integration: full rule → full expression chain ---

// TestBuildExprs_FullRule verifies a complete firewall rule produces the
// exact expected nftables expression chain. An auditor verifies this
// matches nft semantics.
func TestBuildExprs_FullRule(t *testing.T) {
	// Rule: allow TCP port 22 inbound on eth0 from 10.0.0.0/8.
	r := rule.Rule{
		Name:             "ssh",
		Direction:        "inbound",
		InboundInterface: "eth0",
		Protocol:         "tcp",
		DstPort:          []string{"22"},
		Source:           []string{"10.0.0.0/8"},
		Action:           "accept",
	}

	got, err := buildExprs(r, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	want := []expr.Any{
		// 1. Family gate: meta nfproto == ipv4
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syscall.AF_INET}},
		// 2. Interface: meta iifname == "eth0"
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("eth0")},
		// 3. Protocol: meta l4proto == tcp
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{syscall.IPPROTO_TCP}},
		// 4. Dst port: th dport == 22
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: thDstPort, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(22)},
		// 5. Source: nh saddr & 0xff000000 == 0x0a000000
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: ipv4SrcAddr, Len: 4},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: net.CIDRMask(8, 32), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{10, 0, 0, 0}},
		// 6. Verdict: accept
		&expr.Verdict{Kind: expr.VerdictAccept},
	}

	requireExprs(t, want, got)
}

// --- Base Rules ---

func TestBaseRulesInputChain(t *testing.T) {
	rules := baseRules("input")
	if len(rules) != 3 {
		t.Fatalf("input chain: got %d base rules, want 3", len(rules))
	}

	// Rule 0: ct state established,related accept
	requireExprs(t, ctStateAcceptExprs(), rules[0].exprs)
	if string(rules[0].userData) != "__base:ct-accept\x00pf:__base" {
		t.Fatalf("rule 0 userData: got %q", string(rules[0].userData))
	}

	// Rule 1: ct state invalid drop
	requireExprs(t, ctStateInvalidExprs(), rules[1].exprs)
	if string(rules[1].userData) != "__base:ct-invalid\x00pf:__base" {
		t.Fatalf("rule 1 userData: got %q", string(rules[1].userData))
	}

	// Rule 2: iifname "lo" accept
	requireExprs(t, loAcceptExprs(), rules[2].exprs)
	if string(rules[2].userData) != "__base:lo-accept\x00pf:__base" {
		t.Fatalf("rule 2 userData: got %q", string(rules[2].userData))
	}
}

func TestBaseRulesOutputChain(t *testing.T) {
	rules := baseRules("output")
	if len(rules) != 2 {
		t.Fatalf("output chain: got %d base rules, want 2", len(rules))
	}

	// No lo accept for output/forward.
	for _, r := range rules {
		if string(r.userData) == "__base:lo-accept\x00pf:__base" {
			t.Fatal("lo-accept should not appear in output chain")
		}
	}
}

func TestBaseRulesForwardChain(t *testing.T) {
	rules := baseRules("forward")
	if len(rules) != 2 {
		t.Fatalf("forward chain: got %d base rules, want 2", len(rules))
	}
}

func TestBaseRuleCount(t *testing.T) {
	if got := baseRuleCount("input"); got != 3 {
		t.Fatalf("input: got %d, want 3", got)
	}
	if got := baseRuleCount("output"); got != 2 {
		t.Fatalf("output: got %d, want 2", got)
	}
	if got := baseRuleCount("forward"); got != 2 {
		t.Fatalf("forward: got %d, want 2", got)
	}
}

func TestCtStateAcceptExprs(t *testing.T) {
	exprs := ctStateAcceptExprs()
	if len(exprs) != 4 {
		t.Fatalf("got %d exprs, want 4", len(exprs))
	}
	// Check ct state load
	ct, ok := exprs[0].(*expr.Ct)
	if !ok || ct.Key != expr.CtKeySTATE {
		t.Fatal("first expr should be Ct with CtKeySTATE")
	}
	// Check verdict is accept
	v, ok := exprs[3].(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictAccept {
		t.Fatal("last expr should be VerdictAccept")
	}
}

func TestCtStateInvalidExprs(t *testing.T) {
	exprs := ctStateInvalidExprs()
	if len(exprs) != 4 {
		t.Fatalf("got %d exprs, want 4", len(exprs))
	}
	// Check verdict is drop
	v, ok := exprs[3].(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictDrop {
		t.Fatal("last expr should be VerdictDrop")
	}
}

func TestLoAcceptExprs(t *testing.T) {
	exprs := loAcceptExprs()
	if len(exprs) != 3 {
		t.Fatalf("got %d exprs, want 3", len(exprs))
	}
	// Check interface meta load
	meta, ok := exprs[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyIIFNAME {
		t.Fatal("first expr should be Meta IIFNAME")
	}
	// Check lo name comparison
	cmp, ok := exprs[1].(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpEq {
		t.Fatal("second expr should be CmpEq")
	}
	wantLo := make([]byte, ifnamsiz)
	copy(wantLo, "lo")
	if !reflect.DeepEqual(cmp.Data, wantLo) {
		t.Fatalf("interface name: got %v, want %v", cmp.Data, wantLo)
	}
	// Check verdict is accept
	v, ok := exprs[2].(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictAccept {
		t.Fatal("last expr should be VerdictAccept")
	}
}
