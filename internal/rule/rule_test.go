package rule

import (
	"net/netip"
	"testing"
)

func TestParseAddress(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    netip.Prefix
		wantErr bool
	}{
		{"ipv4 host", "10.0.0.1", netip.MustParsePrefix("10.0.0.1/32"), false},
		{"ipv4 cidr", "10.0.0.0/8", netip.MustParsePrefix("10.0.0.0/8"), false},
		{"ipv6 host", "fd00::1", netip.MustParsePrefix("fd00::1/128"), false},
		{"ipv6 cidr", "fd00::/16", netip.MustParsePrefix("fd00::/16"), false},
		{"invalid", "not-an-ip", netip.Prefix{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAddress(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePortOrRange(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLo  uint16
		wantHi  uint16
		wantErr bool
	}{
		{"single port", "443", 443, 443, false},
		{"range", "80-443", 80, 443, false},
		{"max port", "65535", 65535, 65535, false},
		{"inverted range", "443-80", 0, 0, true},
		{"port zero", "0", 0, 0, true},
		{"invalid", "abc", 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lo, hi, err := ParsePortOrRange(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if lo != tt.wantLo || hi != tt.wantHi {
				t.Fatalf("got %d-%d, want %d-%d", lo, hi, tt.wantLo, tt.wantHi)
			}
		})
	}
}

func TestSplitByFamily(t *testing.T) {
	t.Run("no addresses passes through", func(t *testing.T) {
		r := Rule{Name: "test", Action: "allow", Direction: "inbound"}
		got, err := SplitByFamily(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d rules, want 1", len(got))
		}
	})

	t.Run("ipv4 only stays single", func(t *testing.T) {
		r := Rule{Name: "test", Action: "allow", Direction: "inbound", Source: []string{"10.0.0.1"}}
		got, err := SplitByFamily(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d rules, want 1", len(got))
		}
	})

	t.Run("ipv6 only stays single", func(t *testing.T) {
		r := Rule{Name: "test", Action: "allow", Direction: "inbound", Source: []string{"fd00::1"}}
		got, err := SplitByFamily(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d rules, want 1", len(got))
		}
	})

	t.Run("mixed ipv4+ipv6 splits into two", func(t *testing.T) {
		r := Rule{
			Name:      "test",
			Action:    "allow",
			Direction: "inbound",
			Source:    []string{"10.0.0.1", "fd00::1"},
		}
		got, err := SplitByFamily(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d rules, want 2", len(got))
		}
		if len(got[0].Source) != 1 || got[0].Source[0] != "10.0.0.1" {
			t.Fatalf("rule[0] source = %v, want [10.0.0.1]", got[0].Source)
		}
		if len(got[1].Source) != 1 || got[1].Source[0] != "fd00::1" {
			t.Fatalf("rule[1] source = %v, want [fd00::1]", got[1].Source)
		}
	})
}

func TestHashRule(t *testing.T) {
	r := Rule{Name: "test", Action: "allow", Direction: "inbound"}

	t.Run("deterministic", func(t *testing.T) {
		if HashRule(r) != HashRule(r) {
			t.Fatal("same rule produced different hashes")
		}
	})

	t.Run("unique per rule", func(t *testing.T) {
		r2 := Rule{Name: "other", Action: "allow", Direction: "inbound"}
		if HashRule(r) == HashRule(r2) {
			t.Fatal("different rules produced same hash")
		}
	})
}

func TestExpandDataRefs(t *testing.T) {
	resolved := map[string][]string{
		"data.ovh_ips.servers": {"1.2.3.4", "5.6.7.8"},
	}

	t.Run("resolves data refs", func(t *testing.T) {
		got, err := ExpandDataRefs([]string{"data.ovh_ips.servers"}, resolved)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0] != "1.2.3.4" || got[1] != "5.6.7.8" {
			t.Fatalf("got %v, want [1.2.3.4 5.6.7.8]", got)
		}
	})

	t.Run("preserves literals alongside refs", func(t *testing.T) {
		got, err := ExpandDataRefs([]string{"10.0.0.1", "data.ovh_ips.servers"}, resolved)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 || got[0] != "10.0.0.1" || got[1] != "1.2.3.4" || got[2] != "5.6.7.8" {
			t.Fatalf("got %v, want [10.0.0.1 1.2.3.4 5.6.7.8]", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		got, err := ExpandDataRefs(nil, resolved)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("got %v, want nil", got)
		}
	})

	t.Run("unknown data ref errors", func(t *testing.T) {
		_, err := ExpandDataRefs([]string{"data.unknown.ref"}, resolved)
		if err == nil {
			t.Fatal("expected error for unknown data ref")
		}
	})
}
