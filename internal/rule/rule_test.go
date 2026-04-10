package rule

import (
	"net/netip"
	"testing"

	"github.com/shoenig/test/must"
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
				must.Error(t, err)
				return
			}
			must.NoError(t, err)
			must.EqOp(t, tt.want, got)
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
				must.Error(t, err)
				return
			}
			must.NoError(t, err)
			must.EqOp(t, tt.wantLo, lo)
			must.EqOp(t, tt.wantHi, hi)
		})
	}
}

func TestSplitByFamily(t *testing.T) {
	t.Run("no addresses passes through", func(t *testing.T) {
		r := Rule{Name: "test", Action: "accept", Direction: "inbound"}
		got, err := SplitByFamily(r)
		must.NoError(t, err)
		must.Len(t, 1, got)
	})

	t.Run("ipv4 only stays single", func(t *testing.T) {
		r := Rule{Name: "test", Action: "accept", Direction: "inbound", Source: []string{"10.0.0.1"}}
		got, err := SplitByFamily(r)
		must.NoError(t, err)
		must.Len(t, 1, got)
	})

	t.Run("ipv6 only stays single", func(t *testing.T) {
		r := Rule{Name: "test", Action: "accept", Direction: "inbound", Source: []string{"fd00::1"}}
		got, err := SplitByFamily(r)
		must.NoError(t, err)
		must.Len(t, 1, got)
	})

	t.Run("mixed ipv4+ipv6 splits into two", func(t *testing.T) {
		r := Rule{
			Name:      "test",
			Action:    "accept",
			Direction: "inbound",
			Source:    []string{"10.0.0.1", "fd00::1"},
		}
		got, err := SplitByFamily(r)
		must.NoError(t, err)
		must.Len(t, 2, got)
		must.Len(t, 1, got[0].Source)
		must.EqOp(t, "10.0.0.1", got[0].Source[0])
		must.Len(t, 1, got[1].Source)
		must.EqOp(t, "fd00::1", got[1].Source[0])
	})
}

func TestHashRule(t *testing.T) {
	r := Rule{Name: "test", Action: "accept", Direction: "inbound"}

	t.Run("deterministic", func(t *testing.T) {
		must.EqOp(t, HashRule(r), HashRule(r))
	})

	t.Run("unique per rule", func(t *testing.T) {
		r2 := Rule{Name: "other", Action: "accept", Direction: "inbound"}
		must.True(t, HashRule(r) != HashRule(r2))
	})
}

func TestExpandDataRefs(t *testing.T) {
	resolved := map[string][]string{
		"data.ovh_ips.servers": {"1.2.3.4", "5.6.7.8"},
	}

	t.Run("resolves data refs", func(t *testing.T) {
		got, err := ExpandDataRefs([]string{"data.ovh_ips.servers"}, resolved)
		must.NoError(t, err)
		must.Len(t, 2, got)
		must.EqOp(t, "1.2.3.4", got[0])
		must.EqOp(t, "5.6.7.8", got[1])
	})

	t.Run("preserves literals alongside refs", func(t *testing.T) {
		got, err := ExpandDataRefs([]string{"10.0.0.1", "data.ovh_ips.servers"}, resolved)
		must.NoError(t, err)
		must.Len(t, 3, got)
		must.EqOp(t, "10.0.0.1", got[0])
		must.EqOp(t, "1.2.3.4", got[1])
		must.EqOp(t, "5.6.7.8", got[2])
	})

	t.Run("empty input", func(t *testing.T) {
		got, err := ExpandDataRefs(nil, resolved)
		must.NoError(t, err)
		must.Nil(t, got)
	})

	t.Run("unknown data ref errors", func(t *testing.T) {
		_, err := ExpandDataRefs([]string{"data.unknown.ref"}, resolved)
		must.Error(t, err)
	})
}
