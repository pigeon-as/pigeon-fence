//go:build linux

package nftables

import (
	"testing"

	"github.com/shoenig/test/must"

	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

func TestSplitByFamily(t *testing.T) {
	t.Run("no addresses passes through", func(t *testing.T) {
		r := rule.Rule{Name: "test", Action: "accept", Direction: "inbound"}
		got, err := splitByFamily(r)
		must.NoError(t, err)
		must.Len(t, 1, got)
	})

	t.Run("ipv4 only stays single", func(t *testing.T) {
		r := rule.Rule{Name: "test", Action: "accept", Direction: "inbound", Source: []string{"10.0.0.1"}}
		got, err := splitByFamily(r)
		must.NoError(t, err)
		must.Len(t, 1, got)
	})

	t.Run("ipv6 only stays single", func(t *testing.T) {
		r := rule.Rule{Name: "test", Action: "accept", Direction: "inbound", Source: []string{"fd00::1"}}
		got, err := splitByFamily(r)
		must.NoError(t, err)
		must.Len(t, 1, got)
	})

	t.Run("mixed ipv4+ipv6 splits into two", func(t *testing.T) {
		r := rule.Rule{
			Name:      "test",
			Action:    "accept",
			Direction: "inbound",
			Source:    []string{"10.0.0.1", "fd00::1"},
		}
		got, err := splitByFamily(r)
		must.NoError(t, err)
		must.Len(t, 2, got)
		must.Len(t, 1, got[0].Source)
		must.EqOp(t, "10.0.0.1", got[0].Source[0])
		must.Len(t, 1, got[1].Source)
		must.EqOp(t, "fd00::1", got[1].Source[0])
	})
}
