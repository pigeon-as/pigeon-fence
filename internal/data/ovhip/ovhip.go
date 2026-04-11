package ovhip

import (
	"context"
	"fmt"

	"github.com/ovh/go-ovh/ovh"
	"github.com/pigeon-as/pigeon-fence/internal/data"
)

// maxIPs is a sanity bound on OVH API responses. A typical OVH account
// has dozens to low hundreds of IPs. 10 000 is generous enough to never
// trip in normal use but prevents an anomalous result from propagating
// into nftables rule sets. Note: go-ovh handles HTTP and JSON decoding
// internally, so the full response is already in memory at this point.
const maxIPs = 10_000

var _ data.DataSource = (*DataSource)(nil)

type DataSource struct {
	key    string
	client *ovh.Client
}

func New(key string, client *ovh.Client) *DataSource {
	return &DataSource{key: key, client: client}
}

func (s *DataSource) Name() string { return s.key }

func (s *DataSource) Resolve(ctx context.Context) ([]string, error) {
	var ips []string
	if err := s.client.GetWithContext(ctx, "/ip", &ips); err != nil {
		return nil, err
	}
	if len(ips) > maxIPs {
		return nil, fmt.Errorf("OVH /ip returned %d entries (max %d)", len(ips), maxIPs)
	}
	return ips, nil
}
