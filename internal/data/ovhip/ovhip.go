// Package ovhip resolves all IPs from an OVH account via the OVH API.
//
// Credentials come from env vars ($OVH_ENDPOINT, $OVH_APPLICATION_KEY,
// $OVH_APPLICATION_SECRET, $OVH_CONSUMER_KEY) or ~/.ovh.conf — the go-ovh
// SDK's default fallback. No HCL credentials fields.
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
// into nftables rule sets.
const maxIPs = 10_000

var _ data.DataSource = (*DataSource)(nil)

type DataSource struct {
	client *ovh.Client
}

func New() (*DataSource, error) {
	client, err := ovh.NewClient("", "", "", "")
	if err != nil {
		return nil, fmt.Errorf("ovh client: %w", err)
	}
	return &DataSource{client: client}, nil
}

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
