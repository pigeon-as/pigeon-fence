package ovhip

import (
	"context"

	"github.com/ovh/go-ovh/ovh"
)

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
	return ips, nil
}
