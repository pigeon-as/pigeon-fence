package dns

import (
	"context"
	"net"
)

// Config is the HCL body schema for the dns data source.
type Config struct {
	Hostnames  []string `hcl:"hostnames"`           // hostnames to resolve
	Nameserver *string  `hcl:"nameserver,optional"` // custom DNS server (e.g. "8.8.8.8:53")
}

type DataSource struct {
	key       string
	hostnames []string
	resolver  net.Resolver
}

func New(key string, cfg Config) *DataSource {
	s := &DataSource{key: key, hostnames: cfg.Hostnames}
	if cfg.Nameserver != nil && *cfg.Nameserver != "" {
		nameserver := *cfg.Nameserver
		s.resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, nameserver)
		}
	}
	return s
}

func (s *DataSource) Name() string { return s.key }

func (s *DataSource) Resolve(ctx context.Context) ([]string, error) {
	var result []string
	for _, h := range s.hostnames {
		addrs, err := s.resolver.LookupHost(ctx, h)
		if err != nil {
			return nil, err
		}
		result = append(result, addrs...)
	}
	return result, nil
}
