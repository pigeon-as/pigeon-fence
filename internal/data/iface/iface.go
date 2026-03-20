package iface

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// Config is the HCL body schema for the iface data source.
// Exactly one of Name or IP must be set.
type Config struct {
	Name *string `hcl:"name,optional"` // interface name (e.g. "eth0")
	IP   *string `hcl:"ip,optional"`   // find interface by IP address
}

type DataSource struct {
	key    string
	ifname string // set when Name is used
	ip     string // set when IP is used
}

func New(key string, cfg Config) (*DataSource, error) {
	hasName := cfg.Name != nil && *cfg.Name != ""
	hasIP := cfg.IP != nil && *cfg.IP != ""
	if hasName == hasIP {
		return nil, fmt.Errorf("exactly one of \"name\" or \"ip\" must be set")
	}
	s := &DataSource{key: key}
	if cfg.Name != nil {
		s.ifname = *cfg.Name
	}
	if cfg.IP != nil {
		s.ip = *cfg.IP
	}
	return s, nil
}

func (s *DataSource) Name() string { return s.key }

// Resolve returns the IP addresses (without prefix length) assigned to the interface.
func (s *DataSource) Resolve(_ context.Context) ([]string, error) {
	iface, err := s.findInterface()
	if err != nil {
		return nil, err
	}
	return ifaceAddrs(iface)
}

func (s *DataSource) findInterface() (*net.Interface, error) {
	if s.ifname != "" {
		iface, err := net.InterfaceByName(s.ifname)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", s.ifname, err)
		}
		return iface, nil
	}

	target, err := netip.ParseAddr(s.ip)
	if err != nil {
		return nil, fmt.Errorf("invalid ip %q: %w", s.ip, err)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			return nil, fmt.Errorf("interface %q addrs: %w", ifaces[i].Name, err)
		}
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil {
				return nil, fmt.Errorf("interface %q: unparseable address %q: %w", ifaces[i].Name, a.String(), err)
			}
			if p.Addr() == target {
				return &ifaces[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no interface with ip %q", s.ip)
}

func ifaceAddrs(iface *net.Interface) ([]string, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("interface %q addrs: %w", iface.Name, err)
	}
	var result []string
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			return nil, fmt.Errorf("interface %q: unparseable address %q: %w", iface.Name, a.String(), err)
		}
		result = append(result, p.Addr().String())
	}
	return result, nil
}
