//go:build linux

package runner

import (
	"fmt"
	"log/slog"

	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/pigeon-as/pigeon-fence/internal/config"
	"github.com/pigeon-as/pigeon-fence/internal/data"
	"github.com/pigeon-as/pigeon-fence/internal/data/dns"
	"github.com/pigeon-as/pigeon-fence/internal/data/iface"
	"github.com/pigeon-as/pigeon-fence/internal/data/ovhip"
	"github.com/pigeon-as/pigeon-fence/internal/provider"
	nftprov "github.com/pigeon-as/pigeon-fence/internal/provider/nftables"
	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

type providerEntry struct {
	name     string
	provider provider.Provider
	rules    []rule.Rule
}

type dataEntry struct {
	key    string
	source data.DataSource
}

// build creates providers and data sources from config.
// This is the single wiring point — to add a provider or data source,
// add a case here.
func build(logger *slog.Logger, cfg config.Config) ([]providerEntry, []dataEntry, error) {
	var entries []providerEntry
	for _, pc := range cfg.Providers {
		switch pc.Type {
		case "nftables":
			entries = append(entries, providerEntry{
				name:     pc.Type,
				provider: nftprov.New(logger),
				rules:    filterRules(cfg.Rules, pc.Type),
			})
		default:
			return nil, nil, fmt.Errorf("unknown provider type %q", pc.Type)
		}
	}

	var sources []dataEntry
	for _, dc := range cfg.DataSources {
		var ds data.DataSource
		switch dc.Type {
		case "ovh_ips":
			s, err := ovhip.New()
			if err != nil {
				return nil, nil, fmt.Errorf("data source %s: %w", dc.Key(), err)
			}
			ds = s
		case "dns":
			var dcfg dns.Config
			diags := gohcl.DecodeBody(dc.Body, nil, &dcfg)
			if diags.HasErrors() {
				return nil, nil, fmt.Errorf("data source %s: %s", dc.Key(), diags.Error())
			}
			ds = dns.New(dcfg)
		case "iface":
			var dcfg iface.Config
			diags := gohcl.DecodeBody(dc.Body, nil, &dcfg)
			if diags.HasErrors() {
				return nil, nil, fmt.Errorf("data source %s: %s", dc.Key(), diags.Error())
			}
			s, err := iface.New(dcfg)
			if err != nil {
				return nil, nil, fmt.Errorf("data source %s: %w", dc.Key(), err)
			}
			ds = s
		default:
			return nil, nil, fmt.Errorf("unknown data source type %q", dc.Type)
		}
		sources = append(sources, dataEntry{key: dc.Key(), source: ds})
		logger.Debug("created data source", "key", dc.Key(), "type", dc.Type)
	}

	// Reject rules that target a provider without a reconciler.
	reconcilers := make(map[string]bool, len(entries))
	for _, e := range entries {
		reconcilers[e.name] = true
	}
	for _, r := range cfg.Rules {
		if !reconcilers[r.ProviderKey()] {
			return nil, nil, fmt.Errorf("rule %q: provider %q does not support rules", r.Name, r.ProviderKey())
		}
	}

	return entries, sources, nil
}

func filterRules(rules []rule.Rule, key string) []rule.Rule {
	var out []rule.Rule
	for _, r := range rules {
		if r.ProviderKey() == key {
			out = append(out, r)
		}
	}
	return out
}
