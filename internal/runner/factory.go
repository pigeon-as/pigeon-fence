//go:build linux

package runner

import (
	"fmt"
	"log/slog"

	"github.com/hashicorp/hcl/v2/gohcl"
	ovhsdk "github.com/ovh/go-ovh/ovh"
	"github.com/pigeon-as/pigeon-fence/internal/config"
	"github.com/pigeon-as/pigeon-fence/internal/data"
	"github.com/pigeon-as/pigeon-fence/internal/data/dns"
	"github.com/pigeon-as/pigeon-fence/internal/data/iface"
	"github.com/pigeon-as/pigeon-fence/internal/data/ovhip"
	"github.com/pigeon-as/pigeon-fence/internal/provider"
	nftprov "github.com/pigeon-as/pigeon-fence/internal/provider/nftables"
	ovhprov "github.com/pigeon-as/pigeon-fence/internal/provider/ovh"
	"github.com/pigeon-as/pigeon-fence/internal/rule"
)

type providerEntry struct {
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

	// Shared API clients, created by providers and available to data sources.
	var ovhClient *ovhsdk.Client

	for _, pc := range cfg.Providers {
		switch pc.Type {
		case "nftables":
			entries = append(entries, providerEntry{
					provider: nftprov.New(nftprov.Config{
					Name:   pc.Type,
					Logger: logger,
				}),
				rules: filterRules(cfg.Rules, pc.Type),
			})
		case "ovh":
			client, err := ovhprov.NewClient(pc.Body)
			if err != nil {
				return nil, nil, fmt.Errorf("provider %q: %w", pc.Type, err)
			}
			ovhClient = client

			entries = append(entries, providerEntry{
				provider: ovhprov.New(ovhprov.Config{
					Name:   pc.Type,
					Logger: logger,
					Client: client,
				}),
				rules: filterRules(cfg.Rules, pc.Type),
			})
		default:
			return nil, nil, fmt.Errorf("unknown provider type %q", pc.Type)
		}
	}

	// Run provider-specific rule validation if the provider implements it.
	for _, e := range entries {
		v, ok := e.provider.(provider.RuleValidator)
		if !ok {
			continue
		}
		for _, r := range e.rules {
			if err := v.ValidateRule(r); err != nil {
				return nil, nil, fmt.Errorf("rule %q: %w", r.Name, err)
			}
		}
	}

	// Data sources — declaration order preserved for deterministic iteration.
	var sources []dataEntry
	for _, dc := range cfg.DataSources {
		var ds data.DataSource
		switch dc.Type {
		case "ovh_ips":
			if ovhClient == nil {
				return nil, nil, fmt.Errorf("data source %s: requires provider \"ovh\"", dc.Key())
			}
			ds = ovhip.New(dc.Key(), ovhClient)
		case "dns":
			var dcfg dns.Config
			diags := gohcl.DecodeBody(dc.Body, nil, &dcfg)
			if diags.HasErrors() {
				return nil, nil, fmt.Errorf("data source %s: %s", dc.Key(), diags.Error())
			}
			ds = dns.New(dc.Key(), dcfg)
		case "iface":
			var dcfg iface.Config
			diags := gohcl.DecodeBody(dc.Body, nil, &dcfg)
			if diags.HasErrors() {
				return nil, nil, fmt.Errorf("data source %s: %s", dc.Key(), diags.Error())
			}
			var err error
			ds, err = iface.New(dc.Key(), dcfg)
			if err != nil {
				return nil, nil, fmt.Errorf("data source %s: %w", dc.Key(), err)
			}
		default:
			return nil, nil, fmt.Errorf("unknown data source type %q", dc.Type)
		}
		sources = append(sources, dataEntry{key: dc.Key(), source: ds})
		logger.Debug("created data source", "key", dc.Key(), "type", dc.Type)
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
