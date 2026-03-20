package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/dynblock"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/pigeon-as/pigeon-fence/internal/rule"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

type Config struct {
	Locals      []LocalsBlock    `hcl:"locals,block"`
	Providers   []ProviderConfig `hcl:"provider,block"`
	DataSources []DataConfig     `hcl:"data,block"`
	Rules       []rule.Rule      `hcl:"rule,block"`
	Interval    string           `hcl:"interval,optional"`
	LogLevel    string           `hcl:"log_level,optional"`
}

// LocalsBlock: attributes are evaluated during config loading
// and available as local.<name> in expressions.
type LocalsBlock struct {
	Attrs hcl.Body `hcl:",remain"`
}

type ProviderConfig struct {
	Type string   `hcl:"type,label"`
	Body hcl.Body `hcl:",remain"`
}

type DataConfig struct {
	Type string   `hcl:"type,label"`
	Name string   `hcl:"name,label"`
	Body hcl.Body `hcl:",remain"`
}

// Key returns the HCL reference key for this data source (e.g. "data.ovh_ips.servers").
func (d DataConfig) Key() string {
	return "data." + d.Type + "." + d.Name
}

// IntervalDuration parses the validated interval string.
func (c Config) IntervalDuration() time.Duration {
	d, _ := time.ParseDuration(c.Interval)
	return d
}

// SlogLevel parses the validated log level string.
func (c Config) SlogLevel() slog.Level {
	var l slog.Level
	l.UnmarshalText([]byte(c.LogLevel))
	return l
}

// Load reads HCL config from a file or directory.
// Directory: all *.hcl files merged in alphabetical order.
// Two-pass: first extracts labels+locals for EvalContext, then decodes with dynblock expansion.
func Load(path string) (Config, error) {
	body, err := parseBody(path)
	if err != nil {
		return Config{}, err
	}

	// First pass: extract block labels + locals for EvalContext.
	ectx, err := buildEvalContext(body)
	if err != nil {
		return Config{}, err
	}

	// Expand dynamic blocks.
	expanded := dynblock.Expand(body, ectx)

	var cfg Config
	diags := gohcl.DecodeBody(expanded, ectx, &cfg)
	if diags.HasErrors() {
		return Config{}, fmt.Errorf("decode config: %s", diags.Error())
	}

	if cfg.Interval == "" {
		cfg.Interval = "60s"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	if err := validate(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func parseBody(path string) (hcl.Body, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("config path: %w", err)
	}

	parser := hclparse.NewParser()

	if !fi.IsDir() {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		file, diags := parser.ParseHCL(data, path)
		if diags.HasErrors() {
			return nil, fmt.Errorf("parse config: %s", diags.Error())
		}
		return file.Body, nil
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read config dir: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".hcl") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	if len(names) == 0 {
		return nil, fmt.Errorf("no *.hcl files in %s", path)
	}

	var files []*hcl.File
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		file, diags := parser.ParseHCL(data, name)
		if diags.HasErrors() {
			return nil, fmt.Errorf("parse %s: %s", name, diags.Error())
		}
		files = append(files, file)
	}

	return hcl.MergeFiles(files), nil
}

// labelsOnly: first-pass partial decode to extract block labels.
type labelsOnly struct {
	Providers   []singleLabel `hcl:"provider,block"`
	DataSources []labelPair   `hcl:"data,block"`
	Locals      []localsBlock `hcl:"locals,block"`
	Remain      hcl.Body      `hcl:",remain"`
}
type singleLabel struct {
	Type   string   `hcl:"type,label"`
	Remain hcl.Body `hcl:",remain"`
}
type labelPair struct {
	Type   string   `hcl:"type,label"`
	Name   string   `hcl:"name,label"`
	Remain hcl.Body `hcl:",remain"`
}
type localsBlock struct {
	Remain hcl.Body `hcl:",remain"`
}

// buildEvalContext extracts provider/data labels and locals into HCL variables:
//
//	provider.<type>, data.<type>.<name>, local.<name>
func buildEvalContext(body hcl.Body) (*hcl.EvalContext, error) {
	var labels labelsOnly
	// Ignore diags — only care about block labels.
	gohcl.DecodeBody(body, nil, &labels)

	provObj := make(map[string]cty.Value)
	for _, p := range labels.Providers {
		provObj[p.Type] = cty.StringVal(p.Type)
	}

	dataByType := make(map[string]map[string]cty.Value)
	for _, d := range labels.DataSources {
		if dataByType[d.Type] == nil {
			dataByType[d.Type] = make(map[string]cty.Value)
		}
		dataByType[d.Type][d.Name] = cty.StringVal("data." + d.Type + "." + d.Name)
	}
	dataObj := make(map[string]cty.Value)
	for typ, names := range dataByType {
		dataObj[typ] = cty.ObjectVal(names)
	}

	vars := make(map[string]cty.Value)
	if len(provObj) > 0 {
		vars["provider"] = cty.ObjectVal(provObj)
	}
	if len(dataObj) > 0 {
		vars["data"] = cty.ObjectVal(dataObj)
	}

	funcs := map[string]function.Function{
		"concat":   stdlib.ConcatFunc,
		"flatten":  stdlib.FlattenFunc,
		"distinct": stdlib.DistinctFunc,
	}

	// Evaluate locals blocks in order (inter-block references allowed).
	// Within each block, use multi-pass evaluation so intra-block references
	// resolve regardless of map iteration order (Terraform evaluates locals
	// via a dependency DAG; multi-pass is the simpler equivalent).
	ctx := &hcl.EvalContext{Variables: vars, Functions: funcs}
	localVars := make(map[string]cty.Value)
	for _, lb := range labels.Locals {
		attrs, diags := lb.Remain.JustAttributes()
		if diags.HasErrors() {
			return nil, fmt.Errorf("locals: %s", diags.Error())
		}

		// Multi-pass: evaluate what we can, defer the rest, repeat.
		pending := make(map[string]*hcl.Attribute, len(attrs))
		for k, v := range attrs {
			pending[k] = v
		}
		for len(pending) > 0 {
			progress := false
			// Sorted keys for deterministic error messages.
			names := make([]string, 0, len(pending))
			for k := range pending {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, name := range names {
				val, diags := pending[name].Expr.Value(ctx)
				if diags.HasErrors() {
					// Only defer if all errors look like unresolved
					// dependencies (unknown variable/attribute). Real
					// errors (type mismatch, bad function call) surface
					// immediately so they aren't masked as "unresolvable
					// reference".
					if hasFatalDiag(diags) {
						return nil, fmt.Errorf("local.%s: %s", name, diags.Error())
					}
					continue // dependency not yet available
				}
				localVars[name] = val
				delete(pending, name)
				progress = true
			}
			if !progress {
				// All remaining locals have unresolvable references.
				names = names[:0]
				for k := range pending {
					names = append(names, k)
				}
				sort.Strings(names)
				return nil, fmt.Errorf("local.%s: unresolvable reference (circular or undefined)", names[0])
			}
			// Rebuild context so next pass sees newly evaluated locals.
			vars["local"] = cty.ObjectVal(localVars)
			ctx = &hcl.EvalContext{Variables: vars, Functions: funcs}
		}
	}

	return ctx, nil
}

func validate(cfg Config) error {
	d, err := time.ParseDuration(cfg.Interval)
	if err != nil {
		return fmt.Errorf("invalid interval: %w", err)
	}
	if d <= 0 {
		return fmt.Errorf("invalid interval %q: must be greater than 0", cfg.Interval)
	}

	var l slog.Level
	if err := l.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return fmt.Errorf("invalid log_level %q: %w", cfg.LogLevel, err)
	}

	providers := make(map[string]bool)
	for _, p := range cfg.Providers {
		if providers[p.Type] {
			return fmt.Errorf("duplicate provider type %q", p.Type)
		}
		providers[p.Type] = true
	}

	dataNames := make(map[string]bool)
	for _, d := range cfg.DataSources {
		key := d.Type + "." + d.Name
		if dataNames[key] {
			return fmt.Errorf("duplicate data source %q", key)
		}
		dataNames[key] = true
	}

	ruleNames := make(map[string]bool)
	for i, r := range cfg.Rules {
		if ruleNames[r.Name] {
			return fmt.Errorf("rule[%d] %q: duplicate rule name", i, r.Name)
		}
		ruleNames[r.Name] = true

		if r.Direction == "" {
			return fmt.Errorf("rule[%d] %q: direction is required", i, r.Name)
		}
		if r.Direction != "inbound" && r.Direction != "outbound" {
			return fmt.Errorf("rule[%d] %q: direction must be \"inbound\" or \"outbound\"", i, r.Name)
		}
		if r.Action == "" {
			return fmt.Errorf("rule[%d] %q: action is required", i, r.Name)
		}
		if !rule.ValidActions[r.Action] {
			return fmt.Errorf("rule[%d] %q: invalid action %q (must be allow or deny)", i, r.Name, r.Action)
		}
		if !providers[r.Provider] {
			return fmt.Errorf("rule[%d] %q: unknown provider type %q", i, r.Name, r.Provider)
		}

		if r.Protocol != "" && !rule.ValidProtocols[r.Protocol] {
			return fmt.Errorf("rule[%d] %q: invalid protocol %q (must be tcp, udp, icmp, or icmpv6)", i, r.Name, r.Protocol)
		}
		// Linux IFNAMSIZ is 16 (including null terminator), so max name is 15 chars.
		if len(r.Interface) > 15 {
			return fmt.Errorf("rule[%d] %q: interface name %q too long; maximum length is 15 characters", i, r.Name, r.Interface)
		}
		// Ports only make sense for TCP/UDP — transport header offsets are
		// meaningless for ICMP/ICMPv6 and would match wrong header bytes.
		if (len(r.SrcPort) > 0 || len(r.DstPort) > 0) && r.Protocol != "tcp" && r.Protocol != "udp" {
			return fmt.Errorf("rule[%d] %q: src_port/dst_port require protocol \"tcp\" or \"udp\"", i, r.Name)
		}
		for _, p := range r.SrcPort {
			if _, _, err := rule.ParsePortOrRange(p); err != nil {
				return fmt.Errorf("rule[%d] %q: invalid src_port %q: %w", i, r.Name, p, err)
			}
		}
		for _, p := range r.DstPort {
			if _, _, err := rule.ParsePortOrRange(p); err != nil {
				return fmt.Errorf("rule[%d] %q: invalid dst_port %q: %w", i, r.Name, p, err)
			}
		}

		// Validate static address literals (non-data.* refs) at load time.
		for _, s := range r.Source {
			if !strings.HasPrefix(s, "data.") {
				if _, err := rule.ParseAddress(s); err != nil {
					return fmt.Errorf("rule[%d] %q: invalid source address %q: %w", i, r.Name, s, err)
				}
			}
		}
		for _, d := range r.Destination {
			if !strings.HasPrefix(d, "data.") {
				if _, err := rule.ParseAddress(d); err != nil {
					return fmt.Errorf("rule[%d] %q: invalid destination address %q: %w", i, r.Name, d, err)
				}
			}
		}
	}

	return nil
}

// hasFatalDiag returns true if any error diagnostic is NOT a dependency error
// (i.e., not an unresolved variable/attribute). Dependency errors have
// summary "Unknown variable" or "Unsupported attribute" in HCL v2.
func hasFatalDiag(diags hcl.Diagnostics) bool {
	for _, d := range diags {
		if d.Severity != hcl.DiagError {
			continue
		}
		switch d.Summary {
		case "Unknown variable", "Unsupported attribute":
			// Likely an unresolved dependency — defer.
		default:
			return true
		}
	}
	return false
}
