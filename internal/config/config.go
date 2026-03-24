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

// Load reads HCL config from one or more files or directories.
// Directories: all *.hcl files merged in alphabetical order.
// Multiple paths: files collected from all paths, merged together.
// Missing paths are skipped — useful when a config directory doesn't exist yet.
// Two-pass: first extracts labels+locals for EvalContext, then decodes with dynblock expansion.
func Load(paths ...string) (Config, error) {
	body, err := parseBody(paths)
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

func parseBody(paths []string) (hcl.Body, error) {
	parser := hclparse.NewParser()
	var files []*hcl.File

	for _, path := range paths {
		fi, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue // skip missing paths
			}
			return nil, fmt.Errorf("config path %q: %w", path, err)
		}

		if !fi.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read config: %w", err)
			}
			file, diags := parser.ParseHCL(data, path)
			if diags.HasErrors() {
				return nil, fmt.Errorf("parse config: %s", diags.Error())
			}
			files = append(files, file)
			continue
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
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no *.hcl files found in config paths")
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
	// Within each block, topological sort via expr.Variables() ensures
	// intra-block dependencies evaluate in the right order (Terraform pattern).
	ctx := &hcl.EvalContext{Variables: vars, Functions: funcs}
	localVars := make(map[string]cty.Value)
	for _, lb := range labels.Locals {
		attrs, diags := lb.Remain.JustAttributes()
		if diags.HasErrors() {
			return nil, fmt.Errorf("locals: %s", diags.Error())
		}

		order, err := topoSortLocals(attrs)
		if err != nil {
			return nil, err
		}
		for _, name := range order {
			val, diags := attrs[name].Expr.Value(ctx)
			if diags.HasErrors() {
				return nil, fmt.Errorf("local.%s: %s", name, diags.Error())
			}
			localVars[name] = val
			vars["local"] = cty.ObjectVal(localVars)
			ctx = &hcl.EvalContext{Variables: vars, Functions: funcs}
		}
	}

	return ctx, nil
}

// topoSortLocals returns local attribute names in evaluation order using
// Kahn's algorithm. Detects cycles. Dependencies are extracted via the
// HCL expr.Variables() API (same approach as Terraform).
func topoSortLocals(attrs map[string]*hcl.Attribute) ([]string, error) {
	inDegree := make(map[string]int, len(attrs))
	dependents := make(map[string][]string, len(attrs))
	for name := range attrs {
		inDegree[name] = 0
	}
	for name, attr := range attrs {
		for _, t := range attr.Expr.Variables() {
			if t.RootName() != "local" || len(t) < 2 {
				continue
			}
			if step, ok := t[1].(hcl.TraverseAttr); ok {
				if _, exists := attrs[step.Name]; exists {
					inDegree[name]++
					dependents[step.Name] = append(dependents[step.Name], name)
				}
			}
		}
	}

	var queue []string
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}
	sort.Strings(queue)

	order := make([]string, 0, len(attrs))
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		order = append(order, name)
		next := dependents[name]
		sort.Strings(next)
		for _, d := range next {
			inDegree[d]--
			if inDegree[d] == 0 {
				queue = append(queue, d)
			}
		}
		sort.Strings(queue)
	}

	if len(order) != len(attrs) {
		var cyclic []string
		for name, deg := range inDegree {
			if deg > 0 {
				cyclic = append(cyclic, name)
			}
		}
		sort.Strings(cyclic)
		return nil, fmt.Errorf("local.%s: circular dependency", cyclic[0])
	}
	return order, nil
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
		if r.Direction != "inbound" && r.Direction != "outbound" && r.Direction != "forward" {
			return fmt.Errorf("rule[%d] %q: direction must be \"inbound\", \"outbound\", or \"forward\"", i, r.Name)
		}
		if r.Action == "" {
			return fmt.Errorf("rule[%d] %q: action is required", i, r.Name)
		}
		if !rule.ValidActions[r.Action] {
			return fmt.Errorf("rule[%d] %q: invalid action %q (must be accept, drop, or reject)", i, r.Name, r.Action)
		}
		if !providers[r.Provider] {
			return fmt.Errorf("rule[%d] %q: unknown provider type %q", i, r.Name, r.Provider)
		}

		if r.Protocol != "" && !rule.ValidProtocols[r.Protocol] {
			return fmt.Errorf("rule[%d] %q: invalid protocol %q (must be tcp, udp, icmp, or icmpv6)", i, r.Name, r.Protocol)
		}
		// Linux IFNAMSIZ is 16 (including null terminator), so max name is 15 chars.
		if len(r.InboundInterface) > 15 {
			return fmt.Errorf("rule[%d] %q: inbound_interface name %q too long; maximum length is 15 characters", i, r.Name, r.InboundInterface)
		}
		if len(r.OutboundInterface) > 15 {
			return fmt.Errorf("rule[%d] %q: outbound_interface name %q too long; maximum length is 15 characters", i, r.Name, r.OutboundInterface)
		}
		// Input chains only see inbound interfaces; output chains only see outbound.
		// Forward chains see both.
		switch r.Direction {
		case "inbound":
			if r.OutboundInterface != "" {
				return fmt.Errorf("rule[%d] %q: inbound rules may not set outbound_interface", i, r.Name)
			}
		case "outbound":
			if r.InboundInterface != "" {
				return fmt.Errorf("rule[%d] %q: outbound rules may not set inbound_interface", i, r.Name)
			}
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
