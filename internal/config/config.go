package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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
	Locals      []LocalsBlock
	Providers   []ProviderConfig
	DataSources []DataConfig
	Rules       []rule.Rule
	Interval    time.Duration
	LogLevel    slog.Level
}

// rawConfig mirrors Config with HCL tags and string-typed scalars,
// parsed to time.Duration / slog.Level during Load.
type rawConfig struct {
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
	Type string `hcl:"type,label"`
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

	var raw rawConfig
	diags := gohcl.DecodeBody(expanded, ectx, &raw)
	if diags.HasErrors() {
		return Config{}, fmt.Errorf("decode config: %s", diags.Error())
	}

	if raw.Interval == "" {
		raw.Interval = "60s"
	}
	if raw.LogLevel == "" {
		raw.LogLevel = "info"
	}

	interval, err := time.ParseDuration(raw.Interval)
	if err != nil {
		return Config{}, fmt.Errorf("invalid interval: %w", err)
	}
	if interval <= 0 {
		return Config{}, fmt.Errorf("invalid interval %q: must be greater than 0", raw.Interval)
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(raw.LogLevel)); err != nil {
		return Config{}, fmt.Errorf("invalid log_level %q: %w", raw.LogLevel, err)
	}

	cfg := Config{
		Locals:      raw.Locals,
		Providers:   raw.Providers,
		DataSources: raw.DataSources,
		Rules:       raw.Rules,
		Interval:    interval,
		LogLevel:    level,
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
				return nil, fmt.Errorf("read %s: %w", path, err)
			}
			file, diags := parser.ParseHCL(data, path)
			if diags.HasErrors() {
				return nil, fmt.Errorf("parse %s: %s", path, diags.Error())
			}
			files = append(files, file)
			continue
		}

		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("read dir %s: %w", path, err)
		}

		var names []string
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".hcl") {
				continue
			}
			names = append(names, e.Name())
		}
		slices.Sort(names)

		for _, name := range names {
			full := filepath.Join(path, name)
			data, err := os.ReadFile(full)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", full, err)
			}
			file, diags := parser.ParseHCL(data, full)
			if diags.HasErrors() {
				return nil, fmt.Errorf("parse %s: %s", full, diags.Error())
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
	slices.Sort(queue)

	order := make([]string, 0, len(attrs))
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		order = append(order, name)
		next := dependents[name]
		slices.Sort(next)
		for _, d := range next {
			inDegree[d]--
			if inDegree[d] == 0 {
				queue = append(queue, d)
			}
		}
		slices.Sort(queue)
	}

	if len(order) != len(attrs) {
		var cyclic []string
		for name, deg := range inDegree {
			if deg > 0 {
				cyclic = append(cyclic, name)
			}
		}
		slices.Sort(cyclic)
		return nil, fmt.Errorf("local.%s: circular dependency", cyclic[0])
	}
	return order, nil
}

func validate(cfg Config) error {
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
		if !providers[r.Provider] {
			return fmt.Errorf("rule[%d] %q: unknown provider type %q", i, r.Name, r.Provider)
		}
		if err := rule.Validate(r); err != nil {
			return fmt.Errorf("rule[%d] %q: %w", i, r.Name, err)
		}
	}

	return nil
}
