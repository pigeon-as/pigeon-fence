package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shoenig/test/must"
)

// writeFile creates a temporary HCL file. Returns the file path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte(content), 0644)
	must.NoError(t, err)
	return path
}

func TestLoad_MinimalFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "ssh" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["22"]
  action    = "accept"
}
`)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.Len(t, 1, cfg.Providers)
	must.EqOp(t, "nftables", cfg.Providers[0].Type)
	must.Len(t, 1, cfg.Rules)
	must.EqOp(t, "ssh", cfg.Rules[0].Name)
}

func TestLoad_Defaults(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "accept"
}
`)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.EqOp(t, "60s", cfg.Interval)
	must.EqOp(t, "info", cfg.LogLevel)
}

func TestLoad_DirectoryMerge(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "01-provider.hcl", `provider "nftables" {}`)
	writeFile(t, dir, "02-rules.hcl", `
rule "ssh" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["22"]
  action    = "accept"
}
`)

	cfg, err := Load(dir)
	must.NoError(t, err)
	must.Len(t, 1, cfg.Providers)
	must.Len(t, 1, cfg.Rules)
}

func TestLoad_DirectoryIgnoresNonHCL(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.hcl", `
provider "nftables" {}
rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "accept"
}
`)
	writeFile(t, dir, "README.md", "# not HCL")

	cfg, err := Load(dir)
	must.NoError(t, err)
	must.Len(t, 1, cfg.Rules)
}

func TestLoad_EmptyDirectoryErrors(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	must.Error(t, err)
}

func TestLoad_Locals(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

locals {
  port = "443"
}

rule "https" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = [local.port]
  action    = "accept"
}
`)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.EqOp(t, "443", cfg.Rules[0].DstPort[0])
}

func TestLoad_LocalsInterBlock(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

locals {
  base_port = "80"
}

locals {
  port = local.base_port
}

rule "web" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = [local.port]
  action    = "accept"
}
`)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.EqOp(t, "80", cfg.Rules[0].DstPort[0])
}

func TestLoad_LocalsIntraBlockOrder(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

locals {
  b = local.a
  a = "443"
}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = [local.b]
  action    = "accept"
}
`)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.EqOp(t, "443", cfg.Rules[0].DstPort[0])
}

func TestLoad_LocalsCircularErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

locals {
  a = local.b
  b = local.a
}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "accept"
}
`)

	_, err := Load(path)
	must.Error(t, err)
	must.StrContains(t, err.Error(), "circular dependency")
}

func TestLoad_DynamicRules(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

locals {
  services = {
    http  = "80"
    https = "443"
  }
}

dynamic "rule" {
  for_each = local.services
  labels   = [rule.key]
  content {
    provider  = provider.nftables
    direction = "inbound"
    protocol  = "tcp"
    dst_port  = [rule.value]
    action    = "accept"
  }
}
`)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.Len(t, 2, cfg.Rules)
}

func TestLoad_DataSourceRef(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

data "dns" "monitoring" {
  hostnames = ["example.com"]
}

rule "allow_monitoring" {
  provider  = provider.nftables
  direction = "inbound"
  source    = [data.dns.monitoring]
  protocol  = "tcp"
  dst_port  = ["443"]
  action    = "accept"
}
`)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.Len(t, 1, cfg.DataSources)
	// Source should contain the data ref string.
	must.EqOp(t, "data.dns.monitoring", cfg.Rules[0].Source[0])
}

// --- Validation errors ---

func TestValidate_DuplicateProviderErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}
provider "nftables" {}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "accept"
}
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestValidate_DuplicateRuleNameErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "ssh" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "accept"
}

rule "ssh" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "drop"
}
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestValidate_InvalidDirectionErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider  = provider.nftables
  direction = "sideways"
  action    = "accept"
}
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestValidate_InvalidProtocolErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "sctp"
  action    = "accept"
}
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestValidate_InvalidActionErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "bogus"
}
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestValidate_InvalidIntervalErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "accept"
}

interval = "not-a-duration"
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestValidate_ZeroIntervalErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "accept"
}

interval = "0s"
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestLoad_MultipleRules(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "accept"
}

rule "other" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "accept"
}
`)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.Len(t, 2, cfg.Rules)
}

func TestValidate_InboundOutboundInterfaceErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider           = provider.nftables
  direction          = "inbound"
  action             = "accept"
  outbound_interface = "eth0"
}
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestValidate_OutboundInboundInterfaceErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider          = provider.nftables
  direction         = "outbound"
  action            = "accept"
  inbound_interface = "eth0"
}
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestValidate_ForwardBothInterfacesSucceeds(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider           = provider.nftables
  direction          = "forward"
  action             = "accept"
  inbound_interface  = "eth0"
  outbound_interface = "wg0"
}
`)

	_, err := Load(path)
	must.NoError(t, err)
}

func TestValidate_OVHProviderRulePassesConfig(t *testing.T) {
	// OVH rules pass config validation (provider is declared).
	// The factory rejects them because OVH has no reconciler.
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}
provider "ovh" {
  endpoint           = "ovh-eu"
  application_key    = "key"
  application_secret = "secret"
  consumer_key       = "consumer"
}

rule "test" {
  provider  = provider.ovh
  direction = "inbound"
  action    = "accept"
}
`)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.EqOp(t, "ovh", cfg.Rules[0].Provider)
}

func TestValidate_InvalidPortErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["abc"]
  action    = "accept"
}
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestValidate_PortWithoutTcpUdpErrors(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
	}{
		{"icmp", "icmp"},
		{"icmpv6", "icmpv6"},
		{"empty protocol", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			proto := ""
			if tt.protocol != "" {
				proto = `protocol  = "` + tt.protocol + `"`
			}
			writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  `+proto+`
  dst_port  = ["22"]
  action    = "accept"
}
`)
			_, err := Load(dir)
			must.Error(t, err)
			must.StrContains(t, err.Error(), "src_port/dst_port require")
		})
	}
}

func TestValidate_PortWithTcpUdpSucceeds(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		t.Run(proto, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "`+proto+`"
  dst_port  = ["22"]
  action    = "accept"
}
`)
			_, err := Load(dir)
			must.NoError(t, err)
		})
	}
}

func TestValidate_InvalidAddressErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  source    = ["not-an-ip"]
  action    = "accept"
}
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestValidate_IFNAMSIZErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

rule "test" {
  provider     = provider.nftables
  direction    = "inbound"
  inbound_interface = "this-name-is-way-too-long"
  action       = "accept"
}
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestValidate_DuplicateDataSourceErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

data "dns" "test" {
  hostnames = ["a.example.com"]
}

data "dns" "test" {
  hostnames = ["b.example.com"]
}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "accept"
}
`)

	_, err := Load(path)
	must.Error(t, err)
}

func TestLoad_MultiplePaths(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	writeFile(t, dir1, "base.hcl", `
provider "nftables" {}

rule "ssh" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["22"]
  action    = "accept"
}
`)
	writeFile(t, dir2, "extra.hcl", `
rule "https" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["443"]
  action    = "accept"
}
`)

	cfg, err := Load(dir1, dir2)
	must.NoError(t, err)
	must.Len(t, 1, cfg.Providers)
	must.Len(t, 2, cfg.Rules)
}

func TestLoad_MissingPathSkipped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "base.hcl", `
provider "nftables" {}

rule "ssh" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["22"]
  action    = "accept"
}
`)

	cfg, err := Load(dir, "/nonexistent/path/does/not/exist")
	must.NoError(t, err)
	must.Len(t, 1, cfg.Rules)
}

func TestLoad_AllPathsMissingErrors(t *testing.T) {
	_, err := Load("/nonexistent/a", "/nonexistent/b")
	must.Error(t, err)
	must.StrContains(t, err.Error(), "no *.hcl files")
}

func TestLoad_HCLFunctions(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fence.hcl", `
provider "nftables" {}

locals {
  a = ["22"]
  b = ["443"]
  ports = distinct(flatten(concat(local.a, local.b)))
}

rule "test" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = local.ports
  action    = "accept"
}
`)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.Len(t, 2, cfg.Rules[0].DstPort)
}
