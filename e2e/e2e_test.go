//go:build e2e

// Run: make e2e (builds the binary, then runs these tests as root)

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shoenig/test/must"
)

var binary string

func TestMain(m *testing.M) {
	if err := exec.Command("nft", "list", "tables").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "skipping e2e: nftables unavailable: %v\n", err)
		os.Exit(0)
	}

	wd, _ := os.Getwd()
	binary = filepath.Join(wd, "..", "build", "pigeon-fence")
	if _, err := os.Stat(binary); err != nil {
		if p, err := exec.LookPath("pigeon-fence"); err == nil {
			binary = p
		}
	}
	os.Exit(m.Run())
}

// --- Helpers ---

// run executes a command, logs it, returns trimmed stdout, fails on error.
func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	t.Logf("RUN '%s %s'", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	b, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(b))
	if err != nil {
		t.Log("ERR:", err)
		t.Log("OUT:", output)
		t.FailNow()
	}
	return output
}

// cleanup deletes the pigeon-fence table (best-effort).
func cleanup(t *testing.T) {
	t.Helper()
	exec.Command("nft", "delete", "table", "inet", "pigeon-fence").Run()
}

// fence runs pigeon-fence --once with the given HCL config.
func fence(t *testing.T, hcl string) string {
	t.Helper()
	t.Cleanup(func() { cleanup(t) })
	cleanup(t)

	path := filepath.Join(t.TempDir(), "fence.hcl")
	must.NoError(t, os.WriteFile(path, []byte(hcl), 0644))

	run(t, binary, "--once", "--config="+path, "--log-level=debug")
	return tableOutput(t)
}

// fenceFail runs pigeon-fence --once and expects a non-zero exit.
func fenceFail(t *testing.T, hcl string) string {
	t.Helper()
	t.Cleanup(func() { cleanup(t) })
	cleanup(t)

	path := filepath.Join(t.TempDir(), "fence.hcl")
	must.NoError(t, os.WriteFile(path, []byte(hcl), 0644))

	cmd := exec.Command(binary, "--once", "--config="+path)
	out, err := cmd.CombinedOutput()
	must.Error(t, err)
	return string(out)
}

// tableExists checks whether `nft list table inet pigeon-fence` succeeds.
func tableExists(t *testing.T) bool {
	t.Helper()
	return exec.Command("nft", "list", "table", "inet", "pigeon-fence").Run() == nil
}

// tableOutput returns the full `nft list table` output.
func tableOutput(t *testing.T) string {
	t.Helper()
	return run(t, "nft", "list", "table", "inet", "pigeon-fence")
}

// --- Tests ---

func TestBinaryExists(t *testing.T) {
	_, err := os.Stat(binary)
	must.NoError(t, err)
}

func TestStaticRules(t *testing.T) {
	out := fence(t, `
provider "nftables" {}

rule "allow_ssh" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["22"]
  action    = "accept"
  comment   = "SSH"
}

rule "deny_all" {
  provider  = provider.nftables
  direction = "inbound"
  action    = "drop"
  comment   = "default deny"
}
`)

	must.StrContains(t, out, "tcp dport 22 accept")
	must.StrContains(t, out, "drop")
}

func TestOutboundRule(t *testing.T) {
	out := fence(t, `
provider "nftables" {}

rule "block_outbound" {
  provider    = provider.nftables
  direction   = "outbound"
  protocol    = "tcp"
  dst_port    = ["9999"]
  action      = "drop"
}
`)

	must.StrContains(t, out, "tcp dport 9999 drop")
}

func TestMixedDirections(t *testing.T) {
	out := fence(t, `
provider "nftables" {}

rule "allow_ssh" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["22"]
  action    = "accept"
}

rule "allow_dns_out" {
  provider  = provider.nftables
  direction = "outbound"
  protocol  = "udp"
  dst_port  = ["53"]
  action    = "accept"
}
`)

	must.StrContains(t, out, "tcp dport 22 accept")
	must.StrContains(t, out, "udp dport 53 accept")
}

func TestInterfaceFilter(t *testing.T) {
	out := fence(t, `
provider "nftables" {}

rule "allow_lo" {
  provider     = provider.nftables
  direction    = "inbound"
  inbound_interface = "lo"
  action       = "accept"
}
`)

	must.StrContains(t, out, `iifname "lo" accept`)
}

func TestMixedFamilyAddresses(t *testing.T) {
	out := fence(t, `
provider "nftables" {}

rule "mixed" {
  provider    = provider.nftables
  direction   = "inbound"
  source      = ["10.0.0.1", "fd00::1"]
  protocol    = "tcp"
  dst_port    = ["443"]
  action      = "accept"
}
`)

	// SplitByFamily produces separate IPv4 and IPv6 rules.
	must.StrContains(t, out, "ip saddr 10.0.0.1")
	must.StrContains(t, out, "ip6 saddr fd00::1")
}

func TestPortRange(t *testing.T) {
	out := fence(t, `
provider "nftables" {}

rule "high_ports" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["8000-9000"]
  action    = "accept"
}
`)

	must.StrContains(t, out, "tcp dport")
	must.StrContains(t, out, "accept")
}

func TestMultiplePorts(t *testing.T) {
	out := fence(t, `
provider "nftables" {}

rule "web" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["80", "443"]
  action    = "accept"
}
`)

	must.StrContains(t, out, "tcp dport")
	must.StrContains(t, out, "accept")
}

func TestMultipleSourceAddresses(t *testing.T) {
	out := fence(t, `
provider "nftables" {}

rule "trusted" {
  provider    = provider.nftables
  direction   = "inbound"
  source      = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
  protocol    = "tcp"
  dst_port    = ["22"]
  action      = "accept"
}
`)

	must.StrContains(t, out, "ip saddr")
	must.StrContains(t, out, "tcp dport 22")
	must.StrContains(t, out, "accept")
}

func TestCIDRSource(t *testing.T) {
	out := fence(t, `
provider "nftables" {}

rule "subnet" {
  provider    = provider.nftables
  direction   = "inbound"
  source      = ["10.0.0.0/8"]
  protocol    = "tcp"
  dst_port    = ["22"]
  action      = "accept"
}
`)

	must.StrContains(t, out, "ip saddr 10.0.0.0/8")
	must.StrContains(t, out, "tcp dport 22")
	must.StrContains(t, out, "accept")
}

func TestICMP(t *testing.T) {
	out := fence(t, `
provider "nftables" {}

rule "allow_icmp" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "icmp"
  action    = "accept"
}

rule "allow_icmpv6" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "icmpv6"
  action    = "accept"
}
`)

	must.StrContains(t, out, "icmp")
	must.StrContains(t, out, "ipv6-icmp")
}

func TestDNSDataSource(t *testing.T) {
	out := fence(t, `
provider "nftables" {}

data "dns" "local" {
  hostnames = ["localhost"]
}

rule "allow_local" {
  provider    = provider.nftables
  direction   = "inbound"
  source      = [data.dns.local]
  protocol    = "tcp"
  dst_port    = ["22"]
  action      = "accept"
}
`)

	// localhost resolves to 127.0.0.1 and/or ::1.
	must.StrContains(t, out, "tcp dport 22")
	must.StrContains(t, out, "accept")
}

func TestIfaceDataSource(t *testing.T) {
	out := fence(t, `
provider "nftables" {}

data "iface" "loopback" {
  name = "lo"
}

rule "allow_loopback_addrs" {
  provider    = provider.nftables
  direction   = "inbound"
  source      = [data.iface.loopback]
  action      = "accept"
}
`)

	// lo has 127.0.0.1 and/or ::1.
	must.StrContains(t, out, "accept")
}

func TestDynamicRules(t *testing.T) {
	out := fence(t, `
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

	must.StrContains(t, out, "tcp dport 80 accept")
	must.StrContains(t, out, "tcp dport 443 accept")
}

func TestIdempotence(t *testing.T) {
	t.Cleanup(func() { cleanup(t) })
	cleanup(t)

	path := filepath.Join(t.TempDir(), "fence.hcl")
	must.NoError(t, os.WriteFile(path, []byte(`
provider "nftables" {}

rule "ssh" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["22"]
  action    = "accept"
}
`), 0644))
	args := []string{"--once", "--config=" + path, "--log-level=debug"}

	// First run — applies rules.
	run(t, binary, args[0], args[1], args[2])
	out1 := tableOutput(t)

	// Second run — should detect in-sync and not change anything.
	run(t, binary, args[0], args[1], args[2])
	out2 := tableOutput(t)

	must.EqOp(t, out1, out2)
}

func TestDriftRecovery(t *testing.T) {
	t.Cleanup(func() { cleanup(t) })
	cleanup(t)

	path := filepath.Join(t.TempDir(), "fence.hcl")
	must.NoError(t, os.WriteFile(path, []byte(`
provider "nftables" {}

rule "ssh" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["22"]
  action    = "accept"
}

rule "http" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["80"]
  action    = "accept"
}
`), 0644))
	args := []string{"--once", "--config=" + path}

	// Apply rules.
	run(t, binary, args[0], args[1])
	must.StrContains(t, tableOutput(t), "tcp dport 22 accept")
	must.StrContains(t, tableOutput(t), "tcp dport 80 accept")

	// Simulate drift: flush the input chain (removes all rules from it).
	run(t, "nft", "flush", "chain", "inet", "pigeon-fence", "input")
	must.StrNotContains(t, tableOutput(t), "tcp dport 22 accept")

	// Run again — should recover.
	run(t, binary, args[0], args[1])
	must.StrContains(t, tableOutput(t), "tcp dport 22 accept")
	must.StrContains(t, tableOutput(t), "tcp dport 80 accept")
}

func TestNoRulesNoChain(t *testing.T) {
	t.Cleanup(func() { cleanup(t) })
	cleanup(t)

	path := filepath.Join(t.TempDir(), "fence.hcl")
	must.NoError(t, os.WriteFile(path, []byte(`provider "nftables" {}`), 0644))

	run(t, binary, "--once", "--config="+path)
	must.False(t, tableExists(t))
}

func TestInvalidConfigExitCode(t *testing.T) {
	out := fenceFail(t, `
rule "bad" {
  direction = "sideways"
  action    = "accept"
}
`)
	must.StrContains(t, out, "load config")
}
