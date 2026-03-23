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

	"github.com/google/nftables"
)

// binary is the path to the built pigeon-fence binary.
// make e2e builds it before running the tests.
var binary string

func TestMain(m *testing.M) {
	// Pre-flight: nftables requires a Linux kernel with nf_tables.
	conn := &nftables.Conn{}
	if _, err := conn.ListTables(); err != nil {
		fmt.Fprintf(os.Stderr, "skipping e2e: nftables unavailable: %v\n", err)
		os.Exit(0)
	}

	// Locate the binary relative to the repo root.
	// Tests run from e2e/, binary is at build/pigeon-fence.
	wd, _ := os.Getwd()
	binary = filepath.Join(wd, "..", "build", "pigeon-fence")
	if _, err := os.Stat(binary); err != nil {
		// Try PATH fallback.
		if p, err := exec.LookPath("pigeon-fence"); err == nil {
			binary = p
		}
	}
	os.Exit(m.Run())
}

// --- Helpers ---

// cleanup deletes the pigeon-fence table.
func cleanup(t *testing.T) {
	t.Helper()
	conn := &nftables.Conn{}
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return
	}
	for _, tbl := range tables {
		if tbl.Name == "pigeon-fence" {
			conn.DelTable(tbl)
			if err := conn.Flush(); err != nil {
				t.Fatalf("cleanup: flush failed: %v", err)
			}
			return
		}
	}
}

// fence runs pigeon-fence --once with the given HCL config.
// Registers cleanup to remove nftables state after the test.
func fence(t *testing.T, hcl string) {
	t.Helper()
	t.Cleanup(func() { cleanup(t) })
	cleanup(t) // clean leftover state from a previous failed run

	dir := t.TempDir()
	path := filepath.Join(dir, "fence.hcl")
	if err := os.WriteFile(path, []byte(hcl), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binary, "--once", "--config="+path, "--log-level=debug")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("pigeon-fence --once failed: %v", err)
	}
}

// fenceFail runs pigeon-fence --once and expects a non-zero exit.
func fenceFail(t *testing.T, hcl string) string {
	t.Helper()
	t.Cleanup(func() { cleanup(t) })
	cleanup(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "fence.hcl")
	if err := os.WriteFile(path, []byte(hcl), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binary, "--once", "--config="+path)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected pigeon-fence to fail, but it succeeded")
	}
	return string(out)
}

// getChain returns a chain from the pigeon-fence table, or nil.
func getChain(t *testing.T, chainName string) *nftables.Chain {
	t.Helper()
	conn := &nftables.Conn{}
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}
	for _, c := range chains {
		if c.Table.Name == "pigeon-fence" && c.Name == chainName {
			return c
		}
	}
	return nil
}

// getRules returns the rules in a chain of the pigeon-fence table.
func getRules(t *testing.T, chainName string) []*nftables.Rule {
	t.Helper()
	chain := getChain(t, chainName)
	if chain == nil {
		t.Fatalf("chain %q not found in pigeon-fence table", chainName)
	}
	conn := &nftables.Conn{}
	rules, err := conn.GetRules(chain.Table, chain)
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	return rules
}

// getTable returns the pigeon-fence table, or nil.
func getTable(t *testing.T) *nftables.Table {
	t.Helper()
	conn := &nftables.Conn{}
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		t.Fatalf("ListTables: %v", err)
	}
	for _, tbl := range tables {
		if tbl.Name == "pigeon-fence" {
			return tbl
		}
	}
	return nil
}

// hasChain checks whether the pigeon-fence table has a chain with the given name.
func hasChain(t *testing.T, chainName string) bool {
	t.Helper()
	return getChain(t, chainName) != nil
}

func ruleUserData(r *nftables.Rule) string {
	return string(r.UserData)
}

// --- Tests ---

func TestBinaryExists(t *testing.T) {
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("binary not found at %s: run 'make build' first", binary)
	}
}

func TestStaticRules(t *testing.T) {
	fence(t, `
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

	rules := getRules(t, "input")
	if len(rules) != 2 {
		t.Fatalf("rule count = %d, want 2", len(rules))
	}
	if !strings.Contains(ruleUserData(rules[0]), "allow_ssh") {
		t.Errorf("rule[0] UserData = %q, want allow_ssh", ruleUserData(rules[0]))
	}
	if !strings.Contains(ruleUserData(rules[1]), "deny_all") {
		t.Errorf("rule[1] UserData = %q, want deny_all", ruleUserData(rules[1]))
	}
	for i, r := range rules {
		if !strings.Contains(ruleUserData(r), "pf:") {
			t.Errorf("rule[%d] missing hash prefix in UserData: %q", i, ruleUserData(r))
		}
	}
	if !hasChain(t, "input") {
		t.Error("input chain missing in pigeon-fence table")
	}
}

func TestOutboundRule(t *testing.T) {
	fence(t, `
provider "nftables" {}

rule "block_outbound" {
  provider    = provider.nftables
  direction   = "outbound"
  protocol    = "tcp"
  dst_port    = ["9999"]
  action      = "drop"
}
`)

	rules := getRules(t, "output")
	if len(rules) != 1 {
		t.Fatalf("rule count = %d, want 1", len(rules))
	}
	if !hasChain(t, "output") {
		t.Error("output chain missing in pigeon-fence table")
	}
}

func TestMixedDirections(t *testing.T) {
	fence(t, `
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

	inRules := getRules(t, "input")
	if len(inRules) != 1 {
		t.Fatalf("input rule count = %d, want 1", len(inRules))
	}
	outRules := getRules(t, "output")
	if len(outRules) != 1 {
		t.Fatalf("output rule count = %d, want 1", len(outRules))
	}
	if !hasChain(t, "input") {
		t.Error("input chain missing in pigeon-fence table")
	}
	if !hasChain(t, "output") {
		t.Error("output chain missing in pigeon-fence table")
	}
}

func TestInterfaceFilter(t *testing.T) {
	fence(t, `
provider "nftables" {}

rule "allow_lo" {
  provider     = provider.nftables
  direction    = "inbound"
  inbound_interface = "lo"
  action       = "accept"
}
`)

	rules := getRules(t, "input")
	if len(rules) != 1 {
		t.Fatalf("rule count = %d, want 1", len(rules))
	}
	if !strings.Contains(ruleUserData(rules[0]), "allow_lo") {
		t.Errorf("rule UserData = %q, want allow_lo", ruleUserData(rules[0]))
	}
}

func TestMixedFamilyAddresses(t *testing.T) {
	fence(t, `
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

	// SplitByFamily produces 2 rules (one IPv4, one IPv6).
	rules := getRules(t, "input")
	if len(rules) != 2 {
		t.Fatalf("rule count = %d, want 2 (split by family)", len(rules))
	}
}

func TestPortRange(t *testing.T) {
	fence(t, `
provider "nftables" {}

rule "high_ports" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["8000-9000"]
  action    = "accept"
}
`)

	rules := getRules(t, "input")
	if len(rules) != 1 {
		t.Fatalf("rule count = %d, want 1", len(rules))
	}
}

func TestMultiplePorts(t *testing.T) {
	fence(t, `
provider "nftables" {}

rule "web" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["80", "443"]
  action    = "accept"
}
`)

	rules := getRules(t, "input")
	if len(rules) != 1 {
		t.Fatalf("rule count = %d, want 1", len(rules))
	}
}

func TestMultipleSourceAddresses(t *testing.T) {
	fence(t, `
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

	rules := getRules(t, "input")
	if len(rules) != 1 {
		t.Fatalf("rule count = %d, want 1", len(rules))
	}
}

func TestCIDRSource(t *testing.T) {
	fence(t, `
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

	rules := getRules(t, "input")
	if len(rules) != 1 {
		t.Fatalf("rule count = %d, want 1", len(rules))
	}
}

func TestICMP(t *testing.T) {
	fence(t, `
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

	rules := getRules(t, "input")
	if len(rules) != 2 {
		t.Fatalf("rule count = %d, want 2", len(rules))
	}
}

func TestDNSDataSource(t *testing.T) {
	fence(t, `
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
	rules := getRules(t, "input")
	if len(rules) < 1 {
		t.Fatalf("rule count = %d, want >= 1", len(rules))
	}
}

func TestIfaceDataSource(t *testing.T) {
	fence(t, `
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

	// lo has 127.0.0.1 and ::1 — mixed family split.
	rules := getRules(t, "input")
	if len(rules) < 1 {
		t.Fatalf("rule count = %d, want >= 1", len(rules))
	}
}

func TestDynamicRules(t *testing.T) {
	fence(t, `
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

	rules := getRules(t, "input")
	if len(rules) != 2 {
		t.Fatalf("rule count = %d, want 2", len(rules))
	}
}

func TestIdempotence(t *testing.T) {
	t.Cleanup(func() { cleanup(t) })
	cleanup(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "fence.hcl")
	if err := os.WriteFile(path, []byte(`
provider "nftables" {}

rule "ssh" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["22"]
  action    = "accept"
}
`), 0644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--once", "--config=" + path, "--log-level=debug"}

	// First run — applies rules.
	cmd := exec.Command(binary, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("first run: %v", err)
	}
	rules1 := getRules(t, "input")

	// Second run — should detect in-sync.
	cmd = exec.Command(binary, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("second run: %v", err)
	}
	rules2 := getRules(t, "input")

	if len(rules1) != len(rules2) {
		t.Fatalf("rule count changed: %d → %d", len(rules1), len(rules2))
	}
	for i := range rules1 {
		if rules1[i].Handle != rules2[i].Handle {
			t.Errorf("rule[%d] handle changed: %d → %d (unexpected rewrite)", i, rules1[i].Handle, rules2[i].Handle)
		}
	}
}

func TestDriftRecovery(t *testing.T) {
	t.Cleanup(func() { cleanup(t) })
	cleanup(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "fence.hcl")
	if err := os.WriteFile(path, []byte(`
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
`), 0644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--once", "--config=" + path}

	// Apply rules.
	cmd := exec.Command(binary, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if len(getRules(t, "input")) != 2 {
		t.Fatal("expected 2 rules after first run")
	}

	// Simulate drift: delete one rule from kernel.
	chain := getChain(t, "input")
	conn := &nftables.Conn{}
	rules, _ := conn.GetRules(chain.Table, chain)
	if len(rules) > 0 {
		conn.DelRule(rules[0])
		if err := conn.Flush(); err != nil {
			t.Fatalf("manual delete: %v", err)
		}
	}
	if len(getRules(t, "input")) != 1 {
		t.Fatal("expected 1 rule after drift")
	}

	// Run again — should recover.
	cmd = exec.Command(binary, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("recovery run: %v", err)
	}
	if len(getRules(t, "input")) != 2 {
		t.Fatalf("rule count after recovery = %d, want 2", len(getRules(t, "input")))
	}
}

func TestNoRulesNoChain(t *testing.T) {
	fence(t, `provider "nftables" {}`)

	tbl := getTable(t)
	if tbl != nil {
		t.Error("pigeon-fence table should not exist with zero rules")
	}
}

func TestInvalidConfigExitCode(t *testing.T) {
	out := fenceFail(t, `
rule "bad" {
  direction = "sideways"
  action    = "accept"
}
`)
	if !strings.Contains(out, "load config") {
		t.Errorf("expected config error in output, got: %s", out)
	}
}
