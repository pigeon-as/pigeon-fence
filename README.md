# pigeon-fence

**Experimental** pluggable firewall manager. Reconciles firewall rules across multiple providers from a single HCL config. Data sources feed dynamic rule expansion. Linux-only.

> **Defense-in-Depth vs. Operational Burden:**
> NIST defense-in-depth guidance recommends layered boundary protection, such as network firewalls complemented by host-based firewalls ([SP 800-123](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-123.pdf), [SP 800-53 SC-7](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-7)). NIST's firewall guidance further recommends duplicating relevant policies across layers, while noting that multiple layers can be operationally troublesome ([SP 800-41r1](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-41r1.pdf)). This tool tries to reduce the operational burden by reconciling rules across multiple firewall providers from a single config.

## Rules

Firewall rules have the same high-level structure regardless of which provider enforces them. A standard rule type is mapped onto provider-specific resources.

```hcl
rule "ssh" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["22"]
  source    = ["10.0.0.0/8"]
  action    = "accept"
  comment   = "SSH access from private network"
}
```

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | label | yes | Unique rule name |
| `provider` | reference | yes | Target provider (`provider.nftables`) |
| `direction` | string | yes | `"inbound"`, `"outbound"`, or `"forward"` |
| `action` | string | yes | `"accept"`, `"drop"`, or `"reject"` |
| `protocol` | string | | `"tcp"`, `"udp"`, `"icmp"`, or `"icmpv6"` |
| `src_port` | list of strings | | Source ports or ranges (`"80"`, `"1024-65535"`) |
| `dst_port` | list of strings | | Destination ports or ranges |
| `source` | list of strings | | Source IPs, CIDRs, or `data.*` references |
| `destination` | list of strings | | Destination IPs, CIDRs, or `data.*` references |
| `inbound_interface` | string | | Inbound network interface |
| `outbound_interface` | string | | Outbound network interface |
| `comment` | string | | Human-readable description |

## Usage

```
pigeon-fence --config=<path> [--once] [--log-level=info]
```

`--config` accepts a file or directory. If directory, all `*.hcl` files are merged in alphabetical order.

## Providers

| Provider | Description |
|----------|---------|
| `nftables` | Linux nftables (rules + reconciliation) |
| `ovh` | OVH API client (data sources only) |

## Data Sources

| Type | Description | Config |
|------|-------------|--------|
| `dns` | DNS hostname resolution | `hostnames`, optional `nameserver` |
| `iface` | IPs from a network interface | `name` or `ip` (exactly one) |
| `ovh_ips` | All IPs from OVH account | Requires `ovh` provider |

Referenced in rule `source`/`destination` fields as `data.<type>.<name>`.

## Rule Order

Rules are applied in declaration order.

## Config

HCL v2 with `locals`, `dynamic` blocks, and built-in functions (`concat`, `flatten`, `distinct`). See [example/](example/) for full configs.

```hcl
provider "nftables" {}

data "iface" "public" {
  name = "eth0"
}

locals {
  services = {
    vault  = { port = "8200", comment = "Vault API" }
    consul = { port = "8500", comment = "Consul HTTP" }
  }
}

rule "ssh" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["22"]
  action    = "accept"
  inbound_interface = "eth0"
  comment   = "SSH access"
}

dynamic "rule" {
  for_each = local.services
  labels   = [rule.key]
  content {
    provider  = provider.nftables
    direction = "inbound"
    protocol  = "tcp"
    dst_port  = [rule.value.port]
    action    = "accept"
    comment   = rule.value.comment
  }
}

interval  = "60s"
log_level = "info"
```

## Build & Test

```bash
make build    # Build binary → build/pigeon-fence
make test     # Run unit tests
make vet      # Run go vet
```
