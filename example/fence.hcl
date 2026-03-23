# Example config demonstrating all features:
# nftables provider, OVH data sources (for shared client), DNS, iface, locals, dynamic blocks, functions.

provider "nftables" {}

provider "ovh" {
  endpoint           = "ovh-eu"
  application_key    = "ak_xxx"
  application_secret = "as_xxx"
  consumer_key       = "ck_xxx"
}

data "ovh_ips" "servers" {}

data "dns" "monitoring" {
  hostnames  = ["prometheus.example.com"]
  nameserver = "8.8.8.8:53"
}

data "iface" "public" {
  name = "eth0"
}

locals {
  services = {
    vault_api   = { proto = "tcp", port = "8200", comment = "Vault API" }
    consul_http = { proto = "tcp", port = "8500", comment = "Consul HTTP" }
    consul_serf = { proto = "udp", port = "8301", comment = "Consul Serf UDP" }
  }
}

# --- nftables rules (local Linux firewall) ---

# SSH — needs interface binding, kept explicit.
rule "ssh" {
  provider  = provider.nftables
  direction = "inbound"
  protocol  = "tcp"
  dst_port  = ["22"]
  action    = "accept"
  inbound_interface = "eth0"
  comment   = "SSH access"
}

# Services from locals.
dynamic "rule" {
  for_each = local.services
  labels   = [rule.key]
  content {
    provider  = provider.nftables
    direction = "inbound"
    protocol  = rule.value.proto
    dst_port  = [rule.value.port]
    action    = "accept"
    comment   = rule.value.comment
  }
}

# Allow OVH server IPs (from data source).
rule "allow_servers" {
  provider  = provider.nftables
  direction = "inbound"
  source    = [data.ovh_ips.servers]
  protocol  = "tcp"
  action    = "accept"
  comment   = "Allow OVH server traffic"
}

interval  = "60s"
log_level = "info"
