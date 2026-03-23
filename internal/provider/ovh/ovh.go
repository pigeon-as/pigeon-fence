// Package ovh provides OVH API client creation for data sources.
// The OVH provider block in HCL holds API credentials. The shared
// client is used by data sources (e.g. ovh_ips). OVH firewall
// reconciliation has been removed — edge perimeter rules are
// managed by Terraform (ovh_ip_firewall_rule).
package ovh

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	ovhsdk "github.com/ovh/go-ovh/ovh"
)

// credentials is the HCL body schema for the OVH provider block.
// All fields are optional — when empty, the go-ovh SDK falls back
// to OVH_* environment variables and ~/.ovh.conf.
type credentials struct {
	Endpoint          string `hcl:"endpoint,optional"`
	ApplicationKey    string `hcl:"application_key,optional"`
	ApplicationSecret string `hcl:"application_secret,optional"`
	ConsumerKey       string `hcl:"consumer_key,optional"`
}

// NewClient creates an OVH API client from a provider HCL body.
func NewClient(body hcl.Body) (*ovhsdk.Client, error) {
	var creds credentials
	diags := gohcl.DecodeBody(body, nil, &creds)
	if diags.HasErrors() {
		return nil, fmt.Errorf("decode credentials: %s", diags.Error())
	}
	return ovhsdk.NewClient(creds.Endpoint, creds.ApplicationKey, creds.ApplicationSecret, creds.ConsumerKey)
}
