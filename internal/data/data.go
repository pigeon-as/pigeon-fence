package data

import "context"

// DataSource resolves dynamic values for use in rule fields.
// Resolve is called on each reconcile tick. Returned strings are
// typically IP addresses or CIDRs that get expanded into rule
// source/destination fields. An error aborts the entire reconcile
// cycle (fail-closed).
type DataSource interface {
	Name() string
	Resolve(ctx context.Context) ([]string, error)
}
