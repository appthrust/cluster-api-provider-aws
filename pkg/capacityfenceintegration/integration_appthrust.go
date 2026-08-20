//go:build appthrust_owner_bound

// Package capacityfenceintegration selects the AppThrust owner-bound adapter at build time.
package capacityfenceintegration

import (
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/capacityfenceadapter"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/services/ec2"
)

// AddToScheme registers the private owner-bound authority APIs.
func AddToScheme(scheme *runtime.Scheme) error {
	return capacityfenceadapter.AddToScheme(scheme)
}

// NewAuthorizer creates the private owner-bound provider mutation authority.
func NewAuthorizer(c client.Client, reader client.Reader) ec2.CapacityFenceAuthorizer {
	return capacityfenceadapter.NewAdapter(c, reader)
}
