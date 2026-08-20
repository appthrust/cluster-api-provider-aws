//go:build !appthrust_owner_bound

// Package capacityfenceintegration selects the AppThrust owner-bound adapter at build time.
package capacityfenceintegration

import (
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/services/ec2"
)

// AddToScheme leaves the stock CAPA scheme unchanged.
func AddToScheme(*runtime.Scheme) error {
	return nil
}

// NewAuthorizer leaves provider mutation unfenced in a stock CAPA build.
func NewAuthorizer(client.Client, client.Reader) ec2.CapacityFenceAuthorizer {
	return nil
}
