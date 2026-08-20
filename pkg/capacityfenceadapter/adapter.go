//go:build appthrust_owner_bound

/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package capacityfenceadapter translates CAPA provider operations to the
// AppThrust capacity-fence authority.
package capacityfenceadapter

import (
	"context"
	"errors"
	"fmt"

	"github.com/appthrust/model/api/core/v1alpha1/common"
	platformv1alpha1 "github.com/appthrust/model/api/platform/v1alpha1"
	"github.com/appthrust/platform/pkg/capacityfence"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/services/ec2"
)

// Adapter is intentionally CAPA-local. It holds no selected-permit cache:
// each claim and receipt operation resolves the current server-side object.
type Adapter struct {
	selector   *capacityfence.PermitSelector
	authorizer *capacityfence.Authorizer
}

// AddToScheme registers the current AppThrust permit type on CAPA's manager
// scheme so its uncached API reader can decode server responses.
func AddToScheme(scheme *runtime.Scheme) error {
	return platformv1alpha1.AddToScheme(scheme)
}

// NewAdapter always returns a concrete adapter. The manager supplies both the
// cached writer and direct API reader; a missing client is rejected by the
// authorizer before provider I/O rather than silently bypassing capacity fence.
func NewAdapter(writer client.Client, apiReader client.Reader) *Adapter {
	return &Adapter{
		selector:   &capacityfence.PermitSelector{APIReader: apiReader},
		authorizer: &capacityfence.Authorizer{Client: writer, APIReader: apiReader},
	}
}

// Claim resolves or atomically consumes the exact provider mutation authority.
func (a *Adapter) Claim(ctx context.Context, identity ec2.CapacityFenceIdentity) (*ec2.CapacityFenceClaim, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	target := targetFromIdentity(identity)
	_, persisted, err := a.selector.ResolvePersistedClaim(ctx, target)
	if err == nil {
		token, deriveErr := platformv1alpha1.DeriveMachineProvisioningPermitEC2ClientTokenV1(
			platformv1alpha1.MachineProvisioningPermitEC2ClientTokenInput{ClaimBindingDigest: persisted.ClaimBindingDigest},
		)
		if deriveErr != nil {
			return nil, fmt.Errorf("%w: derive persisted EC2 client token: %v", capacityfence.ErrAuthorityInvalid, deriveErr)
		}
		tokenDigest, digestErr := platformv1alpha1.CalculateMachineProvisioningPermitClientTokenDigestV1(token)
		if digestErr != nil || tokenDigest != persisted.ClientTokenDigest {
			return nil, fmt.Errorf("%w: persisted EC2 client token digest does not match", capacityfence.ErrClaimIdentityMismatch)
		}
		return &ec2.CapacityFenceClaim{
			ClaimID: persisted.ClaimID, ClaimBindingDigest: persisted.ClaimBindingDigest.Digest, ClientToken: token,
		}, nil
	}
	if !errors.Is(err, capacityfence.ErrPermitSelectionNoMatch) {
		return nil, err
	}
	request, err := a.selector.ResolveClaimRequest(ctx, target)
	if err != nil {
		return nil, err
	}
	result, err := a.authorizer.Claim(ctx, request)
	if err != nil {
		return nil, err
	}
	return &ec2.CapacityFenceClaim{
		ClaimID: result.ClaimID, ClaimBindingDigest: result.ClaimBindingDigest.Digest, ClientToken: result.ClientToken,
	}, nil
}

// BindProviderRequest binds the finalized token-free RunInstances digest to
// the exact persisted claim before CAPA performs the provider mutation.
func (a *Adapter) BindProviderRequest(ctx context.Context, identity ec2.CapacityFenceIdentity, binding ec2.CapacityFenceProviderRequest) error {
	if err := a.validate(); err != nil {
		return err
	}
	if err := identity.Validate(); err != nil {
		return fmt.Errorf("%w: provider request identity: %v", capacityfence.ErrInvalidRequest, err)
	}
	if err := binding.Validate(); err != nil {
		return fmt.Errorf("%w: provider request binding: %v", capacityfence.ErrInvalidRequest, err)
	}
	request, claim, err := a.selector.ResolvePersistedClaim(ctx, targetFromIdentity(identity))
	if err != nil {
		return err
	}
	if binding.ClaimID != claim.ClaimID || binding.ClaimBindingDigest != claim.ClaimBindingDigest.Digest {
		return fmt.Errorf("%w: provider request does not match the persisted claim", capacityfence.ErrProviderRequestConflict)
	}
	return a.authorizer.BindProviderRequest(ctx, capacityfence.BindProviderRequestRequest{
		PermitKey: request.PermitKey,
		ClaimID:   claim.ClaimID,
		ProviderRequestDigest: common.VersionedCanonicalSHA256Digest{
			SchemaVersion: common.CanonicalDigestSchemaVersionV1,
			Digest:        binding.ProviderRequestDigest,
		},
	})
}

// Record persists one immutable provider receipt for the exact claim.
func (a *Adapter) Record(ctx context.Context, receipt ec2.CapacityFenceMutationReceipt) error {
	if err := a.validate(); err != nil {
		return err
	}
	request, claim, err := a.selector.ResolvePersistedClaim(ctx, targetFromReceipt(receipt))
	if err != nil {
		return err
	}
	if receipt.ClaimID != claim.ClaimID || receipt.ClaimBindingDigest != claim.ClaimBindingDigest.Digest {
		return fmt.Errorf("%w: provider receipt does not match the persisted claim", capacityfence.ErrReceiptConflict)
	}
	return a.authorizer.Record(ctx, capacityfence.RecordRequest{
		PermitKey:          request.PermitKey,
		ClaimID:            claim.ClaimID,
		InstanceID:         receipt.InstanceID,
		ClaimBindingDigest: claim.ClaimBindingDigest,
	})
}

// EnsureReceipt recovers and verifies a provider receipt from instance evidence.
func (a *Adapter) EnsureReceipt(ctx context.Context, identity ec2.CapacityFenceIdentity, instance infrav1.Instance) error {
	if err := a.validate(); err != nil {
		return err
	}
	request, claim, err := a.selector.ResolvePersistedClaim(ctx, targetFromIdentity(identity))
	if err != nil {
		return err
	}
	return a.authorizer.EnsureReceipt(ctx, capacityfence.EnsureReceiptRequest{
		PermitKey:    request.PermitKey,
		ClaimID:      claim.ClaimID,
		InstanceID:   instance.ID,
		ProviderTags: instance.Tags,
	})
}

// HasUnresolvedProviderRequest reports whether deletion must wait because a
// durable claim bound provider work but has no receipt yet. An absent persisted
// claim means this target has no known provider effect; every other selection
// or read error is returned so callers fail closed.
func (a *Adapter) HasUnresolvedProviderRequest(ctx context.Context, identity ec2.CapacityFenceIdentity) (bool, error) {
	if err := a.validate(); err != nil {
		return false, err
	}
	if err := identity.Validate(); err != nil {
		return false, fmt.Errorf("%w: provider request identity: %v", capacityfence.ErrInvalidRequest, err)
	}
	_, claim, err := a.selector.ResolvePersistedClaim(ctx, targetFromIdentity(identity))
	if errors.Is(err, capacityfence.ErrPermitSelectionNoMatch) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return claim.ProviderRequestDigest != nil && claim.ProviderReceipt == nil, nil
}

func (a *Adapter) validate() error {
	if a == nil || a.selector == nil || a.authorizer == nil {
		return fmt.Errorf("%w: adapter is not configured", capacityfence.ErrInvalidConfiguration)
	}
	return nil
}

func targetFromIdentity(identity ec2.CapacityFenceIdentity) capacityfence.TargetIdentity {
	return capacityfence.TargetIdentity{
		MachineRef: common.ExactTypedNamespacedObjectReference{
			Group: "cluster.x-k8s.io", Kind: "Machine",
			Namespace: identity.MachineNamespace,
			Name:      identity.MachineName,
			UID:       common.BoundedUID(identity.MachineUID), Generation: identity.MachineGeneration,
		},
		AWSMachineRef: common.ExactTypedNamespacedObjectReference{
			Group: "infrastructure.cluster.x-k8s.io", Kind: "AWSMachine",
			Namespace: identity.AWSMachineNamespace,
			Name:      identity.AWSMachineName,
			UID:       common.BoundedUID(identity.AWSMachineUID), Generation: identity.AWSMachineGeneration,
		},
	}
}

func targetFromReceipt(receipt ec2.CapacityFenceMutationReceipt) capacityfence.TargetIdentity {
	return targetFromIdentity(ec2.CapacityFenceIdentity{
		MachineNamespace:     receipt.MachineNamespace,
		MachineName:          receipt.MachineName,
		MachineUID:           receipt.MachineUID,
		MachineGeneration:    receipt.MachineGeneration,
		AWSMachineNamespace:  receipt.AWSMachineNamespace,
		AWSMachineName:       receipt.AWSMachineName,
		AWSMachineUID:        receipt.AWSMachineUID,
		AWSMachineGeneration: receipt.AWSMachineGeneration,
	})
}
