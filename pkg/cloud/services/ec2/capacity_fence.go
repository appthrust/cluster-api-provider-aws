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

package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	"k8s.io/apimachinery/pkg/types"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/scope"
)

// CapacityFenceClaimBindingTagKey is reserved for provider-created claim evidence.
// Its value is always a digest; the raw EC2 ClientToken must never be tagged.
const CapacityFenceClaimBindingTagKey = "capacityfence.appthrust.io/claim-binding"

// CapacityFenceIdentity is the concrete CAPI and CAPA identity at the provider mutation boundary.
// Names make an initial reservation binding possible before object UIDs exist; UIDs and generations
// bind the provider-time claim and receipt to the exact objects that reached RunInstances.
type CapacityFenceIdentity struct {
	MachineNamespace     string
	MachineName          string
	MachineUID           types.UID
	MachineGeneration    int64
	AWSMachineNamespace  string
	AWSMachineName       string
	AWSMachineUID        types.UID
	AWSMachineGeneration int64
}

// Validate rejects an incomplete provider-time identity before provider I/O or receipt recovery.
func (i CapacityFenceIdentity) Validate() error {
	if i.MachineNamespace == "" || i.MachineName == "" {
		return fmt.Errorf("machine namespace and name are required")
	}
	if i.MachineUID == "" || i.MachineGeneration <= 0 {
		return fmt.Errorf("machine UID and positive generation are required")
	}
	if i.AWSMachineNamespace == "" || i.AWSMachineName == "" {
		return fmt.Errorf("AWSMachine namespace and name are required")
	}
	if i.AWSMachineUID == "" || i.AWSMachineGeneration <= 0 {
		return fmt.Errorf("AWSMachine UID and positive generation are required")
	}
	return nil
}

// CapacityFenceIdentityFromMachineScope returns the one provider-time identity used by both
// CreateInstance and controller-side discovery/adoption recovery.
func CapacityFenceIdentityFromMachineScope(machineScope *scope.MachineScope) CapacityFenceIdentity {
	return CapacityFenceIdentity{
		MachineNamespace:     machineScope.Machine.Namespace,
		MachineName:          machineScope.Machine.Name,
		MachineUID:           machineScope.Machine.UID,
		MachineGeneration:    machineScope.Machine.Generation,
		AWSMachineNamespace:  machineScope.AWSMachine.Namespace,
		AWSMachineName:       machineScope.AWSMachine.Name,
		AWSMachineUID:        machineScope.AWSMachine.UID,
		AWSMachineGeneration: machineScope.AWSMachine.Generation,
	}
}

// CapacityFenceClaim mirrors capacityfence.ClaimResult without importing an AppThrust module.
// ClaimBindingDigest is supplied by the authority and is copied unchanged into provider evidence.
// ClientToken is a raw 64-hex retry token retained only in process memory.
type CapacityFenceClaim struct {
	ClaimID            string
	ClaimBindingDigest string
	ClientToken        string
}

// Validate rejects an incomplete or noncanonical claim before any provider I/O is attempted.
func (c *CapacityFenceClaim) Validate() error {
	if c == nil {
		return fmt.Errorf("claim is nil")
	}
	if c.ClaimID == "" {
		return fmt.Errorf("claim ID is empty")
	}
	if !isCanonicalSHA256Digest(c.ClaimBindingDigest) {
		return fmt.Errorf("claim binding digest must be canonical sha256:<64hex>")
	}
	if !isLowerHex(c.ClientToken, 64) {
		return fmt.Errorf("client token must be raw 64-character lowercase hexadecimal")
	}
	return nil
}

// isCanonicalSHA256Digest accepts the exact digest representation passed to the provider tag.
func isCanonicalSHA256Digest(digest string) bool {
	return strings.HasPrefix(digest, "sha256:") && isLowerHex(strings.TrimPrefix(digest, "sha256:"), 64)
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// CapacityFenceProviderRequest binds the semantic, finalized provider request
// to an already-recorded claim before provider I/O. It contains no ClientToken.
type CapacityFenceProviderRequest struct {
	ClaimID               string
	ClaimBindingDigest    string
	ProviderRequestDigest string
}

// Validate rejects an incomplete provider request binding before provider I/O.
func (r CapacityFenceProviderRequest) Validate() error {
	if r.ClaimID == "" {
		return fmt.Errorf("claim ID is empty")
	}
	if !isCanonicalSHA256Digest(r.ClaimBindingDigest) {
		return fmt.Errorf("claim binding digest must be canonical sha256:<64hex>")
	}
	if !isCanonicalSHA256Digest(r.ProviderRequestDigest) {
		return fmt.Errorf("provider request digest must be canonical sha256:<64hex>")
	}
	return nil
}

// CapacityFenceProviderRequestDigest canonicalizes the finalized RunInstances
// request with ClientToken removed. The complete AWS request captures the final
// AMI, instance type, subnet or supplied ENI, security groups, user data,
// volumes, metadata options, and every effective resource tag. Order-insensitive
// tag, block-device, and security-group collections are sorted before hashing.
func CapacityFenceProviderRequestDigest(input *awsec2.RunInstancesInput) (string, error) {
	if input == nil {
		return "", fmt.Errorf("RunInstances input is nil")
	}
	withoutToken := *input
	withoutToken.ClientToken = nil
	raw, err := json.Marshal(&withoutToken) // #nosec G117 -- ClientToken is cleared before serialization.
	if err != nil {
		return "", fmt.Errorf("marshal finalized RunInstances input: %w", err)
	}
	var canonical awsec2.RunInstancesInput
	if err := json.Unmarshal(raw, &canonical); err != nil {
		return "", fmt.Errorf("copy finalized RunInstances input: %w", err)
	}
	// The copy was created from token-free bytes; keep this explicit before
	// serializing the canonical request for its digest.
	canonical.ClientToken = nil
	canonicalizeCapacityFenceRunInstancesInput(&canonical)
	raw, err = json.Marshal(&canonical) // #nosec G117 -- ClientToken is cleared before serialization.
	if err != nil {
		return "", fmt.Errorf("marshal canonical RunInstances input: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalizeCapacityFenceRunInstancesInput(input *awsec2.RunInstancesInput) {
	sort.Strings(input.SecurityGroupIds)
	for index := range input.NetworkInterfaces {
		sort.Strings(input.NetworkInterfaces[index].Groups)
	}
	sort.Slice(input.BlockDeviceMappings, func(left, right int) bool {
		return stringPointer(input.BlockDeviceMappings[left].DeviceName) < stringPointer(input.BlockDeviceMappings[right].DeviceName)
	})
	sort.Slice(input.TagSpecifications, func(left, right int) bool {
		return input.TagSpecifications[left].ResourceType < input.TagSpecifications[right].ResourceType
	})
	for index := range input.TagSpecifications {
		tags := input.TagSpecifications[index].Tags
		sort.Slice(tags, func(left, right int) bool {
			leftKey, rightKey := stringPointer(tags[left].Key), stringPointer(tags[right].Key)
			if leftKey != rightKey {
				return leftKey < rightKey
			}
			return stringPointer(tags[left].Value) < stringPointer(tags[right].Value)
		})
		input.TagSpecifications[index].Tags = tags
	}
}

func stringPointer(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// CapacityFenceMutationReceipt binds one completed EC2 instance mutation to the authority claim.
// It stores only the exact target identity and supplied claim-binding digest;
// it never carries ClientToken or authority-only material.
type CapacityFenceMutationReceipt struct {
	ClaimID              string
	ClaimBindingDigest   string
	MachineNamespace     string
	MachineName          string
	MachineUID           types.UID
	MachineGeneration    int64
	AWSMachineNamespace  string
	AWSMachineName       string
	AWSMachineUID        types.UID
	AWSMachineGeneration int64
	InstanceID           string
}

// MutationReceipt constructs the token-safe receipt from the supplied claim digest and exact provider identity.
func (c *CapacityFenceClaim) MutationReceipt(identity CapacityFenceIdentity, instanceID string) (CapacityFenceMutationReceipt, error) {
	if err := c.Validate(); err != nil {
		return CapacityFenceMutationReceipt{}, err
	}
	if err := identity.Validate(); err != nil {
		return CapacityFenceMutationReceipt{}, err
	}
	if instanceID == "" {
		return CapacityFenceMutationReceipt{}, fmt.Errorf("instance ID is empty")
	}
	return CapacityFenceMutationReceipt{
		ClaimID:              c.ClaimID,
		ClaimBindingDigest:   c.ClaimBindingDigest,
		MachineNamespace:     identity.MachineNamespace,
		MachineName:          identity.MachineName,
		MachineUID:           identity.MachineUID,
		MachineGeneration:    identity.MachineGeneration,
		AWSMachineNamespace:  identity.AWSMachineNamespace,
		AWSMachineName:       identity.AWSMachineName,
		AWSMachineUID:        identity.AWSMachineUID,
		AWSMachineGeneration: identity.AWSMachineGeneration,
		InstanceID:           instanceID,
	}, nil
}

// CapacityFenceAuthorizer locally mirrors capacityfence ClaimResult, provider
// request binding, RecordRequest, and EnsureReceiptRequest without importing
// AppThrust modules. A manager-side adapter selects and revalidates the exact
// permit using uncached server reads. Claim durably reserves capacity; the
// finalized request digest is immutable before RunInstances can begin.
type CapacityFenceAuthorizer interface {
	Claim(context.Context, CapacityFenceIdentity) (*CapacityFenceClaim, error)
	BindProviderRequest(context.Context, CapacityFenceIdentity, CapacityFenceProviderRequest) error
	Record(context.Context, CapacityFenceMutationReceipt) error
	EnsureReceipt(context.Context, CapacityFenceIdentity, infrav1.Instance) error
	// HasUnresolvedProviderRequest reports whether the exact persisted claim
	// bound a provider request that does not yet have a durable receipt.
	// It is used only after zero-result deletion discovery.
	HasUnresolvedProviderRequest(context.Context, CapacityFenceIdentity) (bool, error)
}

// EnsureCapacityFenceReceipt is the shared controller adoption seam. Direct stock callers may
// omit an authorizer; the owner-bound manager always supplies one and blocks adoption until its
// durable claim is receipted.
func EnsureCapacityFenceReceipt(ctx context.Context, authorizer CapacityFenceAuthorizer, machineScope *scope.MachineScope, instance *infrav1.Instance) error {
	if authorizer == nil {
		return nil
	}
	if machineScope == nil || machineScope.Machine == nil || machineScope.AWSMachine == nil {
		return fmt.Errorf("capacity fence receipt recovery requires MachineScope identity")
	}
	identity := CapacityFenceIdentityFromMachineScope(machineScope)
	if err := identity.Validate(); err != nil {
		return fmt.Errorf("capacity fence receipt recovery identity is invalid: %w", err)
	}
	if instance == nil || instance.ID == "" {
		return fmt.Errorf("capacity fence receipt recovery requires a discovered instance")
	}
	if err := authorizer.EnsureReceipt(ctx, identity, *instance); err != nil {
		return fmt.Errorf("capacity fence receipt recovery failed: %w", err)
	}
	return nil
}
