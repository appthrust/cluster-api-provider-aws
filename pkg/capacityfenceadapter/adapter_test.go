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

package capacityfenceadapter

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/appthrust/model/api/core/v1alpha1/common"
	platformv1alpha1 "github.com/appthrust/model/api/platform/v1alpha1"
	"github.com/appthrust/platform/pkg/capacityfence"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/services/ec2"
)

func TestCapacityFenceAdapterUsesCurrentPersistedAuthority(t *testing.T) {
	t.Run("missing and ambiguous permits fail before a claim mutation", func(t *testing.T) {
		fixture := newCapacityFenceAdapterFixture(t)
		if err := fixture.client.Delete(t.Context(), fixture.permit.DeepCopy()); err != nil {
			t.Fatalf("delete permit: %v", err)
		}
		adapter := NewAdapter(fixture.client, fixture.client)
		if _, err := adapter.Claim(t.Context(), fixture.identity); !errors.Is(err, capacityfence.ErrPermitSelectionNoMatch) {
			t.Fatalf("Claim() without a permit error = %v, want ErrPermitSelectionNoMatch", err)
		}
		fixture.assertNoClaims(t)

		fixture = newCapacityFenceAdapterFixture(t)
		fixture.createAmbiguousPermit(t)
		adapter = NewAdapter(fixture.client, fixture.client)
		if _, err := adapter.Claim(t.Context(), fixture.identity); !errors.Is(err, capacityfence.ErrPermitSelectionAmbiguous) {
			t.Fatalf("Claim() with multiple permits error = %v, want ErrPermitSelectionAmbiguous", err)
		}
		fixture.assertNoClaims(t)
	})

	t.Run("wrong target identity and authority outage fail before a claim mutation", func(t *testing.T) {
		fixture := newCapacityFenceAdapterFixture(t)
		adapter := NewAdapter(fixture.client, fixture.client)
		wrongIdentity := fixture.identity
		wrongIdentity.MachineUID = "wrong-machine-incarnation"
		if _, err := adapter.Claim(t.Context(), wrongIdentity); !errors.Is(err, capacityfence.ErrTargetIdentityMismatch) {
			t.Fatalf("Claim() with replaced Machine identity error = %v, want ErrTargetIdentityMismatch", err)
		}
		fixture.assertNoClaims(t)

		if _, err := NewAdapter(nil, nil).Claim(t.Context(), fixture.identity); !errors.Is(err, capacityfence.ErrInvalidConfiguration) {
			t.Fatalf("Claim() with unavailable authority clients error = %v, want ErrInvalidConfiguration", err)
		}
		fixture.assertNoClaims(t)
	})

	t.Run("valid authority claims once and recovers receipt from durable status", func(t *testing.T) {
		fixture := newCapacityFenceAdapterFixture(t)
		adapter := NewAdapter(fixture.client, fixture.client)
		claim, err := adapter.Claim(t.Context(), fixture.identity)
		if err != nil {
			t.Fatalf("Claim() error = %v", err)
		}
		if claim == nil || claim.ClientToken == "" || claim.ClaimBindingDigest == "" {
			t.Fatalf("Claim() = %#v, want token-safe claim result", claim)
		}
		stored := fixture.getPermit(t)
		if len(stored.Status.Claims) != 1 || stored.Status.Claims[0].ClaimID != claim.ClaimID {
			t.Fatalf("stored claims = %#v, want exactly one durable claim", stored.Status.Claims)
		}
		raw, err := json.Marshal(stored)
		if err != nil {
			t.Fatalf("marshal stored permit: %v", err)
		}
		if strings.Contains(string(raw), claim.ClientToken) {
			t.Fatalf("raw EC2 ClientToken persisted in MachineProvisioningPermit: %s", raw)
		}
		if err := adapter.BindProviderRequest(t.Context(), fixture.identity, ec2.CapacityFenceProviderRequest{
			ClaimID:               claim.ClaimID,
			ClaimBindingDigest:    claim.ClaimBindingDigest,
			ProviderRequestDigest: "sha256:" + strings.Repeat("a", 64),
		}); err != nil {
			t.Fatalf("BindProviderRequest() before Record() error = %v", err)
		}

		receipt := (&ec2.CapacityFenceClaim{
			ClaimID:            claim.ClaimID,
			ClaimBindingDigest: claim.ClaimBindingDigest,
			ClientToken:        claim.ClientToken,
		})
		record, err := receipt.MutationReceipt(fixture.identity, "i-0123456789abcdef0")
		if err != nil {
			t.Fatalf("construct receipt: %v", err)
		}
		if err := adapter.Record(t.Context(), record); err != nil {
			t.Fatalf("Record() from persisted target identity error = %v", err)
		}

		restarted := NewAdapter(fixture.client, fixture.client)
		if err := restarted.EnsureReceipt(t.Context(), fixture.identity, infrav1.Instance{
			ID: "i-0123456789abcdef0",
			Tags: map[string]string{
				ec2.CapacityFenceClaimBindingTagKey: claim.ClaimBindingDigest,
			},
		}); err != nil {
			t.Fatalf("EnsureReceipt() after adapter restart error = %v", err)
		}
		stored = fixture.getPermit(t)
		if len(stored.Status.Claims) != 1 || stored.Status.Claims[0].ProviderReceipt == nil {
			t.Fatalf("stored claims after restart recovery = %#v, want one provider receipt", stored.Status.Claims)
		}
		if stored.Status.Claims[0].ProviderReceipt.ClaimBindingDigest.Digest != claim.ClaimBindingDigest {
			t.Fatalf("stored receipt = %#v, want exact provider tag binding %q", stored.Status.Claims[0].ProviderReceipt, claim.ClaimBindingDigest)
		}
	})
	t.Run("post-bind current generations recover the persisted pre-bind claim through a receipt", func(t *testing.T) {
		fixture := newCapacityFenceAdapterFixture(t)
		adapter := NewAdapter(fixture.client, fixture.client)
		claim, err := adapter.Claim(t.Context(), fixture.identity)
		if err != nil {
			t.Fatalf("Claim() error = %v", err)
		}
		if err := adapter.BindProviderRequest(t.Context(), fixture.identity, ec2.CapacityFenceProviderRequest{
			ClaimID:               claim.ClaimID,
			ClaimBindingDigest:    claim.ClaimBindingDigest,
			ProviderRequestDigest: "sha256:" + strings.Repeat("b", 64),
		}); err != nil {
			t.Fatalf("BindProviderRequest() error = %v", err)
		}

		preBindIdentity := fixture.identity
		fixture.advanceTargetGenerations(t)
		if fixture.identity.MachineGeneration <= preBindIdentity.MachineGeneration || fixture.identity.AWSMachineGeneration <= preBindIdentity.AWSMachineGeneration {
			t.Fatalf("current target generations = %#v, want both after %#v", fixture.identity, preBindIdentity)
		}
		recreatedTarget := fixture.identity
		recreatedTarget.AWSMachineUID = "recreated-aws-machine"
		if err := adapter.EnsureReceipt(t.Context(), recreatedTarget, infrav1.Instance{
			ID:   "i-0123456789abcdef0",
			Tags: map[string]string{ec2.CapacityFenceClaimBindingTagKey: claim.ClaimBindingDigest},
		}); !errors.Is(err, capacityfence.ErrTargetIdentityMismatch) {
			t.Fatalf("EnsureReceipt() with recreated AWSMachine target error = %v, want ErrTargetIdentityMismatch", err)
		}

		if err := adapter.EnsureReceipt(t.Context(), fixture.identity, infrav1.Instance{
			ID: "i-0123456789abcdef0",
			Tags: map[string]string{
				ec2.CapacityFenceClaimBindingTagKey: claim.ClaimBindingDigest,
			},
		}); err != nil {
			t.Fatalf("EnsureReceipt() at current generation error = %v", err)
		}

		stored := fixture.getPermit(t)
		if len(stored.Status.Claims) != 1 || stored.Status.Claims[0].ProviderReceipt == nil {
			t.Fatalf("stored claims = %#v, want recovered receipt", stored.Status.Claims)
		}
		if stored.Status.Claims[0].MachineRef.Generation != preBindIdentity.MachineGeneration || stored.Status.Claims[0].AWSMachineRef.Generation != preBindIdentity.AWSMachineGeneration {
			t.Fatalf("persisted claim target = %#v, want pre-bind target %#v", stored.Status.Claims[0], preBindIdentity)
		}
	})
	t.Run("claim recovers a gate-persisted pre-bind claim at current generations", func(t *testing.T) {
		fixture := newCapacityFenceAdapterFixture(t)
		adapter := NewAdapter(fixture.client, fixture.client)
		claimed, err := adapter.Claim(t.Context(), fixture.identity)
		if err != nil {
			t.Fatalf("initial Claim() error = %v", err)
		}
		fixture.advanceTargetGenerations(t)

		recovered, err := adapter.Claim(t.Context(), fixture.identity)
		if err != nil {
			t.Fatalf("Claim() from persisted pre-bind target error = %v", err)
		}
		if !reflect.DeepEqual(recovered, claimed) {
			t.Fatalf("recovered claim = %#v, want %#v", recovered, claimed)
		}
		if stored := fixture.getPermit(t); len(stored.Status.Claims) != 1 {
			t.Fatalf("stored claims = %#v, want one durable claim", stored.Status.Claims)
		}
	})
	t.Run("deletion query reports only bound provider requests without receipts", func(t *testing.T) {
		fixture := newCapacityFenceAdapterFixture(t)
		adapter := NewAdapter(fixture.client, fixture.client)

		unresolved, err := adapter.HasUnresolvedProviderRequest(t.Context(), fixture.identity)
		if err != nil {
			t.Fatalf("HasUnresolvedProviderRequest() without persisted claim error = %v", err)
		}
		if unresolved {
			t.Fatal("HasUnresolvedProviderRequest() without persisted claim = true, want false")
		}

		claim, err := adapter.Claim(t.Context(), fixture.identity)
		if err != nil {
			t.Fatalf("Claim() error = %v", err)
		}
		stored := fixture.getPermit(t)
		ambiguousClaim := stored.Status.Claims[0]
		ambiguousClaim.ClaimID = strings.Repeat("e", 64)
		stored.Status.Claims = append(stored.Status.Claims, ambiguousClaim)
		if err := fixture.client.Status().Update(t.Context(), stored); err != nil {
			t.Fatalf("store ambiguous persisted claim: %v", err)
		}
		if _, err := adapter.HasUnresolvedProviderRequest(t.Context(), fixture.identity); !errors.Is(err, capacityfence.ErrPermitSelectionAmbiguous) {
			t.Fatalf("HasUnresolvedProviderRequest() with ambiguous persisted claims error = %v, want ErrPermitSelectionAmbiguous", err)
		}
		stored = fixture.getPermit(t)
		stored.Status.Claims = stored.Status.Claims[:1]
		if err := fixture.client.Status().Update(t.Context(), stored); err != nil {
			t.Fatalf("restore unambiguous persisted claim: %v", err)
		}

		if unresolved, err = adapter.HasUnresolvedProviderRequest(t.Context(), fixture.identity); err != nil || unresolved {
			t.Fatalf("HasUnresolvedProviderRequest() before bind = (%t, %v), want (false, nil)", unresolved, err)
		}
		if err := adapter.BindProviderRequest(t.Context(), fixture.identity, ec2.CapacityFenceProviderRequest{
			ClaimID:               claim.ClaimID,
			ClaimBindingDigest:    claim.ClaimBindingDigest,
			ProviderRequestDigest: "sha256:" + strings.Repeat("c", 64),
		}); err != nil {
			t.Fatalf("BindProviderRequest() error = %v", err)
		}
		if unresolved, err = adapter.HasUnresolvedProviderRequest(t.Context(), fixture.identity); err != nil || !unresolved {
			t.Fatalf("HasUnresolvedProviderRequest() after bind = (%t, %v), want (true, nil)", unresolved, err)
		}
		if err := adapter.EnsureReceipt(t.Context(), fixture.identity, infrav1.Instance{
			ID:   "i-0123456789abcdef0",
			Tags: map[string]string{ec2.CapacityFenceClaimBindingTagKey: "sha256:" + strings.Repeat("d", 64)},
		}); !errors.Is(err, capacityfence.ErrProviderReceiptBinding) {
			t.Fatalf("EnsureReceipt() with wrong claim tag error = %v, want ErrProviderReceiptBinding", err)
		}
		if unresolved, err = adapter.HasUnresolvedProviderRequest(t.Context(), fixture.identity); err != nil || !unresolved {
			t.Fatalf("HasUnresolvedProviderRequest() after rejected receipt = (%t, %v), want (true, nil)", unresolved, err)
		}
		if err := adapter.EnsureReceipt(t.Context(), fixture.identity, infrav1.Instance{
			ID:   "i-0123456789abcdef0",
			Tags: map[string]string{ec2.CapacityFenceClaimBindingTagKey: claim.ClaimBindingDigest},
		}); err != nil {
			t.Fatalf("EnsureReceipt() with exact claim tag error = %v", err)
		}
		if unresolved, err = adapter.HasUnresolvedProviderRequest(t.Context(), fixture.identity); err != nil || unresolved {
			t.Fatalf("HasUnresolvedProviderRequest() after receipt = (%t, %v), want (false, nil)", unresolved, err)
		}

		if _, err := NewAdapter(nil, nil).HasUnresolvedProviderRequest(t.Context(), fixture.identity); !errors.Is(err, capacityfence.ErrInvalidConfiguration) {
			t.Fatalf("HasUnresolvedProviderRequest() with unavailable authority error = %v, want ErrInvalidConfiguration", err)
		}
	})
	t.Run("provider request binds once and rejects drift before provider I/O", func(t *testing.T) {
		fixture := newCapacityFenceAdapterFixture(t)
		adapter := NewAdapter(fixture.client, fixture.client)
		claim, err := adapter.Claim(t.Context(), fixture.identity)
		if err != nil {
			t.Fatalf("Claim() error = %v", err)
		}
		first := ec2.CapacityFenceProviderRequest{
			ClaimID:               claim.ClaimID,
			ClaimBindingDigest:    claim.ClaimBindingDigest,
			ProviderRequestDigest: "sha256:" + strings.Repeat("a", 64),
		}
		if err := adapter.BindProviderRequest(t.Context(), fixture.identity, first); err != nil {
			t.Fatalf("first BindProviderRequest() error = %v", err)
		}
		if err := adapter.BindProviderRequest(t.Context(), fixture.identity, first); err != nil {
			t.Fatalf("exact BindProviderRequest() retry error = %v", err)
		}
		drift := first
		drift.ProviderRequestDigest = "sha256:" + strings.Repeat("b", 64)
		if err := adapter.BindProviderRequest(t.Context(), fixture.identity, drift); !errors.Is(err, capacityfence.ErrProviderRequestConflict) {
			t.Fatalf("drift BindProviderRequest() error = %v, want ErrProviderRequestConflict", err)
		}
	})
}

type capacityFenceAdapterFixture struct {
	client   client.Client
	permit   *platformv1alpha1.MachineProvisioningPermit
	identity ec2.CapacityFenceIdentity
}

func newCapacityFenceAdapterFixture(t *testing.T) *capacityFenceAdapterFixture {
	t.Helper()
	now := time.Now().UTC()
	const namespace = "team-a"
	permit := &platformv1alpha1.MachineProvisioningPermit{
		TypeMeta:   metav1.TypeMeta{APIVersion: platformv1alpha1.GroupVersion.String(), Kind: platformv1alpha1.KindMachineProvisioningPermit},
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "permit", UID: "permit-uid", Generation: 1},
		Spec: platformv1alpha1.MachineProvisioningPermitSpec{
			AppThrustClusterRef:    capacityFenceExactRef(platformv1alpha1.GroupVersion.Group, "AppThrustCluster", namespace, "appthrust-cluster", "appthrust-cluster-uid", 2),
			CAPIClusterRef:         capacityFenceExactRef("cluster.x-k8s.io", "Cluster", namespace, "capi-cluster", "capi-cluster-uid", 7),
			CapacityReservationRef: capacityFenceExactRef(platformv1alpha1.GroupVersion.Group, "CapacityReservation", namespace, "capacity-reservation", "capacity-reservation-uid", 3),
			ClusterOperationRef:    capacityFenceExactRef(platformv1alpha1.GroupVersion.Group, "ClusterOperation", namespace, "cluster-operation", "cluster-operation-uid", 6),
			TopologyOwnerRef:       capacityFenceExactRef("cluster.x-k8s.io", "MachineSet", namespace, "worker-pool", "worker-pool-uid", 4),
			AWSMachineTemplateRef:  capacityFenceExactRef("infrastructure.cluster.x-k8s.io", "AWSMachineTemplate", namespace, "aws-machine-template", "aws-machine-template-uid", 8),
			ProviderIdentityRef:    capacityFenceExactClusterRef("infrastructure.cluster.x-k8s.io", "AWSClusterStaticIdentity", "aws-provider-identity", "aws-provider-identity-uid", 9),
			RealizationDigest:      capacityFenceDigest("1"),
			TemplateDigest:         capacityFenceDigest("2"),
			ProviderIdentityDigest: capacityFenceDigest("3"),
			Action:                 platformv1alpha1.MachineProvisioningPermitActionInitial,
			Role:                   platformv1alpha1.MachineProvisioningPermitRoleWorker,
			Pool:                   "worker-pool",
			AllowedCount:           1,
			ExpiresAt:              metav1.NewTime(now.Add(time.Hour)),
		},
	}
	identity := ec2.CapacityFenceIdentity{
		MachineNamespace: namespace, MachineName: "machine-0", MachineUID: "machine-uid", MachineGeneration: 3,
		AWSMachineNamespace: namespace, AWSMachineName: "aws-machine-0", AWSMachineUID: "aws-machine-uid", AWSMachineGeneration: 5,
	}
	machineGVK := schema.GroupVersionKind{Group: "cluster.x-k8s.io", Version: "v1beta2", Kind: "Machine"}
	awsMachineGVK := schema.GroupVersionKind{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Kind: "AWSMachine"}
	machineSetGVK := schema.GroupVersionKind{Group: "cluster.x-k8s.io", Version: "v1beta2", Kind: "MachineSet"}
	templateGVK := schema.GroupVersionKind{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Kind: "AWSMachineTemplate"}
	providerGVK := schema.GroupVersionKind{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Kind: "AWSClusterStaticIdentity"}
	machine := capacityFenceUnstructured(machineGVK, namespace, identity.MachineName, identity.MachineUID, identity.MachineGeneration)
	awsMachine := capacityFenceUnstructured(awsMachineGVK, namespace, identity.AWSMachineName, identity.AWSMachineUID, identity.AWSMachineGeneration)
	topologyOwner := capacityFenceUnstructured(machineSetGVK, namespace, "worker-pool", "worker-pool-uid", 4)
	controller := true
	machine.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: machineSetGVK.GroupVersion().String(), Kind: machineSetGVK.Kind, Name: topologyOwner.GetName(), UID: topologyOwner.GetUID(), Controller: &controller}})
	awsMachine.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: machineGVK.GroupVersion().String(), Kind: machineGVK.Kind, Name: machine.GetName(), UID: machine.GetUID(), Controller: &controller}})
	templateSpec := map[string]any{"ami": map[string]any{"id": "ami-0123456789abcdef0"}, "instanceType": "m6i.large", "iamInstanceProfile": "team-a-nodes", "rootVolume": map[string]any{"size": int64(64), "type": "gp3"}}
	if err := unstructured.SetNestedMap(awsMachine.Object, templateSpec, "spec"); err != nil {
		t.Fatalf("set AWSMachine spec: %v", err)
	}
	if err := unstructured.SetNestedMap(machine.Object, map[string]any{
		"apiGroup": awsMachineGVK.Group,
		"kind":     awsMachineGVK.Kind,
		"name":     awsMachine.GetName(),
	}, "spec", "infrastructureRef"); err != nil {
		t.Fatalf("set Machine infrastructure reference: %v", err)
	}

	reservationExpiresAt := metav1.NewTime(now.Add(2 * time.Hour))
	reservationDigest := permit.Spec.RealizationDigest
	cluster := &platformv1alpha1.AppThrustCluster{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "appthrust-cluster", UID: "appthrust-cluster-uid", Generation: 2},
		Status: platformv1alpha1.AppThrustClusterStatus{ObservedGeneration: 2, Realization: &platformv1alpha1.AppThrustClusterRealizationStatus{
			ObservedGeneration: 2, CapacityReservationRef: permit.Spec.CapacityReservationRef, CAPIClusterRef: permit.Spec.CAPIClusterRef, RealizationDigest: permit.Spec.RealizationDigest,
		}},
	}
	reservation := &platformv1alpha1.CapacityReservation{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "capacity-reservation", UID: "capacity-reservation-uid", Generation: 3},
		Spec:       platformv1alpha1.CapacityReservationSpec{ClusterRef: platformv1alpha1.LocalObjectReference{Name: permit.Spec.AppThrustClusterRef.Name}, OperationRef: &platformv1alpha1.LocalObjectReference{Name: permit.Spec.ClusterOperationRef.Name}, ExpiresAt: &reservationExpiresAt},
		Status:     platformv1alpha1.CapacityReservationStatus{ObservedGeneration: 3, Phase: platformv1alpha1.CapacityReservationPhaseHeld, RealizationDigest: &reservationDigest, Reserved: platformv1alpha1.CapacityReservationAmount{ControlPlanes: 1, Workers: 1}},
	}
	operation := &platformv1alpha1.ClusterOperation{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "cluster-operation", UID: "cluster-operation-uid", Generation: 6},
		Spec: platformv1alpha1.ClusterOperationSpec{
			ClusterRef: platformv1alpha1.LocalObjectReference{Name: permit.Spec.AppThrustClusterRef.Name},
			Type:       platformv1alpha1.ClusterOperationTypeCreate,
			MachineProvisioningAuthorities: []platformv1alpha1.ClusterOperationMachineProvisioningAuthority{{
				PermitName:            common.DnsLabelName(permit.Name),
				TopologyOwnerRef:      permit.Spec.TopologyOwnerRef,
				AWSMachineTemplateRef: permit.Spec.AWSMachineTemplateRef,
				Action:                permit.Spec.Action,
				Role:                  permit.Spec.Role,
				Pool:                  permit.Spec.Pool,
				AllowedCount:          permit.Spec.AllowedCount,
			}},
			Actor:  platformv1alpha1.ClusterOperationActor{Subject: "controller:capacity-fence-adapter", Kind: "Controller"},
			Reason: "Authorize the exact capacity-fence MachineProvisioningPermit.",
		},
		Status: platformv1alpha1.ClusterOperationStatus{ObservedGeneration: 6, Phase: platformv1alpha1.ClusterOperationPhaseRunning},
	}
	capiCluster := capacityFenceUnstructured(schema.GroupVersionKind{Group: "cluster.x-k8s.io", Version: "v1beta2", Kind: "Cluster"}, namespace, "capi-cluster", "capi-cluster-uid", 7)
	template := capacityFenceUnstructured(templateGVK, namespace, "aws-machine-template", "aws-machine-template-uid", 8)
	if err := unstructured.SetNestedMap(template.Object, templateSpec, "spec", "template", "spec"); err != nil {
		t.Fatalf("set template spec: %v", err)
	}
	templateDigest, err := platformv1alpha1.CalculateAWSMachineTemplateTemplateSpecDigestV1(templateSpec)
	if err != nil {
		t.Fatalf("calculate template digest: %v", err)
	}
	permit.Spec.TemplateDigest = templateDigest
	provider := capacityFenceUnstructured(providerGVK, "", "aws-provider-identity", "aws-provider-identity-uid", 9)
	providerSpec := map[string]any{"secretRef": map[string]any{"name": "capa-static-identity", "namespace": "capa-system"}}
	if err := unstructured.SetNestedMap(provider.Object, providerSpec, "spec"); err != nil {
		t.Fatalf("set provider identity spec: %v", err)
	}
	providerDigest, err := platformv1alpha1.CalculateCAPAProviderIdentitySpecDigestV1(providerGVK.Kind, providerSpec)
	if err != nil {
		t.Fatalf("calculate provider identity digest: %v", err)
	}
	permit.Spec.ProviderIdentityDigest = providerDigest

	scheme := runtime.NewScheme()
	if err := platformv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add platform scheme: %v", err)
	}
	for _, gvk := range []schema.GroupVersionKind{machineGVK, awsMachineGVK, machineSetGVK, templateGVK, providerGVK, capiCluster.GroupVersionKind()} {
		scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
		scheme.AddKnownTypeWithName(gvk.GroupVersion().WithKind(gvk.Kind+"List"), &unstructured.UnstructuredList{})
	}
	objects := []client.Object{permit, cluster, reservation, operation, capiCluster, topologyOwner, template, provider, machine, awsMachine}
	return &capacityFenceAdapterFixture{
		client: fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&platformv1alpha1.MachineProvisioningPermit{}).WithObjects(objects...).Build(),
		permit: permit, identity: identity,
	}
}

func (f *capacityFenceAdapterFixture) getPermit(t *testing.T) *platformv1alpha1.MachineProvisioningPermit {
	t.Helper()
	permit := &platformv1alpha1.MachineProvisioningPermit{}
	if err := f.client.Get(t.Context(), client.ObjectKeyFromObject(f.permit), permit); err != nil {
		t.Fatalf("get permit: %v", err)
	}
	return permit
}

func (f *capacityFenceAdapterFixture) advanceTargetGenerations(t *testing.T) {
	t.Helper()
	advance := func(gvk schema.GroupVersionKind, name string) int64 {
		t.Helper()
		object := &unstructured.Unstructured{}
		object.SetGroupVersionKind(gvk)
		if err := f.client.Get(t.Context(), client.ObjectKey{Namespace: f.identity.MachineNamespace, Name: name}, object); err != nil {
			t.Fatalf("get %s before generation advance: %v", gvk.Kind, err)
		}
		object.SetGeneration(object.GetGeneration() + 1)
		if err := f.client.Update(t.Context(), object); err != nil {
			t.Fatalf("update %s generation: %v", gvk.Kind, err)
		}
		current := &unstructured.Unstructured{}
		current.SetGroupVersionKind(gvk)
		if err := f.client.Get(t.Context(), client.ObjectKey{Namespace: f.identity.MachineNamespace, Name: name}, current); err != nil {
			t.Fatalf("get %s after generation advance: %v", gvk.Kind, err)
		}
		return current.GetGeneration()
	}

	f.identity.MachineGeneration = advance(schema.GroupVersionKind{Group: "cluster.x-k8s.io", Version: "v1beta2", Kind: "Machine"}, f.identity.MachineName)
	f.identity.AWSMachineGeneration = advance(schema.GroupVersionKind{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Kind: "AWSMachine"}, f.identity.AWSMachineName)
}

func (f *capacityFenceAdapterFixture) createAmbiguousPermit(t *testing.T) {
	t.Helper()
	second := f.permit.DeepCopy()
	second.Name, second.UID, second.ResourceVersion = "permit-duplicate", "permit-duplicate-uid", ""
	second.Spec.AppThrustClusterRef.Name, second.Spec.AppThrustClusterRef.UID = "appthrust-cluster-duplicate", "appthrust-cluster-duplicate-uid"
	second.Spec.CapacityReservationRef.Name, second.Spec.CapacityReservationRef.UID = "capacity-reservation-duplicate", "capacity-reservation-duplicate-uid"
	second.Spec.ClusterOperationRef.Name, second.Spec.ClusterOperationRef.UID = "cluster-operation-duplicate", "cluster-operation-duplicate-uid"

	cluster := &platformv1alpha1.AppThrustCluster{}
	if err := f.client.Get(t.Context(), client.ObjectKey{
		Namespace: f.permit.Spec.AppThrustClusterRef.Namespace,
		Name:      f.permit.Spec.AppThrustClusterRef.Name,
	}, cluster); err != nil {
		t.Fatalf("get original AppThrustCluster for ambiguous permit: %v", err)
	}
	cluster.Name, cluster.UID, cluster.ResourceVersion = second.Spec.AppThrustClusterRef.Name, types.UID(second.Spec.AppThrustClusterRef.UID), ""
	if cluster.Status.Realization == nil {
		t.Fatal("original AppThrustCluster has no realization")
	}
	cluster.Status.Realization.CapacityReservationRef = second.Spec.CapacityReservationRef

	reservation := &platformv1alpha1.CapacityReservation{}
	if err := f.client.Get(t.Context(), client.ObjectKey{
		Namespace: f.permit.Spec.CapacityReservationRef.Namespace,
		Name:      f.permit.Spec.CapacityReservationRef.Name,
	}, reservation); err != nil {
		t.Fatalf("get original CapacityReservation for ambiguous permit: %v", err)
	}
	reservation.Name, reservation.UID, reservation.ResourceVersion = second.Spec.CapacityReservationRef.Name, types.UID(second.Spec.CapacityReservationRef.UID), ""
	reservation.Spec.ClusterRef.Name = second.Spec.AppThrustClusterRef.Name
	if reservation.Spec.OperationRef == nil {
		t.Fatal("original CapacityReservation has no operationRef")
	}
	reservation.Spec.OperationRef.Name = second.Spec.ClusterOperationRef.Name

	operation := &platformv1alpha1.ClusterOperation{}
	if err := f.client.Get(t.Context(), client.ObjectKey{
		Namespace: f.permit.Spec.ClusterOperationRef.Namespace,
		Name:      f.permit.Spec.ClusterOperationRef.Name,
	}, operation); err != nil {
		t.Fatalf("get original ClusterOperation for ambiguous permit: %v", err)
	}
	operation.Name, operation.UID, operation.ResourceVersion = second.Spec.ClusterOperationRef.Name, types.UID(second.Spec.ClusterOperationRef.UID), ""
	operation.Spec.ClusterRef.Name = second.Spec.AppThrustClusterRef.Name
	if len(operation.Spec.MachineProvisioningAuthorities) != 1 {
		t.Fatalf("original ClusterOperation machineProvisioningAuthorities = %d, want one", len(operation.Spec.MachineProvisioningAuthorities))
	}
	operation.Spec.MachineProvisioningAuthorities[0].PermitName = common.DnsLabelName(second.Name)

	for _, object := range []client.Object{cluster, reservation, operation, second} {
		if err := f.client.Create(t.Context(), object); err != nil {
			t.Fatalf("create ambiguous permit authority object %T: %v", object, err)
		}
	}
}

func (f *capacityFenceAdapterFixture) assertNoClaims(t *testing.T) {
	t.Helper()
	permit := &platformv1alpha1.MachineProvisioningPermit{}
	if err := f.client.Get(t.Context(), client.ObjectKeyFromObject(f.permit), permit); err != nil {
		if apierrors.IsNotFound(err) {
			return
		}
		t.Fatalf("get permit before checking claims: %v", err)
	}
	if len(permit.Status.Claims) != 0 {
		t.Fatalf("permit claims = %#v, want no status mutation", permit.Status.Claims)
	}
}

func capacityFenceExactRef(group, kind, namespace, name string, uid types.UID, generation int64) common.ExactTypedNamespacedObjectReference {
	return common.ExactTypedNamespacedObjectReference{Group: group, Kind: kind, Namespace: namespace, Name: name, UID: common.BoundedUID(uid), Generation: generation}
}

func capacityFenceExactClusterRef(group, kind, name string, uid types.UID, generation int64) common.ExactTypedObjectReference {
	return common.ExactTypedObjectReference{Group: group, Kind: kind, Name: name, UID: common.BoundedUID(uid), Generation: generation}
}

func capacityFenceDigest(hexDigit string) common.VersionedCanonicalSHA256Digest {
	return common.VersionedCanonicalSHA256Digest{SchemaVersion: common.CanonicalDigestSchemaVersionV1, Digest: "sha256:" + strings.Repeat(hexDigit, 64)}
}

func capacityFenceUnstructured(gvk schema.GroupVersionKind, namespace, name string, uid types.UID, generation int64) *unstructured.Unstructured {
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(gvk)
	object.SetNamespace(namespace)
	object.SetName(name)
	object.SetUID(uid)
	object.SetGeneration(generation)
	return object
}
