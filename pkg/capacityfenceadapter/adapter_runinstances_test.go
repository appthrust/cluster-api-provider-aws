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
	"context"
	"errors"
	"testing"

	"github.com/appthrust/platform/pkg/capacityfence"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	awstypes "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/golang/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/scope"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/services/ec2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/test/mocks"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
)

func TestCapacityFenceAdapterGatesRunInstances(t *testing.T) {
	t.Run("missing, ambiguous, wrong-target, and outage deny before RunInstances", func(t *testing.T) {
		testCases := []struct {
			name    string
			prepare func(t *testing.T, fixture *capacityFenceAdapterFixture) (ec2.CapacityFenceAuthorizer, ec2.CapacityFenceIdentity)
			want    error
		}{
			{
				name: "missing permit",
				prepare: func(t *testing.T, fixture *capacityFenceAdapterFixture) (ec2.CapacityFenceAuthorizer, ec2.CapacityFenceIdentity) {
					t.Helper()
					if err := fixture.client.Delete(t.Context(), fixture.permit.DeepCopy()); err != nil {
						t.Fatalf("delete permit: %v", err)
					}
					return NewAdapter(fixture.client, fixture.client), fixture.identity
				},
				want: capacityfence.ErrPermitSelectionNoMatch,
			},
			{
				name: "ambiguous permit",
				prepare: func(t *testing.T, fixture *capacityFenceAdapterFixture) (ec2.CapacityFenceAuthorizer, ec2.CapacityFenceIdentity) {
					t.Helper()
					fixture.createAmbiguousPermit(t)
					return NewAdapter(fixture.client, fixture.client), fixture.identity
				},
				want: capacityfence.ErrPermitSelectionAmbiguous,
			},
			{
				name: "terminating permit",
				prepare: func(t *testing.T, fixture *capacityFenceAdapterFixture) (ec2.CapacityFenceAuthorizer, ec2.CapacityFenceIdentity) {
					t.Helper()
					permit := fixture.getPermit(t)
					permit.Finalizers = []string{"capacityfence.test/finalizer"}
					if err := fixture.client.Update(t.Context(), permit); err != nil {
						t.Fatalf("add permit finalizer: %v", err)
					}
					if err := fixture.client.Delete(t.Context(), permit); err != nil {
						t.Fatalf("start permit termination: %v", err)
					}
					return NewAdapter(fixture.client, fixture.client), fixture.identity
				},
				want: capacityfence.ErrPermitSelectionNoMatch,
			},
			{
				name: "wrong target incarnation",
				prepare: func(_ *testing.T, fixture *capacityFenceAdapterFixture) (ec2.CapacityFenceAuthorizer, ec2.CapacityFenceIdentity) {
					identity := fixture.identity
					identity.AWSMachineUID = "recreated-aws-machine"
					return NewAdapter(fixture.client, fixture.client), identity
				},
				want: capacityfence.ErrTargetIdentityMismatch,
			},
			{
				name: "authority outage",
				prepare: func(_ *testing.T, fixture *capacityFenceAdapterFixture) (ec2.CapacityFenceAuthorizer, ec2.CapacityFenceIdentity) {
					return NewAdapter(nil, nil), fixture.identity
				},
				want: capacityfence.ErrInvalidConfiguration,
			},
		}
		for _, testCase := range testCases {
			testCase := testCase
			t.Run(testCase.name, func(t *testing.T) {
				fixture := newCapacityFenceAdapterFixture(t)
				authorizer, identity := testCase.prepare(t, fixture)
				service, ec2Mock, machineScope := newCapacityFenceAdapterRunService(t, authorizer, identity, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
				ec2Mock.EXPECT().DescribeInstanceTypes(context.TODO(), gomock.Any()).Return(capacityFenceAdapterInstanceTypes(), nil)

				_, err := service.CreateInstance(t.Context(), machineScope, []byte("userdata"), "")
				if !errors.Is(err, testCase.want) {
					t.Fatalf("CreateInstance() error = %v, want %v", err, testCase.want)
				}
				fixture.assertNoClaims(t)
			})
		}
	})

	t.Run("valid authority reaches RunInstances exactly once with stable token tag and receipt", func(t *testing.T) {
		fixture := newCapacityFenceAdapterFixture(t)
		authorizer := NewAdapter(fixture.client, fixture.client)
		claim, err := authorizer.Claim(t.Context(), fixture.identity)
		if err != nil {
			t.Fatalf("preclaiming exact issuer binding: %v", err)
		}
		service, ec2Mock, machineScope := newCapacityFenceAdapterRunService(t, authorizer, fixture.identity, claim.ClaimBindingDigest)
		ec2Mock.EXPECT().DescribeInstanceTypes(context.TODO(), gomock.Any()).Return(capacityFenceAdapterInstanceTypes(), nil)
		ec2Mock.EXPECT().RunInstances(t.Context(), gomock.Any()).Times(1).DoAndReturn(
			func(_ context.Context, input *awsec2.RunInstancesInput, _ ...func(*awsec2.Options)) (*awsec2.RunInstancesOutput, error) {
				if input.ClientToken == nil || len(aws.ToString(input.ClientToken)) != 64 {
					t.Fatalf("RunInstances ClientToken = %q, want one raw stable 64-hex retry token", aws.ToString(input.ClientToken))
				}
				instanceReserved := 0
				for _, specification := range input.TagSpecifications {
					for _, tag := range specification.Tags {
						if aws.ToString(tag.Key) != ec2.CapacityFenceClaimBindingTagKey {
							continue
						}
						if aws.ToString(tag.Value) == aws.ToString(input.ClientToken) {
							t.Fatalf("reserved claim tag leaked the raw token: %#v", tag)
						}
						if specification.ResourceType == awstypes.ResourceTypeInstance {
							instanceReserved++
						}
					}
				}
				if instanceReserved != 1 {
					t.Fatalf("instance reserved claim tag count = %d, want exactly one", instanceReserved)
				}
				return capacityFenceAdapterRunInstancesOutput("i-0123456789abcdef0"), nil
			},
		)
		ec2Mock.EXPECT().DescribeNetworkInterfaces(context.TODO(), gomock.Any()).Return(&awsec2.DescribeNetworkInterfacesOutput{}, nil)

		instance, err := service.CreateInstance(t.Context(), machineScope, []byte("userdata"), "")
		if err != nil {
			t.Fatalf("CreateInstance() error = %v", err)
		}
		if instance.ID != "i-0123456789abcdef0" {
			t.Fatalf("created instance ID = %q", instance.ID)
		}
		stored := fixture.getPermit(t)
		if len(stored.Status.Claims) != 1 || stored.Status.Claims[0].ProviderReceipt == nil || stored.Status.Claims[0].ProviderReceipt.InstanceID != instance.ID {
			t.Fatalf("permit status = %#v, want one claim with a receipt for %q", stored.Status, instance.ID)
		}
	})
}

func newCapacityFenceAdapterRunService(t *testing.T, authorizer ec2.CapacityFenceAuthorizer, identity ec2.CapacityFenceIdentity, claimBindingDigest string) (*ec2.Service, *mocks.MockEC2API, *scope.MachineScope) {
	t.Helper()
	mockCtrl := gomock.NewController(t)
	ec2Mock := mocks.NewMockEC2API(mockCtrl)
	scheme := runtime.NewScheme()
	for _, addToScheme := range []func(*runtime.Scheme) error{corev1.AddToScheme, clusterv1.AddToScheme, infrav1.AddToScheme} {
		if err := addToScheme(scheme); err != nil {
			t.Fatalf("add run service scheme: %v", err)
		}
	}
	cluster := &clusterv1.Cluster{ObjectMeta: metav1.ObjectMeta{Name: "cluster-0", Namespace: identity.MachineNamespace}}
	machine := &clusterv1.Machine{ObjectMeta: metav1.ObjectMeta{Name: identity.MachineName, Namespace: identity.MachineNamespace, UID: identity.MachineUID, Generation: identity.MachineGeneration}}
	awsMachine := &infrav1.AWSMachine{ObjectMeta: metav1.ObjectMeta{Name: identity.AWSMachineName, Namespace: identity.AWSMachineNamespace, UID: identity.AWSMachineUID, Generation: identity.AWSMachineGeneration}, Spec: infrav1.AWSMachineSpec{
		AMI:            infrav1.AMIReference{ID: aws.String("ami-capacity-fence")},
		InstanceType:   "m5.large",
		AdditionalTags: infrav1.Tags{ec2.CapacityFenceClaimBindingTagKey: claimBindingDigest},
	}}
	scopeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, machine).Build()
	clusterScope, err := scope.NewClusterScope(scope.ClusterScopeParams{
		Client: scopeClient, Cluster: cluster,
		AWSCluster: &infrav1.AWSCluster{ObjectMeta: metav1.ObjectMeta{Name: "aws-cluster-0", Namespace: identity.MachineNamespace}, Spec: infrav1.AWSClusterSpec{NetworkSpec: infrav1.NetworkSpec{VPC: infrav1.VPCSpec{ID: "vpc-capacity-fence"}, Subnets: infrav1.Subnets{{ID: "subnet-capacity-fence", IsPublic: false}}}}, Status: infrav1.AWSClusterStatus{Network: infrav1.NetworkStatus{SecurityGroups: map[infrav1.SecurityGroupRole]infrav1.SecurityGroup{infrav1.SecurityGroupNode: {ID: "sg-node"}, infrav1.SecurityGroupLB: {ID: "sg-lb"}}, APIServerELB: infrav1.LoadBalancer{DNSName: "api.capacity-fence.test"}}}},
	})
	if err != nil {
		t.Fatalf("new ClusterScope: %v", err)
	}
	machineScope, err := scope.NewMachineScope(scope.MachineScopeParams{Client: scopeClient, Cluster: cluster, Machine: machine, AWSMachine: awsMachine, InfraCluster: clusterScope})
	if err != nil {
		t.Fatalf("new MachineScope: %v", err)
	}
	service := ec2.NewService(clusterScope).WithInstanceTypeArchitectureCache(nil).WithCapacityFenceAuthorizer(authorizer)
	service.EC2Client = ec2Mock
	return service, ec2Mock, machineScope
}

func capacityFenceAdapterInstanceTypes() *awsec2.DescribeInstanceTypesOutput {
	return &awsec2.DescribeInstanceTypesOutput{InstanceTypes: []awstypes.InstanceTypeInfo{{ProcessorInfo: &awstypes.ProcessorInfo{SupportedArchitectures: []awstypes.ArchitectureType{awstypes.ArchitectureTypeX8664}}}}}
}

func capacityFenceAdapterRunInstancesOutput(instanceID string) *awsec2.RunInstancesOutput {
	return &awsec2.RunInstancesOutput{Instances: []awstypes.Instance{{InstanceId: aws.String(instanceID), InstanceType: awstypes.InstanceTypeM5Large, ImageId: aws.String("ami-capacity-fence"), State: &awstypes.InstanceState{Name: awstypes.InstanceStateNamePending}, Placement: &awstypes.Placement{AvailabilityZone: aws.String("us-east-1a")}}}}
}
