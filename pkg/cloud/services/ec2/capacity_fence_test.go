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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	awstypes "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/golang/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/scope"
	"sigs.k8s.io/cluster-api-provider-aws/v2/test/mocks"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
)

const capacityFenceTestDefaultClaimBindingDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var capacityFenceTestNow = time.Date(2026, time.August, 17, 0, 0, 0, 0, time.UTC)

func TestCapacityFenceMissingPermitDeniesRunInstances(t *testing.T) {
	authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow)
	service, _ := newCapacityFenceRunService(t, authorizer)

	_, err := service.runMachineInstance(context.Background(), "node", capacityFenceTestInstance(), capacityFenceTestIdentity("machine-0", "aws-machine-0"))
	if err == nil {
		t.Fatal("expected missing permit to deny RunInstances")
	}
	if got := authorizer.GrantedClaims(); got != 0 {
		t.Fatalf("expected no granted claims, got %d", got)
	}
	if got := authorizer.ReceiptCount(); got != 0 {
		t.Fatalf("expected no receipt, got %d", got)
	}
}

func TestCapacityFenceExpiredPermitDeniesRunInstances(t *testing.T) {
	identity := capacityFenceTestIdentity("machine-0", "aws-machine-0")
	permit := newCapacityFenceTestPermit(identity, "expired", "token-expired")
	permit.ExpiresAt = capacityFenceTestNow
	authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow, permit)
	service, _ := newCapacityFenceRunService(t, authorizer)

	_, err := service.runMachineInstance(context.Background(), "node", capacityFenceTestInstance(), identity)
	if err == nil {
		t.Fatal("expected expired permit to deny RunInstances")
	}
	if got := authorizer.GrantedClaims(); got != 0 {
		t.Fatalf("expected no granted claims, got %d", got)
	}
}

func TestCapacityFenceWrongBindingDeniesRunInstances(t *testing.T) {
	identity := capacityFenceTestIdentity("machine-0", "aws-machine-0")
	wrongIdentity := capacityFenceTestIdentity("machine-other", "aws-machine-other")
	authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow, newCapacityFenceTestPermit(wrongIdentity, "wrong-binding", "token-wrong"))
	service, _ := newCapacityFenceRunService(t, authorizer)

	_, err := service.runMachineInstance(context.Background(), "node", capacityFenceTestInstance(), identity)
	if err == nil {
		t.Fatal("expected wrong permit binding to deny RunInstances")
	}
	if got := authorizer.GrantedClaims(); got != 0 {
		t.Fatalf("expected no granted claims, got %d", got)
	}
}

func TestCapacityFenceAuthorizerOutageDeniesRunInstances(t *testing.T) {
	service, _ := newCapacityFenceRunService(t, unavailableCapacityFenceAuthorizer{})

	_, err := service.runMachineInstance(context.Background(), "node", capacityFenceTestInstance(), capacityFenceTestIdentity("machine-0", "aws-machine-0"))
	if err == nil {
		t.Fatal("expected authorizer outage to deny RunInstances")
	}
}

func TestCapacityFenceConcurrentCreatesCapacityOneClaimsOnceAndRunsAtMostOne(t *testing.T) {
	first := capacityFenceTestIdentity("machine-0", "aws-machine-0")
	second := capacityFenceTestIdentity("machine-1", "aws-machine-1")
	firstPermit := newCapacityFenceTestPermit(first, "permit-0", "token-0")
	secondPermit := newCapacityFenceTestPermit(second, "permit-1", "token-1")
	secondPermit.ReservationID = firstPermit.ReservationID
	authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow, firstPermit, secondPermit)
	service, ec2Mock := newCapacityFenceRunService(t, authorizer)

	ec2Mock.EXPECT().RunInstances(gomock.Any(), gomock.Any()).Times(1).DoAndReturn(
		func(_ context.Context, _ *awsec2.RunInstancesInput, _ ...func(*awsec2.Options)) (*awsec2.RunInstancesOutput, error) {
			return capacityFenceRunInstancesOutput("i-capacity-one"), nil
		},
	)

	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, identity := range []CapacityFenceIdentity{first, second} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := service.runMachineInstance(context.Background(), "node", capacityFenceTestInstance(), identity)
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	var successes int
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one create to succeed, got %d", successes)
	}
	if got := authorizer.GrantedClaims(); got != 1 {
		t.Fatalf("expected exactly one granted claim, got %d", got)
	}
	if got := authorizer.ClaimAttempts(); got != 2 {
		t.Fatalf("expected two claim attempts, got %d", got)
	}
	if got := authorizer.ReceiptCount(); got != 1 {
		t.Fatalf("expected exactly one mutation receipt, got %d", got)
	}
}

func TestCapacityFenceValidPermitPropagatesIdentitySetsTokenAndRecordsReceipt(t *testing.T) {
	identity := capacityFenceTestIdentity("machine-0", "aws-machine-0")
	permit := newCapacityFenceTestPermit(identity, "permit-valid", "stable-client-token")
	authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow, permit)
	service, ec2Mock, machineScope := newCapacityFenceCreateService(t, authorizer, identity)
	ordinaryTagKey := "example.com/propagate-to-eni"
	ordinaryTagValue := "ordinary-value"

	ctx := context.WithValue(context.Background(), capacityFenceContextKey{}, "create")
	ec2Mock.EXPECT().DescribeInstanceTypes(context.TODO(), gomock.Any()).Return(
		&awsec2.DescribeInstanceTypesOutput{InstanceTypes: []awstypes.InstanceTypeInfo{{
			ProcessorInfo: &awstypes.ProcessorInfo{SupportedArchitectures: []awstypes.ArchitectureType{awstypes.ArchitectureTypeX8664}},
		}}}, nil,
	)
	ec2Mock.EXPECT().RunInstances(ctx, gomock.Any()).Times(1).DoAndReturn(
		func(gotCtx context.Context, input *awsec2.RunInstancesInput, _ ...func(*awsec2.Options)) (*awsec2.RunInstancesOutput, error) {
			if gotCtx != ctx {
				t.Errorf("expected CreateInstance context at RunInstances boundary")
			}
			assertCapacityFenceRunInstancesBinding(t, input, permit)
			out := capacityFenceRunInstancesOutput("i-valid")
			out.Instances[0].Tags = []awstypes.Tag{
				{Key: aws.String(CapacityFenceClaimBindingTagKey), Value: aws.String(permit.ClaimBindingDigest)},
				{Key: aws.String(ordinaryTagKey), Value: aws.String(ordinaryTagValue)},
			}
			return out, nil
		},
	)
	ec2Mock.EXPECT().DescribeNetworkInterfaces(context.TODO(), gomock.Any()).Return(
		&awsec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: []awstypes.NetworkInterface{{
			NetworkInterfaceId: aws.String("eni-valid"),
		}}}, nil,
	)
	ec2Mock.EXPECT().CreateTags(context.TODO(), gomock.Eq(&awsec2.CreateTagsInput{
		Resources: []string{"eni-valid"},
		Tags: []awstypes.Tag{{
			Key:   aws.String(ordinaryTagKey),
			Value: aws.String(ordinaryTagValue),
		}},
	})).Return(&awsec2.CreateTagsOutput{}, nil)

	instance, err := service.CreateInstance(ctx, machineScope, []byte("userdata"), "")
	if err != nil {
		t.Fatalf("expected valid permit to create an instance: %v", err)
	}
	if instance.ID != "i-valid" {
		t.Fatalf("expected i-valid, got %q", instance.ID)
	}
	if got := instance.Tags[CapacityFenceClaimBindingTagKey]; got != permit.ClaimBindingDigest {
		t.Fatalf("returned instance claim-binding tag = %q, want %q", got, permit.ClaimBindingDigest)
	}
	if got := instance.Tags[ordinaryTagKey]; got != ordinaryTagValue {
		t.Fatalf("returned instance ordinary tag = %q, want %q", got, ordinaryTagValue)
	}
	receipt := authorizer.ReceiptForClaim("claim/permit-valid")
	if receipt == nil {
		t.Fatal("expected a bound provider mutation receipt")
	}
	expectedClaimBindingDigest := capacityFenceTestClaimBindingDigest(t, permit)
	if receipt.ClaimID != "claim/"+permit.ID || receipt.ClaimBindingDigest != expectedClaimBindingDigest {
		t.Fatalf("receipt did not retain the supplied claim and provider evidence: %#v", receipt)
	}
	if receipt.ClaimBindingDigest == permit.ClientToken {
		t.Fatalf("raw ClientToken escaped into the receipt: %#v", receipt)
	}
	if receipt.MachineUID != identity.MachineUID || receipt.MachineGeneration != identity.MachineGeneration || receipt.AWSMachineUID != identity.AWSMachineUID || receipt.AWSMachineGeneration != identity.AWSMachineGeneration {
		t.Fatalf("receipt did not bind exact Machine and AWSMachine identities: %#v", receipt)
	}
	if receipt.InstanceID != instance.ID {
		t.Fatalf("receipt instance ID %q does not match returned instance %q", receipt.InstanceID, instance.ID)
	}
}

func TestCapacityFenceReservedBindingTagIsNeverMutatedAfterCreate(t *testing.T) {
	service, ec2Mock := newCapacityFenceRunService(t, unavailableCapacityFenceAuthorizer{})
	resourceID := aws.String("i-owner-bound")

	ec2Mock.EXPECT().CreateTags(context.TODO(), gomock.Eq(&awsec2.CreateTagsInput{
		Resources: []string{aws.ToString(resourceID)},
		Tags: []awstypes.Tag{{
			Key:   aws.String("example.com/ordinary"),
			Value: aws.String("ordinary-value"),
		}},
	})).Return(&awsec2.CreateTagsOutput{}, nil)
	ec2Mock.EXPECT().DeleteTags(gomock.Any(), gomock.Any()).Times(0)

	err := service.UpdateResourceTags(resourceID, map[string]string{
		CapacityFenceClaimBindingTagKey: capacityFenceTestDefaultClaimBindingDigest,
		"example.com/ordinary":          "ordinary-value",
	}, map[string]string{
		CapacityFenceClaimBindingTagKey: capacityFenceTestDefaultClaimBindingDigest,
	})
	if err != nil {
		t.Fatalf("UpdateResourceTags() error = %v", err)
	}
}

func TestCapacityFenceRejectsSpoofedReservedTag(t *testing.T) {
	identity := capacityFenceTestIdentity("machine-0", "aws-machine-0")
	permit := newCapacityFenceTestPermit(identity, "permit-spoof", "stable-spoof-token")
	authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow, permit)
	service, _ := newCapacityFenceRunService(t, authorizer)
	instanceInput := capacityFenceTestInstance()
	instanceInput.Tags[CapacityFenceClaimBindingTagKey] = "sha256:" + capacityFenceTestHexDigest("spoofed-binding")

	if _, err := service.runMachineInstance(context.Background(), "node", instanceInput, identity); err == nil {
		t.Fatal("expected a stale caller claim-binding tag to deny RunInstances")
	}
}

func TestCapacityFenceImmediateRecordRejectsWrongClaimBindingDigest(t *testing.T) {
	identity := capacityFenceTestIdentity("machine-0", "aws-machine-0")
	permit := newCapacityFenceTestPermit(identity, "permit-record", "stable-record-token")
	authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow, permit)
	claim, err := authorizer.Claim(context.Background(), identity)
	if err != nil {
		t.Fatalf("claiming capacity: %v", err)
	}
	receipt, err := claim.MutationReceipt(identity, "i-record")
	if err != nil {
		t.Fatalf("constructing receipt: %v", err)
	}
	receipt.ClaimBindingDigest = "wrong-binding"
	if err := authorizer.Record(context.Background(), receipt); err == nil {
		t.Fatal("expected immediate Record to reject the wrong claim-binding digest")
	}
	if got := authorizer.ReceiptCount(); got != 0 {
		t.Fatalf("expected rejected Record to store no receipt, got %d", got)
	}
}

func TestCapacityFenceLostRunInstancesResponseRetriesOneProviderEffect(t *testing.T) {
	identity := capacityFenceTestIdentity("machine-0", "aws-machine-0")
	permit := newCapacityFenceTestPermit(identity, "permit-retry", "stable-retry-token")
	authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow, permit)
	service, ec2Mock := newCapacityFenceRunService(t, authorizer)
	ec2Mock.EXPECT().DescribeInstances(gomock.Any(), gomock.Any()).Times(0)

	var rpcCount int
	effectsByToken := map[string]string{}
	ec2Mock.EXPECT().RunInstances(gomock.Any(), gomock.Any()).Times(2).DoAndReturn(
		func(_ context.Context, input *awsec2.RunInstancesInput, _ ...func(*awsec2.Options)) (*awsec2.RunInstancesOutput, error) {
			rpcCount++
			token := aws.ToString(input.ClientToken)
			if _, exists := effectsByToken[token]; !exists {
				effectsByToken[token] = "i-retry"
				return nil, errors.New("lost RunInstances response after provider effect")
			}
			return capacityFenceRunInstancesOutput(effectsByToken[token]), nil
		},
	)

	if _, err := service.runMachineInstance(context.Background(), "node", capacityFenceTestInstance(), identity); err == nil {
		t.Fatal("expected the lost first RunInstances response to reach the caller as an error")
	}
	if _, err := service.runMachineInstance(context.Background(), "node", capacityFenceTestInstance(), identity); err != nil {
		t.Fatalf("expected same-token RunInstances retry to recover one provider effect: %v", err)
	}
	if rpcCount != 2 {
		t.Fatalf("RunInstances RPC count = %d, want 2", rpcCount)
	}
	if len(effectsByToken) != 1 || effectsByToken[permit.ClientToken] != "i-retry" {
		t.Fatalf("provider effects = %#v, want exactly one effect for the stable token", effectsByToken)
	}
	if got := authorizer.GrantedClaims(); got != 1 {
		t.Fatalf("expected retry to reuse one claim, got %d grants", got)
	}
}

func TestCapacityFenceProviderRequestDriftFailsBeforeSecondRunInstances(t *testing.T) {
	identity := capacityFenceTestIdentity("machine-0", "aws-machine-0")
	permit := newCapacityFenceTestPermit(identity, "permit-drift", "stable-drift-token")
	authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow, permit)
	service, ec2Mock := newCapacityFenceRunService(t, authorizer)
	ec2Mock.EXPECT().RunInstances(gomock.Any(), gomock.Any()).Times(1).Return(capacityFenceRunInstancesOutput("i-drift"), nil)

	if _, err := service.runMachineInstance(context.Background(), "node", capacityFenceTestInstance(), identity); err != nil {
		t.Fatalf("first exact request failed: %v", err)
	}
	drifted := capacityFenceTestInstance()
	drifted.UserData = aws.String("different-finalized-user-data")
	if _, err := service.runMachineInstance(context.Background(), "node", drifted, identity); err == nil {
		t.Fatal("expected finalized provider request drift to deny before a second RunInstances RPC")
	}
	if got := authorizer.ProviderRequestForClaim("claim/permit-drift"); got == "" {
		t.Fatal("expected the first finalized request digest to be retained")
	}
}

func TestCapacityFenceProviderRequestDigestBindsFinalizedCreateSemantics(t *testing.T) {
	base := capacityFenceFinalizedRunInstancesInput()
	want, err := CapacityFenceProviderRequestDigest(base)
	if err != nil {
		t.Fatalf("digest finalized input: %v", err)
	}
	withDifferentToken := capacityFenceFinalizedRunInstancesInput()
	withDifferentToken.ClientToken = aws.String("different-raw-token")
	if got, err := CapacityFenceProviderRequestDigest(withDifferentToken); err != nil || got != want {
		t.Fatalf("ClientToken-only digest = %q, %v; want token-free digest %q", got, err, want)
	}
	for name, mutate := range map[string]func(*awsec2.RunInstancesInput){
		"AMI":           func(input *awsec2.RunInstancesInput) { input.ImageId = aws.String("ami-drift") },
		"instance type": func(input *awsec2.RunInstancesInput) { input.InstanceType = awstypes.InstanceTypeM6iLarge },
		"subnet": func(input *awsec2.RunInstancesInput) {
			input.NetworkInterfaces[0].SubnetId = aws.String("subnet-drift")
		},
		"security groups": func(input *awsec2.RunInstancesInput) {
			input.NetworkInterfaces[0].Groups = append(input.NetworkInterfaces[0].Groups, "sg-drift")
		},
		"user data": func(input *awsec2.RunInstancesInput) { input.UserData = aws.String("drifted-user-data") },
		"volumes":   func(input *awsec2.RunInstancesInput) { input.BlockDeviceMappings[0].Ebs.VolumeSize = aws.Int32(128) },
		"metadata options": func(input *awsec2.RunInstancesInput) {
			input.MetadataOptions.HttpTokens = awstypes.HttpTokensStateRequired
		},
		"effective tags": func(input *awsec2.RunInstancesInput) {
			input.TagSpecifications[0].Tags[0].Value = aws.String("drifted-tag")
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := capacityFenceFinalizedRunInstancesInput()
			mutate(input)
			got, err := CapacityFenceProviderRequestDigest(input)
			if err != nil {
				t.Fatalf("digest drifted input: %v", err)
			}
			if got == want {
				t.Fatal("finalized provider request drift did not change its canonical digest")
			}
		})
	}
}

func TestCapacityFenceProviderRequestDigestCanonicalizesSetLikeCollections(t *testing.T) {
	testCases := []struct {
		name    string
		arrange func(*awsec2.RunInstancesInput)
		permute func(*awsec2.RunInstancesInput)
		drift   func(*awsec2.RunInstancesInput)
	}{
		{
			name: "security group IDs",
			arrange: func(input *awsec2.RunInstancesInput) {
				input.NetworkInterfaces = nil
				input.SubnetId = aws.String("subnet-finalized")
				input.SecurityGroupIds = []string{"sg-top-a", "sg-top-b"}
			},
			permute: func(input *awsec2.RunInstancesInput) {
				input.SecurityGroupIds[0], input.SecurityGroupIds[1] = input.SecurityGroupIds[1], input.SecurityGroupIds[0]
			},
			drift: func(input *awsec2.RunInstancesInput) {
				input.SecurityGroupIds[0] = "sg-top-drift"
			},
		},
		{
			name: "network interface groups",
			arrange: func(input *awsec2.RunInstancesInput) {
				input.NetworkInterfaces = append(input.NetworkInterfaces, awstypes.InstanceNetworkInterfaceSpecification{
					DeviceIndex: aws.Int32(1),
					SubnetId:    aws.String("subnet-secondary"),
					Groups:      []string{"sg-d", "sg-c"},
				})
			},
			permute: func(input *awsec2.RunInstancesInput) {
				for index := range input.NetworkInterfaces {
					groups := input.NetworkInterfaces[index].Groups
					groups[0], groups[1] = groups[1], groups[0]
				}
			},
			drift: func(input *awsec2.RunInstancesInput) {
				input.NetworkInterfaces[1].Groups[0] = "sg-drift"
			},
		},
		{
			name: "block device mappings",
			arrange: func(input *awsec2.RunInstancesInput) {
				input.BlockDeviceMappings = append(input.BlockDeviceMappings, awstypes.BlockDeviceMapping{
					DeviceName: aws.String("/dev/xvdb"),
					Ebs:        &awstypes.EbsBlockDevice{VolumeSize: aws.Int32(32), VolumeType: awstypes.VolumeTypeGp3},
				})
			},
			permute: func(input *awsec2.RunInstancesInput) {
				input.BlockDeviceMappings[0], input.BlockDeviceMappings[1] = input.BlockDeviceMappings[1], input.BlockDeviceMappings[0]
			},
			drift: func(input *awsec2.RunInstancesInput) {
				input.BlockDeviceMappings[1].Ebs.VolumeSize = aws.Int32(48)
			},
		},
		{
			name: "tag specifications",
			arrange: func(input *awsec2.RunInstancesInput) {
				input.TagSpecifications = append(input.TagSpecifications, awstypes.TagSpecification{
					ResourceType: awstypes.ResourceTypeVolume,
					Tags: []awstypes.Tag{
						{Key: aws.String("volume/tag-a"), Value: aws.String("value-a")},
						{Key: aws.String("volume/tag-b"), Value: aws.String("value-b")},
					},
				})
			},
			permute: func(input *awsec2.RunInstancesInput) {
				input.TagSpecifications[0], input.TagSpecifications[1] = input.TagSpecifications[1], input.TagSpecifications[0]
			},
			drift: func(input *awsec2.RunInstancesInput) {
				input.TagSpecifications[1].ResourceType = awstypes.ResourceTypeNetworkInterface
			},
		},
		{
			name:    "tags",
			arrange: func(_ *awsec2.RunInstancesInput) {},
			permute: func(input *awsec2.RunInstancesInput) {
				tags := input.TagSpecifications[0].Tags
				tags[0], tags[1] = tags[1], tags[0]
			},
			drift: func(input *awsec2.RunInstancesInput) {
				input.TagSpecifications[0].Tags[1].Value = aws.String("drifted-value")
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			canonical := capacityFenceFinalizedRunInstancesInput()
			testCase.arrange(canonical)
			want, err := CapacityFenceProviderRequestDigest(canonical)
			if err != nil {
				t.Fatalf("digest canonical input: %v", err)
			}

			permuted := capacityFenceFinalizedRunInstancesInput()
			testCase.arrange(permuted)
			testCase.permute(permuted)
			got, err := CapacityFenceProviderRequestDigest(permuted)
			if err != nil {
				t.Fatalf("digest permuted input: %v", err)
			}
			if got != want {
				t.Fatalf("set-like collection permutation digest = %q, want %q", got, want)
			}

			changed := capacityFenceFinalizedRunInstancesInput()
			testCase.arrange(changed)
			testCase.drift(changed)
			got, err = CapacityFenceProviderRequestDigest(changed)
			if err != nil {
				t.Fatalf("digest semantically changed input: %v", err)
			}
			if got == want {
				t.Fatal("semantic collection change did not change its canonical digest")
			}
		})
	}
}

func TestCapacityFenceProviderRequestDigestPreservesPositionalCollectionOrder(t *testing.T) {
	first := capacityFenceFinalizedRunInstancesInput()
	first.NetworkInterfaces = append(first.NetworkInterfaces, awstypes.InstanceNetworkInterfaceSpecification{
		DeviceIndex: aws.Int32(1),
		SubnetId:    aws.String("subnet-secondary"),
		Groups:      []string{"sg-d", "sg-c"},
	})
	want, err := CapacityFenceProviderRequestDigest(first)
	if err != nil {
		t.Fatalf("digest ordered network interfaces: %v", err)
	}

	reordered := capacityFenceFinalizedRunInstancesInput()
	reordered.NetworkInterfaces = append(reordered.NetworkInterfaces, awstypes.InstanceNetworkInterfaceSpecification{
		DeviceIndex: aws.Int32(1),
		SubnetId:    aws.String("subnet-secondary"),
		Groups:      []string{"sg-d", "sg-c"},
	})
	reordered.NetworkInterfaces[0], reordered.NetworkInterfaces[1] = reordered.NetworkInterfaces[1], reordered.NetworkInterfaces[0]
	got, err := CapacityFenceProviderRequestDigest(reordered)
	if err != nil {
		t.Fatalf("digest reordered network interfaces: %v", err)
	}
	if got == want {
		t.Fatal("positional network interface reordering did not change its canonical digest")
	}
}

func TestCapacityFenceExactDiscoveryFiltersBindingPagesAllStatesAndCardinality(t *testing.T) {
	identity := capacityFenceTestIdentity("machine-0", "aws-machine-0")
	permit := newCapacityFenceTestPermit(identity, "permit-discovery", "stable-discovery-token")
	for _, testCase := range []struct {
		name        string
		pages       []*awsec2.DescribeInstancesOutput
		wantID      string
		wantFailure bool
	}{
		{
			name:        "stale wrong binding",
			pages:       []*awsec2.DescribeInstancesOutput{capacityFenceDescribePage("", capacityFenceSDKInstance("i-stale", awstypes.InstanceStateNameRunning, "sha256:"+capacityFenceTestHexDigest("stale")))},
			wantFailure: true,
		},
		{
			name:   "correct binding",
			pages:  []*awsec2.DescribeInstancesOutput{capacityFenceDescribePage("", capacityFenceSDKInstance("i-correct", awstypes.InstanceStateNameRunning, permit.ClaimBindingDigest))},
			wantID: "i-correct",
		},
		{
			name: "stale and correct",
			pages: []*awsec2.DescribeInstancesOutput{capacityFenceDescribePage("",
				capacityFenceSDKInstance("i-stale", awstypes.InstanceStateNameRunning, "sha256:"+capacityFenceTestHexDigest("stale")),
				capacityFenceSDKInstance("i-correct", awstypes.InstanceStateNameRunning, permit.ClaimBindingDigest),
			)},
			wantFailure: true,
		},
		{
			name: "same binding ambiguity crosses pages and states",
			pages: []*awsec2.DescribeInstancesOutput{
				capacityFenceDescribePage("page-2", capacityFenceSDKInstance("i-pending", awstypes.InstanceStateNamePending, permit.ClaimBindingDigest)),
				capacityFenceDescribePage("", capacityFenceSDKInstance("i-terminated", awstypes.InstanceStateNameTerminated, permit.ClaimBindingDigest)),
			},
			wantFailure: true,
		},
		{
			name:  "zero matches",
			pages: []*awsec2.DescribeInstancesOutput{capacityFenceDescribePage("")},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow, permit)
			service, ec2Mock, machineScope := newCapacityFenceCreateService(t, authorizer, identity)
			machineScope.AWSMachine.Spec.AdditionalTags[CapacityFenceClaimBindingTagKey] = permit.ClaimBindingDigest
			for pageIndex, page := range testCase.pages {
				ec2Mock.EXPECT().DescribeInstances(context.TODO(), gomock.Any()).Times(1).DoAndReturn(
					func(_ context.Context, input *awsec2.DescribeInstancesInput, _ ...func(*awsec2.Options)) (*awsec2.DescribeInstancesOutput, error) {
						assertCapacityFenceDiscoveryInput(t, input, permit.ClaimBindingDigest, pageIndex)
						return page, nil
					},
				)
			}
			instance, err := service.GetRunningInstanceByTags(machineScope)
			if testCase.wantFailure {
				if err == nil {
					t.Fatal("expected exact binding discovery to fail closed")
				}
				return
			}
			if err != nil {
				t.Fatalf("exact binding discovery error: %v", err)
			}
			if testCase.wantID == "" {
				if instance != nil {
					t.Fatalf("exact binding discovery = %#v, want no instance", instance)
				}
				return
			}
			if instance == nil || instance.ID != testCase.wantID {
				t.Fatalf("exact binding discovery = %#v, want %q", instance, testCase.wantID)
			}
		})
	}
}

func TestCapacityFenceTerminatedExactInstanceBlocksReplacement(t *testing.T) {
	identity := capacityFenceTestIdentity("machine-0", "aws-machine-0")
	permit := newCapacityFenceTestPermit(identity, "permit-terminated", "stable-terminated-token")
	authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow, permit)
	service, ec2Mock, machineScope := newCapacityFenceCreateService(t, authorizer, identity)
	machineScope.AWSMachine.Spec.AdditionalTags[CapacityFenceClaimBindingTagKey] = permit.ClaimBindingDigest
	ec2Mock.EXPECT().DescribeInstances(context.TODO(), gomock.Any()).Times(1).Return(
		capacityFenceDescribePage("", capacityFenceSDKInstance("i-terminated", awstypes.InstanceStateNameTerminated, permit.ClaimBindingDigest)), nil,
	)
	instance, err := service.GetRunningInstanceByTags(machineScope)
	if err != nil {
		t.Fatalf("discover terminated exact instance: %v", err)
	}
	if instance == nil || instance.State != infrav1.InstanceStateTerminated {
		t.Fatalf("discovered instance = %#v, want the terminated exact instance", instance)
	}
}

func TestCapacityFenceReceiptRecoveryAfterImmediateRecordFailureIsIdempotent(t *testing.T) {
	identity := capacityFenceTestIdentity("machine-0", "aws-machine-0")
	permit := newCapacityFenceTestPermit(identity, "permit-recovery", "stable-recovery-token")
	authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow, permit)
	authorizer.FailNextRecords(1)
	service, ec2Mock, machineScope := newCapacityFenceCreateService(t, authorizer, identity)

	createBaseCtx, cancelCreate := context.WithCancel(context.Background())
	createCtx := context.WithValue(createBaseCtx, capacityFenceContextKey{}, "create")
	ec2Mock.EXPECT().RunInstances(createCtx, gomock.Any()).Times(1).DoAndReturn(
		func(_ context.Context, input *awsec2.RunInstancesInput, _ ...func(*awsec2.Options)) (*awsec2.RunInstancesOutput, error) {
			if got := aws.ToString(input.ClientToken); got != permit.ClientToken {
				t.Errorf("expected stable ClientToken %q, got %q", permit.ClientToken, got)
			}
			return capacityFenceRunInstancesOutput("i-recovered"), nil
		},
	)

	if _, err := service.runMachineInstance(createCtx, "node", capacityFenceTestInstance(), identity); err == nil {
		t.Fatal("expected immediate receipt recording to fail after RunInstances")
	}
	cancelCreate()
	if got := authorizer.ReceiptCount(); got != 0 {
		t.Fatalf("expected failed immediate Record to leave an outstanding receipt obligation, got %d receipts", got)
	}

	expectedClaimBindingDigest := capacityFenceTestClaimBindingDigest(t, permit)
	discovered := capacityFenceDiscoveredInstance("i-recovered", expectedClaimBindingDigest)
	recoveryCtx := context.WithValue(context.Background(), capacityFenceContextKey{}, "fresh-reconcile")
	if err := EnsureCapacityFenceReceipt(recoveryCtx, authorizer, machineScope, discovered); err != nil {
		t.Fatalf("expected matching provider evidence to recover the receipt: %v", err)
	}
	if err := EnsureCapacityFenceReceipt(context.Background(), authorizer, machineScope, discovered); err != nil {
		t.Fatalf("expected repeated recovery to be idempotent: %v", err)
	}
	ambiguous := capacityFenceDiscoveredInstance("i-ambiguous", expectedClaimBindingDigest)
	if err := EnsureCapacityFenceReceipt(context.Background(), authorizer, machineScope, ambiguous); err == nil {
		t.Fatal("expected one claim to reject a second discovered instance")
	}
	machineScope.Machine = machineScope.Machine.DeepCopy()
	machineScope.Machine.Generation++
	if err := EnsureCapacityFenceReceipt(context.Background(), authorizer, machineScope, discovered); err == nil {
		t.Fatal("expected recovery to reject changed provider-time identity")
	}
	if got := authorizer.EnsureAttempts(); got != 4 {
		t.Fatalf("expected four recovery attempts, got %d", got)
	}
	if got := authorizer.GrantedClaims(); got != 1 {
		t.Fatalf("expected recovery to reuse one durable claim, got %d grants", got)
	}
	if got := authorizer.ReceiptCount(); got != 1 {
		t.Fatalf("expected exactly one bound receipt after recovery, got %d", got)
	}
	receipt := authorizer.ReceiptForClaim("claim/permit-recovery")
	if receipt == nil || receipt.InstanceID != "i-recovered" {
		t.Fatalf("expected recovered receipt to bind i-recovered, got %#v", receipt)
	}
	if receipt.ClaimBindingDigest != expectedClaimBindingDigest ||
		receipt.ClaimBindingDigest == permit.ClientToken {
		t.Fatalf("expected only the supplied token-safe claim binding in the recovered receipt, got %#v", receipt)
	}
}

func TestCapacityFenceReceiptRecoveryRejectsUnboundFirstMatch(t *testing.T) {
	identity := capacityFenceTestIdentity("machine-0", "aws-machine-0")
	permit := newCapacityFenceTestPermit(identity, "permit-unbound-first", "stable-unbound-first-token")
	otherIdentity := capacityFenceTestIdentity("machine-other", "aws-machine-other")
	otherPermit := newCapacityFenceTestPermit(otherIdentity, "permit-other", "stable-other-token")
	otherPermit.ClaimBindingDigest = "sha256:" + capacityFenceTestHexDigest("claim-binding/permit-other")
	otherClaimBindingDigest := capacityFenceTestClaimBindingDigest(t, otherPermit)

	testCases := []struct {
		name       string
		discovered *infrav1.Instance
	}{
		{
			name:       "missing reserved tag",
			discovered: &infrav1.Instance{ID: "i-first-missing"},
		},
		{
			name:       "wrong reserved tag",
			discovered: capacityFenceDiscoveredInstance("i-first-wrong", "wrong-binding"),
		},
		{
			name:       "other claim reserved tag",
			discovered: capacityFenceDiscoveredInstance("i-first-other-claim", otherClaimBindingDigest),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			authorizer := newCapacityFenceTestAuthorizer(capacityFenceTestNow, permit)
			if _, err := authorizer.Claim(context.Background(), identity); err != nil {
				t.Fatalf("claiming capacity: %v", err)
			}
			_, _, machineScope := newCapacityFenceCreateService(t, authorizer, identity)

			if err := EnsureCapacityFenceReceipt(context.Background(), authorizer, machineScope, testCase.discovered); err == nil {
				t.Fatal("expected unbound first tag-discovered instance to fail closed")
			}
			if got := authorizer.ReceiptCount(); got != 0 {
				t.Fatalf("expected rejection before receipt persistence, got %d receipts", got)
			}
			if got := authorizer.EnsureAttempts(); got != 1 {
				t.Fatalf("expected exactly one failed recovery attempt, got %d", got)
			}
		})
	}
}

func TestCapacityFenceStockRunInstanceBypassesAuthorizer(t *testing.T) {
	service, ec2Mock := newCapacityFenceRunService(t, unavailableCapacityFenceAuthorizer{})
	ec2Mock.EXPECT().RunInstances(context.TODO(), gomock.Any()).Times(1).Return(
		capacityFenceRunInstancesOutput("i-bastion"), nil,
	)

	instance, err := service.runInstance("bastion", capacityFenceTestInstance())
	if err != nil {
		t.Fatalf("expected stock runInstance to bypass unavailable create authorizer: %v", err)
	}
	if instance.ID != "i-bastion" {
		t.Fatalf("expected i-bastion, got %q", instance.ID)
	}
}

func TestCapacityFenceTerminateInstancesRemainsAvailableDuringAuthorizerOutage(t *testing.T) {
	service, ec2Mock := newCapacityFenceRunService(t, unavailableCapacityFenceAuthorizer{})
	ec2Mock.EXPECT().TerminateInstances(context.TODO(), gomock.Eq(&awsec2.TerminateInstancesInput{InstanceIds: []string{"i-delete"}})).Return(
		&awsec2.TerminateInstancesOutput{}, nil,
	)

	if err := service.TerminateInstance("i-delete"); err != nil {
		t.Fatalf("expected TerminateInstances to bypass unavailable create authorizer: %v", err)
	}
}

type capacityFenceContextKey struct{}

type capacityFenceTestBinding struct {
	machineNamespace    string
	machineName         string
	awsMachineNamespace string
	awsMachineName      string
}

type capacityFenceTestPermit struct {
	ID                 string
	ClaimBindingDigest string
	ReservationID      string
	InitialBinding     capacityFenceTestBinding
	ExpiresAt          time.Time
	Capacity           int
	ClientToken        string
}

type capacityFenceTestClaim struct {
	claim    CapacityFenceClaim
	identity CapacityFenceIdentity
}

// capacityFenceTestAuthorizer is test-local. It supplies ClaimResult-shaped values and
// retains the raw 64-hex ClientToken only in its in-memory claim while Claim atomically records
// concrete UIDs and generations before RunInstances can begin.
type capacityFenceTestAuthorizer struct {
	mu                      sync.Mutex
	now                     time.Time
	permits                 map[capacityFenceTestBinding]capacityFenceTestPermit
	claimsByBinding         map[capacityFenceTestBinding]capacityFenceTestClaim
	claimsByID              map[string]capacityFenceTestClaim
	claimedByReservation    map[string]int
	providerRequestsByClaim map[string]string
	receiptsByClaim         map[string]CapacityFenceMutationReceipt
	receiptsByInstance      map[string]string
	recordFailuresRemaining int
	claimAttempts           int
	grantedClaims           int
	ensureAttempts          int
}

func newCapacityFenceTestAuthorizer(now time.Time, permits ...capacityFenceTestPermit) *capacityFenceTestAuthorizer {
	byBinding := make(map[capacityFenceTestBinding]capacityFenceTestPermit, len(permits))
	for _, permit := range permits {
		byBinding[permit.InitialBinding] = permit
	}
	return &capacityFenceTestAuthorizer{
		now:                     now,
		permits:                 byBinding,
		claimsByBinding:         map[capacityFenceTestBinding]capacityFenceTestClaim{},
		claimsByID:              map[string]capacityFenceTestClaim{},
		claimedByReservation:    map[string]int{},
		providerRequestsByClaim: map[string]string{},
		receiptsByClaim:         map[string]CapacityFenceMutationReceipt{},
		receiptsByInstance:      map[string]string{},
	}
}

func (a *capacityFenceTestAuthorizer) Claim(ctx context.Context, identity CapacityFenceIdentity) (*CapacityFenceClaim, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := identity.Validate(); err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.claimAttempts++

	binding := capacityFenceTestBindingFor(identity)
	if existing, ok := a.claimsByBinding[binding]; ok {
		if existing.identity != identity {
			return nil, errors.New("claim identity changed after initial binding")
		}
		claim := existing.claim
		return &claim, nil
	}

	permit, ok := a.permits[binding]
	if !ok {
		return nil, errors.New("no permit matches the initial binding")
	}
	if !a.now.Before(permit.ExpiresAt) {
		return nil, errors.New("permit expired")
	}
	if a.claimedByReservation[permit.ReservationID] >= permit.Capacity {
		return nil, errors.New("reservation capacity exhausted")
	}

	claim := CapacityFenceClaim{
		ClaimID:            "claim/" + permit.ID,
		ClaimBindingDigest: permit.ClaimBindingDigest,
		ClientToken:        permit.ClientToken,
	}
	if existing, ok := a.claimsByID[claim.ClaimID]; ok && existing.identity != identity {
		return nil, errors.New("claim ID is already bound to a different identity")
	}

	stored := capacityFenceTestClaim{claim: claim, identity: identity}
	a.claimsByBinding[binding] = stored
	a.claimsByID[claim.ClaimID] = stored
	a.claimedByReservation[permit.ReservationID]++
	a.grantedClaims++
	return &claim, nil
}

func (a *capacityFenceTestAuthorizer) BindProviderRequest(ctx context.Context, identity CapacityFenceIdentity, binding CapacityFenceProviderRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := identity.Validate(); err != nil {
		return err
	}
	if err := binding.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	claim, ok := a.claimsByID[binding.ClaimID]
	if !ok || claim.identity != identity || claim.claim.ClaimBindingDigest != binding.ClaimBindingDigest {
		return errors.New("provider request does not match the durable claim")
	}
	if existing, ok := a.providerRequestsByClaim[binding.ClaimID]; ok {
		if existing != binding.ProviderRequestDigest {
			return errors.New("provider request digest drift")
		}
		return nil
	}
	a.providerRequestsByClaim[binding.ClaimID] = binding.ProviderRequestDigest
	return nil
}

func (a *capacityFenceTestAuthorizer) Record(ctx context.Context, receipt CapacityFenceMutationReceipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.recordFailuresRemaining > 0 {
		a.recordFailuresRemaining--
		return errors.New("transient receipt store failure")
	}
	return a.recordLocked(receipt)
}

func (a *capacityFenceTestAuthorizer) EnsureReceipt(ctx context.Context, identity CapacityFenceIdentity, instance infrav1.Instance) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := identity.Validate(); err != nil {
		return err
	}
	if instance.ID == "" {
		return errors.New("receipt recovery is missing instance ID")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.ensureAttempts++

	claim, ok := a.claimsByBinding[capacityFenceTestBindingFor(identity)]
	if !ok {
		return errors.New("receipt recovery has no durable claim")
	}
	if claim.identity != identity {
		return errors.New("receipt recovery identity does not match durable claim")
	}
	expectedClaimBindingDigest := claim.claim.ClaimBindingDigest
	providerClaimBindingDigest, ok := instance.Tags[CapacityFenceClaimBindingTagKey]
	if !ok || providerClaimBindingDigest == "" {
		return errors.New("receipt recovery instance is missing claim-binding provider evidence")
	}
	if providerClaimBindingDigest != expectedClaimBindingDigest {
		return errors.New("receipt recovery instance claim-binding evidence does not match durable claim")
	}
	receipt, err := claim.claim.MutationReceipt(identity, instance.ID)
	if err != nil {
		return err
	}
	if a.recordFailuresRemaining > 0 {
		a.recordFailuresRemaining--
		return errors.New("transient receipt store failure")
	}
	return a.recordLocked(receipt)
}

func (a *capacityFenceTestAuthorizer) HasUnresolvedProviderRequest(ctx context.Context, identity CapacityFenceIdentity) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := identity.Validate(); err != nil {
		return false, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	claim, ok := a.claimsByBinding[capacityFenceTestBindingFor(identity)]
	if !ok {
		return false, nil
	}
	if claim.identity != identity {
		return false, errors.New("deletion query identity does not match durable claim")
	}
	_, providerRequestBound := a.providerRequestsByClaim[claim.claim.ClaimID]
	_, receipted := a.receiptsByClaim[claim.claim.ClaimID]
	return providerRequestBound && !receipted, nil
}

func (a *capacityFenceTestAuthorizer) recordLocked(receipt CapacityFenceMutationReceipt) error {
	claim, ok := a.claimsByID[receipt.ClaimID]
	if !ok {
		return errors.New("receipt has no known claim")
	}
	if receipt.ClaimBindingDigest != claim.claim.ClaimBindingDigest {
		return errors.New("receipt claim-binding digest does not match claim")
	}
	if receipt.MachineUID != claim.identity.MachineUID || receipt.MachineGeneration != claim.identity.MachineGeneration || receipt.AWSMachineUID != claim.identity.AWSMachineUID || receipt.AWSMachineGeneration != claim.identity.AWSMachineGeneration {
		return errors.New("receipt identity does not match provider-time claim")
	}
	if receipt.InstanceID == "" {
		return errors.New("receipt is missing instance ID")
	}
	if existing, ok := a.receiptsByClaim[receipt.ClaimID]; ok {
		if existing.InstanceID != receipt.InstanceID {
			return errors.New("claim attempted to bind a second instance")
		}
		return nil
	}
	if existingClaimID, ok := a.receiptsByInstance[receipt.InstanceID]; ok && existingClaimID != receipt.ClaimID {
		return errors.New("instance is already bound to a different claim")
	}
	a.receiptsByClaim[receipt.ClaimID] = receipt
	a.receiptsByInstance[receipt.InstanceID] = receipt.ClaimID
	return nil
}

func (a *capacityFenceTestAuthorizer) FailNextRecords(count int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.recordFailuresRemaining = count
}

func (a *capacityFenceTestAuthorizer) ClaimAttempts() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.claimAttempts
}

func (a *capacityFenceTestAuthorizer) GrantedClaims() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.grantedClaims
}

func (a *capacityFenceTestAuthorizer) EnsureAttempts() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ensureAttempts
}

func (a *capacityFenceTestAuthorizer) ReceiptCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.receiptsByClaim)
}

func (a *capacityFenceTestAuthorizer) ReceiptForClaim(id string) *CapacityFenceMutationReceipt {
	a.mu.Lock()
	defer a.mu.Unlock()
	receipt, ok := a.receiptsByClaim[id]
	if !ok {
		return nil
	}
	return &receipt
}

func (a *capacityFenceTestAuthorizer) ProviderRequestForClaim(id string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.providerRequestsByClaim[id]
}

type unavailableCapacityFenceAuthorizer struct{}

func (unavailableCapacityFenceAuthorizer) BindProviderRequest(context.Context, CapacityFenceIdentity, CapacityFenceProviderRequest) error {
	return errors.New("authorizer unavailable")
}

func (unavailableCapacityFenceAuthorizer) Claim(context.Context, CapacityFenceIdentity) (*CapacityFenceClaim, error) {
	return nil, errors.New("authorizer unavailable")
}

func (unavailableCapacityFenceAuthorizer) Record(context.Context, CapacityFenceMutationReceipt) error {
	return errors.New("authorizer unavailable")
}

func (unavailableCapacityFenceAuthorizer) EnsureReceipt(context.Context, CapacityFenceIdentity, infrav1.Instance) error {
	return errors.New("authorizer unavailable")
}

func (unavailableCapacityFenceAuthorizer) HasUnresolvedProviderRequest(context.Context, CapacityFenceIdentity) (bool, error) {
	return false, errors.New("authorizer unavailable")
}

func capacityFenceTestBindingFor(identity CapacityFenceIdentity) capacityFenceTestBinding {
	return capacityFenceTestBinding{
		machineNamespace:    identity.MachineNamespace,
		machineName:         identity.MachineName,
		awsMachineNamespace: identity.AWSMachineNamespace,
		awsMachineName:      identity.AWSMachineName,
	}
}

func capacityFenceTestIdentity(machineName, awsMachineName string) CapacityFenceIdentity {
	return CapacityFenceIdentity{
		MachineNamespace:     "default",
		MachineName:          machineName,
		MachineUID:           apimachinerytypes.UID("uid-" + machineName),
		MachineGeneration:    7,
		AWSMachineNamespace:  "default",
		AWSMachineName:       awsMachineName,
		AWSMachineUID:        apimachinerytypes.UID("uid-" + awsMachineName),
		AWSMachineGeneration: 11,
	}
}

func newCapacityFenceTestPermit(identity CapacityFenceIdentity, id, clientTokenSeed string) capacityFenceTestPermit {
	return capacityFenceTestPermit{
		ID:                 id,
		ClaimBindingDigest: capacityFenceTestDefaultClaimBindingDigest,
		ReservationID:      "reservation-capacity-one",
		InitialBinding:     capacityFenceTestBindingFor(identity),
		ExpiresAt:          capacityFenceTestNow.Add(time.Hour),
		Capacity:           1,
		ClientToken:        capacityFenceTestHexDigest("client-token/" + clientTokenSeed),
	}
}

func capacityFenceTestHexDigest(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func capacityFenceTestClaimBindingDigest(t *testing.T, permit capacityFenceTestPermit) string {
	t.Helper()
	claim := &CapacityFenceClaim{
		ClaimID:            "claim/" + permit.ID,
		ClaimBindingDigest: permit.ClaimBindingDigest,
		ClientToken:        permit.ClientToken,
	}
	if err := claim.Validate(); err != nil {
		t.Fatalf("validating supplied claim result: %v", err)
	}
	return claim.ClaimBindingDigest
}

func assertCapacityFenceRunInstancesBinding(t *testing.T, input *awsec2.RunInstancesInput, permit capacityFenceTestPermit) {
	t.Helper()
	if input.ClientToken == nil || aws.ToString(input.ClientToken) != permit.ClientToken {
		t.Fatalf("expected exactly one stable ClientToken %q, got %q", permit.ClientToken, aws.ToString(input.ClientToken))
	}
	expectedClaimBindingDigest := capacityFenceTestClaimBindingDigest(t, permit)
	var instanceReservedTags int
	for _, specification := range input.TagSpecifications {
		for _, tag := range specification.Tags {
			if aws.ToString(tag.Key) != CapacityFenceClaimBindingTagKey {
				continue
			}
			if got := aws.ToString(tag.Value); got != expectedClaimBindingDigest {
				t.Errorf("expected claim-binding digest %q, got %q on resource type %q", expectedClaimBindingDigest, got, specification.ResourceType)
			}
			if got := aws.ToString(tag.Value); got == permit.ClientToken {
				t.Errorf("raw ClientToken escaped into the reserved tag")
			}
			if specification.ResourceType == awstypes.ResourceTypeInstance {
				instanceReservedTags++
			}
		}
	}
	if instanceReservedTags != 1 {
		t.Fatalf("instance claim-binding tag count = %d, want exactly one", instanceReservedTags)
	}
}

func capacityFenceFinalizedRunInstancesInput() *awsec2.RunInstancesInput {
	return &awsec2.RunInstancesInput{
		ImageId:      aws.String("ami-finalized"),
		InstanceType: awstypes.InstanceTypeM5Large,
		ClientToken:  aws.String("raw-token-not-digested"),
		UserData:     aws.String("finalized-user-data"),
		NetworkInterfaces: []awstypes.InstanceNetworkInterfaceSpecification{{
			DeviceIndex: aws.Int32(0),
			SubnetId:    aws.String("subnet-finalized"),
			Groups:      []string{"sg-b", "sg-a"},
		}},
		BlockDeviceMappings: []awstypes.BlockDeviceMapping{{
			DeviceName: aws.String("/dev/xvda"),
			Ebs:        &awstypes.EbsBlockDevice{VolumeSize: aws.Int32(64), VolumeType: awstypes.VolumeTypeGp3},
		}},
		MetadataOptions: &awstypes.InstanceMetadataOptionsRequest{
			HttpEndpoint: awstypes.InstanceMetadataEndpointStateEnabled,
			HttpTokens:   awstypes.HttpTokensStateOptional,
		},
		TagSpecifications: []awstypes.TagSpecification{{
			ResourceType: awstypes.ResourceTypeInstance,
			Tags: []awstypes.Tag{
				{Key: aws.String(CapacityFenceClaimBindingTagKey), Value: aws.String(capacityFenceTestDefaultClaimBindingDigest)},
				{Key: aws.String("complete.effective/tag"), Value: aws.String("value")},
			},
		}},
	}
}

func capacityFenceDescribePage(nextToken string, instances ...awstypes.Instance) *awsec2.DescribeInstancesOutput {
	output := &awsec2.DescribeInstancesOutput{}
	if nextToken != "" {
		output.NextToken = aws.String(nextToken)
	}
	if len(instances) != 0 {
		output.Reservations = []awstypes.Reservation{{Instances: instances}}
	}
	return output
}

func capacityFenceSDKInstance(instanceID string, state awstypes.InstanceStateName, claimBindingDigest string) awstypes.Instance {
	return awstypes.Instance{
		InstanceId:   aws.String(instanceID),
		InstanceType: awstypes.InstanceTypeM5Large,
		ImageId:      aws.String("ami-capacity-fence"),
		State:        &awstypes.InstanceState{Name: state},
		Placement:    &awstypes.Placement{AvailabilityZone: aws.String("us-east-1a")},
		Tags: []awstypes.Tag{{
			Key:   aws.String(CapacityFenceClaimBindingTagKey),
			Value: aws.String(claimBindingDigest),
		}},
	}
}

func assertCapacityFenceDiscoveryInput(t *testing.T, input *awsec2.DescribeInstancesInput, claimBindingDigest string, pageIndex int) {
	t.Helper()
	if pageIndex == 0 {
		if input.NextToken != nil {
			t.Fatalf("first exact discovery page NextToken = %q, want empty", aws.ToString(input.NextToken))
		}
	} else if aws.ToString(input.NextToken) != "page-2" {
		t.Fatalf("exact discovery page %d NextToken = %q, want page-2", pageIndex, aws.ToString(input.NextToken))
	}
	foundBinding, foundState := false, false
	for _, filter := range input.Filters {
		switch aws.ToString(filter.Name) {
		case "tag:" + CapacityFenceClaimBindingTagKey:
			foundBinding = len(filter.Values) == 1 && filter.Values[0] == claimBindingDigest
		case "instance-state-name":
			foundState = true
		}
	}
	if !foundBinding || foundState {
		t.Fatalf("exact discovery filters = %#v, want exact claim binding and no state filter", input.Filters)
	}
}

func capacityFenceDiscoveredInstance(instanceID, claimBindingDigest string) *infrav1.Instance {
	return &infrav1.Instance{
		ID: instanceID,
		Tags: map[string]string{
			CapacityFenceClaimBindingTagKey: claimBindingDigest,
		},
	}
}

func capacityFenceTestInstance() *infrav1.Instance {
	return &infrav1.Instance{
		Type:              "m5.large",
		ImageID:           "ami-capacity-fence",
		UserData:          aws.String("userdata"),
		NetworkInterfaces: []string{"eni-capacity-fence"},
		Tags: infrav1.Tags{
			CapacityFenceClaimBindingTagKey: capacityFenceTestDefaultClaimBindingDigest,
		},
	}
}

func capacityFenceRunInstancesOutput(instanceID string) *awsec2.RunInstancesOutput {
	return &awsec2.RunInstancesOutput{Instances: []awstypes.Instance{{
		InstanceId:   aws.String(instanceID),
		InstanceType: awstypes.InstanceTypeM5Large,
		ImageId:      aws.String("ami-capacity-fence"),
		State:        &awstypes.InstanceState{Name: awstypes.InstanceStateNamePending},
		Placement:    &awstypes.Placement{AvailabilityZone: aws.String("us-east-1a")},
	}}}
}

func newCapacityFenceRunService(t *testing.T, authorizer CapacityFenceAuthorizer) (*Service, *mocks.MockEC2API) {
	t.Helper()
	mockCtrl := gomock.NewController(t)
	ec2Mock := mocks.NewMockEC2API(mockCtrl)
	scheme := capacityFenceTestScheme(t)
	clusterScope := newCapacityFenceClusterScope(t, fake.NewClientBuilder().WithScheme(scheme).Build())
	service := NewService(clusterScope).WithCapacityFenceAuthorizer(authorizer)
	service.EC2Client = ec2Mock
	return service, ec2Mock
}

func newCapacityFenceCreateService(t *testing.T, authorizer CapacityFenceAuthorizer, identity CapacityFenceIdentity) (*Service, *mocks.MockEC2API, *scope.MachineScope) {
	t.Helper()
	mockCtrl := gomock.NewController(t)
	ec2Mock := mocks.NewMockEC2API(mockCtrl)
	scheme := capacityFenceTestScheme(t)
	cluster := &clusterv1.Cluster{ObjectMeta: metav1.ObjectMeta{Name: "cluster-0", Namespace: "default"}}
	machine := &clusterv1.Machine{ObjectMeta: metav1.ObjectMeta{
		Name:       identity.MachineName,
		Namespace:  identity.MachineNamespace,
		UID:        identity.MachineUID,
		Generation: identity.MachineGeneration,
	}}
	awsMachine := &infrav1.AWSMachine{ObjectMeta: metav1.ObjectMeta{
		Name:       identity.AWSMachineName,
		Namespace:  identity.AWSMachineNamespace,
		UID:        identity.AWSMachineUID,
		Generation: identity.AWSMachineGeneration,
	}, Spec: infrav1.AWSMachineSpec{
		AMI:          infrav1.AMIReference{ID: aws.String("ami-capacity-fence")},
		InstanceType: "m5.large",
		AdditionalTags: infrav1.Tags{
			CapacityFenceClaimBindingTagKey: capacityFenceTestDefaultClaimBindingDigest,
		},
	}}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster, machine).Build()
	clusterScope := newCapacityFenceClusterScope(t, client)
	machineScope, err := scope.NewMachineScope(scope.MachineScopeParams{
		Client:       client,
		Cluster:      cluster,
		Machine:      machine,
		AWSMachine:   awsMachine,
		InfraCluster: clusterScope,
	})
	if err != nil {
		t.Fatalf("creating machine scope: %v", err)
	}
	service := NewService(clusterScope).WithInstanceTypeArchitectureCache(nil).WithCapacityFenceAuthorizer(authorizer)
	service.EC2Client = ec2Mock
	return service, ec2Mock, machineScope
}

func capacityFenceTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, addToScheme := range []func(*runtime.Scheme) error{corev1.AddToScheme, clusterv1.AddToScheme, infrav1.AddToScheme} {
		if err := addToScheme(scheme); err != nil {
			t.Fatalf("adding test scheme: %v", err)
		}
	}
	return scheme
}

func newCapacityFenceClusterScope(t *testing.T, client client.Client) *scope.ClusterScope {
	t.Helper()
	clusterScope, err := scope.NewClusterScope(scope.ClusterScopeParams{
		Client:  client,
		Cluster: &clusterv1.Cluster{ObjectMeta: metav1.ObjectMeta{Name: "cluster-0", Namespace: "default"}},
		AWSCluster: &infrav1.AWSCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "aws-cluster-0", Namespace: "default"},
			Spec: infrav1.AWSClusterSpec{NetworkSpec: infrav1.NetworkSpec{
				VPC:     infrav1.VPCSpec{ID: "vpc-capacity-fence"},
				Subnets: infrav1.Subnets{{ID: "subnet-capacity-fence", IsPublic: false}},
			}},
			Status: infrav1.AWSClusterStatus{Network: infrav1.NetworkStatus{
				SecurityGroups: map[infrav1.SecurityGroupRole]infrav1.SecurityGroup{
					infrav1.SecurityGroupNode: {ID: "sg-node"},
					infrav1.SecurityGroupLB:   {ID: "sg-lb"},
				},
				APIServerELB: infrav1.LoadBalancer{DNSName: "api.capacity-fence.test"},
			}},
		},
	})
	if err != nil {
		t.Fatalf("creating cluster scope: %v", err)
	}
	return clusterScope
}
