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

package bootstrap

import (
	"reflect"
	"testing"

	iamv1 "sigs.k8s.io/cluster-api-provider-aws/v2/iam/api/v1beta1"
)

func TestControllersPolicyDeniesReservedClaimBindingTagMutations(t *testing.T) {
	const (
		reservedTagKey             = "capacityfence.appthrust.io/claim-binding"
		forAnyValueStringEquals    = iamv1.ConditionOperator("ForAnyValue:StringEquals")
		createTagsDenyStatementSID = "DenyReservedClaimBindingCreateTagsOutsideRunInstances"
		deleteTagsDenyStatementSID = "DenyReservedClaimBindingDeleteTags"
	)

	expected := map[string]iamv1.StatementEntry{
		createTagsDenyStatementSID: {
			Sid:      createTagsDenyStatementSID,
			Effect:   iamv1.EffectDeny,
			Action:   iamv1.Actions{"ec2:CreateTags"},
			Resource: iamv1.Resources{iamv1.Any},
			Condition: iamv1.Conditions{
				forAnyValueStringEquals: map[string]string{
					"aws:TagKeys": reservedTagKey,
				},
				iamv1.StringNotEquals: map[string]string{
					"ec2:CreateAction": "RunInstances",
				},
			},
		},
		deleteTagsDenyStatementSID: {
			Sid:      deleteTagsDenyStatementSID,
			Effect:   iamv1.EffectDeny,
			Action:   iamv1.Actions{"ec2:DeleteTags"},
			Resource: iamv1.Resources{iamv1.Any},
			Condition: iamv1.Conditions{
				forAnyValueStringEquals: map[string]string{
					"aws:TagKeys": reservedTagKey,
				},
			},
		},
	}

	policy := NewTemplate().ControllersPolicy()
	found := map[string]iamv1.StatementEntry{}
	reservedTagStatementCount := 0
	broadTagAllow := false

	for _, statement := range policy.Statement {
		if tagKeys, ok := statement.Condition[forAnyValueStringEquals].(map[string]string); ok && tagKeys["aws:TagKeys"] == reservedTagKey {
			reservedTagStatementCount++
		}
		if statement.Effect == iamv1.EffectAllow && reflect.DeepEqual(statement.Resource, iamv1.Resources{iamv1.Any}) && containsControllerAction(statement.Action, "ec2:CreateTags") && containsControllerAction(statement.Action, "ec2:DeleteTags") {
			broadTagAllow = true
		}

		expectedStatement, isReservedTagDeny := expected[statement.Sid]
		if !isReservedTagDeny {
			continue
		}
		if _, duplicate := found[statement.Sid]; duplicate {
			t.Fatalf("ControllersPolicy contains duplicate statement %q", statement.Sid)
		}
		if !reflect.DeepEqual(statement, expectedStatement) {
			t.Errorf("ControllersPolicy statement %q = %#v, want %#v", statement.Sid, statement, expectedStatement)
		}
		found[statement.Sid] = statement
	}

	if len(found) != len(expected) {
		t.Errorf("ControllersPolicy found %d reserved claim-binding tag Deny statements, want %d", len(found), len(expected))
	}
	if reservedTagStatementCount != len(expected) {
		t.Errorf("ControllersPolicy contains %d statements scoped to the reserved claim-binding tag, want %d", reservedTagStatementCount, len(expected))
	}
	if !broadTagAllow {
		t.Error("ControllersPolicy must retain its broad Allow for ec2:CreateTags and ec2:DeleteTags")
	}
}

func containsControllerAction(actions iamv1.Actions, action string) bool {
	for _, candidate := range actions {
		if candidate == action {
			return true
		}
	}
	return false
}
