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

package controllers

import (
	"os"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func TestManagerRoleGrantsCapacityFenceAuthority(t *testing.T) {
	raw, err := os.ReadFile("../config/rbac/role.yaml")
	if err != nil {
		t.Fatalf("read manager role: %v", err)
	}
	role := &rbacv1.ClusterRole{}
	if err := yaml.Unmarshal(raw, role); err != nil {
		t.Fatalf("unmarshal manager role: %v", err)
	}

	for _, required := range []struct {
		apiGroup string
		resource string
		verbs    []string
	}{
		{apiGroup: "platform.appthrust.io", resource: "machineprovisioningpermits", verbs: []string{"get", "list", "watch"}},
		{apiGroup: "platform.appthrust.io", resource: "machineprovisioningpermits/status", verbs: []string{"get", "patch", "update"}},
		{apiGroup: "platform.appthrust.io", resource: "appthrustclusters", verbs: []string{"get"}},
		{apiGroup: "platform.appthrust.io", resource: "capacityreservations", verbs: []string{"get"}},
		{apiGroup: "platform.appthrust.io", resource: "clusteroperations", verbs: []string{"get"}},
		{apiGroup: "controlplane.appthrust.io", resource: "appthrusttaloscontrolplanes", verbs: []string{"get"}},
	} {
		if !managerRoleAllows(role.Rules, required.apiGroup, required.resource, required.verbs...) {
			t.Errorf("manager role lacks %s %s with verbs %v", required.apiGroup, required.resource, required.verbs)
		}
	}
}

func managerRoleAllows(rules []rbacv1.PolicyRule, apiGroup, resource string, verbs ...string) bool {
	for _, rule := range rules {
		if !managerRoleContains(rule.APIGroups, apiGroup) || !managerRoleContains(rule.Resources, resource) {
			continue
		}
		allVerbsAllowed := true
		for _, verb := range verbs {
			if !managerRoleContains(rule.Verbs, verb) {
				allVerbsAllowed = false
				break
			}
		}
		if allVerbsAllowed {
			return true
		}
	}
	return false
}

func managerRoleContains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
