/*
Copyright 2026.

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

package controller

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
)

// dynamicFromRule returns a rule whose source is the given knock path.
func dynamicFromRule(path string) securityv1alpha1.HostFirewallRuleSpec {
	return securityv1alpha1.HostFirewallRuleSpec{
		Action:   securityv1alpha1.ActionAllow,
		Protocol: securityv1alpha1.ProtocolTCP,
		From: &securityv1alpha1.EndpointSpec{
			Dynamic: &securityv1alpha1.DynamicEndpointSpec{Path: path},
		},
		To: &securityv1alpha1.ToSpec{Ports: []securityv1alpha1.Port{"22"}},
	}
}

// dynamicToRule returns a rule whose destination is the given knock path.
func dynamicToRule(path string) securityv1alpha1.HostFirewallRuleSpec {
	return securityv1alpha1.HostFirewallRuleSpec{
		Action:   securityv1alpha1.ActionAllow,
		Protocol: securityv1alpha1.ProtocolTCP,
		From: &securityv1alpha1.EndpointSpec{
			CIDR: new("198.51.100.0/24"),
		},
		To: &securityv1alpha1.ToSpec{
			EndpointSpec: securityv1alpha1.EndpointSpec{
				Dynamic: &securityv1alpha1.DynamicEndpointSpec{Path: path},
			},
			Ports: []securityv1alpha1.Port{"22"},
		},
	}
}

// dynamicGrant returns a grant for the given path and side.
func dynamicGrant(path, side string, expiresAt *metav1.Time) *securityv1alpha1.DynamicGrant {
	return &securityv1alpha1.DynamicGrant{
		Path:       path,
		Side:       side,
		Address:    "203.0.113.9",
		ObservedAt: metav1.NewTime(time.Now()),
		ExpiresAt:  expiresAt,
	}
}

var _ = Describe("dynamic expansion", func() {
	var reconciler *HostFirewallRuleReconciler

	BeforeEach(func() {
		nodeName := "node-" + rand.String(6)
		newNode(nodeName, nil)
		reconciler = newReconciler(newFakeHost(true), nodeName)
	})

	It("has no rule and a waiting message before the first knock", func() {
		name := uniqueRuleName("dynamic-waiting")
		createRule(name, dynamicFromRule("/knock/home"))

		exp := reconciler.expand(ctx, fetchRule(name), securityv1alpha1.NodeStatus{})

		Expect(exp.Rules).To(BeEmpty())
		Expect(exp.Message).To(ContainSubstring("Waiting for a knock"))
		Expect(exp.Degraded).To(BeFalse())
	})

	It("applies the grant address as the source", func() {
		name := uniqueRuleName("dynamic-source")
		createRule(name, dynamicFromRule("/knock/home"))
		seedDynamicGrant(name, dynamicGrant("/knock/home", "from", nil))

		exp := reconciler.expand(ctx, fetchRule(name), securityv1alpha1.NodeStatus{})

		Expect(exp.Rules).To(HaveLen(1))
		Expect(exp.Rules[0].From.Address).To(Equal("203.0.113.9"))
		Expect(exp.Resolved.From).To(Equal([]string{"203.0.113.9"}))
	})

	It("applies the grant address as the destination", func() {
		name := uniqueRuleName("dynamic-destination")
		createRule(name, dynamicToRule("/knock/to"))
		seedDynamicGrant(name, dynamicGrant("/knock/to", "to", nil))

		exp := reconciler.expand(ctx, fetchRule(name), securityv1alpha1.NodeStatus{})

		Expect(exp.Rules).To(HaveLen(1))
		Expect(exp.Rules[0].To.Address).To(Equal("203.0.113.9"))
		Expect(exp.Resolved.To).To(Equal([]string{"203.0.113.9"}))
	})

	It("ignores an expired grant", func() {
		name := uniqueRuleName("dynamic-expired-expand")
		createRule(name, dynamicFromRule("/knock/expired-expand"))
		past := metav1.NewTime(time.Now().Add(-time.Minute))
		seedDynamicGrant(name, dynamicGrant("/knock/expired-expand", "from", &past))

		exp := reconciler.expand(ctx, fetchRule(name), securityv1alpha1.NodeStatus{})

		Expect(exp.Rules).To(BeEmpty())
		Expect(exp.Message).To(ContainSubstring("expired"))
		Expect(exp.Degraded).To(BeFalse())
	})

	It("ignores a grant whose path no longer matches", func() {
		name := uniqueRuleName("dynamic-stale-path")
		createRule(name, dynamicFromRule("/knock/new"))
		seedDynamicGrant(name, dynamicGrant("/knock/old", "from", nil))

		exp := reconciler.expand(ctx, fetchRule(name), securityv1alpha1.NodeStatus{})

		Expect(exp.Rules).To(BeEmpty())
		Expect(exp.Message).To(ContainSubstring("does not match"))
		Expect(exp.Degraded).To(BeFalse())
	})

	It("degrades when the path is duplicated", func() {
		path := "/knock/duplicate-" + rand.String(8)
		name := uniqueRuleName("dynamic-duplicate-a")
		createRule(name, dynamicFromRule(path))
		createRule(uniqueRuleName("dynamic-duplicate-b"), dynamicFromRule(path))
		seedDynamicGrant(name, dynamicGrant(path, "from", nil))

		exp := reconciler.expand(ctx, fetchRule(name), securityv1alpha1.NodeStatus{})

		Expect(exp.Rules).To(BeEmpty())
		Expect(exp.Degraded).To(BeTrue())
		Expect(exp.Message).To(ContainSubstring("multiple"))
	})

	It("requeues at the TTL", func() {
		name := uniqueRuleName("dynamic-ttl")
		createRule(name, dynamicFromRule("/knock/ttl"))
		future := metav1.NewTime(time.Now().Add(time.Hour))
		seedDynamicGrant(name, dynamicGrant("/knock/ttl", "from", &future))

		exp := reconciler.expand(ctx, fetchRule(name), securityv1alpha1.NodeStatus{})

		Expect(exp.RequeueAfter).To(BeNumerically(">", 0))
		Expect(exp.RequeueAfter).To(BeNumerically("<=", time.Hour))
	})

	It("does not requeue for a grant without a TTL", func() {
		name := uniqueRuleName("dynamic-no-ttl")
		createRule(name, dynamicFromRule("/knock/no-ttl"))
		seedDynamicGrant(name, dynamicGrant("/knock/no-ttl", "from", nil))

		exp := reconciler.expand(ctx, fetchRule(name), securityv1alpha1.NodeStatus{})

		Expect(exp.RequeueAfter).To(BeZero())
	})
})
