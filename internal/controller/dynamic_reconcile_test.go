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

var _ = Describe("dynamic reconcile", func() {
	var (
		reconciler *HostFirewallRuleReconciler
		host       *fakeHost
		nodeName   string
	)

	BeforeEach(func() {
		nodeName = "node-" + rand.String(6)
		newNode(nodeName, map[string]string{testRoleKey: "web"})
		host = newFakeHost(true)
		reconciler = newReconciler(host, nodeName)
	})

	It("removes an expired grant and its ufw rule", func() {
		name := uniqueRuleName("dynamic-reconcile-expired")
		createRule(name, dynamicFromRule("/knock/expired"))
		future := metav1.NewTime(time.Now().Add(time.Hour))
		seedDynamicGrant(name, dynamicGrant("/knock/expired", "from", &future))

		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		past := metav1.NewTime(time.Now().Add(-time.Minute))
		seedDynamicGrant(name, dynamicGrant("/knock/expired", "from", &past))

		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(0))
		Expect(fetchRule(name).Status.Dynamic).To(BeNil())
		// The status apply must drop the addresses too. A value-typed
		// Resolved field that is sent as an empty object is rejected by the API
		// server once this manager already owned its subfields.
		Expect(fetchRule(name).Status.Nodes[nodeName].Resolved.From).To(BeEmpty())
	})

	It("keeps a valid grant and applies its rule", func() {
		name := uniqueRuleName("dynamic-reconcile-valid")
		createRule(name, dynamicFromRule("/knock/valid"))
		future := metav1.NewTime(time.Now().Add(time.Hour))
		seedDynamicGrant(name, dynamicGrant("/knock/valid", "from", &future))

		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(1))
		stored := fetchRule(name).Status.Dynamic
		Expect(stored).NotTo(BeNil())
		Expect(stored.Address).To(Equal("203.0.113.9"))
		Expect(stored.ExpiresAt).NotTo(BeNil())
	})

	It("clears a grant when the path changes", func() {
		name := uniqueRuleName("dynamic-reconcile-path")
		createRule(name, dynamicFromRule("/knock/old"))
		future := metav1.NewTime(time.Now().Add(time.Hour))
		seedDynamicGrant(name, dynamicGrant("/knock/old", "from", &future))

		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		rule := fetchRule(name)
		rule.Spec.From.Dynamic.Path = "/knock/new"
		Expect(k8sClient.Update(ctx, rule)).To(Succeed())

		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(0))
		Expect(fetchRule(name).Status.Dynamic).To(BeNil())
	})

	It("clears a grant when the rule stops being dynamic", func() {
		name := uniqueRuleName("dynamic-reconcile-static")
		createRule(name, dynamicFromRule("/knock/static"))
		future := metav1.NewTime(time.Now().Add(time.Hour))
		seedDynamicGrant(name, dynamicGrant("/knock/static", "from", &future))

		rule := fetchRule(name)
		rule.Spec.From = &securityv1alpha1.EndpointSpec{CIDR: new("198.51.100.0/24")}
		Expect(k8sClient.Update(ctx, rule)).To(Succeed())

		mustReconcile(reconciler, name)

		Expect(fetchRule(name).Status.Dynamic).To(BeNil())
		// The former dynamic endpoint is now a static CIDR, so the rule still
		// converges; only the shared grant is gone.
		Expect(host.count()).To(Equal(1))
	})

	It("clears an expired grant during a sweep", func() {
		name := uniqueRuleName("dynamic-sweep-expired")
		createRule(name, dynamicFromRule("/knock/sweep-expired"))
		future := metav1.NewTime(time.Now().Add(time.Hour))
		seedDynamicGrant(name, dynamicGrant("/knock/sweep-expired", "from", &future))

		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		past := metav1.NewTime(time.Now().Add(-time.Minute))
		seedDynamicGrant(name, dynamicGrant("/knock/sweep-expired", "from", &past))

		Expect(reconciler.ReconcileSweep(ctx)).To(Succeed())

		Expect(host.count()).To(Equal(0))
		Expect(fetchRule(name).Status.Dynamic).To(BeNil())
	})

	It("removes a dynamic rule when its path becomes ambiguous", func() {
		path := "/knock/ambiguous-" + rand.String(8)
		nameA := uniqueRuleName("dynamic-reconcile-ambiguous-a")
		createRule(nameA, dynamicFromRule(path))
		future := metav1.NewTime(time.Now().Add(time.Hour))
		seedDynamicGrant(nameA, dynamicGrant(path, "from", &future))

		mustReconcile(reconciler, nameA)
		Expect(host.count()).To(Equal(1))

		createRule(uniqueRuleName("dynamic-reconcile-ambiguous-b"), dynamicFromRule(path))

		mustReconcile(reconciler, nameA)

		Expect(host.count()).To(Equal(0))
	})

	It("clears an expired grant during a sweep even when the rule does not match this node", func() {
		name := uniqueRuleName("dynamic-sweep-other")
		spec := dynamicFromRule("/knock/sweep-other")
		spec.NodeSelector = &metav1.LabelSelector{MatchLabels: map[string]string{testRoleKey: "other"}}
		createRule(name, spec)
		past := metav1.NewTime(time.Now().Add(-time.Minute))
		seedDynamicGrant(name, dynamicGrant("/knock/sweep-other", "from", &past))

		Expect(reconciler.ReconcileSweep(ctx)).To(Succeed())

		Expect(fetchRule(name).Status.Dynamic).To(BeNil())
	})
})
