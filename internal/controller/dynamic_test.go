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
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/event"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
)

func TestDynamicAddress(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	inAnHour := metav1.NewTime(now.Add(time.Hour))
	anHourAgo := metav1.NewTime(now.Add(-time.Hour))
	observedAt := metav1.NewTime(now)

	dynamicSpec := func() securityv1alpha1.HostFirewallRuleSpec {
		return securityv1alpha1.HostFirewallRuleSpec{
			Action: securityv1alpha1.ActionAllow,
			From: &securityv1alpha1.EndpointSpec{
				Dynamic: &securityv1alpha1.DynamicEndpointSpec{Path: "/knock/home"},
			},
			To: &securityv1alpha1.ToSpec{Ports: []securityv1alpha1.Port{"22"}},
		}
	}
	withGrant := func(mutate func(*securityv1alpha1.DynamicGrant)) *securityv1alpha1.DynamicGrant {
		grant := &securityv1alpha1.DynamicGrant{
			Path:       "/knock/home",
			Side:       "from",
			Address:    "203.0.113.9",
			ObservedAt: observedAt,
		}
		if mutate != nil {
			mutate(grant)
		}
		return grant
	}

	tests := []struct {
		name        string
		spec        securityv1alpha1.HostFirewallRuleSpec
		grant       *securityv1alpha1.DynamicGrant
		wantAddr    string
		wantMsg     string
		wantRequeue time.Duration
		wantOK      bool
	}{
		{
			name:   "no dynamic endpoint",
			spec:   securityv1alpha1.HostFirewallRuleSpec{Action: securityv1alpha1.ActionAllow},
			grant:  withGrant(nil),
			wantOK: false,
		},
		{
			name:    "no grant",
			spec:    dynamicSpec(),
			grant:   nil,
			wantMsg: "Waiting for a knock on /knock/home",
			wantOK:  false,
		},
		{
			name:     "matching grant without expiry",
			spec:     dynamicSpec(),
			grant:    withGrant(nil),
			wantAddr: "203.0.113.9",
			wantOK:   true,
		},
		{
			name:        "matching grant expiring in one hour",
			spec:        dynamicSpec(),
			grant:       withGrant(func(g *securityv1alpha1.DynamicGrant) { g.ExpiresAt = &inAnHour }),
			wantAddr:    "203.0.113.9",
			wantRequeue: time.Hour,
			wantOK:      true,
		},
		{
			name:    "expired grant",
			spec:    dynamicSpec(),
			grant:   withGrant(func(g *securityv1alpha1.DynamicGrant) { g.ExpiresAt = &anHourAgo }),
			wantMsg: "Dynamic grant expired",
			wantOK:  false,
		},
		{
			name:    "wrong path",
			spec:    dynamicSpec(),
			grant:   withGrant(func(g *securityv1alpha1.DynamicGrant) { g.Path = "/knock/other" }),
			wantMsg: "Dynamic grant does not match the current spec",
			wantOK:  false,
		},
		{
			name:    "wrong side",
			spec:    dynamicSpec(),
			grant:   withGrant(func(g *securityv1alpha1.DynamicGrant) { g.Side = "to" }),
			wantMsg: "Dynamic grant does not match the current spec",
			wantOK:  false,
		},
		{
			name:    "invalid address",
			spec:    dynamicSpec(),
			grant:   withGrant(func(g *securityv1alpha1.DynamicGrant) { g.Address = "not-an-ip" }),
			wantMsg: "Dynamic grant does not match the current spec",
			wantOK:  false,
		},
		{
			name:    "unspecified IPv4 address",
			spec:    dynamicSpec(),
			grant:   withGrant(func(g *securityv1alpha1.DynamicGrant) { g.Address = "0.0.0.0" }),
			wantMsg: "Dynamic grant does not match the current spec",
			wantOK:  false,
		},
		{
			name:    "unspecified IPv6 address",
			spec:    dynamicSpec(),
			grant:   withGrant(func(g *securityv1alpha1.DynamicGrant) { g.Address = "::" }),
			wantMsg: "Dynamic grant does not match the current spec",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := &securityv1alpha1.HostFirewallRule{
				Spec:   tt.spec,
				Status: securityv1alpha1.HostFirewallRuleStatus{Dynamic: tt.grant},
			}

			addr, msg, requeue, ok := dynamicAddress(cr, now)

			if addr != tt.wantAddr {
				t.Errorf("address = %q, want %q", addr, tt.wantAddr)
			}
			if msg != tt.wantMsg {
				t.Errorf("message = %q, want %q", msg, tt.wantMsg)
			}
			if requeue != tt.wantRequeue {
				t.Errorf("requeue = %v, want %v", requeue, tt.wantRequeue)
			}
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

// dynamicRule returns a rule with from.dynamic.path "/knock/home" and the given
// grant address.
func dynamicRule(address string) *securityv1alpha1.HostFirewallRule {
	return &securityv1alpha1.HostFirewallRule{
		ObjectMeta: metav1.ObjectMeta{Name: "dynamic"},
		Spec: securityv1alpha1.HostFirewallRuleSpec{
			Action: securityv1alpha1.ActionAllow,
			From: &securityv1alpha1.EndpointSpec{
				Dynamic: &securityv1alpha1.DynamicEndpointSpec{Path: "/knock/home"},
			},
		},
		Status: securityv1alpha1.HostFirewallRuleStatus{
			Dynamic: &securityv1alpha1.DynamicGrant{
				Path:       "/knock/home",
				Side:       "from",
				Address:    address,
				ObservedAt: metav1.NewTime(time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)),
			},
		},
	}
}

// seedDynamicGrant writes a grant directly to the rule's status.
func seedDynamicGrant(name string, grant *securityv1alpha1.DynamicGrant) {
	rule := fetchRule(name)
	rule.Status.Dynamic = grant
	Expect(k8sClient.Status().Update(ctx, rule)).To(Succeed())
}

var _ = Describe("dynamic grant", func() {
	dynamicSpec := func(path string) securityv1alpha1.HostFirewallRuleSpec {
		return securityv1alpha1.HostFirewallRuleSpec{
			Action:   securityv1alpha1.ActionAllow,
			Protocol: securityv1alpha1.ProtocolTCP,
			From: &securityv1alpha1.EndpointSpec{
				Dynamic: &securityv1alpha1.DynamicEndpointSpec{Path: path},
			},
			To: &securityv1alpha1.ToSpec{Ports: []securityv1alpha1.Port{"22"}},
		}
	}
	grant := func(address, path string, expiresAt *metav1.Time) *securityv1alpha1.DynamicGrant {
		return &securityv1alpha1.DynamicGrant{
			Path:       path,
			Side:       "from",
			Address:    address,
			ObservedAt: metav1.NewTime(time.Now()),
			ExpiresAt:  expiresAt,
		}
	}

	var r *HostFirewallRuleReconciler
	BeforeEach(func() {
		r = &HostFirewallRuleReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
	})

	Describe("dynamicGrantChanged predicate", func() {
		It("reconciles when only status.dynamic changes", func() {
			oldRule := dynamicRule("203.0.113.9")
			newRule := dynamicRule("198.51.100.7")

			Expect(dynamicGrantChanged().Update(event.UpdateEvent{
				ObjectOld: oldRule,
				ObjectNew: newRule,
			})).To(BeTrue())
		})

		It("does not reconcile when only status.nodes changes", func() {
			oldRule := dynamicRule("203.0.113.9")
			newRule := dynamicRule("203.0.113.9")
			newRule.Status.Nodes = map[string]securityv1alpha1.NodeStatus{
				"node-a": {Generation: 1, Applied: true},
			}

			Expect(dynamicGrantChanged().Update(event.UpdateEvent{
				ObjectOld: oldRule,
				ObjectNew: newRule,
			})).To(BeFalse())
		})

		It("does not reconcile when the grant is unchanged", func() {
			Expect(dynamicGrantChanged().Update(event.UpdateEvent{
				ObjectOld: dynamicRule("203.0.113.9"),
				ObjectNew: dynamicRule("203.0.113.9"),
			})).To(BeFalse())
		})

		It("does not reconcile on create, delete, or generic events", func() {
			rule := dynamicRule("203.0.113.9")

			Expect(dynamicGrantChanged().Create(event.CreateEvent{Object: rule})).To(BeFalse())
			Expect(dynamicGrantChanged().Delete(event.DeleteEvent{Object: rule})).To(BeFalse())
			Expect(dynamicGrantChanged().Generic(event.GenericEvent{Object: rule})).To(BeFalse())
		})
	})

	Describe("clearStaleDynamicGrant", func() {
		It("clears an expired grant", func() {
			name := uniqueRuleName("dynamic-expired")
			createRule(name, dynamicSpec("/knock/expired"))
			past := metav1.NewTime(time.Now().Add(-time.Minute))
			seedDynamicGrant(name, grant("203.0.113.9", "/knock/expired", &past))

			Expect(r.clearStaleDynamicGrant(ctx, fetchRule(name))).To(Succeed())
			Expect(fetchRule(name).Status.Dynamic).To(BeNil())
		})

		It("keeps a matching unexpired grant", func() {
			name := uniqueRuleName("dynamic-valid")
			createRule(name, dynamicSpec("/knock/valid"))
			future := metav1.NewTime(time.Now().Add(time.Hour))
			seedDynamicGrant(name, grant("203.0.113.9", "/knock/valid", &future))

			Expect(r.clearStaleDynamicGrant(ctx, fetchRule(name))).To(Succeed())

			rule := fetchRule(name)
			Expect(rule.Status.Dynamic).NotTo(BeNil())
			Expect(rule.Status.Dynamic.Address).To(Equal("203.0.113.9"))
		})

		It("keeps a matching grant without an expiry", func() {
			name := uniqueRuleName("dynamic-no-expiry")
			createRule(name, dynamicSpec("/knock/no-expiry"))
			seedDynamicGrant(name, grant("203.0.113.9", "/knock/no-expiry", nil))

			Expect(r.clearStaleDynamicGrant(ctx, fetchRule(name))).To(Succeed())

			rule := fetchRule(name)
			Expect(rule.Status.Dynamic).NotTo(BeNil())
			Expect(rule.Status.Dynamic.Address).To(Equal("203.0.113.9"))
		})

		It("clears a grant when the path no longer matches the spec", func() {
			name := uniqueRuleName("dynamic-path-changed")
			createRule(name, dynamicSpec("/knock/new"))
			future := metav1.NewTime(time.Now().Add(time.Hour))
			seedDynamicGrant(name, grant("203.0.113.9", "/knock/old", &future))

			Expect(r.clearStaleDynamicGrant(ctx, fetchRule(name))).To(Succeed())
			Expect(fetchRule(name).Status.Dynamic).To(BeNil())
		})

		It("clears a grant when the rule has no dynamic endpoint", func() {
			name := uniqueRuleName("dynamic-endpoint-removed")
			createRule(name, allowTCP("22"))
			future := metav1.NewTime(time.Now().Add(time.Hour))
			seedDynamicGrant(name, grant("203.0.113.9", "/knock/home", &future))

			Expect(r.clearStaleDynamicGrant(ctx, fetchRule(name))).To(Succeed())
			Expect(fetchRule(name).Status.Dynamic).To(BeNil())
		})

		It("clears a grant with an invalid address", func() {
			name := uniqueRuleName("dynamic-bad-address")
			createRule(name, dynamicSpec("/knock/bad-address"))
			future := metav1.NewTime(time.Now().Add(time.Hour))
			seedDynamicGrant(name, grant("not-an-ip", "/knock/bad-address", &future))

			Expect(r.clearStaleDynamicGrant(ctx, fetchRule(name))).To(Succeed())
			Expect(fetchRule(name).Status.Dynamic).To(BeNil())
		})

		It("does not lose a grant replaced between fetch and clear", func() {
			name := uniqueRuleName("dynamic-race")
			createRule(name, dynamicSpec("/knock/race"))
			past := metav1.NewTime(time.Now().Add(-time.Minute))
			seedDynamicGrant(name, grant("203.0.113.9", "/knock/race", &past))
			stale := fetchRule(name)

			future := metav1.NewTime(time.Now().Add(time.Hour))
			seedDynamicGrant(name, grant("198.51.100.7", "/knock/race", &future))

			// The JSON patch test operation fails because a newer knock won the
			// race. That is routine on every TTL expiry, not an error.
			Expect(r.clearStaleDynamicGrant(ctx, stale)).To(Succeed())

			rule := fetchRule(name)
			Expect(rule.Status.Dynamic).NotTo(BeNil())
			Expect(rule.Status.Dynamic.Address).To(Equal("198.51.100.7"))
		})

		It("treats a grant already cleared by another pod as benign", func() {
			name := uniqueRuleName("dynamic-cleared-race")
			createRule(name, dynamicSpec("/knock/cleared-race"))
			past := metav1.NewTime(time.Now().Add(-time.Minute))
			seedDynamicGrant(name, grant("203.0.113.9", "/knock/cleared-race", &past))
			stale := fetchRule(name)

			seedDynamicGrant(name, nil)

			// The JSON patch test fails because status.dynamic is already gone.
			Expect(r.clearStaleDynamicGrant(ctx, stale)).To(Succeed())
			Expect(fetchRule(name).Status.Dynamic).To(BeNil())
		})
	})

	Describe("dynamicPathAmbiguous", func() {
		It("detects a path used by more than one rule", func() {
			path := "/knock/ambiguous-" + rand.String(8)
			createRule(uniqueRuleName("dynamic-ambiguous-a"), dynamicSpec(path))
			createRule(uniqueRuleName("dynamic-ambiguous-b"), dynamicSpec(path))

			ambiguous, err := r.dynamicPathAmbiguous(ctx, path)
			Expect(err).NotTo(HaveOccurred())
			Expect(ambiguous).To(BeTrue())
		})

		It("does not flag a path used by one rule", func() {
			path := "/knock/unique-" + rand.String(8)
			createRule(uniqueRuleName("dynamic-unique"), dynamicSpec(path))

			ambiguous, err := r.dynamicPathAmbiguous(ctx, path)
			Expect(err).NotTo(HaveOccurred())
			Expect(ambiguous).To(BeFalse())
		})
	})
})
