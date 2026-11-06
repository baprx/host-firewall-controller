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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
)

var _ = Describe("dynamic API", func() {
	dynamicFrom := func(path string) *securityv1alpha1.EndpointSpec {
		return &securityv1alpha1.EndpointSpec{
			Dynamic: &securityv1alpha1.DynamicEndpointSpec{Path: path},
		}
	}

	It("accepts a dynamic from endpoint with path, ttl, and tokenSecretRef", func() {
		name := uniqueRuleName("dynamic-valid")
		createRule(name, securityv1alpha1.HostFirewallRuleSpec{
			Action:   securityv1alpha1.ActionAllow,
			Protocol: securityv1alpha1.ProtocolTCP,
			From: &securityv1alpha1.EndpointSpec{
				Dynamic: &securityv1alpha1.DynamicEndpointSpec{
					Path: "/knock/home",
					TTL:  &metav1.Duration{Duration: time.Hour},
					TokenSecretRef: &securityv1alpha1.SecretKeyRef{
						Name: "ssh-knock-token",
						Key:  "token",
					},
				},
			},
			To: &securityv1alpha1.ToSpec{
				Ports: []securityv1alpha1.Port{"22"},
			},
		})

		rule := fetchRule(name)
		Expect(rule.Spec.From.Dynamic).NotTo(BeNil())
		Expect(rule.Spec.From.Dynamic.Path).To(Equal("/knock/home"))
		Expect(rule.Spec.From.Dynamic.TTL.Duration).To(Equal(time.Hour))
		Expect(rule.Spec.From.Dynamic.TokenSecretRef.Key).To(Equal("token"))

		side, spec := rule.Spec.DynamicEndpoint()
		Expect(side).To(Equal("from"))
		Expect(spec).NotTo(BeNil())
		Expect(spec.Path).To(Equal("/knock/home"))
	})

	It("accepts a dynamic endpoint without ttl", func() {
		name := uniqueRuleName("dynamic-nottl")
		createRule(name, securityv1alpha1.HostFirewallRuleSpec{
			Action: securityv1alpha1.ActionAllow,
			From:   dynamicFrom("/knock/no-ttl"),
			To:     &securityv1alpha1.ToSpec{Ports: []securityv1alpha1.Port{"22"}},
		})

		rule := fetchRule(name)
		Expect(rule.Spec.From.Dynamic.TTL).To(BeNil())
	})

	It("reports the dynamic side and handles rules without one", func() {
		spec := securityv1alpha1.HostFirewallRuleSpec{}
		side, dynamic := spec.DynamicEndpoint()
		Expect(side).To(BeEmpty())
		Expect(dynamic).To(BeNil())

		spec.To = &securityv1alpha1.ToSpec{
			EndpointSpec: securityv1alpha1.EndpointSpec{
				Dynamic: &securityv1alpha1.DynamicEndpointSpec{Path: "/knock/to"},
			},
		}
		side, dynamic = spec.DynamicEndpoint()
		Expect(side).To(Equal("to"))
		Expect(dynamic).NotTo(BeNil())
		Expect(dynamic.Path).To(Equal("/knock/to"))
	})

	It("rejects from.dynamic combined with from.cidr", func() {
		name := uniqueRuleName("dynamic-from-cidr")
		cidr := "10.0.0.0/8"
		expectInvalid(name, securityv1alpha1.HostFirewallRuleSpec{
			Action: securityv1alpha1.ActionAllow,
			From: &securityv1alpha1.EndpointSpec{
				CIDR:    &cidr,
				Dynamic: &securityv1alpha1.DynamicEndpointSpec{Path: "/knock/both"},
			},
			To: &securityv1alpha1.ToSpec{Ports: []securityv1alpha1.Port{"22"}},
		}, "from must set exactly one of cidr, host or dynamic")
	})

	It("rejects from.dynamic combined with to.dynamic", func() {
		name := uniqueRuleName("dynamic-both-sides")
		expectInvalid(name, securityv1alpha1.HostFirewallRuleSpec{
			Action: securityv1alpha1.ActionAllow,
			From:   dynamicFrom("/knock/from"),
			To: &securityv1alpha1.ToSpec{
				EndpointSpec: securityv1alpha1.EndpointSpec{
					Dynamic: &securityv1alpha1.DynamicEndpointSpec{Path: "/knock/to"},
				},
			},
		}, "at most one of from.dynamic and to.dynamic may be set")
	})

	It("rejects to.dynamic combined with to.host", func() {
		name := uniqueRuleName("dynamic-to-host")
		host := "example.com"
		expectInvalid(name, securityv1alpha1.HostFirewallRuleSpec{
			Action: securityv1alpha1.ActionAllow,
			To: &securityv1alpha1.ToSpec{
				EndpointSpec: securityv1alpha1.EndpointSpec{
					Host:    &host,
					Dynamic: &securityv1alpha1.DynamicEndpointSpec{Path: "/knock/to"},
				},
			},
		}, "to may set at most one of cidr, host or dynamic")
	})

	It("rejects a path without a leading slash", func() {
		name := uniqueRuleName("dynamic-bad-path")
		expectInvalid(name, securityv1alpha1.HostFirewallRuleSpec{
			Action: securityv1alpha1.ActionAllow,
			From:   dynamicFrom("knock/home"),
			To:     &securityv1alpha1.ToSpec{Ports: []securityv1alpha1.Port{"22"}},
		}, "spec.from.dynamic.path")
	})

	It("rejects a ttl below one minute", func() {
		name := uniqueRuleName("dynamic-short-ttl")
		expectInvalid(name, securityv1alpha1.HostFirewallRuleSpec{
			Action: securityv1alpha1.ActionAllow,
			From: &securityv1alpha1.EndpointSpec{
				Dynamic: &securityv1alpha1.DynamicEndpointSpec{
					Path: "/knock/short",
					TTL:  &metav1.Duration{Duration: 30 * time.Second},
				},
			},
			To: &securityv1alpha1.ToSpec{Ports: []securityv1alpha1.Port{"22"}},
		}, "ttl must be at least 1m")
	})

	It("rejects a tokenSecretRef without a key", func() {
		name := uniqueRuleName("dynamic-no-key")
		expectInvalid(name, securityv1alpha1.HostFirewallRuleSpec{
			Action: securityv1alpha1.ActionAllow,
			From: &securityv1alpha1.EndpointSpec{
				Dynamic: &securityv1alpha1.DynamicEndpointSpec{
					Path:           "/knock/no-key",
					TokenSecretRef: &securityv1alpha1.SecretKeyRef{Name: "ssh-knock-token"},
				},
			},
			To: &securityv1alpha1.ToSpec{Ports: []securityv1alpha1.Port{"22"}},
		}, "spec.from.dynamic.tokenSecretRef.key")
	})
})

// expectInvalid creates a rule and asserts the API server rejects it with a
// message containing want.
func expectInvalid(name string, spec securityv1alpha1.HostFirewallRuleSpec, want string) {
	rule := &securityv1alpha1.HostFirewallRule{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
	err := k8sClient.Create(ctx, rule)
	Expect(err).To(HaveOccurred())
	Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected Invalid, got %v", err)
	Expect(err.Error()).To(ContainSubstring(want))
}
