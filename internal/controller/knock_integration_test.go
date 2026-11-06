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
	"net/http"
	"net/http/httptest"
	"net/netip"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
	"github.com/baprx/host-firewall-controller/internal/knock"
)

// knockRequest sends one request through the knock handler with the given
// method, path, remote address, and headers.
func knockRequest(
	srv *knock.Server,
	method, path, remoteAddr string,
	headers map[string]string,
) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remoteAddr
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, req)
	return recorder
}

// createKnockSecret creates a Secret and removes it after the spec.
func createKnockSecret(namespace, name string, data map[string][]byte) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data:       data,
	}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	DeferCleanup(func() { _ = k8sClient.Delete(ctx, secret) })
}

var _ = Describe("knock server", func() {
	fixedNow := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

	var (
		host       *fakeHost
		nodeName   string
		reconciler *HostFirewallRuleReconciler
		namespace  string
		srv        *knock.Server
		now        time.Time
	)

	BeforeEach(func() {
		nodeName = "node-" + rand.String(6)
		newNode(nodeName, nil)
		host = newFakeHost(true)
		reconciler = newReconciler(host, nodeName)

		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "knock-" + rand.String(8)}}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, ns) })
		namespace = ns.Name

		now = fixedNow
		srv = &knock.Server{
			Client:    k8sClient,
			Reader:    k8sClient,
			Namespace: namespace,
			Now:       func() time.Time { return now },
		}
	})

	// dynamicRule returns a from.dynamic rule with a path unique to this spec.
	dynamicRule := func(prefix string) (string, string, securityv1alpha1.HostFirewallRuleSpec) {
		path := "/knock/" + prefix + "-" + rand.String(8)
		return uniqueRuleName(prefix), path, dynamicFromRule(path)
	}

	It("records the source IP for a valid knock", func() {
		name, path, spec := dynamicRule("valid")
		spec.From.Dynamic.TTL = &metav1.Duration{Duration: time.Hour}
		spec.From.Dynamic.TokenSecretRef = &securityv1alpha1.SecretKeyRef{
			Name: "ssh-knock-" + rand.String(6),
			Key:  "token",
		}
		createRule(name, spec)
		createKnockSecret(namespace, spec.From.Dynamic.TokenSecretRef.Name, map[string][]byte{
			"token": []byte("secret"),
		})

		recorder := knockRequest(srv, http.MethodGet, path, "203.0.113.9:1234", map[string]string{
			"Authorization": "Bearer secret",
		})

		Expect(recorder.Code).To(Equal(http.StatusOK))
		Expect(recorder.Body.String()).To(Equal("ok\n"))

		grant := fetchRule(name).Status.Dynamic
		Expect(grant).NotTo(BeNil())
		Expect(grant.Path).To(Equal(path))
		Expect(grant.Side).To(Equal("from"))
		Expect(grant.Address).To(Equal("203.0.113.9"))
		Expect(grant.ObservedAt.Time.Equal(fixedNow)).To(BeTrue(),
			"observedAt = %v, want %v", grant.ObservedAt.Time, fixedNow)
		Expect(grant.ExpiresAt).NotTo(BeNil())
		Expect(grant.ExpiresAt.Time.Equal(fixedNow.Add(time.Hour))).To(BeTrue(),
			"expiresAt = %v, want %v", grant.ExpiresAt.Time, fixedNow.Add(time.Hour))
	})

	It("applies the grant to a rule without a token", func() {
		name, path, spec := dynamicRule("no-token")
		createRule(name, spec)

		recorder := knockRequest(srv, http.MethodPost, path, "203.0.113.9:1234", nil)

		Expect(recorder.Code).To(Equal(http.StatusOK))
		grant := fetchRule(name).Status.Dynamic
		Expect(grant).NotTo(BeNil())
		Expect(grant.Address).To(Equal("203.0.113.9"))
		Expect(grant.ExpiresAt).To(BeNil())
	})

	It("returns 404 for an unknown path", func() {
		name, _, spec := dynamicRule("unknown")
		createRule(name, spec)

		recorder := knockRequest(srv, http.MethodGet, "/knock/missing-"+rand.String(8),
			"203.0.113.9:1234", nil)

		Expect(recorder.Code).To(Equal(http.StatusNotFound))
		Expect(fetchRule(name).Status.Dynamic).To(BeNil())
	})

	It("returns 409 for a duplicated path", func() {
		path := "/knock/duplicate-" + rand.String(8)
		firstName := uniqueRuleName("duplicate-a")
		secondName := uniqueRuleName("duplicate-b")
		createRule(firstName, dynamicFromRule(path))
		createRule(secondName, dynamicFromRule(path))

		recorder := knockRequest(srv, http.MethodGet, path, "203.0.113.9:1234", nil)

		Expect(recorder.Code).To(Equal(http.StatusConflict))
		Expect(fetchRule(firstName).Status.Dynamic).To(BeNil())
		Expect(fetchRule(secondName).Status.Dynamic).To(BeNil())
	})

	It("returns 401 for a missing or wrong token", func() {
		name, path, spec := dynamicRule("unauthorized")
		spec.From.Dynamic.TokenSecretRef = &securityv1alpha1.SecretKeyRef{
			Name: "ssh-knock-" + rand.String(6),
			Key:  "token",
		}
		createRule(name, spec)
		createKnockSecret(namespace, spec.From.Dynamic.TokenSecretRef.Name, map[string][]byte{
			"token": []byte("secret"),
		})

		missing := knockRequest(srv, http.MethodGet, path, "203.0.113.9:1234", nil)
		Expect(missing.Code).To(Equal(http.StatusUnauthorized))
		Expect(fetchRule(name).Status.Dynamic).To(BeNil())

		wrong := knockRequest(srv, http.MethodGet, path, "203.0.113.9:1234", map[string]string{
			"Authorization": "Bearer not-the-token",
		})
		Expect(wrong.Code).To(Equal(http.StatusUnauthorized))
		Expect(fetchRule(name).Status.Dynamic).To(BeNil())
	})

	It("returns 503 when the token Secret is missing", func() {
		name, path, spec := dynamicRule("missing-secret")
		spec.From.Dynamic.TokenSecretRef = &securityv1alpha1.SecretKeyRef{
			Name: "absent-" + rand.String(8),
			Key:  "token",
		}
		createRule(name, spec)

		recorder := knockRequest(srv, http.MethodGet, path, "203.0.113.9:1234", map[string]string{
			"Authorization": "Bearer secret",
		})

		Expect(recorder.Code).To(Equal(http.StatusServiceUnavailable))
		Expect(fetchRule(name).Status.Dynamic).To(BeNil())
	})

	It("returns 405 for non-GET/POST methods", func() {
		name, path, spec := dynamicRule("method")
		createRule(name, spec)

		recorder := knockRequest(srv, http.MethodPut, path, "203.0.113.9:1234", nil)

		Expect(recorder.Code).To(Equal(http.StatusMethodNotAllowed))
		Expect(fetchRule(name).Status.Dynamic).To(BeNil())
	})

	It("rejects an invalid RemoteAddr", func() {
		name, path, spec := dynamicRule("bad-remote")
		createRule(name, spec)

		recorder := knockRequest(srv, http.MethodGet, path, "not-an-ip", nil)

		Expect(recorder.Code).To(Equal(http.StatusBadRequest))
		Expect(fetchRule(name).Status.Dynamic).To(BeNil())
	})

	It("replaces the previous grant on a second knock", func() {
		name, path, spec := dynamicRule("replace")
		spec.From.Dynamic.TTL = &metav1.Duration{Duration: time.Hour}
		createRule(name, spec)

		first := knockRequest(srv, http.MethodGet, path, "203.0.113.9:1234", nil)
		Expect(first.Code).To(Equal(http.StatusOK))

		now = fixedNow.Add(30 * time.Minute)
		second := knockRequest(srv, http.MethodGet, path, "198.51.100.7:5678", nil)
		Expect(second.Code).To(Equal(http.StatusOK))

		grant := fetchRule(name).Status.Dynamic
		Expect(grant).NotTo(BeNil())
		Expect(grant.Address).To(Equal("198.51.100.7"))
		Expect(grant.ObservedAt.Time.Equal(fixedNow.Add(30 * time.Minute))).To(BeTrue())
		Expect(grant.ExpiresAt).NotTo(BeNil())
		Expect(grant.ExpiresAt.Time.Equal(fixedNow.Add(30*time.Minute + time.Hour))).To(BeTrue())
	})

	It("stores a grant even when the local node is not selected", func() {
		name, path, spec := dynamicRule("other-node")
		spec.NodeSelector = &metav1.LabelSelector{
			MatchLabels: map[string]string{testRoleKey: "other"},
		}
		createRule(name, spec)

		recorder := knockRequest(srv, http.MethodGet, path, "203.0.113.9:1234", nil)
		Expect(recorder.Code).To(Equal(http.StatusOK))

		grant := fetchRule(name).Status.Dynamic
		Expect(grant).NotTo(BeNil())
		Expect(grant.Address).To(Equal("203.0.113.9"))

		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(0))
	})

	It("uses X-Forwarded-For only from a trusted proxy", func() {
		name, path, spec := dynamicRule("trusted-proxy")
		createRule(name, spec)
		srv.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}

		recorder := knockRequest(srv, http.MethodGet, path, "203.0.113.9:1234", map[string]string{
			"X-Forwarded-For": "198.51.100.7",
		})

		Expect(recorder.Code).To(Equal(http.StatusOK))
		grant := fetchRule(name).Status.Dynamic
		Expect(grant).NotTo(BeNil())
		Expect(grant.Address).To(Equal("198.51.100.7"))
	})

	It("ignores X-Forwarded-For from an untrusted peer", func() {
		name, path, spec := dynamicRule("untrusted-proxy")
		createRule(name, spec)
		srv.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}

		recorder := knockRequest(srv, http.MethodGet, path, "198.51.100.7:1234", map[string]string{
			"X-Forwarded-For": "203.0.113.9",
		})

		Expect(recorder.Code).To(Equal(http.StatusOK))
		grant := fetchRule(name).Status.Dynamic
		Expect(grant).NotTo(BeNil())
		Expect(grant.Address).To(Equal("198.51.100.7"))
	})

	It("keeps per-node status when a later knock replaces the grant", func() {
		name, path, spec := dynamicRule("ssa")
		createRule(name, spec)

		first := knockRequest(srv, http.MethodGet, path, "203.0.113.9:1234", nil)
		Expect(first.Code).To(Equal(http.StatusOK))

		mustReconcile(newReconciler(host, nodeName), name)
		Expect(host.count()).To(Equal(1))
		Expect(fetchRule(name).Status.Nodes[nodeName].Applied).To(BeTrue())

		second := knockRequest(srv, http.MethodGet, path, "198.51.100.7:5678", nil)
		Expect(second.Code).To(Equal(http.StatusOK))

		rule := fetchRule(name)
		Expect(rule.Status.Nodes[nodeName].Applied).To(BeTrue(),
			"the hfc-dynamic field manager must not clobber status.nodes")
		Expect(rule.Status.Dynamic).NotTo(BeNil())
		Expect(rule.Status.Dynamic.Address).To(Equal("198.51.100.7"))

		mustReconcile(newReconciler(host, nodeName), name)
		Expect(host.count()).To(Equal(1))
		Expect(host.snapshot()[0].rule.Command()).To(ContainSubstring("198.51.100.7"))
	})
})
