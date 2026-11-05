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
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
	"github.com/baprx/host-firewall-controller/internal/dnsresolver"
	"github.com/baprx/host-firewall-controller/internal/ufw"
)

const (
	testRoleKey = "role"
)

// fakeRule is one rule stored by fakeHost, in the v4 or v6 rule list.
type fakeRule struct {
	rule ufw.Rule
	v6   bool
}

// fakeHost is a stateful stand-in for the host ufw binary. It understands just
// enough of status/show/delete/add to exercise the reconciler end to end. Like
// ufw, an add replaces an existing rule with the same match key, and an
// any-address rule becomes a v4/v6 twin when IPv6 is enabled.
type fakeHost struct {
	mu sync.Mutex

	enabled        bool
	ipv6           bool
	reportComments bool
	version        string

	rules []fakeRule
	ops   []string

	failAdd     error
	failPrepend error
	failStatus  error
}

func newFakeHost(enabled bool) *fakeHost {
	return &fakeHost{
		enabled:        enabled,
		reportComments: true,
		version:        "ufw 0.36.2",
	}
}

func (f *fakeHost) Run(_ context.Context, args ...string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case len(args) == 1 && args[0] == "--version":
		return f.version + "\n", nil

	case len(args) >= 2 && args[0] == "status" && args[1] == "numbered":
		if f.failStatus != nil {
			return "", f.failStatus
		}
		return f.renderStatus(), nil

	case len(args) >= 2 && args[0] == "show" && args[1] == "added":
		if f.failStatus != nil {
			return "", f.failStatus
		}
		return f.renderAdded(), nil

	case len(args) >= 3 && args[0] == "--force" && args[1] == "delete":
		number, err := strconv.Atoi(args[2])
		if err != nil || number < 1 || number > len(f.rules) {
			return "", fmt.Errorf("invalid rule number %q", args[2])
		}
		f.rules = slices.Delete(f.rules, number-1, number)
		f.ops = append(f.ops, fmt.Sprintf("delete %d", number))
		return "Rule deleted\n", nil

	case len(args) >= 2 && args[0] == "delete":
		return f.deleteSpec(args[1:])

	default:
		if f.failAdd != nil {
			return "", f.failAdd
		}
		if f.failPrepend != nil && len(args) > 0 && args[0] == "prepend" {
			return "", f.failPrepend
		}
		return f.add(args)
	}
}

func (f *fakeHost) add(args []string) (string, error) {
	rule, ok := parseFakeRule(args)
	if !ok {
		return "", fmt.Errorf("invalid rule %q", strings.Join(args, " "))
	}
	if !f.reportComments {
		// Like an old ufw, accept the comment argument but do not store it.
		rule.Comment = ""
	}

	f.ops = append(f.ops, "add "+strings.Join(args, " "))
	response := "Rule added\n"
	for _, v6 := range f.families(rule) {
		index := f.findMatch(rule, v6)
		if index < 0 {
			if rule.Prepend {
				f.rules = append([]fakeRule{{rule: rule, v6: v6}}, f.rules...)
			} else {
				f.rules = append(f.rules, fakeRule{rule: rule, v6: v6})
			}
			continue
		}

		existing := f.rules[index]
		if rule.Prepend {
			response = "Skipping inserting existing rule\n"
			continue
		}
		if existing.rule.Action == rule.Action && existing.rule.Log == rule.Log &&
			existing.rule.Comment == rule.Comment {
			response = "Skipping adding existing rule\n"
			continue
		}

		rule.Prepend = false
		existing.rule = rule
		f.rules[index] = existing
		response = "Rules updated\n"
	}
	return response, nil
}

func (f *fakeHost) deleteSpec(spec []string) (string, error) {
	target, ok := parseFakeRule(spec)
	if !ok {
		return "", fmt.Errorf("invalid rule %q", strings.Join(spec, " "))
	}

	deleted := map[bool]bool{}
	for i, rule := range f.rules {
		if deleted[rule.v6] || rule.rule.MatchKey() != target.MatchKey() {
			continue
		}
		if rule.rule.Action != target.Action || rule.rule.Log != target.Log {
			continue
		}
		if target.Comment != "" && rule.rule.Comment != target.Comment {
			continue
		}
		if !f.familyAllowed(target, rule.v6) {
			continue
		}

		f.rules = slices.Delete(f.rules, i, i+1)
		deleted[rule.v6] = true
	}

	if len(deleted) == 0 {
		return "", fmt.Errorf("could not find rule %q to delete", strings.Join(spec, " "))
	}
	f.ops = append(f.ops, "delete "+strings.Join(spec, " "))
	return "Rule deleted\n", nil
}

func (f *fakeHost) findMatch(rule ufw.Rule, v6 bool) int {
	key := rule.MatchKey()
	for i, existing := range f.rules {
		if existing.v6 == v6 && existing.rule.MatchKey() == key {
			return i
		}
	}
	return -1
}

// families returns the v4/v6 rule lists a rule is written to.
func (f *fakeHost) families(rule ufw.Rule) []bool {
	hasV4, hasV6 := false, false
	for _, address := range []string{rule.From.Address, rule.To.Address} {
		if fakeIsAnyAddress(address) {
			continue
		}
		if strings.Contains(address, ":") {
			hasV6 = true
		} else {
			hasV4 = true
		}
	}
	if !hasV4 && !hasV6 {
		hasV4 = true
		hasV6 = f.ipv6
	}
	out := make([]bool, 0, 2)
	if hasV4 {
		out = append(out, false)
	}
	if hasV6 {
		out = append(out, true)
	}
	return out
}

func (f *fakeHost) familyAllowed(rule ufw.Rule, v6 bool) bool {
	return slices.Contains(f.families(rule), v6)
}

func (f *fakeHost) renderStatus() string {
	if !f.enabled {
		return "Status: inactive\n"
	}

	var builder strings.Builder
	builder.WriteString("Status: active\n\nTo                         Action      From\n")
	builder.WriteString("--                         ------      ----\n")
	for i, rule := range f.rules {
		fmt.Fprintf(&builder, "[%2d] rule ALLOW IN Anywhere", i+1)
		if rule.v6 {
			builder.WriteString(" (v6)")
		}
		if rule.rule.Comment != "" && f.reportComments {
			fmt.Fprintf(&builder, " # %s", rule.rule.Comment)
		}
		builder.WriteString("\n")
	}
	return builder.String()
}

func (f *fakeHost) renderAdded() string {
	var builder strings.Builder
	builder.WriteString("Added user rules (see 'ufw status' for running firewall):\n")
	seen := map[string]bool{}
	for _, rule := range f.rules {
		line := rule.rule.Command()
		if seen[line] {
			// "show added" lists the v4/v6 twins once.
			continue
		}
		seen[line] = true
		builder.WriteString("ufw ")
		builder.WriteString(line)
		builder.WriteString("\n")
	}
	return builder.String()
}

func (f *fakeHost) seedUnmanaged(args []string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	prepend := len(args) > 0 && args[0] == "prepend"
	if prepend {
		args = args[1:]
	}
	rule, ok := parseFakeRule(args)
	if !ok {
		panic("invalid unmanaged rule: " + strings.Join(args, " "))
	}
	rule.Prepend = prepend
	if prepend {
		f.rules = append([]fakeRule{{rule: rule}}, f.rules...)
		return
	}
	f.rules = append(f.rules, fakeRule{rule: rule})
}

func (f *fakeHost) clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = nil
}

func (f *fakeHost) duplicate(index int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, f.rules[index])
}

func (f *fakeHost) snapshot() []fakeRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.rules)
}

func (f *fakeHost) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rules)
}

func (f *fakeHost) opsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ops)
}

func (f *fakeHost) resetOps() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = nil
}

// fakeIsAnyAddress mirrors ufw: only an omitted address (parsed as "any") spans
// both families. An explicit 0.0.0.0/0 or ::/0 is still one family.
func fakeIsAnyAddress(address string) bool {
	return address == "" || address == "any"
}

// parseFakeRule understands the short and extended forms ufw writes to
// "show added". It only needs to be accurate for the rules in these tests.
func parseFakeRule(args []string) (ufw.Rule, bool) {
	if len(args) == 0 {
		return ufw.Rule{}, false
	}

	rule := ufw.Rule{
		Direction: ufw.DirectionIn,
		Protocol:  ufw.ProtocolAny,
	}
	i := 0
	if args[i] == "prepend" {
		rule.Prepend = true
		i++
	}
	if i >= len(args) {
		return ufw.Rule{}, false
	}
	rule.Action = ufw.Action(args[i])
	i++
	if i < len(args) && (args[i] == "in" || args[i] == "out") {
		rule.Direction = ufw.Direction(args[i])
		i++
		if i < len(args) && args[i] == "on" {
			i++
			if i < len(args) {
				rule.Interface = args[i]
				i++
			}
		}
	}
	if i < len(args) && (args[i] == "log" || args[i] == "log-all") {
		rule.Log = true
		i++
	}

	keywords := map[string]bool{"proto": true, "from": true, "to": true, "app": true, "port": true, "comment": true}
	if i < len(args) && !keywords[args[i]] {
		// Short syntax: dport[/protocol].
		dport, protocol, hasProtocol := strings.Cut(args[i], "/")
		i++
		if hasProtocol {
			rule.Protocol = ufw.Protocol(protocol)
		}
		rule.ToPorts = strings.Split(dport, ",")
	} else {
		i = parseFullFakeRule(&rule, args, i)
	}

	if i < len(args) && args[i] == "comment" {
		i++
		if i < len(args) {
			rule.Comment = args[i]
		}
	}
	return rule, true
}

func parseFullFakeRule(rule *ufw.Rule, args []string, i int) int {
	last := ""
	for i < len(args) {
		switch args[i] {
		case "proto":
			i++
			if i < len(args) {
				rule.Protocol = ufw.Protocol(args[i])
				i++
			}
		case "from", "to":
			last = args[i]
			i++
			if i < len(args) {
				address := args[i]
				if address == "any" {
					address = ""
				}
				if last == "from" {
					rule.From.Address = address
				} else {
					rule.To.Address = address
				}
				i++
			}
		case "port":
			i++
			if i < len(args) {
				if last == "from" {
					rule.From.Port = args[i]
				} else {
					rule.To.Port = args[i]
				}
				i++
			}
		case "app":
			i += 2
		case "comment":
			i++
			if i < len(args) {
				rule.Comment = args[i]
			}
			i = len(args)
		default:
			i++
		}
	}
	return i
}

// helpers shared by the controller specs.

// recordingRecorder captures emitted event reasons for assertions.
type recordingRecorder struct {
	events []string
}

func (r *recordingRecorder) Eventf(
	_ runtime.Object, _ runtime.Object, _, reason, _, note string, _ ...any,
) {
	r.events = append(r.events, reason+" "+note)
}

func newReconciler(host *fakeHost, nodeName string) *HostFirewallRuleReconciler {
	return &HostFirewallRuleReconciler{
		Client:                 k8sClient,
		Scheme:                 k8sClient.Scheme(),
		NodeName:               nodeName,
		Ufw:                    host,
		Resolver:               &dnsresolver.FakeResolver{Addrs: map[string][]netip.Addr{}, Errs: map[string]error{}},
		DefaultRefreshInterval: time.Hour,
		MinRefreshInterval:     time.Second,
		MaxRulesPerNode:        256,
		MaxRulesPerCR:          64,
		MaxAddresses:           16,
		UFWVersion:             "ufw 0.36.2",
	}
}

func newNode(name string, labels map[string]string) {
	if labels == nil {
		labels = map[string]string{testRoleKey: "web"}
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
	Expect(k8sClient.Create(ctx, node)).To(Succeed())
	DeferCleanup(func() { _ = k8sClient.Delete(ctx, node) })
}

func createRule(name string, spec securityv1alpha1.HostFirewallRuleSpec) {
	rule := &securityv1alpha1.HostFirewallRule{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
	Expect(k8sClient.Create(ctx, rule)).To(Succeed())
	DeferCleanup(func() { _ = k8sClient.Delete(ctx, rule) })
}

func fetchRule(name string) *securityv1alpha1.HostFirewallRule {
	rule := &securityv1alpha1.HostFirewallRule{}
	Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name}, rule)).To(Succeed())
	return rule
}

func reconcileOnce(reconciler *HostFirewallRuleReconciler, name string) (reconcile.Result, error) {
	return reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: name},
	})
}

func mustReconcile(reconciler *HostFirewallRuleReconciler, name string) reconcile.Result {
	result, err := reconcileOnce(reconciler, name)
	Expect(err).NotTo(HaveOccurred())
	return result
}

func allowTCP(port string) securityv1alpha1.HostFirewallRuleSpec {
	return securityv1alpha1.HostFirewallRuleSpec{
		Action:   securityv1alpha1.ActionAllow,
		Protocol: securityv1alpha1.ProtocolTCP,
		To: &securityv1alpha1.ToSpec{
			Ports: []securityv1alpha1.Port{securityv1alpha1.Port(port)},
		},
	}
}

func uniqueRuleName(prefix string) string {
	return prefix + "-" + rand.String(6)
}

var _ = Describe("fakeHost", func() {
	It("round-trips add, status, delete", func() {
		host := newFakeHost(true)
		_, err := host.Run(ctx, "allow", "proto", "tcp", "to", "any", "port", "22", "comment", "HFC:a:0123456789ab")
		Expect(err).NotTo(HaveOccurred())

		state := ufw.ParseStatusNumbered(mustRender(host, "status", "numbered"))
		Expect(state.Enabled).To(BeTrue())
		Expect(state.Entries).To(HaveLen(1))

		_, err = host.Run(ctx, "--force", "delete", "1")
		Expect(err).NotTo(HaveOccurred())
		Expect(host.count()).To(Equal(0))
	})
})

func mustRender(host *fakeHost, args ...string) string {
	out, err := host.Run(context.Background(), args...)
	Expect(err).NotTo(HaveOccurred())
	return out
}

var _ = Describe("HostFirewallRule API", func() {
	It("is cluster scoped", func() {
		namespaced, err := k8sClient.IsObjectNamespaced(&securityv1alpha1.HostFirewallRule{})
		Expect(err).NotTo(HaveOccurred())
		Expect(namespaced).To(BeFalse(), "HostFirewallRule applies to hosts, not namespaces")
	})
})

var _ = Describe("HostFirewallRule controller", func() {
	var (
		host       *fakeHost
		nodeName   string
		reconciler *HostFirewallRuleReconciler
	)

	BeforeEach(func() {
		nodeName = "node-" + rand.String(6)
		newNode(nodeName, nil)
		host = newFakeHost(true)
		reconciler = newReconciler(host, nodeName)
	})

	It("adds a missing rule and reports it as applied", func() {
		name := uniqueRuleName("add")
		createRule(name, allowTCP("22"))

		mustReconcile(reconciler, name)

		rules := host.snapshot()
		Expect(rules).To(HaveLen(1))
		Expect(rules[0].rule.Comment).To(HavePrefix("HFC:" + name + ":"))

		rule := fetchRule(name)
		status := rule.Status.Nodes[nodeName]
		Expect(status.Applied).To(BeTrue())
		Expect(status.UFWEnabled).To(BeTrue())
		Expect(status.Generation).To(Equal(rule.Generation))
		Expect(status.Markers).To(HaveLen(1))
	})

	It("adds the replacement before deleting the old rule", func() {
		name := uniqueRuleName("update")
		createRule(name, allowTCP("80"))
		mustReconcile(reconciler, name)
		host.resetOps()

		rule := fetchRule(name)
		rule.Spec.To.Ports = []securityv1alpha1.Port{"443"}
		Expect(k8sClient.Update(ctx, rule)).To(Succeed())

		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(1))
		ops := host.opsSnapshot()
		addIndex := slices.IndexFunc(ops, func(op string) bool { return strings.HasPrefix(op, "add") })
		deleteIndex := slices.IndexFunc(ops, func(op string) bool { return strings.HasPrefix(op, "delete") })
		Expect(addIndex).To(BeNumerically(">=", 0))
		Expect(deleteIndex).To(BeNumerically(">=", 0))
		Expect(addIndex).To(BeNumerically("<", deleteIndex))
	})

	It("updates the action of its own rule in place", func() {
		name := uniqueRuleName("actionchange")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		rule := fetchRule(name)
		rule.Spec.Action = securityv1alpha1.ActionDeny
		Expect(k8sClient.Update(ctx, rule)).To(Succeed())

		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(1))
		Expect(host.snapshot()[0].rule.Action).To(Equal(ufw.ActionDeny))
		Expect(fetchRule(name).Status.Nodes[nodeName].Applied).To(BeTrue())
	})

	It("moves its own rule when prepend changes", func() {
		name := uniqueRuleName("prependchange")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))
		Expect(host.snapshot()[0].rule.Prepend).To(BeFalse())

		rule := fetchRule(name)
		rule.Spec.Prepend = true
		Expect(k8sClient.Update(ctx, rule)).To(Succeed())

		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(1))
		Expect(host.snapshot()[0].rule.Prepend).To(BeTrue())
		Expect(fetchRule(name).Status.Nodes[nodeName].Applied).To(BeTrue())
	})

	It("restores the rule when the prepend move fails", func() {
		name := uniqueRuleName("prependfail")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		rule := fetchRule(name)
		rule.Spec.Prepend = true
		Expect(k8sClient.Update(ctx, rule)).To(Succeed())

		host.failPrepend = errors.New("ufw: rule file is read-only")
		_, err := reconcileOnce(reconciler, name)
		Expect(err).To(HaveOccurred())

		// Moving a rule requires deleting it first. If the prepend then fails,
		// the rule must be restored in its old position.
		Expect(host.count()).To(Equal(1))
		Expect(host.snapshot()[0].rule.Prepend).To(BeFalse())
	})

	It("does nothing on a node that does not match the selector", func() {
		name := uniqueRuleName("nomatch")
		spec := allowTCP("22")
		spec.NodeSelector = &metav1.LabelSelector{MatchLabels: map[string]string{testRoleKey: "database"}}
		createRule(name, spec)

		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(0))
		status := fetchRule(name).Status.Nodes[nodeName]
		Expect(status.Applied).To(BeTrue())
		Expect(status.Message).To(ContainSubstring("does not match"))
	})

	It("removes rules when the selector stops matching", func() {
		name := uniqueRuleName("selchange")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		rule := fetchRule(name)
		rule.Spec.NodeSelector = &metav1.LabelSelector{MatchLabels: map[string]string{testRoleKey: "database"}}
		Expect(k8sClient.Update(ctx, rule)).To(Succeed())

		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(0))
	})

	It("never touches an identical unmanaged rule", func() {
		host.seedUnmanaged([]string{"allow", "proto", "tcp", "to", "any", "port", "22"})

		name := uniqueRuleName("unmanaged")
		createRule(name, allowTCP("22"))

		// ufw would update the unmanaged rule in place because the match key is
		// identical. The operator must refuse instead of silently adopting it.
		_, err := reconcileOnce(reconciler, name)
		Expect(err).To(HaveOccurred())

		rules := host.snapshot()
		Expect(rules).To(HaveLen(1))
		Expect(rules[0].rule.Comment).To(BeEmpty())

		status := fetchRule(name).Status.Nodes[nodeName]
		Expect(status.Applied).To(BeFalse())
		Expect(status.Degraded).To(BeTrue())
		Expect(status.Message).To(ContainSubstring("refusing to modify"))

		Expect(k8sClient.Delete(ctx, fetchRule(name))).To(Succeed())
		Expect(reconciler.ReconcileSweep(ctx)).To(Succeed())

		rules = host.snapshot()
		Expect(rules).To(HaveLen(1))
		Expect(rules[0].rule.Comment).To(BeEmpty())
	})

	It("never touches rules owned by another HostFirewallRule", func() {
		otherName := uniqueRuleName("other")
		createRule(otherName, allowTCP("9999"))
		mustReconcile(reconciler, otherName)
		Expect(host.count()).To(Equal(1))

		name := uniqueRuleName("mine")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(2))
		Expect(reconciler.ReconcileSweep(ctx)).To(Succeed())
		Expect(host.count()).To(Equal(2))
	})

	It("refuses to steal a rule owned by another HostFirewallRule", func() {
		first := uniqueRuleName("first")
		createRule(first, allowTCP("22"))
		mustReconcile(reconciler, first)
		Expect(host.count()).To(Equal(1))

		second := uniqueRuleName("second")
		createRule(second, allowTCP("22"))

		_, err := reconcileOnce(reconciler, second)
		Expect(err).To(HaveOccurred())

		rules := host.snapshot()
		Expect(rules).To(HaveLen(1))
		Expect(rules[0].rule.Comment).To(HavePrefix("HFC:" + first + ":"))

		status := fetchRule(second).Status.Nodes[nodeName]
		Expect(status.Applied).To(BeFalse())
		Expect(status.Degraded).To(BeTrue())
		Expect(status.Message).To(ContainSubstring("refusing to modify"))
	})

	It("reduces duplicate operator rules to one", func() {
		name := uniqueRuleName("dup")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		host.duplicate(0)
		Expect(host.count()).To(Equal(2))

		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))
	})

	It("keeps the IPv4 and IPv6 twins of a dual-stack rule", func() {
		host.ipv6 = true

		name := uniqueRuleName("twins")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(2))
		Expect(host.snapshot()[0].v6).To(BeFalse())
		Expect(host.snapshot()[1].v6).To(BeTrue())

		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(2))

		Expect(reconciler.ReconcileSweep(ctx)).To(Succeed())
		Expect(host.count()).To(Equal(2))

		status := fetchRule(name).Status.Nodes[nodeName]
		Expect(status.Applied).To(BeTrue())
	})

	It("does not re-add an explicit 0.0.0.0/0 rule on a dual-stack host", func() {
		host.ipv6 = true

		// Another managed rule makes ufw report an IPv6 entry.
		anchor := uniqueRuleName("v6anchor")
		createRule(anchor, allowTCP("9999"))
		mustReconcile(reconciler, anchor)
		Expect(host.count()).To(Equal(2))

		name := uniqueRuleName("explicitany")
		spec := allowTCP("22")
		spec.From = &securityv1alpha1.EndpointSpec{CIDR: new("0.0.0.0/0")}
		createRule(name, spec)
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(3))

		host.resetOps()
		mustReconcile(reconciler, name)

		// An explicit 0.0.0.0/0 is a single-family rule, not "any": there is
		// nothing to add on the second reconcile.
		Expect(host.opsSnapshot()).To(BeEmpty())
		Expect(host.count()).To(Equal(3))
	})

	It("enforces the node cap across all matching HostFirewallRules", func() {
		reconciler.MaxRulesPerNode = 1

		first := uniqueRuleName("capfirst")
		createRule(first, allowTCP("22"))
		mustReconcile(reconciler, first)
		Expect(host.count()).To(Equal(1))

		second := uniqueRuleName("capsecond")
		createRule(second, allowTCP("80"))

		_, err := reconcileOnce(reconciler, second)
		Expect(err).To(HaveOccurred())
		Expect(host.count()).To(Equal(1))

		status := fetchRule(second).Status.Nodes[nodeName]
		Expect(status.Applied).To(BeFalse())
		Expect(status.Degraded).To(BeTrue())
		Expect(status.Message).To(ContainSubstring("node maximum"))

		// The sweep applies the same union-wide cap before adding anything.
		Expect(reconciler.ReconcileSweep(ctx)).To(HaveOccurred())
		Expect(host.count()).To(Equal(1))
	})

	It("works while ufw is inactive, using the added rules report", func() {
		host = newFakeHost(false)
		reconciler = newReconciler(host, nodeName)

		name := uniqueRuleName("inactive")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(1))
		status := fetchRule(name).Status.Nodes[nodeName]
		Expect(status.UFWEnabled).To(BeFalse())
		Expect(status.Applied).To(BeTrue())
	})

	It("deletes its own rule by identity while ufw is inactive", func() {
		host = newFakeHost(false)
		reconciler = newReconciler(host, nodeName)

		name := uniqueRuleName("inactivedelete")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		// An identical unmanaged rule, prepended so it is first in the file.
		// Deleting by specification without the comment would remove it.
		host.seedUnmanaged([]string{"prepend", "allow", "proto", "tcp", "to", "any", "port", "22"})
		Expect(host.count()).To(Equal(2))

		Expect(k8sClient.Delete(ctx, fetchRule(name))).To(Succeed())
		Expect(reconciler.ReconcileSweep(ctx)).To(Succeed())

		rules := host.snapshot()
		Expect(rules).To(HaveLen(1))
		Expect(rules[0].rule.Comment).To(BeEmpty())
	})

	It("stops adding rules when ufw does not report comments", func() {
		host.reportComments = false

		name := uniqueRuleName("nocomments")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(1))
		status := fetchRule(name).Status.Nodes[nodeName]
		Expect(status.CommentsUnsupported).To(BeTrue())
		Expect(status.Applied).To(BeFalse())

		host.resetOps()
		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(1))
		Expect(host.opsSnapshot()).To(BeEmpty())
	})

	It("keeps the previous rule when the replacement add fails", func() {
		name := uniqueRuleName("addfail")
		createRule(name, allowTCP("80"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		rule := fetchRule(name)
		rule.Spec.To.Ports = []securityv1alpha1.Port{"443"}
		Expect(k8sClient.Update(ctx, rule)).To(Succeed())

		host.failAdd = errors.New("ufw: rule file is read-only")
		_, err := reconcileOnce(reconciler, name)
		Expect(err).To(HaveOccurred())

		// The old deny/allow rule must survive; deleting it after a failed
		// replacement would remove the only working rule.
		rules := host.snapshot()
		Expect(rules).To(HaveLen(1))
		Expect(rules[0].rule.Command()).To(ContainSubstring("80"))
	})

	It("keeps the previous rule when a sweep replacement add fails", func() {
		name := uniqueRuleName("sweepaddfail")
		createRule(name, allowTCP("80"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		rule := fetchRule(name)
		rule.Spec.To.Ports = []securityv1alpha1.Port{"443"}
		Expect(k8sClient.Update(ctx, rule)).To(Succeed())

		host.failAdd = errors.New("ufw: rule file is read-only")
		Expect(reconciler.ReconcileSweep(ctx)).To(HaveOccurred())

		// Pruning after a failed add would remove the only working rule.
		rules := host.snapshot()
		Expect(rules).To(HaveLen(1))
		Expect(rules[0].rule.Command()).To(ContainSubstring("80"))
	})

	It("retries after a spec change when comments are not reported", func() {
		host.reportComments = false

		name := uniqueRuleName("nocommentsupdate")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		rule := fetchRule(name)
		rule.Spec.To.Ports = []securityv1alpha1.Port{"80"}
		Expect(k8sClient.Update(ctx, rule)).To(Succeed())

		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(2))

		status := fetchRule(name).Status.Nodes[nodeName]
		Expect(status.CommentsUnsupported).To(BeTrue())
		Expect(status.Applied).To(BeTrue())
	})

	It("re-adds a commentless rule that was deleted manually", func() {
		host.reportComments = false

		name := uniqueRuleName("nocommentsdelete")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		host.clear()
		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(1))
	})

	It("reports a failed ufw invocation", func() {
		host.failAdd = errors.New("permission denied")

		name := uniqueRuleName("failure")
		createRule(name, allowTCP("22"))

		_, err := reconcileOnce(reconciler, name)
		Expect(err).To(HaveOccurred())

		status := fetchRule(name).Status.Nodes[nodeName]
		Expect(status.Applied).To(BeFalse())
		Expect(status.Degraded).To(BeTrue())
		Expect(status.Message).To(ContainSubstring("permission denied"))
	})

	It("does not repeat the same failure event", func() {
		recorded := &recordingRecorder{}
		reconciler.Recorder = recorded
		host.failAdd = errors.New("permission denied")

		name := uniqueRuleName("eventrepeat")
		createRule(name, allowTCP("22"))

		_, err := reconcileOnce(reconciler, name)
		Expect(err).To(HaveOccurred())
		_, err = reconcileOnce(reconciler, name)
		Expect(err).To(HaveOccurred())

		// A repeated reconcile with the same failure must not spam the object.
		Expect(recorded.events).To(HaveLen(1))
	})

	It("repairs a missing rule during a sweep", func() {
		name := uniqueRuleName("drift")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		// Simulate an administrator (or a restore) deleting the rule.
		host.clear()

		Expect(reconciler.ReconcileSweep(ctx)).To(Succeed())
		Expect(host.count()).To(Equal(1))
		Expect(host.snapshot()[0].rule.Comment).To(HavePrefix("HFC:" + name + ":"))
	})

	It("refreshes status after a sweep repairs drift", func() {
		name := uniqueRuleName("sweepstatus")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		// Simulate a status left stale by an earlier failure.
		rule := fetchRule(name)
		stale := rule.Status.Nodes[nodeName]
		stale.Applied = false
		stale.Degraded = true
		stale.Message = "stale"
		rule.Status.Nodes[nodeName] = stale
		Expect(reconciler.patchStatus(ctx, rule, stale)).To(Succeed())

		host.clear()
		Expect(reconciler.ReconcileSweep(ctx)).To(Succeed())

		status := fetchRule(name).Status.Nodes[nodeName]
		Expect(status.Applied).To(BeTrue())
		Expect(status.Degraded).To(BeFalse())
		Expect(status.Message).To(BeEmpty())
	})

	It("does not touch lastAppliedTime on a no-op sweep", func() {
		name := uniqueRuleName("sweeptimestamp")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)

		rule := fetchRule(name)
		prev := rule.Status.Nodes[nodeName]
		old := metav1.NewTime(time.Now().Add(-time.Hour))
		prev.LastAppliedTime = &old
		Expect(reconciler.patchStatus(ctx, rule, prev)).To(Succeed())
		patched := fetchRule(name).Status.Nodes[nodeName].LastAppliedTime
		Expect(patched).NotTo(BeNil())

		Expect(reconciler.ReconcileSweep(ctx)).To(Succeed())

		// lastAppliedTime also gates the hostname resolution cache. A sweep that
		// changes nothing must not make cached addresses look fresh forever.
		after := fetchRule(name).Status.Nodes[nodeName]
		Expect(after.LastAppliedTime.Time.Equal(patched.Time)).To(BeTrue())
	})

	It("prunes rules after the HostFirewallRule is deleted", func() {
		name := uniqueRuleName("sweep")
		createRule(name, allowTCP("22"))
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		Expect(k8sClient.Delete(ctx, fetchRule(name))).To(Succeed())
		Expect(reconciler.ReconcileSweep(ctx)).To(Succeed())

		Expect(host.count()).To(Equal(0))
	})

	It("resolves a hostname and refreshes it", func() {
		resolver := reconciler.Resolver.(*dnsresolver.FakeResolver)
		resolver.Addrs["web.example.com"] = []netip.Addr{netip.MustParseAddr("192.0.2.10")}

		name := uniqueRuleName("dns")
		spec := allowTCP("443")
		spec.From = &securityv1alpha1.EndpointSpec{Host: new("web.example.com")}
		createRule(name, spec)

		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(1))
		Expect(host.snapshot()[0].rule.Command()).To(ContainSubstring("192.0.2.10"))
		status := fetchRule(name).Status.Nodes[nodeName]
		Expect(status.Resolved.From).To(ConsistOf("192.0.2.10"))
		Expect(status.Degraded).To(BeFalse())

		resolver.Addrs["web.example.com"] = []netip.Addr{netip.MustParseAddr("192.0.2.11")}
		reconciler.DefaultRefreshInterval = time.Nanosecond
		reconciler.MinRefreshInterval = time.Nanosecond

		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(1))
		joined := host.snapshot()[0].rule.Command()
		Expect(joined).To(ContainSubstring("192.0.2.11"))
		Expect(joined).NotTo(ContainSubstring("192.0.2.10"))
	})

	It("keeps last known-good rules when DNS resolution fails", func() {
		resolver := reconciler.Resolver.(*dnsresolver.FakeResolver)
		resolver.Addrs["db.example.com"] = []netip.Addr{netip.MustParseAddr("198.51.100.10")}

		name := uniqueRuleName("dnsfail")
		spec := allowTCP("5432")
		spec.From = &securityv1alpha1.EndpointSpec{Host: new("db.example.com")}
		createRule(name, spec)

		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		delete(resolver.Addrs, "db.example.com")
		resolver.Errs["db.example.com"] = errors.New("NXDOMAIN")
		reconciler.DefaultRefreshInterval = time.Nanosecond
		reconciler.MinRefreshInterval = time.Nanosecond

		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(1))
		Expect(host.snapshot()[0].rule.Command()).To(ContainSubstring("198.51.100.10"))

		status := fetchRule(name).Status.Nodes[nodeName]
		Expect(status.Degraded).To(BeTrue())
		Expect(status.Applied).To(BeTrue())
		Expect(status.Message).To(ContainSubstring("last known-good"))
	})

	It("retries DNS after a failure instead of serving the last-known-good cache", func() {
		resolver := reconciler.Resolver.(*dnsresolver.FakeResolver)
		resolver.Addrs["retry.example.com"] = []netip.Addr{netip.MustParseAddr("198.51.100.10")}

		name := uniqueRuleName("dnsretry")
		spec := allowTCP("443")
		spec.From = &securityv1alpha1.EndpointSpec{Host: new("retry.example.com")}
		createRule(name, spec)

		reconciler.DefaultRefreshInterval = 50 * time.Millisecond
		reconciler.MinRefreshInterval = 10 * time.Millisecond
		mustReconcile(reconciler, name)
		Expect(host.count()).To(Equal(1))

		delete(resolver.Addrs, "retry.example.com")
		resolver.Errs["retry.example.com"] = errors.New("NXDOMAIN")
		time.Sleep(80 * time.Millisecond)
		mustReconcile(reconciler, name)

		status := fetchRule(name).Status.Nodes[nodeName]
		Expect(status.Degraded).To(BeTrue())
		Expect(status.Message).To(ContainSubstring("last known-good"))

		// The next reconcile is only seconds later, well inside a one-hour
		// refresh interval. A degraded status must force a new lookup rather
		// than postponing recovery for the whole interval.
		reconciler.DefaultRefreshInterval = time.Hour
		reconciler.MinRefreshInterval = time.Second
		delete(resolver.Errs, "retry.example.com")
		resolver.Addrs["retry.example.com"] = []netip.Addr{netip.MustParseAddr("198.51.100.11")}
		mustReconcile(reconciler, name)

		Expect(host.snapshot()[0].rule.Command()).To(ContainSubstring("198.51.100.11"))
		status = fetchRule(name).Status.Nodes[nodeName]
		Expect(status.Degraded).To(BeFalse())
	})

	It("creates no rule when a hostname has never resolved", func() {
		resolver := reconciler.Resolver.(*dnsresolver.FakeResolver)
		resolver.Errs["never.example.com"] = errors.New("NXDOMAIN")

		name := uniqueRuleName("neversolved")
		spec := allowTCP("443")
		spec.From = &securityv1alpha1.EndpointSpec{Host: new("never.example.com")}
		createRule(name, spec)

		mustReconcile(reconciler, name)

		Expect(host.count()).To(Equal(0))
		status := fetchRule(name).Status.Nodes[nodeName]
		Expect(status.Degraded).To(BeTrue())
		Expect(status.Message).To(ContainSubstring("never.example.com"))
	})

	It("keeps per-node status isolated with server-side apply", func() {
		otherNodeName := "node-" + rand.String(6)
		newNode(otherNodeName, nil)
		otherReconciler := newReconciler(newFakeHost(true), otherNodeName)

		name := uniqueRuleName("twonodes")
		createRule(name, allowTCP("22"))

		mustReconcile(reconciler, name)
		mustReconcile(otherReconciler, name)

		status := fetchRule(name).Status.Nodes
		Expect(status).To(HaveKey(nodeName))
		Expect(status).To(HaveKey(otherNodeName))
	})

	It("refuses to delete a rule with no number or arguments", func() {
		err := reconciler.deleteEntry(ctx, ufw.Entry{})
		Expect(err).To(HaveOccurred())
		Expect(host.opsSnapshot()).To(BeEmpty())
	})

	It("maps node label changes to every rule on that node only", func() {
		first := uniqueRuleName("map1")
		second := uniqueRuleName("map2")
		createRule(first, allowTCP("22"))
		createRule(second, allowTCP("80"))

		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}}
		Expect(reconciler.mapNodeToRules(ctx, node)).To(HaveLen(2))

		foreign := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "some-other-node"}}
		Expect(reconciler.mapNodeToRules(ctx, foreign)).To(BeEmpty())
	})

	It("rejects invalid specs at the API server", func() {
		invalid := []securityv1alpha1.HostFirewallRuleSpec{
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := allowTCP("22")
				spec.From = &securityv1alpha1.EndpointSpec{
					CIDR: new("10.0.0.0/8"),
					Host: new("example.com"),
				}
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := allowTCP("22")
				spec.From = &securityv1alpha1.EndpointSpec{Port: "1024:2048"}
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := securityv1alpha1.HostFirewallRuleSpec{Action: securityv1alpha1.ActionLimit}
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := allowTCP("not-a-port")
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := securityv1alpha1.HostFirewallRuleSpec{
					Action:   securityv1alpha1.ActionAllow,
					Protocol: securityv1alpha1.ProtocolTCP,
					To:       &securityv1alpha1.ToSpec{},
				}
				for i := range 16 {
					spec.To.Ports = append(spec.To.Ports, securityv1alpha1.Port(strconv.Itoa(1000+i)))
				}
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := securityv1alpha1.HostFirewallRuleSpec{
					Action:   securityv1alpha1.ActionAllow,
					Protocol: securityv1alpha1.ProtocolTCP,
					To:       &securityv1alpha1.ToSpec{},
				}
				for i := range 8 {
					start := 1000 + i*10
					spec.To.Ports = append(spec.To.Ports,
						securityv1alpha1.Port(fmt.Sprintf("%d:%d", start, start+5)))
				}
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := allowTCP("22")
				spec.Comment = "it's not allowed"
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := allowTCP("22")
				spec.Comment = "first line\nsecond line"
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := allowTCP("22")
				spec.From = &securityv1alpha1.EndpointSpec{CIDR: new("not-a-cidr")}
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := allowTCP("22")
				spec.From = &securityv1alpha1.EndpointSpec{CIDR: new("10.0.0.0/33")}
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := allowTCP("22")
				spec.To.CIDR = new("2001:db8::/129")
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := allowTCP("22")
				spec.From = &securityv1alpha1.EndpointSpec{Host: new("bad host!")}
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				return allowTCP("70000")
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				return allowTCP("80:70")
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := allowTCP("22")
				spec.To.Port = "80"
				return spec
			}(),
			func() securityv1alpha1.HostFirewallRuleSpec {
				spec := allowTCP("22")
				spec.Interface = strings.Repeat("a", 16)
				return spec
			}(),
		}

		for i, spec := range invalid {
			rule := &securityv1alpha1.HostFirewallRule{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("invalid-%d-%s", i, rand.String(5)),
				},
				Spec: spec,
			}
			Expect(k8sClient.Create(ctx, rule)).NotTo(Succeed(), "case %d should be rejected", i)
		}
	})

	It("accepts ports that fit ufw's 15-entry limit", func() {
		singles := securityv1alpha1.HostFirewallRuleSpec{
			Action:   securityv1alpha1.ActionAllow,
			Protocol: securityv1alpha1.ProtocolTCP,
			To:       &securityv1alpha1.ToSpec{},
		}
		for i := range 15 {
			singles.To.Ports = append(singles.To.Ports, securityv1alpha1.Port(strconv.Itoa(1000+i)))
		}
		createRule(uniqueRuleName("fifteenports"), singles)

		// A range counts as two, so seven ranges plus one port is exactly 15.
		ranges := securityv1alpha1.HostFirewallRuleSpec{
			Action:   securityv1alpha1.ActionAllow,
			Protocol: securityv1alpha1.ProtocolTCP,
			To:       &securityv1alpha1.ToSpec{},
		}
		for i := range 7 {
			start := 2000 + i*10
			ranges.To.Ports = append(ranges.To.Ports,
				securityv1alpha1.Port(fmt.Sprintf("%d:%d", start, start+5)))
		}
		ranges.To.Ports = append(ranges.To.Ports, securityv1alpha1.Port("80"))
		createRule(uniqueRuleName("rangesandport"), ranges)
	})
})
