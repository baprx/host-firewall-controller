//go:build e2e
// +build e2e

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

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/baprx/host-firewall-controller/internal/ufw"
	"github.com/baprx/host-firewall-controller/test/utils"
)

const (
	namespace   = "host-firewall-controller-system"
	releaseName = "hfc-e2e"
	daemonSet   = "hfc-e2e"
	ufwBinary   = "/usr/sbin/ufw"

	// controllerLockPath is the manager's host lock (--lock-path default for
	// hostRoot /host). Tests take it to freeze sweeps while observing ufw.
	controllerLockPath = "/run/host-firewall-controller.lock"
)

var (
	podName  string
	nodeName string
)

var _ = Describe("UFW rules on a kind node", Ordered, func() {
	var initialStatus string

	BeforeAll(func() {
		repository, tag := splitImage(managerImage)

		By("installing the Helm chart")
		install := exec.Command("helm", "upgrade", "--install", releaseName,
			"charts/host-firewall-controller",
			"--namespace", namespace,
			"--create-namespace",
			"--set", "fullnameOverride="+daemonSet,
			"--set", "image.repository="+repository,
			"--set", "image.tag="+tag,
			"--set", "image.pullPolicy=IfNotPresent",
			"--set", "sweepInterval=5s",
			"--set", "metrics.enabled=false",
			"--set", "knock.enabled=true",
		)
		output, err := utils.Run(install)
		Expect(err).NotTo(HaveOccurred(), "helm install failed: %s", output)

		By("waiting for the DaemonSet rollout")
		rollout := exec.Command("kubectl", "-n", namespace, "rollout", "status",
			"daemonset/"+daemonSet, "--timeout=180s")
		output, err = utils.Run(rollout)
		Expect(err).NotTo(HaveOccurred(), "DaemonSet did not roll out: %s", output)

		By("locating the operator pod and its node")
		podName = strings.TrimSpace(mustKubectl("get", "pods", "-n", namespace,
			"-l", "app.kubernetes.io/name=host-firewall-controller",
			"-o", "jsonpath={.items[0].metadata.name}"))
		Expect(podName).NotTo(BeEmpty())
		nodeName = strings.TrimSpace(mustKubectl("get", "pod", podName, "-n", namespace,
			"-o", "jsonpath={.spec.nodeName}"))

		By("recording the initial global ufw state")
		initialStatus = firstLine(ufwRun("status"))
		_, _ = fmt.Fprintf(GinkgoWriter,
			"node=%s pod=%s initial ufw status=%q\n", nodeName, podName, initialStatus)
	})

	AfterAll(func() {
		By("uninstalling the Helm chart")
		uninstall := exec.Command("helm", "uninstall", releaseName, "-n", namespace)
		_, _ = utils.Run(uninstall)

		By("removing the namespace and CRDs")
		_, _ = utils.Run(exec.Command("kubectl", "delete", "namespace", namespace,
			"--ignore-not-found", "--wait=false"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "-f",
			"charts/host-firewall-controller/crds", "--ignore-not-found"))
	})

	It("adds a rule, marks it as owned, and reports per-node status", func() {
		name := "e2e-allow-ssh"
		applyRule(name, `
  action: allow
  protocol: tcp
  comment: "e2e ssh"
  to:
    ports: ["2222"]
`)

		Eventually(func(g Gomega) {
			added := ufwRun("show", "added")
			g.Expect(added).To(ContainSubstring("2222"))
			g.Expect(added).To(ContainSubstring("HFC:" + name + ":"))
			g.Expect(added).To(ContainSubstring("e2e ssh"))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		Eventually(func(g Gomega) {
			status := nodeStatus(name, nodeName)
			g.Expect(status).NotTo(BeNil())
			g.Expect(status["applied"]).To(BeTrue())
			g.Expect(status["ufwVersion"]).NotTo(BeEmpty())
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	It("replaces a rule in place when its ports change", func() {
		name := "e2e-update"
		applyRule(name, `
  action: allow
  protocol: tcp
  to:
    ports: ["3333"]
`)

		Eventually(func(g Gomega) {
			g.Expect(ufwRun("show", "added")).To(ContainSubstring("3333"))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		applyRule(name, `
  action: allow
  protocol: tcp
  to:
    ports: ["3334"]
`)

		Eventually(func(g Gomega) {
			added := ufwRun("show", "added")
			g.Expect(added).To(ContainSubstring("3334"))
			g.Expect(added).NotTo(ContainSubstring("3333"))
			g.Expect(strings.Count(added, "HFC:"+name+":")).To(Equal(1))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	It("refuses to coalesce with an identical unmanaged rule", func() {
		const unmanagedPort = "9995"
		ufwRun("allow", "proto", "tcp", "to", "any", "port", unmanagedPort)

		name := "e2e-unmanaged-collision"
		applyRule(name, `
  action: allow
  protocol: tcp
  to:
    ports: ["9995"]
`)

		Eventually(func(g Gomega) {
			status := nodeStatus(name, nodeName)
			g.Expect(status).NotTo(BeNil())
			g.Expect(status["applied"]).To(BeFalse())
			g.Expect(status["degraded"]).To(BeTrue())
			g.Expect(status["message"]).To(ContainSubstring("refusing to modify"))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		added := ufwRun("show", "added")
		Expect(added).NotTo(ContainSubstring("HFC:" + name + ":"))
		Expect(added).To(ContainSubstring(unmanagedPort))

		ufwRun("delete", "allow", "proto", "tcp", "to", "any", "port", unmanagedPort)
	})

	It("repairs a deleted managed rule on the next sweep", func() {
		name := "e2e-drift-repair"
		applyRule(name, `
  action: allow
  protocol: tcp
  to:
    ports: ["9994"]
`)

		marker := "HFC:" + name + ":"
		Eventually(func(g Gomega) {
			g.Expect(ufwRun("show", "added")).To(ContainSubstring(marker))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		// Delete the rule while holding the controller's host lock. The sweep
		// takes that lock non-blocking, so it cannot repair the rule between the
		// deletion and the assertion. Without the lock the next sweep can land
		// in that window and the absence check races the repair.
		locked := nodeRun("flock", controllerLockPath, "sh", "-c",
			ufwBinary+" delete allow proto tcp to any port 9994 && "+
				ufwBinary+" show added")
		Expect(locked).NotTo(ContainSubstring(marker))

		Eventually(func(g Gomega) {
			g.Expect(ufwRun("show", "added")).To(ContainSubstring(marker))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	It("never deletes or edits an unmanaged rule", func() {
		const unmanagedPort = "9998"
		ufwRun("allow", "proto", "tcp", "to", "any", "port", unmanagedPort)

		name := "e2e-unmanaged"
		applyRule(name, `
  action: allow
  protocol: tcp
  to:
    ports: ["2223"]
`)

		Eventually(func(g Gomega) {
			g.Expect(ufwRun("show", "added")).To(ContainSubstring("2223"))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		mustKubectl("delete", "hfr", name)

		Eventually(func(g Gomega) {
			added := ufwRun("show", "added")
			g.Expect(added).NotTo(ContainSubstring("HFC:" + name + ":"))
			g.Expect(added).To(ContainSubstring(unmanagedPort))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		ufwRun("delete", "allow", "proto", "tcp", "to", "any", "port", unmanagedPort)
	})

	It("skips nodes that do not match the selector", func() {
		name := "e2e-selector-mismatch"
		applyRule(name, `
  action: allow
  protocol: tcp
  nodeSelector:
    matchLabels:
      e2e.example.com/absent: "true"
  to:
    ports: ["9997"]
`)

		Eventually(func(g Gomega) {
			status := nodeStatus(name, nodeName)
			g.Expect(status).NotTo(BeNil())
			g.Expect(status["message"]).To(ContainSubstring("does not match"))
		}, time.Minute, 2*time.Second).Should(Succeed())

		Expect(ufwRun("show", "added")).NotTo(ContainSubstring("HFC:" + name + ":"))
	})

	It("resolves a hostname to an address", func() {
		name := "e2e-dns"
		applyRule(name, `
  action: allow
  protocol: tcp
  from:
    host: localhost
  resolve:
    ipFamilies: ["IPv4"]
    refreshInterval: 30s
  to:
    ports: ["9996"]
`)

		Eventually(func(g Gomega) {
			added := ufwRun("show", "added")
			g.Expect(added).To(ContainSubstring("from 127.0.0.1"))
			g.Expect(added).To(ContainSubstring("9996"))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		Eventually(func(g Gomega) {
			status := nodeStatus(name, nodeName)
			g.Expect(status).NotTo(BeNil())
			g.Expect(status["applied"]).To(BeTrue())
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	It("applies a dynamic rule after an HTTP knock", func() {
		name := "e2e-dynamic"
		path := "/knock/e2e"
		applyRule(name, fmt.Sprintf(`
  action: allow
  protocol: tcp
  from:
    dynamic:
      path: %s
      ttl: 10m
  to:
    ports: ["4444"]
`, path))

		// Use loopback so ufw's default-deny policy cannot block the knock port.
		// The server sees 127.0.0.1 as the source and the rule must match it.
		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command(containerCLI, "exec", nodeName,
				"curl", "-fsS", "http://127.0.0.1:8082"+path))
			g.Expect(err).NotTo(HaveOccurred(), "curl failed: %s", out)
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		Eventually(func(g Gomega) {
			added := ufwRun("show", "added")
			g.Expect(added).To(ContainSubstring("HFC:" + name + ":"))
			g.Expect(added).To(ContainSubstring("4444"))
			g.Expect(added).To(ContainSubstring("127.0.0.1"))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		Eventually(func(g Gomega) {
			address := strings.TrimSpace(mustKubectl("get", "hfr", name,
				"-o", "jsonpath={.status.dynamic.address}"))
			g.Expect(address).To(Equal("127.0.0.1"))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	It("never changes the global ufw state", func() {
		Expect(firstLine(ufwRun("status"))).To(Equal(initialStatus))
	})
})

// nodeRun executes a command on this test's kind node. The manager image is
// distroless, so tools such as flock are only available on the node itself.
func nodeRun(args ...string) string {
	cmd := exec.Command(containerCLI, append([]string{"exec", nodeName}, args...)...)
	output, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		"%s failed: %s", strings.Join(cmd.Args, " "), output)
	return output
}

// ufwRun executes the host ufw inside the operator pod's node through the
// manager's built-in chroot helper.
func ufwRun(args ...string) string {
	kubectlArgs := append([]string{
		"exec", "-n", namespace, podName, "--", "/manager", ufw.SelfExecCommand,
		"/host", ufwBinary,
	}, args...)
	return mustKubectl(kubectlArgs...)
}

// nodeStatus returns this node's status entry for a rule.
func nodeStatus(ruleName, node string) map[string]any {
	raw := mustKubectl("get", "hfr", ruleName, "-o", "json")
	var object struct {
		Status struct {
			Nodes map[string]map[string]any `json:"nodes"`
		} `json:"status"`
	}
	ExpectWithOffset(1, json.Unmarshal([]byte(raw), &object)).To(Succeed())
	return object.Status.Nodes[node]
}

// applyRule creates or updates a cluster-scoped HostFirewallRule.
func applyRule(name, spec string) {
	manifest := fmt.Sprintf(`apiVersion: security.baprx.github.io/v1alpha1
kind: HostFirewallRule
metadata:
  name: %s
spec:
%s`, name, spec)

	file, err := os.CreateTemp("", "hfc-e2e-*.yaml")
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	ExpectWithOffset(1, os.WriteFile(file.Name(), []byte(manifest), 0o600)).To(Succeed())

	DeferCleanup(func() {
		_, _ = utils.Run(exec.Command("kubectl", "delete", "hfr", name,
			"--ignore-not-found"))
		_ = os.Remove(file.Name())
	})

	output, err := utils.Run(exec.Command("kubectl", "apply", "-f", file.Name()))
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "kubectl apply failed: %s", output)
}

func mustKubectl(args ...string) string {
	output, err := utils.Run(exec.Command("kubectl", args...))
	ExpectWithOffset(1, err).NotTo(HaveOccurred(),
		"kubectl %s failed: %s", strings.Join(args, " "), output)
	return output
}

func firstLine(output string) string {
	lines := strings.SplitN(strings.TrimSpace(output), "\n", 2)
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}

func splitImage(image string) (repository, tag string) {
	index := strings.LastIndex(image, ":")
	if index < 0 {
		return image, "latest"
	}
	return image[:index], image[index+1:]
}
