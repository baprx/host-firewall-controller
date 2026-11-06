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
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/baprx/host-firewall-controller/test/utils"
)

var (
	// managerImage is the image built and loaded into the kind cluster.
	managerImage = "ghcr.io/baprx/host-firewall-controller:e2e"
	// kindCluster is the kind cluster created by `make setup-test-e2e`.
	kindCluster = os.Getenv("KIND_CLUSTER")
	// containerCLI is the container runtime kind uses.
	containerCLI = "docker"
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting host-firewall-controller e2e test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	if provider := os.Getenv("KIND_EXPERIMENTAL_PROVIDER"); provider != "" {
		containerCLI = provider
	}

	By("building the manager image")
	cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", managerImage))
	output, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager image: %s", output)

	By("loading the manager image into the kind cluster")
	ExpectWithOffset(1, utils.LoadImageToKindClusterWithName(managerImage)).To(Succeed())

	By("installing ufw on every kind node")
	installUFWOnKindNodes()
})

// installUFWOnKindNodes installs ufw inside the kind node containers. The
// operator is designed to work while ufw is inactive, so ufw is installed but
// deliberately never enabled.
func installUFWOnKindNodes() {
	nodes := kindNodeNames()
	ExpectWithOffset(1, nodes).NotTo(BeEmpty(), "no kind nodes found")

	for _, node := range nodes {
		script := "set -e; " +
			"if ! command -v ufw >/dev/null 2>&1; then " +
			"apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ufw iptables; " +
			"fi; " +
			"if ! command -v curl >/dev/null 2>&1; then " +
			"apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl; " +
			"fi"
		cmd := exec.Command(containerCLI, "exec", node, "sh", "-c", script)
		output, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(),
			"Failed to install e2e prerequisites on node %s: %s", node, output)
	}
}

// kindNodeNames returns the node container names of the e2e cluster.
func kindNodeNames() []string {
	if kindCluster == "" {
		kindCluster = "host-firewall-controller-test-e2e"
	}

	cmd := exec.Command(containerCLI, "ps",
		"--filter", "label=io.x-k8s.kind.cluster="+kindCluster,
		"--format", "{{.Names}}")
	output, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to list kind nodes: %s", output)

	return utils.GetNonEmptyLines(strings.TrimSpace(output))
}
