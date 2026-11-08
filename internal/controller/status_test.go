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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
)

var _ = Describe("statusSummary", func() {
	DescribeTable("aggregates the per-node status",
		func(nodes map[string]securityv1alpha1.NodeStatus, expected string) {
			Expect(statusSummary(nodes)).To(Equal(expected))
		},
		Entry("no node has reported yet", nil, ""),
		Entry("every node applied", map[string]securityv1alpha1.NodeStatus{
			"node-a": {Applied: true},
			"node-b": {Applied: true},
			"node-c": {Applied: true},
		}, "3/3 applied"),
		Entry("a degraded node is not applied", map[string]securityv1alpha1.NodeStatus{
			"node-a": {Applied: true},
			"node-b": {Applied: true},
			"node-c": {Degraded: true},
		}, "2/3 applied, 1 degraded"),
		Entry("a degraded node can still be applied", map[string]securityv1alpha1.NodeStatus{
			"node-a": {Applied: true},
			"node-b": {Applied: true},
			"node-c": {Applied: true, Degraded: true},
		}, "3/3 applied, 1 degraded"),
		Entry("no node applied", map[string]securityv1alpha1.NodeStatus{
			"node-a": {Degraded: true},
			"node-b": {Degraded: true},
		}, "0/2 applied, 2 degraded"),
	)
})

// fetchTable asks the API server for the table kubectl renders for one rule.
func fetchTable(name string) *metav1.Table {
	gv := securityv1alpha1.GroupVersion
	config := rest.CopyConfig(cfg)
	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()

	restClient, err := rest.RESTClientFor(config)
	Expect(err).NotTo(HaveOccurred())

	table := &metav1.Table{}
	err = restClient.Get().
		Resource("hostfirewallrules").
		Name(name).
		SetHeader("Accept", "application/json;as=Table;v=v1;g=meta.k8s.io").
		Do(ctx).Into(table)
	Expect(err).NotTo(HaveOccurred())
	return table
}

// tableCells maps each printer column to the single row's cell.
func tableCells(table *metav1.Table) map[string]any {
	Expect(table.Rows).To(HaveLen(1))
	cells := make(map[string]any, len(table.ColumnDefinitions))
	for i, column := range table.ColumnDefinitions {
		cells[column.Name] = table.Rows[0].Cells[i]
	}
	return cells
}
