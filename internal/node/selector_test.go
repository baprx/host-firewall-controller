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

package node

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testRoleKey = "role"

func TestMatches(t *testing.T) {
	t.Parallel()

	nodeLabels := map[string]string{
		testRoleKey:         "web",
		"kubernetes.io/os":  "linux",
		"topology.zone":     "a",
		"example.com/empty": "",
	}

	tests := []struct {
		name     string
		selector *metav1.LabelSelector
		want     bool
		wantErr  bool
	}{
		{name: "nil selector", selector: nil, want: true},
		{name: "empty selector", selector: &metav1.LabelSelector{}, want: true},
		{name: "matching label", selector: &metav1.LabelSelector{MatchLabels: map[string]string{testRoleKey: "web"}}, want: true},
		{name: "non matching label", selector: &metav1.LabelSelector{MatchLabels: map[string]string{testRoleKey: "db"}}, want: false},
		{name: "In expression", selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: testRoleKey, Operator: metav1.LabelSelectorOpIn, Values: []string{"web", "db"}},
		}}, want: true},
		{name: "NotIn expression", selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: testRoleKey, Operator: metav1.LabelSelectorOpNotIn, Values: []string{"db"}},
		}}, want: true},
		{name: "Exists expression", selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "topology.zone", Operator: metav1.LabelSelectorOpExists},
		}}, want: true},
		{name: "DoesNotExist expression", selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "absent", Operator: metav1.LabelSelectorOpDoesNotExist},
		}}, want: true},
		{name: "invalid operator", selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: testRoleKey, Operator: "Bogus"},
		}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Matches(tt.selector, nodeLabels)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Matches() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}
