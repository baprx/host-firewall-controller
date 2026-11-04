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

// Package node evaluates a rule's node selector against this node's labels.
package node

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Matches reports whether the selector matches the given labels. A nil or empty
// selector matches every node.
func Matches(selector *metav1.LabelSelector, nodeLabels map[string]string) (bool, error) {
	if selector == nil {
		return true, nil
	}

	compiled, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false, err
	}

	return compiled.Matches(labels.Set(nodeLabels)), nil
}
