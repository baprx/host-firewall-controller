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
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
	"github.com/baprx/host-firewall-controller/internal/ufw"
)

// statusFor builds this node's status entry from the convergence result.
func (r *HostFirewallRuleReconciler) statusFor(
	cr *securityv1alpha1.HostFirewallRule,
	exp expansion,
	result convergeResult,
	prev securityv1alpha1.NodeStatus,
	matches bool,
) securityv1alpha1.NodeStatus {
	now := metav1.Time{Time: time.Now()}
	token := ufw.TokenFor(cr.Namespace, cr.Name, string(cr.UID))

	status := securityv1alpha1.NodeStatus{
		Generation:      cr.Generation,
		UFWVersion:      r.UFWVersion,
		UFWEnabled:      result.State.Enabled,
		Markers:         markersOf(exp.Rules, token),
		Resolved:        exp.Resolved,
		LastAppliedTime: &now,
		Degraded:        exp.Degraded || result.Err != nil,
		Message:         exp.Message,
	}

	markerPresent := 0
	present := 0
	for _, rule := range exp.Rules {
		marker := ufw.MarkerFor(token, rule).String()
		if result.State.Has(marker) {
			markerPresent++
			present++
			continue
		}
		// On ufw versions that do not report comments, the operator's own rule
		// is indistinguishable from an unmanaged one except by its match key.
		if prev.CommentsUnsupported && hasUnmarkedMatch(result.State, rule) {
			present++
		}
	}

	status.Applied = result.Err == nil && present == len(exp.Rules)

	// If ufw accepted rules but does not report our comments, keep the flag so
	// subsequent reconciles adopt the unmarked rules instead of duplicating
	// them. It clears as soon as a marker becomes visible again.
	status.CommentsUnsupported = (len(status.Markers) > 0 && markerPresent == 0 &&
		((result.Added > 0 && result.Err == nil) || prev.CommentsUnsupported))

	if !matches && status.Message == "" {
		status.Message = "Node does not match the rule's nodeSelector"
	}

	if result.Err != nil {
		status.Applied = false
		status.Message = joinMessages(exp.Message, result.Err.Error())
	}

	return status
}

func joinMessages(messages ...string) string {
	nonEmpty := make([]string, 0, len(messages))
	for _, message := range messages {
		if strings.TrimSpace(message) != "" {
			nonEmpty = append(nonEmpty, message)
		}
	}
	return strings.Join(nonEmpty, "; ")
}

// patchStatus writes only this node's status entry, using server-side apply so
// pods never overwrite each other's node entries.
func (r *HostFirewallRuleReconciler) patchStatus(
	ctx context.Context,
	cr *securityv1alpha1.HostFirewallRule,
	status securityv1alpha1.NodeStatus,
) error {
	patch := &securityv1alpha1.HostFirewallRule{
		TypeMeta: metav1.TypeMeta{
			APIVersion: securityv1alpha1.GroupVersion.String(),
			Kind:       "HostFirewallRule",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cr.Namespace,
			Name:      cr.Name,
		},
		Status: securityv1alpha1.HostFirewallRuleStatus{
			Nodes: map[string]securityv1alpha1.NodeStatus{r.NodeName: status},
		},
	}

	return r.SubResource("status").Apply(ctx, patch,
		client.FieldOwner(fieldManagerFor(r.NodeName)),
		client.ForceOwnership,
	)
}

// fieldManagerFor turns a node name into a field manager that fits the 128
// character limit regardless of node name length.
func fieldManagerFor(nodeName string) string {
	sum := sha256.Sum256([]byte(nodeName))
	return "hfc-" + hex.EncodeToString(sum[:])[:12]
}

// emitEvents records transitions worth surfacing to users.
func (r *HostFirewallRuleReconciler) emitEvents(
	cr *securityv1alpha1.HostFirewallRule,
	status securityv1alpha1.NodeStatus,
	err error,
) {
	if r.Recorder == nil {
		return
	}

	switch {
	case err != nil:
		r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, "ApplyFailed", "ApplyRule",
			"Node %s could not apply the rule: %v", r.NodeName, err)
	case status.CommentsUnsupported:
		r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, "CommentsUnsupported", "SkipAdds",
			"Node %s: ufw accepted the rule but does not report rule comments; refusing to add more rules", r.NodeName)
	case status.Degraded:
		r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, "Degraded", "Resolve",
			"Node %s: %s", r.NodeName, status.Message)
	}
}
