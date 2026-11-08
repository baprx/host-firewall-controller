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
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	token := ufw.TokenFor(cr.Name, string(cr.UID))

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
		// Another HostFirewallRule already provides this exact ufw rule, so
		// the node matches this CR's intent even though its marker is absent.
		if _, shared := result.Shared[marker]; shared {
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
	shared := sharedRuleMessage(result.Shared)
	if shared != "" {
		status.Message = joinMessages(status.Message, shared)
	}

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
		status.Message = joinMessages(status.Message, result.Err.Error())
	}

	return status
}

// sharedRuleMessage explains that some desired rules are already provided by
// another HostFirewallRule. Owners are deduplicated and sorted so the status
// does not churn between reconciles.
func sharedRuleMessage(shared map[string]string) string {
	if len(shared) == 0 {
		return ""
	}

	owners := make([]string, 0, len(shared))
	seen := map[string]struct{}{}
	for _, owner := range shared {
		if _, ok := seen[owner]; ok {
			continue
		}
		seen[owner] = struct{}{}
		owners = append(owners, owner)
	}
	slices.Sort(owners)

	subject := "rule already provided by another HostFirewallRule"
	if len(shared) > 1 {
		subject = fmt.Sprintf("%d rules already provided by other HostFirewallRules", len(shared))
	}
	return fmt.Sprintf("%s (%s)", subject, strings.Join(owners, ", "))
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

// statusSummary aggregates the per-node status into the single line exposed by
// the Applied printer column. The nodes map cannot be rendered by a column: the
// API server's table convertor reads one element of a wildcard JSONPath, which
// is an arbitrary node. The value is display-only and last-writer-wins between
// pods, so it can lag one reconcile during a transition and self-heals on the
// next one.
func statusSummary(nodes map[string]securityv1alpha1.NodeStatus) string {
	if len(nodes) == 0 {
		return ""
	}

	applied := 0
	degraded := 0
	for _, node := range nodes {
		if node.Applied {
			applied++
		}
		if node.Degraded {
			degraded++
		}
	}

	summary := fmt.Sprintf("%d/%d applied", applied, len(nodes))
	if degraded > 0 {
		summary += fmt.Sprintf(", %d degraded", degraded)
	}
	return summary
}

// summaryNodes returns the reported node statuses with this node's fresh entry
// replacing its previous one.
func summaryNodes(
	reported map[string]securityv1alpha1.NodeStatus,
	nodeName string,
	status securityv1alpha1.NodeStatus,
) map[string]securityv1alpha1.NodeStatus {
	nodes := make(map[string]securityv1alpha1.NodeStatus, len(reported)+1)
	maps.Copy(nodes, reported)
	nodes[nodeName] = status
	return nodes
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
			Name: cr.Name,
		},
		Status: securityv1alpha1.HostFirewallRuleStatus{
			Nodes: map[string]securityv1alpha1.NodeStatus{r.NodeName: status},
			// The apply body only owns this node's key, but the summary must
			// account for every node that has reported so far.
			Summary: statusSummary(summaryNodes(cr.Status.Nodes, r.NodeName, status)),
		},
	}

	// A rule that expands to nothing has no resolved addresses. NodeStatus's
	// Resolved field is a value struct, so omitempty never drops it, and the
	// JSON encoder emits "resolved": {}. When this manager previously owned
	// resolved.from, the API server turns that empty object into null, which the
	// CRD's structural schema rejects with 422. Omit the field from the apply
	// body instead: server-side apply then removes the subfields this manager
	// owned. This happens whenever a dynamic grant expires, its path changes, or
	// its path becomes ambiguous, so it is part of the normal lifecycle.
	if len(status.Resolved.From) == 0 && len(status.Resolved.To) == 0 {
		body, err := statusApplyBody(patch, r.NodeName)
		if err != nil {
			return err
		}
		return r.SubResource("status").Patch(ctx, patch,
			client.RawPatch(types.ApplyPatchType, body),
			client.FieldOwner(fieldManagerFor(r.NodeName)),
			client.ForceOwnership,
		)
	}

	return r.SubResource("status").Apply(ctx, patch,
		client.FieldOwner(fieldManagerFor(r.NodeName)),
		client.ForceOwnership,
	)
}

// statusApplyBody marshals an apply document and drops an empty resolved object
// for the given node. The CRD cannot store that object as null, and omission is
// the only way to remove it through server-side apply.
func statusApplyBody(
	patch *securityv1alpha1.HostFirewallRule,
	nodeName string,
) ([]byte, error) {
	raw, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}

	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}

	status, ok := document["status"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("status is not an object")
	}
	nodes, ok := status["nodes"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("status.nodes is not an object")
	}
	node, ok := nodes[nodeName].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("status.nodes[%q] is not an object", nodeName)
	}
	delete(node, "resolved")

	return json.Marshal(document)
}

// fieldManagerFor turns a node name into a field manager that fits the 128
// character limit regardless of node name length.
func fieldManagerFor(nodeName string) string {
	sum := sha256.Sum256([]byte(nodeName))
	return "hfc-" + hex.EncodeToString(sum[:])[:12]
}

// emitEvents records transitions worth surfacing to users. Repeating the same
// failure or degraded message on every reconcile (degraded hostname rules
// requeue every 30s) would spam the object, so only changes are emitted.
func (r *HostFirewallRuleReconciler) emitEvents(
	cr *securityv1alpha1.HostFirewallRule,
	status securityv1alpha1.NodeStatus,
	prev securityv1alpha1.NodeStatus,
	err error,
) {
	if r.Recorder == nil {
		return
	}

	if err != nil {
		if prev.Message == status.Message {
			return
		}
		r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, "ApplyFailed", "ApplyRule",
			"Node %s could not apply the rule: %v", r.NodeName, err)
		return
	}

	if status.CommentsUnsupported {
		if prev.CommentsUnsupported {
			return
		}
		r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, "CommentsUnsupported", "SkipAdds",
			"Node %s: ufw accepted the rule but does not report rule comments; refusing to add more rules", r.NodeName)
		return
	}

	if status.Degraded && (!prev.Degraded || prev.Message != status.Message) {
		r.Recorder.Eventf(cr, nil, corev1.EventTypeWarning, "Degraded", "Resolve",
			"Node %s: %s", r.NodeName, status.Message)
	}
}
