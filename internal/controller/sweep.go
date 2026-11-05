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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
	"github.com/baprx/host-firewall-controller/internal/node"
	"github.com/baprx/host-firewall-controller/internal/ufw"
)

// ReconcileSweep makes the node converge all matching HostFirewallRules and
// removes every rule owned by the operator that is no longer desired by a live,
// matching CR. It is the periodic drift-repair path: non-hostname rules do not
// requeue, and informer resyncs are filtered out by the generation predicate.
func (r *HostFirewallRuleReconciler) ReconcileSweep(ctx context.Context) error {
	log := logf.FromContext(ctx).WithValues("node", r.NodeName)

	nodeObject, err := r.getNode(ctx)
	if err != nil {
		return err
	}

	var list securityv1alpha1.HostFirewallRuleList
	if err := r.List(ctx, &list); err != nil {
		return fmt.Errorf("list rules: %w", err)
	}

	// Re-fetch and expand every matching CR before touching ufw. The CR is
	// fetched again so a rule deleted between List and now cannot be
	// resurrected from the snapshot, and the whole node is checked against the
	// cap before any rule is added.
	type sweepTarget struct {
		cr       securityv1alpha1.HostFirewallRule
		token    string
		rules    []ufw.Rule
		exp      expansion
		prev     securityv1alpha1.NodeStatus
		comments bool
	}
	var targets []sweepTarget
	var errs []error
	ruleCount := 0
	for i := range list.Items {
		cr := &list.Items[i]
		key := types.NamespacedName{Name: cr.Name}

		var current securityv1alpha1.HostFirewallRule
		if err := r.Get(ctx, key, &current); err != nil {
			if !apierrors.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("get rule %s: %w", key, err))
			}
			continue
		}

		matches, err := node.Matches(current.Spec.NodeSelector, nodeObject.Labels)
		if err != nil || !matches {
			continue
		}

		prev := current.Status.Nodes[r.NodeName]
		exp := r.expand(ctx, &current, prev)
		targets = append(targets, sweepTarget{
			cr:       current,
			token:    ufw.TokenFor(current.Name, string(current.UID)),
			rules:    exp.Rules,
			exp:      exp,
			prev:     prev,
			comments: prev.CommentsUnsupported,
		})
		ruleCount += len(exp.Rules)
	}

	if r.MaxRulesPerNode > 0 && ruleCount > r.MaxRulesPerNode {
		err := fmt.Errorf("node would need %d rules, above the configured maximum of %d",
			ruleCount, r.MaxRulesPerNode)
		log.Error(err, "Refusing to converge")
		return errors.Join(append(errs, err)...)
	}

	// Reconcile each CR through the normal convergence path. This repairs
	// drift (not only stale rules) and reuses the collision and add-failure
	// safeguards.
	for _, target := range targets {
		result := r.converge(ctx, target.token, target.rules, target.comments)
		if result.Err != nil {
			errs = append(errs, result.Err)
		}

		// The sweep repairs drift that no reconcile will report, so it must
		// publish the resulting status itself. A CR deleted while the sweep
		// runs has no status to update.
		status := r.statusFor(&target.cr, target.exp, result, target.prev, true)
		// lastAppliedTime also gates the hostname resolution cache, so a sweep
		// that changed nothing must leave it alone.
		if result.Added == 0 && result.Deleted == 0 {
			status.LastAppliedTime = target.prev.LastAppliedTime
		}
		if err := r.patchStatus(ctx, &target.cr, status); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("patch status for rule %s: %w",
				target.cr.Name, err))
		}
	}

	// Compute the expected set again after convergence. A CR deleted while the
	// loop was running must not keep its just-added rules until the next sweep.
	expected, ruleCount, err := r.expectedRules(ctx, nodeObject.Labels)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}

	if r.MaxRulesPerNode > 0 && ruleCount > r.MaxRulesPerNode {
		err := fmt.Errorf("node would need %d rules, above the configured maximum of %d",
			ruleCount, r.MaxRulesPerNode)
		log.Error(err, "Refusing to prune")
		return errors.Join(append(errs, err)...)
	}

	// The delete phase is only safe when every rule converged. If a CR could
	// not be fetched or an add failed or was refused, pruning would delete the
	// last working rule (and rules of a CR that was only transiently
	// unreadable) instead of keeping the previous configuration.
	if len(errs) > 0 {
		log.Error(errors.Join(errs...), "Skipping prune because convergence failed")
		return errors.Join(errs...)
	}

	pruneErr := r.withLock(func() error {
		state, err := r.readState(ctx)
		if err != nil {
			return err
		}

		counts := map[string]int{}
		for _, entry := range state.Entries {
			counts[entry.Marker.String()]++
		}

		targets := map[string]int{}
		for marker, count := range counts {
			rule, ok := expected[marker]
			if !ok {
				targets[marker] = -1
				continue
			}
			if want := expectedFamilyCount(rule, state); count > want {
				targets[marker] = count - want
			}
		}

		if len(targets) > 0 {
			if _, err := r.pruneMarkers(ctx, targets); err != nil {
				return err
			}
		}

		if fresh, err := r.readState(ctx); err == nil {
			managedRules.Set(float64(len(fresh.Entries)))
		}
		return nil
	})
	if pruneErr != nil {
		errs = append(errs, pruneErr)
	}

	return errors.Join(errs...)
}

// expectedRules lists the concrete markers and rules every CR matching this node
// wants. It is recomputed after convergence so a CR deleted mid-sweep cannot
// leave rules behind.
func (r *HostFirewallRuleReconciler) expectedRules(
	ctx context.Context,
	nodeLabels map[string]string,
) (map[string]ufw.Rule, int, error) {
	var fresh securityv1alpha1.HostFirewallRuleList
	if err := r.List(ctx, &fresh); err != nil {
		return nil, 0, fmt.Errorf("list rules: %w", err)
	}

	expected := map[string]ufw.Rule{}
	count := 0
	for i := range fresh.Items {
		cr := &fresh.Items[i]

		matches, err := node.Matches(cr.Spec.NodeSelector, nodeLabels)
		if err != nil || !matches {
			continue
		}

		prev := cr.Status.Nodes[r.NodeName]
		exp := r.expand(ctx, cr, prev)

		token := ufw.TokenFor(cr.Name, string(cr.UID))
		for _, rule := range exp.Rules {
			expected[ufw.MarkerFor(token, rule).String()] = rule
			count++
		}
	}
	return expected, count, nil
}
