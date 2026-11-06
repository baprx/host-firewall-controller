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
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
)

const (
	dynamicWaitingMessage  = "Waiting for a knock on %s"
	dynamicMismatchMessage = "Dynamic grant does not match the current spec"
	dynamicExpiredMessage  = "Dynamic grant expired"
)

// dynamicAddress returns the address a dynamic endpoint currently applies. ok is
// false when the endpoint has no usable grant; message explains why.
func dynamicAddress(
	cr *securityv1alpha1.HostFirewallRule,
	now time.Time,
) (address, message string, requeue time.Duration, ok bool) {
	side, dynamic := cr.Spec.DynamicEndpoint()
	if dynamic == nil {
		return "", "", 0, false
	}

	grant := cr.Status.Dynamic
	if grant == nil {
		return "", fmt.Sprintf(dynamicWaitingMessage, dynamic.Path), 0, false
	}
	if grant.Path != dynamic.Path || grant.Side != side {
		return "", dynamicMismatchMessage, 0, false
	}

	addr, err := netip.ParseAddr(grant.Address)
	if err != nil || addr.IsUnspecified() {
		// Fail closed: a malformed or "any" grant must never widen the rule.
		return "", dynamicMismatchMessage, 0, false
	}

	if grant.ExpiresAt != nil && !now.Before(grant.ExpiresAt.Time) {
		return "", dynamicExpiredMessage, 0, false
	}
	if grant.ExpiresAt != nil {
		return addr.String(), "", grant.ExpiresAt.Sub(now), true
	}
	return addr.String(), "", 0, true
}

// dynamicGrantChanged wakes every pod when the cluster-wide grant changes.
// GenerationChangedPredicate already handles create/delete, so only Update can
// return true here. Ordinary per-node status.nodes writes must not match.
func dynamicGrantChanged() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return false },
		DeleteFunc:  func(event.DeleteEvent) bool { return false },
		GenericFunc: func(event.GenericEvent) bool { return false },
		UpdateFunc: func(ev event.UpdateEvent) bool {
			oldRule, ok := ev.ObjectOld.(*securityv1alpha1.HostFirewallRule)
			if !ok {
				return false
			}
			newRule, ok := ev.ObjectNew.(*securityv1alpha1.HostFirewallRule)
			if !ok {
				return false
			}
			return !equality.Semantic.DeepEqual(oldRule.Status.Dynamic, newRule.Status.Dynamic)
		},
	}
}

// clearDynamicGrant removes status.dynamic with a JSON patch that tests the
// exact grant first. A knock that lands between the fetch and this call changes
// the grant, the test fails, and the newer grant is left untouched.
//
// Losing that test is routine, not an error: every pod watches status.dynamic
// and requeues at the same TTL boundary, so when a grant expires one pod clears
// it and the others arrive with a stale copy. The API rejects their test step
// with 422 Invalid, which must not count as a reconcile failure (it would
// increment the error metric and make a sweep skip pruning). Return nil: the
// winning grant, if any, is already in the API and the next reconcile expands
// it. A NotFound means the rule itself is gone, which is equally benign.
//
// The 422 is the precise signal here. The patch body is built from a typed
// grant, so the API can only reject it because the test operation no longer
// matches. Re-fetching the rule instead is not reliable: this reconciler's
// Client is the manager cache and may still serve the stale grant right after
// the API rejected the test.
func (r *HostFirewallRuleReconciler) clearDynamicGrant(
	ctx context.Context,
	cr *securityv1alpha1.HostFirewallRule,
) error {
	grant, err := json.Marshal(cr.Status.Dynamic)
	if err != nil {
		return err
	}
	body := fmt.Sprintf(
		`[{"op":"test","path":"/status/dynamic","value":%s},{"op":"remove","path":"/status/dynamic"}]`,
		grant,
	)
	if err := r.SubResource("status").Patch(ctx, cr,
		client.RawPatch(types.JSONPatchType, []byte(body))); err != nil {
		if apierrors.IsInvalid(err) || apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

// clearStaleDynamicGrant removes a grant that no longer applies: a missing
// dynamic endpoint, a path or side change, an invalid address, or an expiry.
func (r *HostFirewallRuleReconciler) clearStaleDynamicGrant(
	ctx context.Context,
	cr *securityv1alpha1.HostFirewallRule,
) error {
	grant := cr.Status.Dynamic
	if grant == nil {
		return nil
	}

	side, dynamic := cr.Spec.DynamicEndpoint()
	if dynamic != nil && grant.Path == dynamic.Path && grant.Side == side {
		if addr, err := netip.ParseAddr(grant.Address); err == nil && !addr.IsUnspecified() {
			if grant.ExpiresAt == nil || time.Now().Before(grant.ExpiresAt.Time) {
				return nil
			}
		}
	}

	if err := r.clearDynamicGrant(ctx, cr); err != nil {
		return err
	}
	cr.Status.Dynamic = nil
	return nil
}

// dynamicPathAmbiguous reports whether more than one rule binds the same knock
// path. Ambiguous paths fail closed: no dynamic rule is applied for them.
func (r *HostFirewallRuleReconciler) dynamicPathAmbiguous(
	ctx context.Context,
	path string,
) (bool, error) {
	var list securityv1alpha1.HostFirewallRuleList
	if err := r.List(ctx, &list); err != nil {
		return false, fmt.Errorf("list rules: %w", err)
	}

	count := 0
	for i := range list.Items {
		_, dynamic := list.Items[i].Spec.DynamicEndpoint()
		if dynamic != nil && dynamic.Path == path {
			count++
		}
	}
	return count > 1, nil
}
