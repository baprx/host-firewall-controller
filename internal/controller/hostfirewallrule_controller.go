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
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
	"github.com/baprx/host-firewall-controller/internal/dnsresolver"
	"github.com/baprx/host-firewall-controller/internal/node"
	"github.com/baprx/host-firewall-controller/internal/ufw"
)

// HostFirewallRuleReconciler reconciles a HostFirewallRule object on one node.
type HostFirewallRuleReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	// NodeName is the node this manager runs on (downward API).
	NodeName string
	// Ufw executes the host ufw binary.
	Ufw ufw.Runner
	// Locker takes the host-wide ufw lock.
	Locker func() (func() error, error)
	// Resolver resolves FQDN endpoints.
	Resolver dnsresolver.Resolver

	SweepInterval          time.Duration
	DefaultRefreshInterval time.Duration
	MinRefreshInterval     time.Duration
	MaxRulesPerNode        int
	MaxRulesPerCR          int
	MaxAddresses           int
	UFWVersion             string
	DryRun                 bool

	// mu serializes every ufw batch in this process.
	mu sync.Mutex
}

// +kubebuilder:rbac:groups=security.baprx.github.io,resources=hostfirewallrules,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.baprx.github.io,resources=hostfirewallrules/status,verbs=get;patch;update
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile converges the ufw rules of one HostFirewallRule on this node.
func (r *HostFirewallRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("node", r.NodeName, "rule", req.Name)

	var cr securityv1alpha1.HostFirewallRule
	if err := r.Get(ctx, req.NamespacedName, &cr); err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("Rule was deleted, pruning orphaned ufw rules")
			return ctrl.Result{}, r.ReconcileSweep(ctx)
		}
		return ctrl.Result{}, err
	}

	nodeObject, err := r.getNode(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}

	prev := cr.Status.Nodes[r.NodeName]
	matches, selectorErr := node.Matches(cr.Spec.NodeSelector, nodeObject.Labels)
	if selectorErr != nil {
		status := prev
		status.Generation = cr.Generation
		status.Applied = false
		status.Degraded = true
		status.Message = fmt.Sprintf("Invalid nodeSelector: %v", selectorErr)
		status.LastAppliedTime = &metav1.Time{Time: time.Now()}
		if err := r.patchStatus(ctx, &cr, status); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, selectorErr
	}

	token := ufw.TokenFor(cr.Name, string(cr.UID))

	exp := expansion{}
	if !matches {
		exp.Message = "Node does not match the rule's nodeSelector"
	} else {
		exp = r.expand(ctx, &cr, prev)
	}

	// Clear a stale grant for every rule, before the max-rules check can
	// return early. exp is kept from before the clear so an expired or
	// mismatched grant still explains the per-node status.
	clearErr := r.clearStaleDynamicGrant(ctx, &cr)

	if matches && r.MaxRulesPerNode > 0 {
		total, err := r.nodeRuleCount(ctx, &cr, exp.Rules, nodeObject.Labels)
		if err != nil {
			return ctrl.Result{}, err
		}
		if total > r.MaxRulesPerNode {
			status := prev
			status.Generation = cr.Generation
			status.Applied = false
			status.Degraded = true
			status.UFWVersion = r.UFWVersion
			status.LastAppliedTime = &metav1.Time{Time: time.Now()}
			status.Message = fmt.Sprintf("Rules matching this node would need %d rules, above the node maximum of %d",
				total, r.MaxRulesPerNode)
			if err := r.patchStatus(ctx, &cr, status); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, fmt.Errorf("%s", status.Message)
		}
	}

	result := r.converge(ctx, token, exp.Rules, prev.CommentsUnsupported)

	status := r.statusFor(&cr, exp, result, prev, matches)
	if err := r.patchStatus(ctx, &cr, status); err != nil {
		return ctrl.Result{}, err
	}

	r.emitEvents(&cr, status, prev, result.Err)

	if err := errors.Join(result.Err, clearErr); err != nil {
		reconcileErrors.Inc()
		return ctrl.Result{}, err
	}
	if exp.RequeueAfter > 0 {
		return ctrl.Result{RequeueAfter: exp.RequeueAfter}, nil
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *HostFirewallRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.HostFirewallRule{}, builder.WithPredicates(predicate.Or(
			predicate.GenerationChangedPredicate{},
			dynamicGrantChanged(),
		))).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.mapNodeToRules), builder.WithPredicates(nodeLabelsChanged())).
		Named("hostfirewallrule").
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// nodeRuleCount counts the unique concrete rules every matching CR would add
// to this node, including the CR being reconciled. The cap must apply to the
// whole node, not just one CR, otherwise N CRs can each stay under the limit.
func (r *HostFirewallRuleReconciler) nodeRuleCount(
	ctx context.Context,
	current *securityv1alpha1.HostFirewallRule,
	currentRules []ufw.Rule,
	nodeLabels map[string]string,
) (int, error) {
	markers := map[string]struct{}{}
	add := func(cr *securityv1alpha1.HostFirewallRule, rules []ufw.Rule) {
		token := ufw.TokenFor(cr.Name, string(cr.UID))
		for _, rule := range rules {
			markers[ufw.MarkerFor(token, rule).String()] = struct{}{}
		}
	}
	add(current, currentRules)

	var list securityv1alpha1.HostFirewallRuleList
	if err := r.List(ctx, &list); err != nil {
		return 0, fmt.Errorf("list rules: %w", err)
	}

	for i := range list.Items {
		cr := &list.Items[i]
		if cr.UID == current.UID {
			continue
		}
		matches, err := node.Matches(cr.Spec.NodeSelector, nodeLabels)
		if err != nil || !matches {
			continue
		}
		prev := cr.Status.Nodes[r.NodeName]
		add(cr, r.expand(ctx, cr, prev).Rules)
	}
	return len(markers), nil
}

// getNode returns the Node object this manager runs on.
func (r *HostFirewallRuleReconciler) getNode(ctx context.Context) (*corev1.Node, error) {
	var nodeObject corev1.Node
	if err := r.Get(ctx, types.NamespacedName{Name: r.NodeName}, &nodeObject); err != nil {
		return nil, fmt.Errorf("get node %q: %w", r.NodeName, err)
	}
	return &nodeObject, nil
}

// mapNodeToRules re-reconciles every rule when this node's labels change, since
// label changes alter which rules apply.
func (r *HostFirewallRuleReconciler) mapNodeToRules(ctx context.Context, object client.Object) []reconcile.Request {
	if object.GetName() != r.NodeName {
		return nil
	}

	var list securityv1alpha1.HostFirewallRuleList
	if err := r.List(ctx, &list); err != nil {
		logf.FromContext(ctx).Error(err, "Could not list rules after node label change")
		return nil
	}

	requests := make([]reconcile.Request, 0, len(list.Items))
	for _, item := range list.Items {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{
			Name: item.Name,
		}})
	}
	return requests
}

func nodeLabelsChanged() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return false },
		DeleteFunc:  func(event.DeleteEvent) bool { return false },
		GenericFunc: func(event.GenericEvent) bool { return false },
		UpdateFunc: func(ev event.UpdateEvent) bool {
			oldNode, ok := ev.ObjectOld.(*corev1.Node)
			if !ok {
				return false
			}
			newNode, ok := ev.ObjectNew.(*corev1.Node)
			if !ok {
				return false
			}
			return !equalStringMaps(oldNode.Labels, newNode.Labels)
		},
	}
}

func equalStringMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

// withLock serializes ufw access in this process and across pods via flock.
func (r *HostFirewallRuleReconciler) withLock(fn func() error) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.Locker != nil {
		release, err := r.Locker()
		if err != nil {
			return fmt.Errorf("acquire ufw lock: %w", err)
		}
		defer func() { _ = release() }()
	}

	return fn()
}
