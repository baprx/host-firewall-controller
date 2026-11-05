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
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
	"github.com/baprx/host-firewall-controller/internal/ufw"
)

const (
	defaultRefreshInterval = 5 * time.Minute
	defaultMinInterval     = 30 * time.Second
	defaultMaxAddresses    = 16
	defaultMaxRulesPerCR   = 64
)

// expansion is the result of turning one logical rule into concrete ufw rules
// for this node.
type expansion struct {
	Rules        []ufw.Rule
	Resolved     securityv1alpha1.ResolvedAddresses
	Degraded     bool
	Message      string
	RequeueAfter time.Duration
}

func (r *HostFirewallRuleReconciler) refreshInterval(cr *securityv1alpha1.HostFirewallRule) time.Duration {
	interval := r.DefaultRefreshInterval
	if interval <= 0 {
		interval = defaultRefreshInterval
	}
	if cr.Spec.Resolve != nil && cr.Spec.Resolve.RefreshInterval != nil {
		interval = cr.Spec.Resolve.RefreshInterval.Duration
	}

	minInterval := r.MinRefreshInterval
	if minInterval <= 0 {
		minInterval = defaultMinInterval
	}
	if interval < minInterval {
		interval = minInterval
	}
	return interval
}

func (r *HostFirewallRuleReconciler) familiesFor(cr *securityv1alpha1.HostFirewallRule) []securityv1alpha1.IPFamily {
	if cr.Spec.Resolve != nil && len(cr.Spec.Resolve.IPFamilies) > 0 {
		return cr.Spec.Resolve.IPFamilies
	}
	return []securityv1alpha1.IPFamily{securityv1alpha1.IPv4, securityv1alpha1.IPv6}
}

func (r *HostFirewallRuleReconciler) maxAddressesFor(cr *securityv1alpha1.HostFirewallRule) int {
	if cr.Spec.Resolve != nil && cr.Spec.Resolve.MaxAddresses != nil {
		return int(*cr.Spec.Resolve.MaxAddresses)
	}
	if r.MaxAddresses > 0 {
		return r.MaxAddresses
	}
	return defaultMaxAddresses
}

func (r *HostFirewallRuleReconciler) maxRulesPerCR() int {
	if r.MaxRulesPerCR > 0 {
		return r.MaxRulesPerCR
	}
	return defaultMaxRulesPerCR
}

// expand turns the CR into the set of concrete rules this node should have.
func (r *HostFirewallRuleReconciler) expand(
	ctx context.Context,
	cr *securityv1alpha1.HostFirewallRule,
	prev securityv1alpha1.NodeStatus,
) expansion {
	token := ufw.TokenFor(cr.Name, string(cr.UID))
	interval := r.refreshInterval(cr)
	maxAddresses := r.maxAddressesFor(cr)
	families := r.familiesFor(cr)

	out := expansion{RequeueAfter: interval}
	var messages []string

	fromAddrs, fromDegraded, fromMessage, fromRequeue := r.resolveEndpoint(
		ctx, cr, cr.Spec.From, prev.Resolved.From, prev, interval, families, maxAddresses,
	)
	if fromMessage != "" {
		messages = append(messages, fromMessage)
	}
	if fromDegraded {
		out.Degraded = true
	}
	if fromRequeue > 0 && fromRequeue < out.RequeueAfter {
		out.RequeueAfter = fromRequeue
	}

	toAddrs, toDegraded, toMessage, toRequeue := r.resolveEndpoint(
		ctx, cr, toEndpoint(cr.Spec.To), prev.Resolved.To, prev, interval, families, maxAddresses,
	)
	if toMessage != "" {
		messages = append(messages, toMessage)
	}
	if toDegraded {
		out.Degraded = true
	}
	if toRequeue > 0 && toRequeue < out.RequeueAfter {
		out.RequeueAfter = toRequeue
	}

	if len(fromAddrs) == 0 || len(toAddrs) == 0 {
		out.Message = strings.Join(messages, "; ")
		return out
	}

	seen := map[string]struct{}{}
	for _, from := range fromAddrs {
		for _, to := range toAddrs {
			rule := buildRule(cr, from, to)
			rule.Comment = ufw.ComposeComment(ufw.MarkerFor(token, rule), cr.Spec.Comment)

			key := rule.Comment
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out.Rules = append(out.Rules, rule)
		}
	}

	if capRules := r.maxRulesPerCR(); len(out.Rules) > capRules {
		out.Rules = out.Rules[:capRules]
		out.Degraded = true
		messages = append(messages, fmt.Sprintf("Rule expansion exceeded %d rules and was truncated", capRules))
	}

	out.Resolved = securityv1alpha1.ResolvedAddresses{
		From: uniqueStrings(fromAddrs),
		To:   uniqueStrings(toAddrs),
	}
	out.Message = strings.Join(messages, "; ")

	// Only hostname rules need periodic re-resolution.
	if !hasHostname(cr.Spec.From) && !hasHostname(toEndpoint(cr.Spec.To)) {
		out.RequeueAfter = 0
	}

	return out
}

func hasHostname(spec *securityv1alpha1.EndpointSpec) bool {
	return spec != nil && spec.Host != nil && *spec.Host != ""
}

func toEndpoint(spec *securityv1alpha1.ToSpec) *securityv1alpha1.EndpointSpec {
	if spec == nil {
		return nil
	}
	return &spec.EndpointSpec
}

func buildRule(cr *securityv1alpha1.HostFirewallRule, from, to string) ufw.Rule {
	rule := ufw.Rule{
		Action:    ufw.Action(cr.Spec.Action),
		Direction: ufw.Direction(cr.Spec.Direction),
		Protocol:  ufw.Protocol(cr.Spec.Protocol),
		Interface: cr.Spec.Interface,
		Log:       cr.Spec.Log,
		Prepend:   cr.Spec.Prepend,
	}

	if from != "" {
		rule.From.Address = from
	}
	if cr.Spec.From != nil {
		rule.From.Port = string(cr.Spec.From.Port)
	}

	if to != "" {
		rule.To.Address = to
	}
	if cr.Spec.To != nil {
		if len(cr.Spec.To.Ports) > 0 {
			for _, port := range cr.Spec.To.Ports {
				rule.ToPorts = append(rule.ToPorts, string(port))
			}
		} else {
			rule.To.Port = string(cr.Spec.To.Port)
		}
	}

	return rule
}

// resolveEndpoint returns the addresses an endpoint expands to. The empty
// address means "any".
func (r *HostFirewallRuleReconciler) resolveEndpoint(
	ctx context.Context,
	cr *securityv1alpha1.HostFirewallRule,
	spec *securityv1alpha1.EndpointSpec,
	prevAddrs []string,
	prev securityv1alpha1.NodeStatus,
	interval time.Duration,
	families []securityv1alpha1.IPFamily,
	maxAddresses int,
) (addrs []string, degraded bool, message string, requeue time.Duration) {
	if spec == nil {
		return []string{""}, false, "", interval
	}
	if spec.CIDR != nil && *spec.CIDR != "" {
		return []string{*spec.CIDR}, false, "", interval
	}
	if spec.Host == nil || *spec.Host == "" {
		return []string{""}, false, "", interval
	}

	host := *spec.Host
	if prev.Generation == cr.Generation && !prev.Degraded && prev.LastAppliedTime != nil &&
		time.Since(prev.LastAppliedTime.Time) < interval && len(prevAddrs) > 0 {
		return prevAddrs, false, "", interval
	}

	resolved, err := r.Resolver.LookupHost(ctx, host)
	if err != nil {
		resolutionFailures.Inc()
		message = fmt.Sprintf("Could not resolve %q: %v", host, err)
		if len(prevAddrs) > 0 {
			return prevAddrs, true, message + ", keeping last known-good addresses", shorter(interval)
		}
		return nil, true, message, shorter(interval)
	}

	filtered := filterFamilies(resolved, families)
	if len(filtered) > maxAddresses {
		filtered = filtered[:maxAddresses]
		degraded = true
		message = fmt.Sprintf("Hostname %q resolved to more than %d addresses; using the first %d",
			host, maxAddresses, maxAddresses)
	}

	if len(filtered) == 0 {
		resolutionFailures.Inc()
		msg := fmt.Sprintf("Hostname %q resolved to no usable address", host)
		if len(prevAddrs) > 0 {
			return prevAddrs, true, msg + ", keeping last known-good addresses", shorter(interval)
		}
		return nil, true, msg, shorter(interval)
	}

	out := make([]string, 0, len(filtered))
	for _, addr := range filtered {
		out = append(out, addr.String())
	}

	requeue = interval
	if degraded && requeue > shorter(interval) {
		requeue = shorter(interval)
	}
	return out, degraded, message, requeue
}

// filterFamilies keeps the addresses of the requested families.
func filterFamilies(addrs []netip.Addr, families []securityv1alpha1.IPFamily) []netip.Addr {
	wantV4, wantV6 := false, false
	for _, family := range families {
		switch family {
		case securityv1alpha1.IPv4:
			wantV4 = true
		case securityv1alpha1.IPv6:
			wantV6 = true
		}
	}
	if !wantV4 && !wantV6 {
		wantV4, wantV6 = true, true
	}

	out := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if addr.Is4() && wantV4 {
			out = append(out, addr)
		}
		if addr.Is6() && !addr.Is4() && wantV6 {
			out = append(out, addr)
		}
	}
	return out
}

func shorter(interval time.Duration) time.Duration {
	limit := defaultMinInterval
	if interval < limit {
		return interval
	}
	return limit
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

// markersOf returns the sorted ownership markers of a rule set.
func markersOf(rules []ufw.Rule, token string) []string {
	markers := make([]string, 0, len(rules))
	for _, rule := range rules {
		markers = append(markers, ufw.MarkerFor(token, rule).String())
	}
	slices.Sort(markers)
	return markers
}
