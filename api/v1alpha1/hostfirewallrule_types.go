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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Action is a ufw rule action.
// +kubebuilder:validation:Enum=allow;deny;reject;limit
type Action string

const (
	ActionAllow  Action = "allow"
	ActionDeny   Action = "deny"
	ActionReject Action = "reject"
	ActionLimit  Action = "limit"
)

// Direction is the traffic direction a rule applies to.
// +kubebuilder:validation:Enum=in;out
type Direction string

const (
	DirectionIn  Direction = "in"
	DirectionOut Direction = "out"
)

// Protocol is the layer 4 protocol of a rule.
// +kubebuilder:validation:Enum=tcp;udp;any
type Protocol string

const (
	ProtocolAny Protocol = "any"
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// IPFamily selects which resolved addresses are turned into rules.
// +kubebuilder:validation:Enum=IPv4;IPv6
type IPFamily string

const (
	IPv4 IPFamily = "IPv4"
	IPv6 IPFamily = "IPv6"
)

// Port is a single port or a "start:end" range.
// +kubebuilder:validation:MaxLength=11
// +kubebuilder:validation:Pattern=`^[0-9]{1,5}(:[0-9]{1,5})?$`
// +kubebuilder:validation:XValidation:rule="int(self.split(':')[0]) <= 65535 && (self.split(':').size() == 1 || int(self.split(':')[1]) <= 65535)",message="port must be between 0 and 65535"
// +kubebuilder:validation:XValidation:rule="self.split(':').size() == 1 || int(self.split(':')[0]) <= int(self.split(':')[1])",message="port range start must not exceed its end"
type Port string

// SecretKeyRef points at one key in a Secret in the operator namespace.
type SecretKeyRef struct {
	// name is the Secret name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// key is the key inside the Secret.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key"`
}

// DynamicEndpointSpec turns one endpoint into an HTTP-triggered address.
type DynamicEndpointSpec struct {
	// path is the exact request path, for example /knock/home. Query strings
	// and fragments are not part of the rule.
	// +required
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^/[A-Za-z0-9._~/-]*$`
	Path string `json:"path"`

	// ttl is how long a granted address stays in the rule. When omitted the
	// grant never expires.
	// +optional
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1m')",message="ttl must be at least 1m"
	TTL *metav1.Duration `json:"ttl,omitempty"`

	// tokenSecretRef requires a bearer token. The Secret must be in the
	// operator namespace and carry the label
	// security.baprx.github.io/knock-token=true. When omitted, the path alone
	// authorizes the knock.
	// +optional
	TokenSecretRef *SecretKeyRef `json:"tokenSecretRef,omitempty"`
}

// EndpointSpec is one side of a rule. Exactly one of cidr, host and dynamic
// must be set when the endpoint is used as the source; the destination may also
// omit all of them to mean "any".
type EndpointSpec struct {
	// cidr is an IP address or CIDR block, for example 10.0.0.0/8 or 2001:db8::1.
	// +optional
	CIDR *string `json:"cidr,omitempty"`

	// host is a fully qualified domain name that the operator resolves on every
	// node. The resolved addresses are refreshed periodically.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$`
	Host *string `json:"host,omitempty"`

	// port is the port or port range on this side of the rule.
	// +optional
	Port Port `json:"port,omitempty"`

	// dynamic makes this endpoint the target of an HTTP knock.
	// +optional
	Dynamic *DynamicEndpointSpec `json:"dynamic,omitempty"`
}

// ToSpec is the destination side of a rule.
type ToSpec struct {
	EndpointSpec `json:",inline"`

	// ports lists destination ports. Ranges use the "start:end" form. ufw
	// accepts at most 15 entries, counting a range as two.
	// +optional
	// +kubebuilder:validation:MaxItems=15
	// +kubebuilder:validation:XValidation:rule="self.filter(p, p.contains(':')).size() * 2 + self.filter(p, !p.contains(':')).size() <= 15",message="ports must expand to at most 15 ufw entries, counting a range as two"
	Ports []Port `json:"ports,omitempty"`
}

// ResolveSpec tunes hostname resolution for a rule.
type ResolveSpec struct {
	// refreshInterval is how often hostnames are resolved again. Values below
	// 30s are clamped. Defaults to the operator's defaultRefreshInterval.
	// +optional
	RefreshInterval *metav1.Duration `json:"refreshInterval,omitempty"`

	// maxAddresses caps how many addresses are used per hostname.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=64
	// +kubebuilder:default=16
	MaxAddresses *int32 `json:"maxAddresses,omitempty"`

	// ipFamilies selects which resolved families become rules.
	// +optional
	// +kubebuilder:default={IPv4,IPv6}
	IPFamilies []IPFamily `json:"ipFamilies,omitempty"`
}

// HostFirewallRuleSpec defines the desired state of HostFirewallRule.
// +kubebuilder:validation:XValidation:rule="!has(self.from) || ((has(self.from.cidr) ? 1 : 0) + (has(self.from.host) ? 1 : 0) + (has(self.from.dynamic) ? 1 : 0) == 1)",message="from must set exactly one of cidr, host or dynamic"
// +kubebuilder:validation:XValidation:rule="!has(self.to) || ((has(self.to.cidr) ? 1 : 0) + (has(self.to.host) ? 1 : 0) + (has(self.to.dynamic) ? 1 : 0) <= 1)",message="to may set at most one of cidr, host or dynamic"
// +kubebuilder:validation:XValidation:rule="!(has(self.from) && has(self.from.dynamic) && has(self.to) && has(self.to.dynamic))",message="at most one of from.dynamic and to.dynamic may be set"
// +kubebuilder:validation:XValidation:rule="self.action != 'limit' || (has(self.to) && has(self.to.ports) && size(self.to.ports) > 0)",message="limit rules require at least one destination port"
// +kubebuilder:validation:XValidation:rule="!has(self.from) || !has(self.from.cidr) || isIP(self.from.cidr) || isCIDR(self.from.cidr)",message="from.cidr must be a valid IP address or CIDR"
// +kubebuilder:validation:XValidation:rule="!has(self.to) || !has(self.to.cidr) || isIP(self.to.cidr) || isCIDR(self.to.cidr)",message="to.cidr must be a valid IP address or CIDR"
// +kubebuilder:validation:XValidation:rule="!has(self.to) || !has(self.to.port) || !has(self.to.ports) || size(self.to.ports) == 0",message="to must not set both port and ports"
type HostFirewallRuleSpec struct {
	// nodeSelector selects the nodes this rule applies to. An empty selector
	// applies the rule to every node.
	// +optional
	NodeSelector *metav1.LabelSelector `json:"nodeSelector,omitempty"`

	// action is the ufw action.
	// +required
	Action Action `json:"action"`

	// direction is the traffic direction.
	// +optional
	// +kubebuilder:default=in
	Direction Direction `json:"direction,omitempty"`

	// interface limits the rule to one network interface.
	// +optional
	// +kubebuilder:validation:MaxLength=15
	Interface string `json:"interface,omitempty"`

	// protocol is the layer 4 protocol. "any" lets ufw handle both tcp and udp.
	// +optional
	// +kubebuilder:default=any
	Protocol Protocol `json:"protocol,omitempty"`

	// log enables per-rule logging.
	// +optional
	// +kubebuilder:default=false
	Log bool `json:"log,omitempty"`

	// prepend places the rule before all existing rules of the same IP family
	// instead of appending it.
	// +optional
	// +kubebuilder:default=false
	Prepend bool `json:"prepend,omitempty"`

	// from is the source of the traffic. When omitted, ufw's "any" is used.
	// +optional
	From *EndpointSpec `json:"from,omitempty"`

	// to is the destination of the traffic. When omitted, ufw's "any" is used.
	// +optional
	To *ToSpec `json:"to,omitempty"`

	// comment is an optional human readable note appended after the ownership
	// marker in the ufw rule comment.
	// +optional
	// +kubebuilder:validation:MaxLength=200
	// ufw's comment parser does not accept a single quote or a line break.
	// +kubebuilder:validation:Pattern=`^[^'\r\n]*$`
	Comment string `json:"comment,omitempty"`

	// resolve tunes hostname resolution.
	// +optional
	Resolve *ResolveSpec `json:"resolve,omitempty"`
}

// DynamicEndpoint returns the side ("from" or "to") and spec of the dynamic
// endpoint, or "" and nil when the rule has none.
func (s *HostFirewallRuleSpec) DynamicEndpoint() (string, *DynamicEndpointSpec) {
	if s.From != nil && s.From.Dynamic != nil {
		return "from", s.From.Dynamic
	}
	if s.To != nil && s.To.Dynamic != nil {
		return "to", s.To.Dynamic
	}
	return "", nil
}

// ResolvedAddresses records the addresses a rule was expanded to on one node.
type ResolvedAddresses struct {
	// +optional
	From []string `json:"from,omitempty"`

	// +optional
	To []string `json:"to,omitempty"`
}

// NodeStatus is this node's view of a HostFirewallRule. Firewall state is per
// node, so status is kept per node and written with server-side apply by the
// pod that owns that node.
type NodeStatus struct {
	// generation is the spec generation this node last reconciled.
	Generation int64 `json:"generation"`

	// applied reports whether every desired rule is present on this node.
	Applied bool `json:"applied"`

	// ufwVersion is the version reported by the host ufw binary.
	// +optional
	UFWVersion string `json:"ufwVersion,omitempty"`

	// ufwEnabled reports whether ufw is currently enabled. The operator never
	// changes this.
	UFWEnabled bool `json:"ufwEnabled"`

	// markers lists the ownership markers this node expects to find.
	// +optional
	Markers []string `json:"markers,omitempty"`

	// resolved records the addresses used on this node.
	// +optional
	Resolved ResolvedAddresses `json:"resolved,omitempty"`

	// lastAppliedTime is when this node last attempted to converge the rule.
	// +optional
	LastAppliedTime *metav1.Time `json:"lastAppliedTime,omitempty"`

	// degraded reports that the rule is not fully converged for a reason other
	// than a hard error, for example an unresolvable hostname.
	Degraded bool `json:"degraded"`

	// commentsUnsupported is set when ufw accepted a rule but does not report
	// its comment back. The operator then stops adding rules for this CR on this
	// node instead of duplicating them on every sweep.
	CommentsUnsupported bool `json:"commentsUnsupported"`

	// message explains a degraded or failed state.
	// +optional
	Message string `json:"message,omitempty"`
}

// DynamicGrant is the cluster-wide address learned from the last knock.
type DynamicGrant struct {
	// path is the path that produced the grant.
	// +required
	Path string `json:"path"`

	// side is "from" or "to".
	// +required
	Side string `json:"side"`

	// address is the observed source IP, normalized to IPv4 or IPv6.
	// +required
	Address string `json:"address"`

	// observedAt is when the knock was accepted.
	// +required
	ObservedAt metav1.Time `json:"observedAt"`

	// expiresAt is when the grant stops applying. Absent means never.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
}

// DynamicGrantFieldManager owns status.dynamic when the HTTP knock server
// writes a grant with server-side apply.
const DynamicGrantFieldManager = "hfc-dynamic"

// HostFirewallRuleStatus defines the observed state of HostFirewallRule.
type HostFirewallRuleStatus struct {
	// nodes maps a node name to that node's view of the rule.
	// +optional
	Nodes map[string]NodeStatus `json:"nodes,omitempty"`

	// dynamic is the cluster-wide grant shared by every node.
	// +optional
	Dynamic *DynamicGrant `json:"dynamic,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=hfr,scope=Cluster
// +kubebuilder:printcolumn:name="Action",type=string,JSONPath=`.spec.action`
// +kubebuilder:printcolumn:name="Direction",type=string,JSONPath=`.spec.direction`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// HostFirewallRule is the Schema for the hostfirewallrules API
type HostFirewallRule struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of HostFirewallRule
	// +required
	Spec HostFirewallRuleSpec `json:"spec"`

	// status defines the observed state of HostFirewallRule
	// +optional
	Status HostFirewallRuleStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// HostFirewallRuleList contains a list of HostFirewallRule
type HostFirewallRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []HostFirewallRule `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &HostFirewallRule{}, &HostFirewallRuleList{})
		return nil
	})
}
