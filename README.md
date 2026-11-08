# host-firewall-controller

A Kubernetes operator that manages [UFW](https://launchpad.net/ufw) rules on
every node from `HostFirewallRule` custom resources.

- One `HostFirewallRule` is one logical rule. A rule with an FQDN endpoint expands
  to one concrete ufw rule per resolved address.
- Rules are visibly owned by the operator through a ufw comment marker. The
  operator **never** touches a rule it did not create.
- The operator **never** enables, disables, resets, reloads, or changes the
  default policy or logging of ufw. It only adds and deletes its own rules.
- Status is reported per node, because firewall state is per node.

The install path is the Helm chart in
[`charts/host-firewall-controller`](charts/host-firewall-controller).

## Requirements

- Linux nodes with `ufw` **0.36 or newer** installed on the host (0.36 is the
  first release with rule comments, which the operator uses to prove ownership).
- A container runtime able to run a privileged pod with the host root filesystem
  mounted at `/host`.
- Helm 3.8+ and Kubernetes 1.31+. The CRD uses the CEL `isIP`/`isCIDR`
  functions, which are available from Kubernetes 1.31.

ufw does not have to be enabled. When it is inactive, the operator manages the
rules that ufw records with `ufw show added`; it never enables the firewall.

## Install

From a checkout of this repository:

```bash
helm upgrade --install host-firewall-controller ./charts/host-firewall-controller \
  --namespace host-firewall-system --create-namespace
```

The chart is also designed to be packaged and published as an OCI artifact; once
published it can be installed with:

```bash
helm upgrade --install host-firewall-controller \
  oci://ghcr.io/baprx/charts/host-firewall-controller \
  --namespace host-firewall-system --create-namespace
```

The chart installs a privileged DaemonSet with `hostNetwork: true`, the host root
mounted at `/host`, a ClusterRole that can read rules and nodes and write rule
status, and a metrics Service. When the knock endpoint is enabled, the chart can
also expose it through a Service with an Ingress or an HTTPRoute.

The CRD lives in the chart's `crds/` directory. Helm installs it but does not
upgrade it on `helm upgrade`, so apply it explicitly when it changes:

```bash
kubectl apply -f charts/host-firewall-controller/crds/security.baprx.github.io_hostfirewallrules.yaml
```

## Quick start

Allow SSH from an office network on every node:

```yaml
apiVersion: security.baprx.github.io/v1alpha1
kind: HostFirewallRule
metadata:
  name: allow-ssh-office
spec:
  action: allow
  protocol: tcp
  comment: SSH from the office
  from:
    cidr: 203.0.113.0/24
  to:
    ports: ["22"]
```

```bash
kubectl apply -f config/samples/security_v1alpha1_hostfirewallrule.yaml
kubectl get hfr
# NAME               ACTION   DIRECTION   APPLIED        GRANTED   AGE
# allow-ssh-office   allow    in          3/3 applied              4d2h
kubectl get hfr -o wide
kubectl get hfr allow-ssh-office -o jsonpath='{.status.nodes}' | jq
```

On the node:

```bash
ufw status numbered | grep HFC:
# [ 1] 22/tcp  ALLOW IN  203.0.113.0/24  # HFC:allow-ssh-office:1a2b3c4d5e6f | SSH from the office
```

## API

`HostFirewallRule` is `security.baprx.github.io/v1alpha1`, cluster-scoped, short
name `hfr`.

| Field | Description |
| --- | --- |
| `spec.action` | `allow`, `deny`, `reject` or `limit` (required). |
| `spec.direction` | `in` (default) or `out`. |
| `spec.interface` | Optional network interface; ufw's `on <iface>`. |
| `spec.protocol` | `tcp`, `udp` or `any` (default). |
| `spec.log` | Enable per-rule ufw logging (default `false`). |
| `spec.prepend` | Insert at the top instead of appending (default `false`). |
| `spec.from` | Source endpoint: exactly one of `cidr`, `host` or `dynamic`, plus optional `port`. |
| `spec.to` | Destination endpoint: at most one of `cidr`, `host` or `dynamic`, optional `port` or `ports` (max 15 entries). |
| `spec.from.dynamic.path` | Exact HTTP path (starts with `/`, max 256 characters) whose requests update the endpoint. |
| `spec.from.dynamic.ttl` | How long a granted address applies (minimum `1m`). Omitted means no expiry. |
| `spec.from.dynamic.tokenSecretRef.name` | Secret in the operator namespace that holds the bearer token. It must carry the label `security.baprx.github.io/knock-token=true`. |
| `spec.from.dynamic.tokenSecretRef.key` | Key inside that Secret. |
| `spec.to.dynamic` | Same shape as `spec.from.dynamic`. At most one of `from.dynamic` and `to.dynamic` may be set. |
| `spec.comment` | Human-readable note appended after the ownership marker. |
| `spec.nodeSelector` | Standard label selector; empty means every node. |
| `spec.resolve.refreshInterval` | FQDN refresh interval (default 5m, floor 30s). |
| `spec.resolve.maxAddresses` | Addresses per hostname (default 16, max 64). |
| `spec.resolve.ipFamilies` | `IPv4`, `IPv6` or both (default both). |

`status.nodes` maps a node name to that node's view:

```yaml
status:
  summary: 3/3 applied
  nodes:
    node-a:
      generation: 3
      applied: true
      ufwVersion: "ufw 0.36.2"
      ufwEnabled: true
      markers:
        - HFC:allow-ssh-office:1a2b3c4d5e6f
      resolved:
        from: ["203.0.113.10", "203.0.113.11"]
      lastAppliedTime: "2026-11-02T15:04:05Z"
      degraded: false
      commentsUnsupported: false
```

Each pod writes only its own node entry with server-side apply and a per-node
field manager, so pods never overwrite each other.

`status.summary` backs the `Applied` column of `kubectl get hfr`: the API
server's table convertor cannot render a map, so the operator publishes one
aggregate line, `<applied>/<reported> applied`, with `, <n> degraded` appended
when some node reports a degraded state. The denominator counts the nodes that
have reported for that rule. The field is display-only and recomputed by every
pod, so it is last-writer-wins and can lag one reconcile during a transition.
`-o wide` adds `From`, `Host`, `Ports`, `Knock path` and `Grant expires`; the
`Granted` column shows the address of the last accepted knock, and `Grant
expires` its RFC3339 expiry.

## FQDN endpoints

`spec.from.host` and `spec.to.host` are resolved by the operator, on each node,
with the node's resolver. Resolution happens at most every
`resolve.refreshInterval`, and every resolved address becomes a concrete rule.

- On resolution failure, the last known-good addresses are kept, existing rules
  stay in place, and the node status is marked `degraded` with the resolver
  error. The next reconcile retries the lookup even if the refresh interval has
  not elapsed, so recovery is not postponed for the whole interval.
- A hostname that has never resolved produces no rule.
- Addresses are sorted and capped by `resolve.maxAddresses`; the rule set is
  stable across reconciles.
- A rule may expand to at most 64 concrete rules per node by default
  (`--max-rules-per-cr`). The node cap (`--max-rules-per-node`, default 256) is
  enforced over the union of every CR that matches the node, not per CR.
  Exceeding the cap stops convergence instead of deleting anything.

## Dynamic IP knocks

`spec.from.dynamic` or `spec.to.dynamic` replaces a static endpoint with an
address learned from an HTTP request. A request to the configured path records
the caller's source address as a **cluster-wide grant** on the rule; every node
selected by the rule then converges its ufw state with that address. Put the
block under `to` instead to learn the destination. At most one side of a rule
may be dynamic.

```yaml
apiVersion: security.baprx.github.io/v1alpha1
kind: HostFirewallRule
metadata:
  name: allow-ssh-home
spec:
  action: allow
  protocol: tcp
  comment: SSH from the last knock
  from:
    dynamic:
      path: /knock/change-me-to-a-long-random-path
      ttl: 1h
      tokenSecretRef:
        name: ssh-knock-token
        key: token
  to:
    ports: ["22"]
```

The path is matched exactly, including a trailing slash. It is at most 256
characters and may contain only `[A-Za-z0-9._~/-]`.

With `tokenSecretRef`, create the Secret in the **operator namespace** (the
chart release namespace, exposed to the pod as `POD_NAMESPACE`) before applying
the rule. The rule is cluster-scoped, so there is no per-rule namespace:

```bash
kubectl create secret generic ssh-knock-token \
  --namespace host-firewall-system \
  --from-literal=token="$(openssl rand -hex 32)"
kubectl label secret ssh-knock-token -n host-firewall-system \
  security.baprx.github.io/knock-token=true

TOKEN="$(kubectl get secret ssh-knock-token -n host-firewall-system \
  -o jsonpath='{.data.token}' | base64 -d)"
```

The knock server reads a Secret only when it carries the
`security.baprx.github.io/knock-token=true` label. Without that gate, a rule
author could point `tokenSecretRef` at any Secret in the operator namespace and
use the `401`/`503` split to probe whether a key exists. Label only dedicated
knock token Secrets.

Omitting `tokenSecretRef` makes the path alone authorize the knock (path-only),
so such a path must be high-entropy.

Send a knock to any node's endpoint:

```bash
# Path-only rule, like the sample.
curl --fail-with-body \
  http://node.example.com:8082/knock/change-me-to-a-long-random-path

# Rule with tokenSecretRef.
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  http://node.example.com:8082/knock/change-me-to-a-long-random-path
```

When a TLS reverse proxy fronts the endpoint, use the proxy's HTTPS URL
instead; the port in that URL is the proxy's, not necessarily 8082.

Replace the placeholder path with your own long, random value before applying
the rule. The
[dynamic sample](config/samples/security_v1alpha1_hostfirewallrule_dynamic.yaml)
is path-only. A path-only path **is the credential**: it appears in operator
and proxy logs, so use a long, high-entropy path and treat it as a secret.

Any node's endpoint accepts the knock, even one the rule does not select. The
grant is cluster-wide; the nodes that match `spec.nodeSelector` apply it. A
`200` means the grant was recorded, not that every node has already converged.
Inspect the shared grant and wait for each node:

```bash
kubectl get hfr allow-ssh-home -o jsonpath='{.status.dynamic}' | jq
kubectl get hfr allow-ssh-home -o jsonpath='{.status.nodes}' | jq
```

`status.dynamic` holds the grant:

```yaml
status:
  dynamic:
    path: /knock/change-me-to-a-long-random-path
    side: from
    address: 203.0.113.10
    observedAt: "2026-11-02T15:04:05Z"
    expiresAt: "2026-11-02T16:04:05Z"
```

- The last accepted knock wins. It replaces the previous address and restarts
  the TTL; only one dynamic address applies at a time.
- `ttl` omitted means the grant never expires. When set, it must be at least
  `1m`. The TTL is included in the requeue bound: the rule requeues at the
  shorter of the refresh interval and the remaining TTL, so the expired grant
  is removed without another user event. When the other endpoint is an FQDN,
  the shorter of the FQDN resolution interval and the remaining TTL is used.
- A rule with no grant yet applies nothing and reports `Waiting for a knock on
  <path>`; it is not degraded.
- If the path or side changes, or the TTL passes, the grant is ignored and
  cleared from status, and the ufw rule is removed.
- Two rules may not share a knock path. While a path is ambiguous, the handler
  returns `409` and the controller applies no dynamic rule for either rule.

| Code | Meaning |
| --- | --- |
| `200` | Grant recorded; nodes converge asynchronously. |
| `400` | Invalid client address, or a malformed `X-Forwarded-For` header. |
| `401` | Missing or wrong bearer token. |
| `404` | No rule binds the path. |
| `405` | Method is not `GET` or `POST`. |
| `409` | Several rules bind the path. |
| `500` | The rule list or the status update failed. |
| `503` | The token Secret is unreadable, has no value, or `POD_NAMESPACE` is unset. |

By default the source address is the immediate peer's address.
`X-Forwarded-For` is honored only when that peer is in `knock.trustedProxies`
(or `--knock-trusted-proxies` outside the chart); other requests ignore the
header. A malformed forwarding header is rejected with `400` instead of falling
back to the proxy's address. Behind a Service or load balancer, source-IP
preservation depends on `externalTrafficPolicy`; the supported setup is a
trusted proxy plus its CIDR in `knock.trustedProxies`.

The endpoint is disabled by default: the chart value `knock.enabled` is
`false`, so no new host port appears on existing installs. To enable it:

```yaml
knock:
  enabled: true
  bindAddress: ":8082"
  port: 8082
  trustedProxies:
    - 10.0.0.0/8
```

- The default port is `8082`, published as a `hostPort` on every node. Change
  `knock.bindAddress` and `knock.port` together so the host port reaches the
  address the server actually binds.
- The chart does **not** add a ufw rule for the knock port. On a host whose
  firewall is default-deny, the knock is dropped before it reaches the server.
  Allow the port from your trusted proxy or management network with a static
  rule, for example `from.cidr: 10.0.0.0/8` and `to.ports: ["8082"]`; otherwise
  bind the server to a loopback or private address that is already reachable.
- When `knock.enabled=true` and `rbac.create=true`, the chart creates a
  namespaced `Role` and `RoleBinding` granting only `get` on `secrets` in the
  release namespace. If `rbac.create=false`, provide that namespaced Role and
  RoleBinding yourself.
- Outside the chart, pass `--knock-bind-address=:8082` (`0` or empty disables
  the server) and optionally `--knock-trusted-proxies=10.0.0.0/8`. Set
  `POD_NAMESPACE` to the namespace that holds the token Secrets; leave it unset
  only when every dynamic rule is path-only. A non-chart install that uses
  `tokenSecretRef` also needs a namespaced `get` Role and RoleBinding on
  `secrets` in that namespace, equivalent to the chart's.

### Exposing the knock endpoint

The chart can create a Service for the knock port and expose it through either a
classic Ingress or a Gateway API HTTPRoute. The Service is required by both, and
the two routing options are mutually exclusive.

A Service without routing exposes the port inside the cluster:

```yaml
knock:
  enabled: true
  service:
    enabled: true
    type: ClusterIP
```

An Ingress exposes it through an Ingress controller:

```yaml
knock:
  enabled: true
  service:
    enabled: true
  ingress:
    enabled: true
    className: nginx
    hosts:
      - host: knock.example.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: knock-tls
        hosts:
          - knock.example.com
```

Or an HTTPRoute through a Gateway API implementation:

```yaml
knock:
  enabled: true
  service:
    enabled: true
  httpRoute:
    enabled: true
    parentRefs:
      - name: my-gateway
        namespace: gateway-system
    hostnames:
      - knock.example.com
    matches:
      - path:
          type: PathPrefix
          value: /
```

To put the listener on a `ListenerSet` instead of on the Gateway itself, enable
`knock.listenerSet`. The chart renders the `ListenerSet`, and when the
HTTPRoute has no `parentRefs` it attaches the route to that `ListenerSet`:

```yaml
knock:
  enabled: true
  service:
    enabled: true
  httpRoute:
    enabled: true
    hostnames:
      - knock.example.com
    matches:
      - path:
          type: PathPrefix
          value: /
  listenerSet:
    enabled: true
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt
    parentRef:
      name: my-gateway
      namespace: gateway-system
    listeners:
      - name: knock-https
        hostname: knock.example.com
        port: 443
        protocol: HTTPS
        tls:
          mode: Terminate
          certificateRefs:
            - name: knock-tls
```

`knock.listenerSet.listeners` takes Gateway API listener objects as-is, so any
listener field the implementation supports can be set. Explicit
`knock.httpRoute.parentRefs` entries take precedence over the automatic
`ListenerSet` parent.

The chart does not install Gateway API CRDs or a Gateway controller. The
`ListenerSet` resource also has to be installed by the cluster.

For `NodePort` and `LoadBalancer` Services the chart sets
`externalTrafficPolicy` (default `Local`), which preserves the caller's source
IP so the knock allows the right address. Through an Ingress or HTTPRoute the
immediate peer is the proxy instead: add the proxy's CIDR to
`knock.trustedProxies` and make sure the proxy forwards `X-Forwarded-For`.

The chart also appends arbitrary manifests from `extraObjects` to the release.
Each entry is a manifest map rendered with Helm's `tpl`, so it can use release
values and chart helpers:

```yaml
extraObjects:
  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: '{{ include "hfc.fullname" . }}-extra'
      namespace: '{{ .Release.Namespace }}'
    data:
      endpoint: 'http://{{ include "hfc.fullname" . }}-knock:{{ .Values.knock.port }}'
```

Literal `{{` in a manifest must be escaped for Helm, for example
`{{ "{{" }}`.

> **Warning:** the endpoint speaks plain HTTP. The path and the bearer token
> are visible to anyone on the network path. Put a TLS reverse proxy or VPN in
> front, or bind the server to a private address that is not reachable from
> untrusted networks.

## Ownership and safety

Every rule the operator creates ends with a ufw comment:

```
HFC:<name>:<fingerprint> | <optional user comment>
```

`HFC:` identifies the operator, `<name>` identifies the `HostFirewallRule`, and
the 12-hex fingerprint covers every semantic field of the rule. The comment is
never truncated; the user part is truncated to keep the whole comment within 200
bytes.

Reconciliation only adopts rules whose comment parses as one of its markers.
Anything else, including a rule with identical ports but no comment, is left
alone. ufw would silently update such a rule in place when given the same match
key, so the operator checks all of `ufw show added` first and refuses the add
with a degraded status instead.

Two `HostFirewallRule` objects may legitimately expand to the same concrete
rule, for example a static allow and a dynamic knock grant that resolved to the
same address. ufw can hold only one of them, and the comment (not the match key)
carries ownership. The second CR therefore reports the rule as *shared* and
leaves the existing marker alone; if the owning CR is later deleted or stops
wanting that rule, the survivor takes it over under its own marker. See
[docs/safety.md](docs/safety.md) for the full list of invariants.

## Operations

- `/healthz` and `/readyz` are served on `:8081`.
- Prometheus metrics are served on `:8080` (disable with `metrics.enabled=false`).
  Because the pod uses the host network, the metrics port is bound on the node.
- Flags mirror the chart values; see
  [charts/host-firewall-controller/docs/values.md](charts/host-firewall-controller/docs/values.md).
- `--dry-run` logs the ufw commands instead of executing them.

Useful metrics:

| Metric | Meaning |
| --- | --- |
| `hfc_managed_rules` | Managed rules currently on this node. |
| `hfc_apply_duration_seconds` | Duration of one ufw add/delete. |
| `hfc_resolution_failures_total` | Failed DNS resolutions. |
| `hfc_knock_requests_total` | Knock requests by result (`ok`, `not_found`, `ambiguous`, `unauthorized`, `bad_request`, `error`). |
| `hfc_reconcile_errors_total` | Reconciliations that returned an error. |

## Removing the operator

There are no finalizers. Deleting a `HostFirewallRule` removes its rules on the
next reconcile; the periodic node sweep (default 5 minutes) also removes rules
whose CR no longer exists, and repairs drift.

Uninstalling the chart removes the pods but deliberately leaves ufw rules on the
nodes, because the operator will not run destructive ufw commands blindly.
Remove them explicitly if needed:

```bash
# On each node: list operator-owned rules, then delete by number.
ufw status numbered | grep 'HFC:'
ufw --force delete <number>
```

## Development

```bash
make test          # unit + envtest (downloads envtest binaries)
make lint-fix      # golangci-lint with fixes
make chart-check   # helm lint + render (syncs the CRD into the chart)
make helm-docs     # regenerate charts/.../docs/values.md
make test-e2e      # kind + real ufw; requires Docker (or podman via KIND_EXPERIMENTAL_PROVIDER)
```

The tools those targets and the pre-commit hooks need are pinned in
`mise.toml`; `mise install` sets them up. Hooks run through `pre-commit`
(`pre-commit install` once, then `pre-commit run --all-files`). The
helm-schema hook also needs the helm-values-schema-json plugin; see the
install command next to it in `.pre-commit-config.yaml`.

The controller tests use envtest and a stateful fake ufw host. The e2e suite
creates a kind cluster, installs ufw inside every node (without enabling it),
installs the chart, and asserts on the real `ufw show added` output.

## Further reading

- [docs/architecture.md](docs/architecture.md): components, reconciliation
  flow, concurrency and failure handling.
- [docs/safety.md](docs/safety.md): invariants, ownership proof, and
  troubleshooting.
