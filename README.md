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
status, and a metrics Service.

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
| `spec.from` | Source endpoint: exactly one of `cidr` or `host`, plus optional `port`. |
| `spec.to` | Destination endpoint: at most one of `cidr` or `host`, optional `port` or `ports` (max 15 entries). |
| `spec.comment` | Human-readable note appended after the ownership marker. |
| `spec.nodeSelector` | Standard label selector; empty means every node. |
| `spec.resolve.refreshInterval` | FQDN refresh interval (default 5m, floor 30s). |
| `spec.resolve.maxAddresses` | Addresses per hostname (default 16, max 64). |
| `spec.resolve.ipFamilies` | `IPv4`, `IPv6` or both (default both). |

`status.nodes` maps a node name to that node's view:

```yaml
status:
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
with a degraded status instead. See [docs/safety.md](docs/safety.md) for the
full list of invariants.

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
