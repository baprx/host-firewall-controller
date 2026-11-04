# Architecture

## Goals

- Manage UFW rules on every node from namespaced `HostFirewallRule` CRs.
- Make ownership obvious to a human running `ufw status numbered`.
- Never touch rules the operator did not create.
- Never change global UFW state.
- Support CIDR and FQDN endpoints, with periodic re-resolution and a
  last-known-good fallback.
- Keep the design small enough to audit: no webhooks, no finalizers, no
  leader election.

## Non-goals

- Enabling or disabling ufw, or changing its default policy.
- Replacing a CNI, a cloud firewall, or NetworkPolicy.
- Managing `ufw route` rules, application profiles, or per-interface defaults.
- Central ordering of rules across CRs. `prepend: true` is the only ordering
  control.

## Components

```
                       Kubernetes API
        +-------------------------------------------+
        | HostFirewallRule (namespaced)             |
        | Node (labels)                             |
        +---------------------+---------------------+
                              |
                   watch / list / status patch
                              |
+-----------------------------v-----------------------------+
| DaemonSet pod, one per node (hostNetwork, privileged)      |
|                                                            |
|  HostFirewallRuleReconciler                                |
|    - selector check              internal/node              |
|    - expansion / DNS             internal/dnsresolver       |
|    - convergence                 internal/controller        |
|    - node sweep                  internal/controller        |
|    - per-node status (SSA)       internal/controller        |
|                                                            |
|  internal/ufw                                               |
|    - rule rendering, markers, state parsing                 |
|    - ChrootRunner -> self re-exec -> chroot(hostRoot)       |
|    - flock on <hostRoot>/run/host-firewall-controller.lock  |
+-----------------------------+------------------------------+
                              |
                       chroot /host, exec /usr/sbin/ufw
                              |
                        host ufw + iptables
```

There is one manager per node and no leader election. Each manager only writes
its own entry in `status.nodes` and only reconciles rules on its own node. This
is why the operator scales horizontally without coordination.

## Reconcile flow

1. **Fetch the CR.** If it has been deleted, run a node sweep immediately so its
   rules do not wait for the periodic sweep.
2. **Fetch this node** and evaluate `spec.nodeSelector`. A node that does not
   match converges to an empty desired set, which removes its rules for that CR.
3. **Expand** the logical rule into concrete ufw rules:
   - CIDR endpoints become one address.
   - Hostname endpoints are resolved (or served from the last result within the
     refresh interval). Each address produces one rule, so `from.host` and
     `to.host` together produce the cross product.
   - Duplicate rules are collapsed by ownership marker.
   - Per-CR and per-node caps are applied. Hitting the per-node cap aborts
     convergence without deleting anything.
4. **Converge** under the ufw lock:
   - Read state.
   - Add every desired marker that is missing.
   - Before each add, refuse to proceed if the same ufw match key already
     belongs to an unmanaged rule or to another CR: ufw would update that rule
     in place instead of appending.
   - Delete every marker owned by this CR that is not desired, plus duplicate
     copies beyond the expected number of IP families. A dual-stack rule
     normally has one IPv4 and one IPv6 twin with the same marker, so twins are
     not duplicates.
   - If any add failed or was refused, skip the delete phase. Removing a working
     rule after its replacement failed would create a coverage gap.
   - Re-read state for the final status.
5. **Report status** for this node with server-side apply.
6. **Requeue** after `resolve.refreshInterval` when a hostname is involved, or
   return an error (exponential backoff) when a ufw call failed.

## Reading ufw state

`ufw status numbered` is the primary source because it exposes rule numbers,
which are required for safe deletion. It only lists rules while ufw is enabled.

The operator also reads `ufw show added` on every convergence. That output lists
rules as they were added and includes comments, and unlike `status numbered` it
also lists unmanaged rules. It is used to detect an add that ufw would apply as
an update to an existing rule.

```
always:    ufw show added       -> all command lines, canonical form
enabled:   ufw status numbered  -> numbers + comments + (v6) markers
inactive:  ufw show added       -> command lines + comments, delete by spec
```

Only lines whose comment parses as `HFC:<token>:<fingerprint>` become managed
entries. Unmanaged rules are still parsed for collision detection, but can never
be selected for deletion.

## Convergence ordering

Adds happen before deletes, and deletes only run if every add succeeded. When a
rule changes address (for example a DNS record moves), the new rule exists
before the old one is removed, so a `deny` or `limit` rule never has a gap in
coverage. The trade-off is a brief window with both rules present, which is
safer for allow rules as well.

Deletion re-reads state before every single delete and targets the rule number
from that fresh listing if ufw is enabled, so a number is never reused blindly
after another change shifted the numbering. While ufw is inactive there are no
numbers, so deletion uses the full rule arguments including the ownership
comment. That makes ufw match the exact rule instead of the first rule with the
same ports, which could be an identical unmanaged rule.

## Sweep

The per-node sweep is the garbage collector and the drift repair mechanism. It:

1. Lists all CRs, re-fetches each one, and runs the normal convergence path for
   every matching CR. This adds missing rules, so the sweep repairs drift rather
   than only deleting stale entries.
2. Lists the CRs again and computes the union of markers every matching CR wants
   on this node. Re-listing prevents a CR deleted during the sweep from keeping
   its rules until the next interval.
3. Deletes every operator marker that is not in the union, and reduces duplicate
   markers beyond the expected number of IP families. v4/v6 twins are kept.

It runs at startup, every `--sweep-interval` (default 5 minutes), and whenever a
CR is deleted. This is why there are no finalizers: a CR, a namespace, or an
entire cluster can disappear without leaving reconciliation blocked, and the
next sweep still cleans up.

## Status

Firewall state is per node, so status is per node:

```yaml
status:
  nodes:
    node-a: { generation: 2, applied: true, ... }
```

Each pod patches only `status.nodes[<its node>]` with server-side apply and the
field manager `hfc-<sha256(node)[:12]>`. The API server merges map keys per
owner, so pods never fight over the status object. The CRD status subresource is
the only thing the operator writes.

`applied` means every desired rule was found after convergence, either by marker
or, when `commentsUnsupported` is set, by matching an unmarked rule's ufw match
key. `degraded` means a non-fatal problem (DNS failure with last-known-good
rules, truncation, a refused add). `commentsUnsupported` is described in
[safety.md](safety.md).

## Concurrency and locking

Two levels of locking protect ufw:

- a process-local mutex, because the controller and the sweep goroutine share
  the reconciler;
- an exclusive `flock` on a file under the host's `/run`, because a terminating
  pod and its replacement can briefly overlap during a DaemonSet rollout.

The flock is non-blocking. Losing the race returns an error, the reconcile is
retried with backoff, and no two processes ever interleave ufw commands.

## Running ufw without shipping chroot

The image is distroless and contains no shell or `chroot` binary. The manager
re-executes **its own binary** with a hidden `__ufw-exec <hostRoot> <ufwPath>`
argument. That mode performs `chroot(hostRoot)`, `chdir("/")`, and
`execve(<ufwPath> ...)`. The host's own Python, ufw and iptables are used, so
version drift between image and node cannot happen.

`LC_ALL=C` and `LANG=C` are set for every invocation so output parsing does not
depend on the node locale.

## Failure handling

| Failure | Behaviour |
| --- | --- |
| DNS lookup fails, previous addresses known | Keep last-known-good rules, set `degraded` and a message, retry after `min(refreshInterval, 30s)`; a degraded status bypasses the refresh-interval cache. |
| DNS lookup fails, no previous addresses | No rule for that endpoint, `degraded`, retry soon. |
| ufw command fails | Status `applied=false`, message contains the ufw stderr, reconcile returns an error for backoff, event `ApplyFailed`; the delete phase is skipped. |
| Desired rule collides with an unmanaged or other-CR rule | Refuse to add or modify it, set `applied=false`/`degraded`, return an error; the delete phase is skipped. |
| ufw accepts rules but never reports comments | `commentsUnsupported=true`; adopt a matching unmarked rule by match key instead of adding a duplicate. A missing rule or a new spec is retried; the old unmarked rule cannot be identified and may need manual cleanup. |
| Another pod holds the flock | Retry with backoff; no ufw command runs. |
| Rule cap exceeded over all matching CRs | Abort convergence, keep existing rules, status message explains the cap. |
| Invalid `nodeSelector` | Status `degraded` with the selector error; no rules are changed. |
| CR is deleted while the pod is down | The startup or periodic sweep removes its rules. |

## Why these choices

- **Comments for ownership** require ufw 0.36+, but make ownership human-visible
  and survive CR recreation, pod restarts, and `ufw show added` parsing.
- **No finalizers** keeps deletion non-blocking. The sweep is sufficient because
  the set of live CRs is always available from the API.
- **Per-node status with SSA** avoids a leader and status write conflicts.
- **No webhooks** keeps installation to the Helm chart and the API server's own
  CEL validation.
- **One DaemonSet manager per node** matches the physical scope of ufw; there is
  no way for the wrong node to be changed.
