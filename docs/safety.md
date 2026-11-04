# Safety model

This operator changes packet filtering on production hosts. The rules below are
deliberate and are enforced by code, not convention.

## Invariants

1. **Global ufw state is never changed.** The operator never runs `ufw enable`,
   `ufw disable`, `ufw reset`, `ufw reload`, `ufw default`, or `ufw logging`. If
   ufw is disabled, rules are recorded but not enforced; enabling ufw remains an
   explicit human action.
2. **Unmanaged rules are never touched.** A rule is managed only if its comment
   starts with `HFC:` and parses as a marker. Rules with the same ports but no
   comment are left alone, and rules belonging to another CR have a different
   token. ufw updates an existing rule in place when an add has the same match
   key, so before adding, the operator compares the desired rule with every
   entry from `ufw show added`. A collision with an unmanaged or other-CR rule
   is refused rather than applied.
3. **Adds happen before deletes.** A changed rule never leaves a coverage gap.
   If any add fails or is refused, the delete phase is skipped entirely.
4. **Deletion targets a freshly read state.** Before each delete the operator
   re-reads ufw state. When ufw is enabled it deletes the number that currently
   carries its marker; it never deletes a number captured earlier. When ufw is
   inactive it deletes by specification *including the ownership comment*, so
   ufw cannot select an identical unmanaged rule instead.
5. **No destructive fallback.** If ufw state cannot be read or parsed, the
   reconcile fails; the operator does not guess and does not delete.
6. **Bounded work.** The node cap (`--max-rules-per-node`, default 256) applies
   to the union of every CR that matches the node, and one CR is capped at
   `--max-rules-per-cr` (default 64) concrete rules. Exceeding the node cap never
   deletes existing rules.
7. **No duplicate rules without proof.** A desired rule that ufw does not report
   back with its comment is not re-added on every reconcile. The node sets
   `commentsUnsupported` and recognizes its own rule by match key. If the rule
   is missing it is added again; a spec change can leave the previous unmarked
   rule behind because it cannot be identified safely.

## Ownership marker

```
HFC:<token>:<fingerprint>[ | <user comment>]
```

- `HFC:` is the operator prefix.
- The token is `<namespace>/<name>`; if longer than 100 characters it is
  truncated and suffixed with `~<uid hash>` so two long-named CRs cannot collide.
- The fingerprint is 12 hex characters of SHA-256 over every semantic field of
  the rule (action, direction, protocol, interface, log, prepend, addresses,
  ports), excluding the comment. Changing only `spec.comment` does not recreate
  the rule.
- The marker is never truncated; the user comment is truncated so the total
  comment stays within 200 bytes.

A human can audit ownership directly:

```bash
ufw status numbered | grep 'HFC:'
```

## Convergence algorithm

For each CR on each node:

```
desired = expand(spec)                     # markers, one per concrete rule
state   = read ufw                         # managed entries + all show-added rules

for marker in sorted(desired):
    if marker is missing:
        if the match key belongs to an unmanaged/other-CR rule:
            refuse, mark degraded, skip all deletes
        ufw <args with marker comment>     # add first

for marker owned by this CR but not desired:
    while state has marker:
        state = read ufw                   # fresh numbers
        ufw --force delete <current number>

for marker in desired:
    expected = number of IP families   # one for explicit v4/v6, two for any/any
    delete copies beyond expected
```

The sweep runs the same convergence for every matching CR, then prunes orphaned
markers from the union of all live CRs. v4/v6 twins of a dual-stack rule are
kept.

## Reading state safely

| ufw state | Source | Deletion |
| --- | --- | --- |
| enabled | `ufw status numbered` | `ufw --force delete <number>` |
| inactive | `ufw show added` | `ufw delete <args including comment>` |

Output is parsed with `LC_ALL=C`. Rules without a marker are never managed
entries, so the reconciler cannot select them for deletion. `ufw show added` is
also read on every convergence and its unmanaged rules are used only to detect
match-key collisions.

## The comments-unsupported circuit breaker

Some ufw builds accept a `comment` clause but do not print it back (locale
issues, old builds, wrappers). Without a guard, the operator would add the same
rule on every reconcile and duplicate it indefinitely.

When a node adds a rule, immediately re-reads state, and finds none of its
expected markers, it sets `status.nodes[<node>].commentsUnsupported=true`. From
then on it recognizes its own rule by matching the desired ufw match key against
unmarked rules, so it does not duplicate the whole rule set. If the rule is
missing, it is added again; if the spec changed, the new rule is added, but the
old unmarked rule cannot be identified and may remain until manual cleanup.
Deletion still works from `show added` when comments are reported there.

Resolution: upgrade ufw to 0.36+, or remove the CR. Once a subsequent add is
reported with a marker again, the flag clears automatically.

## Locking

A terminating DaemonSet pod and its replacement can overlap. Both take an
exclusive, non-blocking `flock` on
`<hostRoot>/run/host-firewall-controller.lock` before any ufw invocation. The
loser retries later. A process-local mutex protects the controller and sweep
goroutine from each other.

## What the operator does on failure

- **ufw error:** no partial success is claimed. Status `applied=false` and the
  ufw stderr is in the message; the reconcile returns an error and is retried
  with backoff. If any add failed, no rule is deleted in that pass.
- **DNS failure:** last known-good addresses are kept and status is `degraded`.
  Existing rules are not removed.
- **Missing/old ufw:** startup fails unless `--allow-missing-ufw` is set. With
  that flag the pod runs and reports failures in status instead of crash
  looping.
- **CR deleted, pod down:** the next sweep removes the rules.

## Uninstall behaviour

The operator deliberately has no finalizers and the chart does not run cleanup
hooks against ufw. Uninstalling the chart leaves rules on the nodes. This is the
safe default: a chart uninstall should not silently delete firewall rules while
the pods that understand them are gone.

To clean up manually on each node:

```bash
ufw status numbered | grep 'HFC:'
# Delete from the highest number down so numbering stays valid.
ufw --force delete <number>
```

If ufw is inactive:

```bash
ufw show added | grep 'HFC:'
# Re-run the printed command with "delete" instead of the action.
ufw delete allow proto tcp to any port 22
```

## Pre-flight checklist for a new cluster

1. ufw is installed on every node and `ufw --version` reports 0.36 or newer.
2. The chart is installed with the CRD applied.
3. The DaemonSet has one Ready pod per node.
4. `ufw status` still reports the expected global state (enabled or inactive);
   the operator never changes it.
5. Unmanaged rules captured before installation are still present after applying
   and deleting a test `HostFirewallRule`.
6. `kubectl get hfr -A` shows `applied: true` for every expected node.
