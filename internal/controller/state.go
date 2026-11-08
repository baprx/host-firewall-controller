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
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/baprx/host-firewall-controller/internal/ufw"
)

// convergeResult reports what happened during one convergence attempt.
type convergeResult struct {
	State   ufw.State
	Added   int
	Deleted int
	// Shared maps a desired marker to the marker of another HostFirewallRule
	// that already provides a rule with the same ufw match key. ufw identifies
	// rules without their comment, so the node already matches this CR's intent
	// and the existing entry's marker must not be rewritten.
	Shared map[string]string
	Err    error
}

// converge makes the node's ufw match the desired rule set. Missing rules are
// added first and stale rules are deleted second, so a deny rule that changes
// address never briefly opens the port.
func (r *HostFirewallRuleReconciler) converge(
	ctx context.Context,
	token string,
	desired []ufw.Rule,
	commentsUnsupported bool,
) convergeResult {
	log := logf.FromContext(ctx)
	result := convergeResult{}

	err := r.withLock(func() error {
		state, err := r.readState(ctx)
		if err != nil {
			result.State = state
			return err
		}
		result.State = state
		managedRules.Set(float64(len(state.Entries)))

		desiredByMarker := make(map[string]ufw.Rule, len(desired))
		for _, rule := range desired {
			desiredByMarker[ufw.MarkerFor(token, rule).String()] = rule
		}

		expectedCounts := make(map[string]int, len(desiredByMarker))
		for marker, rule := range desiredByMarker {
			expectedCounts[marker] = expectedFamilyCount(rule, state)
		}

		var errs []error
		canPrune := true
		for _, marker := range slices.Sorted(maps.Keys(desiredByMarker)) {
			if state.Count(marker) >= expectedCounts[marker] {
				continue
			}
			rule := desiredByMarker[marker]

			// Adding a rule whose match key already exists is not an append:
			// ufw updates the existing rule in place (or silently skips a
			// prepend). That would steal an unmanaged rule or rewrite another
			// HostFirewallRule's ownership marker.
			conflict, conflictFound := conflictingEntry(state, rule)
			if conflictFound && conflict.Marker.Token != token {
				switch {
				case conflict.Marker.Token == "" && commentsUnsupported:
					// The operator's own rule on a ufw that does not report
					// comments: it is necessarily unmarked, so adopt it rather
					// than duplicating.
					continue
				case conflict.Marker.Token == "":
					// Never touch a rule the operator does not manage.
					errs = append(errs, fmt.Errorf(
						"rule %s would replace existing ufw rule %q; refusing to modify a rule this CR does not own",
						marker, ufw.ArgsString(conflict.Args)))
					canPrune = false
					continue
				default:
					// Another HostFirewallRule already provides a rule with
					// this exact match key. The node already matches this CR's
					// intent, and adding ours would only rewrite that CR's
					// marker. Report the rule as shared instead.
					if result.Shared == nil {
						result.Shared = map[string]string{}
					}
					result.Shared[marker] = conflict.Marker.Token
					continue
				}
			}

			// A rule of this CR whose match key is unchanged but whose
			// fingerprint differs is an in-place update: ufw replaces it and
			// stores the new action, logging and comment. The one exception is
			// prepend, where ufw reports "Skipping inserting existing rule" and
			// leaves the old rule untouched. Delete it first so the move
			// actually happens; the rule is briefly absent, which ufw cannot
			// avoid.
			replacedForPrepend := false
			if conflictFound && rule.Prepend && conflict.Marker.String() != marker {
				if r.DryRun {
					log.Info("Dry run: would move rule", "marker", marker)
					continue
				}
				if err := r.deleteEntry(ctx, conflict); err != nil {
					errs = append(errs, fmt.Errorf("delete rule %s before prepending: %w", marker, err))
					canPrune = false
					continue
				}
				result.Deleted++
				replacedForPrepend = true
			}

			if r.DryRun {
				log.Info("Dry run: would add rule", "command", ufw.ArgsString(rule.Args()))
				continue
			}

			start := time.Now()
			if _, err := r.Ufw.Run(ctx, rule.Args()...); err != nil {
				errs = append(errs, fmt.Errorf("add rule %s: %w", marker, err))
				canPrune = false
				if replacedForPrepend {
					// The move deleted the old rule; keep the host protected by
					// restoring the new semantics in the old position.
					fallback := rule
					fallback.Prepend = false
					if _, restoreErr := r.Ufw.Run(ctx, fallback.Args()...); restoreErr != nil {
						errs = append(errs, fmt.Errorf("restore rule %s: %w", marker, restoreErr))
					} else {
						result.Added++
					}
				}
				continue
			}
			applyDuration.Observe(time.Since(start).Seconds())
			result.Added++
		}

		// Everything carrying our token but not desired is stale. A desired
		// marker appearing more than once is a crash leftover; keep one copy.
		counts := map[string]int{}
		targets := map[string]int{}
		for _, entry := range state.Entries {
			if entry.Marker.Token != token {
				continue
			}
			marker := entry.Marker.String()
			counts[marker]++
			if _, ok := desiredByMarker[marker]; !ok {
				targets[marker] = -1
			}
		}
		for marker, count := range counts {
			expected, ok := expectedCounts[marker]
			if ok && count > expected {
				targets[marker] = count - expected
			}
		}

		if canPrune {
			deleted, err := r.pruneMarkers(ctx, targets)
			result.Deleted = deleted
			if err != nil {
				errs = append(errs, err)
			}
		}

		if fresh, err := r.readState(ctx); err == nil {
			result.State = fresh
		} else {
			errs = append(errs, err)
		}
		managedRules.Set(float64(len(result.State.Entries)))

		return errors.Join(errs...)
	})

	result.Err = err
	return result
}

// expectedFamilyCount is how many rules ufw creates for one concrete rule.
// An address with no family produces one rule per enabled IP family. An
// explicit 0.0.0.0/0 or ::/0 is not "any": ufw creates a rule for that literal's
// family only. When the host does not list any IPv6 rule we conservatively
// expect one, so duplicate v4 rules are still reduced on hosts where IPv6 is
// disabled.
func expectedFamilyCount(rule ufw.Rule, state ufw.State) int {
	hasV4, hasV6 := false, false
	for _, address := range []string{rule.From.Address, rule.To.Address} {
		if address == "" {
			continue
		}
		if strings.Contains(address, ":") {
			hasV6 = true
		} else {
			hasV4 = true
		}
	}

	count := 0
	if hasV4 {
		count++
	}
	if hasV6 {
		count++
	}
	if count == 0 {
		if state.HasV6() {
			return 2
		}
		return 1
	}
	return count
}

// hasUnmarkedMatch reports whether an unmarked rule has the same ufw match key
// as the desired rule. On a ufw that does not report comments this is how the
// operator recognizes a rule it added earlier.
func hasUnmarkedMatch(state ufw.State, rule ufw.Rule) bool {
	key := rule.MatchKey()
	for _, entry := range state.All {
		if entry.Marker.Token == "" && ufw.MatchKeyForArgs(entry.Args) == key {
			return true
		}
	}
	return false
}

// conflictingEntry returns an existing rule that ufw would replace if the
// desired rule were added. It deliberately includes rules owned by the caller:
// the caller distinguishes an in-place update of its own rule from an attempt to
// take over a rule it does not own.
func conflictingEntry(state ufw.State, rule ufw.Rule) (ufw.Entry, bool) {
	key := rule.MatchKey()
	for _, entry := range state.All {
		if ufw.MatchKeyForArgs(entry.Args) == key {
			return entry, true
		}
	}
	return ufw.Entry{}, false
}

// readState reads the rule set ufw reports. When ufw is inactive,
// "status numbered" lists nothing, so the added-rules report is used instead.
func (r *HostFirewallRuleReconciler) readState(ctx context.Context) (ufw.State, error) {
	out, err := r.Ufw.Run(ctx, "status", "numbered")
	if err != nil {
		return ufw.State{}, fmt.Errorf("read ufw status: %w", err)
	}

	state := ufw.ParseStatusNumbered(out)

	// "show added" works whether the firewall is enabled or not, and unlike
	// "status numbered" it includes unmanaged rules. It is also the only place
	// where rules are shown in ufw's canonical command form, which is needed to
	// detect adds that would be applied as an update to an existing rule.
	added, err := r.Ufw.Run(ctx, "show", "added")
	if err != nil {
		return ufw.State{}, fmt.Errorf("read ufw added rules: %w", err)
	}
	addedState := ufw.ParseShowAdded(added)
	state.All = addedState.All
	if state.Enabled {
		return state, nil
	}
	return addedState, nil
}

// pruneMarkers deletes entries by marker. A negative count means "all"; a
// positive count deletes that many, which is how duplicate markers are reduced
// to one. The state is re-read before every deletion and the deletion targets
// the entry from that fresh listing, so a rule number is never reused blindly.
func (r *HostFirewallRuleReconciler) pruneMarkers(ctx context.Context, targets map[string]int) (int, error) {
	log := logf.FromContext(ctx)
	deleted := 0
	var errs []error

	for _, marker := range slices.Sorted(maps.Keys(targets)) {
		remaining := targets[marker]
		for remaining != 0 {
			fresh, err := r.readState(ctx)
			if err != nil {
				errs = append(errs, err)
				break
			}

			entries := fresh.Find(marker)
			if len(entries) == 0 {
				break
			}

			entry := entries[len(entries)-1]
			if r.DryRun {
				log.Info("Dry run: would delete rule", "marker", marker)
			} else {
				start := time.Now()
				if err := r.deleteEntry(ctx, entry); err != nil {
					errs = append(errs, fmt.Errorf("delete rule %s: %w", marker, err))
					break
				}
				applyDuration.Observe(time.Since(start).Seconds())
			}

			deleted++
			if remaining > 0 {
				remaining--
			}
			if r.DryRun && remaining < 0 {
				break
			}
		}
	}

	return deleted, errors.Join(errs...)
}

func (r *HostFirewallRuleReconciler) deleteEntry(ctx context.Context, entry ufw.Entry) error {
	if entry.Number > 0 {
		_, err := r.Ufw.Run(ctx, "--force", "delete", strconv.Itoa(entry.Number))
		return err
	}

	if len(entry.Args) == 0 {
		return fmt.Errorf("ufw entry has neither a rule number nor arguments; refusing to delete it")
	}

	// Keep the comment: ufw's delete matches the first rule with the same
	// specification when the delete rule has no comment, which could remove an
	// identical unmanaged rule. The comment makes the deletion target exactly
	// the rule this operator owns.
	args := append([]string{"delete"}, entry.Args...)
	_, err := r.Ufw.Run(ctx, args...)
	return err
}
