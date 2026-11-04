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

package ufw

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	statusLineRE  = regexp.MustCompile(`^\[\s*(\d+)\]\s+(.*)$`)
	commentRE     = regexp.MustCompile(`\s+#\s*(.*)$`)
	versionRE     = regexp.MustCompile(`ufw\s+(\d+)\.(\d+)(?:\.(\d+))?`)
	commentToken  = "comment"
	routeKeyword  = "route"
	addedLinePref = "ufw "
)

// Entry is one rule as reported by ufw. Number is zero for entries parsed from
// "ufw show added", which does not expose rule numbers.
type Entry struct {
	Number int
	Marker Marker
	Args   []string
	// V6 reports whether "status numbered" listed this entry as an IPv6 rule.
	V6 bool
}

// State is the set of rules ufw reports on this host.
type State struct {
	Enabled bool
	// Entries contains only rules carrying an operator marker. Unmanaged rules
	// are deliberately excluded so callers cannot prune them by accident.
	Entries []Entry
	// All contains every non-route rule from "ufw show added", including
	// unmanaged rules. It is used to detect rules ufw would update in place.
	All []Entry
}

// Find returns every entry carrying the given marker. A marker can appear more
// than once after a crash mid-apply, or once per IP family when numbering is
// available.
func (s State) Find(marker string) []Entry {
	var out []Entry
	for _, e := range s.Entries {
		if e.Marker.String() == marker {
			out = append(out, e)
		}
	}
	return out
}

// Has reports whether the marker is present at least once.
func (s State) Has(marker string) bool {
	return len(s.Find(marker)) > 0
}

// Count returns how many entries carry the given marker.
func (s State) Count(marker string) int {
	return len(s.Find(marker))
}

// HasV6 reports whether "status numbered" has listed any IPv6 rule. It is used
// to tell a v4/v6 twin pair apart from a duplicate v4 rule on a host where
// IPv6 is disabled.
func (s State) HasV6() bool {
	for _, entry := range s.Entries {
		if entry.V6 {
			return true
		}
	}
	return false
}

// ParseStatusNumbered parses "ufw status numbered". Only lines carrying an
// operator marker become entries; unmanaged rules are ignored entirely.
func ParseStatusNumbered(out string) State {
	state := State{}
	for raw := range strings.SplitSeq(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		if status, ok := strings.CutPrefix(line, "Status:"); ok {
			state.Enabled = strings.TrimSpace(status) == "active"
			continue
		}

		match := statusLineRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		comment := commentRE.FindStringSubmatch(line)
		if comment == nil {
			continue
		}

		marker, ok := ParseMarker(strings.TrimSpace(comment[1]))
		if !ok {
			continue
		}

		var number int
		if _, err := fmt.Sscanf(match[1], "%d", &number); err != nil {
			continue
		}

		rulePart, _, _ := strings.Cut(match[2], "#")
		state.Entries = append(state.Entries, Entry{
			Number: number,
			Marker: marker,
			// The status table is a human readable view, not a ufw command
			// line, so it cannot produce deletable arguments. Deletion of an
			// enabled rule always uses Number.
			V6: strings.Contains(rulePart, "(v6)"),
		})
	}
	return state
}

// ParseShowAdded parses "ufw show added", which lists rules as they were added
// and works whether or not the firewall is currently enabled.
func ParseShowAdded(out string) State {
	state := State{}
	for raw := range strings.SplitSeq(out, "\n") {
		line := strings.TrimSpace(raw)
		added, ok := strings.CutPrefix(line, addedLinePref)
		if !ok {
			continue
		}

		args, err := SplitArgs(added)
		if err != nil {
			continue
		}

		// Route rules are a different netfilter path and are never managed by
		// this operator.
		if len(args) > 0 && (args[0] == routeKeyword || (len(args) > 1 && args[1] == routeKeyword)) {
			continue
		}

		entry := Entry{Args: args}
		for i := 0; i+1 < len(args); i++ {
			if args[i] != commentToken {
				continue
			}
			if marker, ok := ParseMarker(args[i+1]); ok {
				entry.Marker = marker
				state.Entries = append(state.Entries, entry)
			}
			break
		}
		state.All = append(state.All, entry)
	}
	return state
}

// SplitArgs splits a command line into arguments, understanding the single and
// double quotes ufw uses when printing comments.
func SplitArgs(line string) ([]string, error) {
	var (
		out                                  []string
		current                              strings.Builder
		inSingle, inDouble, escaped, started bool
	)

	for _, r := range line {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\' && !inSingle:
			escaped = true
			started = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			started = true
		case r == '"' && !inSingle:
			inDouble = !inDouble
			started = true
		case (r == ' ' || r == '\t') && !inSingle && !inDouble:
			if started {
				out = append(out, current.String())
				current.Reset()
				started = false
			}
		default:
			current.WriteRune(r)
			started = true
		}
	}

	if escaped || inSingle || inDouble {
		return nil, fmt.Errorf("unbalanced quoting in %q", line)
	}
	if started {
		out = append(out, current.String())
	}
	return out, nil
}

// SupportsComments reports whether the ufw version in the given "--version"
// output is new enough to store rule comments (0.36 is the first release).
func SupportsComments(versionOutput string) bool {
	major, minor, ok := parseVersion(versionOutput)
	if !ok {
		return false
	}
	if major != 0 {
		return major > 0
	}
	return minor >= 36
}

func parseVersion(output string) (major, minor int, ok bool) {
	match := versionRE.FindStringSubmatch(output)
	if match == nil {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(match[1], "%d", &major); err != nil {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(match[2], "%d", &minor); err != nil {
		return 0, 0, false
	}
	return major, minor, true
}
