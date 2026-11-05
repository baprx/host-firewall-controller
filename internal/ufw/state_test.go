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
	"reflect"
	"testing"
)

const activeStatus = `Status: active

To                         Action      From
--                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # HFC:allow-ssh:0123456789ab
[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)              # HFC:allow-ssh:0123456789ab
[ 3] 80/tcp                     ALLOW IN    Anywhere
[ 4] Anywhere on eth0           ALLOW       192.168.0.0/16             # HFC:web:abcdef012345
[ 5] 10.0.0.0/8                ALLOW OUT   Anywhere on eth1           # HFC:out:111111111111 | office range
`

func TestParseStatusNumberedHasNoCommandArgs(t *testing.T) {
	t.Parallel()

	state := ParseStatusNumbered(activeStatus)
	for _, entry := range state.Entries {
		if len(entry.Args) != 0 {
			t.Fatalf("status entry %d exposes args %q; the status table is not a ufw command line",
				entry.Number, entry.Args)
		}
	}
}

func TestParseStatusNumbered(t *testing.T) {
	t.Parallel()

	state := ParseStatusNumbered(activeStatus)

	if !state.Enabled {
		t.Fatal("expected Enabled")
	}
	if len(state.Entries) != 4 {
		t.Fatalf("got %d entries, want 4", len(state.Entries))
	}

	ssh := state.Find("HFC:allow-ssh:0123456789ab")
	if len(ssh) != 2 {
		t.Fatalf("dual-stack twins not both found: %#v", ssh)
	}
	if ssh[0].Number != 1 || ssh[1].Number != 2 {
		t.Fatalf("unexpected numbers: %d, %d", ssh[0].Number, ssh[1].Number)
	}
	if ssh[0].V6 || !ssh[1].V6 {
		t.Fatalf("v6 markers = %v, %v; want false, true", ssh[0].V6, ssh[1].V6)
	}
	if !state.HasV6() {
		t.Fatal("HasV6() = false, want true")
	}
	if got := state.Count("HFC:allow-ssh:0123456789ab"); got != 2 {
		t.Fatalf("Count() = %d, want 2", got)
	}

	if state.Has("HFC:absent:0123456789ab") {
		t.Fatal("absent marker reported as present")
	}

	// The unmanaged rule on line 3 must not show up at all.
	for _, entry := range state.Entries {
		if entry.Number == 3 {
			t.Fatal("unmanaged rule was parsed as managed")
		}
	}

	// A user comment containing the separator still parses back to the marker.
	out, ok := ParseMarker("HFC:out:111111111111 | office range")
	if !ok || out.Token != "out" {
		t.Fatalf("marker with user comment = %#v, %v", out, ok)
	}
}

func TestParseStatusNumberedInactive(t *testing.T) {
	t.Parallel()

	state := ParseStatusNumbered("Status: inactive\n")
	if state.Enabled {
		t.Fatal("inactive firewall reported as enabled")
	}
	if len(state.Entries) != 0 {
		t.Fatalf("inactive status must not list rules, got %#v", state.Entries)
	}
}

const showAdded = `Added user rules (see 'ufw status' for running firewall):
ufw allow proto tcp from 10.0.0.0/8 comment 'HFC:allow-ssh:0123456789ab'
ufw limit 22/tcp comment 'HFC:ssh:aaaaaaaaaaaa | rate limited'
ufw allow 3333
ufw route allow in on eth0 out on eth1 comment 'HFC:route:bbbbbbbbbbbb'
`

func TestParseShowAdded(t *testing.T) {
	t.Parallel()

	state := ParseShowAdded(showAdded)

	if len(state.Entries) != 2 {
		t.Fatalf("got %d entries, want 2: %#v", len(state.Entries), state.Entries)
	}
	if len(state.All) != 3 {
		t.Fatalf("got %d all entries, want 3 (including the unmanaged rule): %#v", len(state.All), state.All)
	}

	first := state.Entries[0]
	if first.Number != 0 {
		t.Fatalf("show added entries must not have a number, got %d", first.Number)
	}
	if first.Marker.Token != "allow-ssh" {
		t.Fatalf("unexpected marker %#v", first.Marker)
	}

	second := state.Entries[1]
	if !state.Has(second.Marker.String()) {
		t.Fatal("limit rule not found by marker")
	}
}

func TestSplitArgs(t *testing.T) {
	t.Parallel()

	got, err := SplitArgs("allow 22/tcp comment 'a b | c'")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"allow", "22/tcp", "comment", "a b | c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SplitArgs() = %#v, want %#v", got, want)
	}

	if _, err := SplitArgs("comment 'unterminated"); err == nil {
		t.Fatal("expected an error for unterminated quoting")
	}
}

func TestSupportsComments(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		version string
		want    bool
	}{
		{"ufw 0.36.2", true},
		{"ufw 0.36", true},
		{"ufw 0.35", false},
		{"ufw 0.40.1", true},
		{"garbage", false},
		{"", false},
	} {
		if got := SupportsComments(tt.version); got != tt.want {
			t.Errorf("SupportsComments(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}
