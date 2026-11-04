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
	"strings"
	"testing"
)

func TestTokenFor(t *testing.T) {
	t.Parallel()

	if got := TokenFor("infra", "allow-ssh", "uid"); got != "infra/allow-ssh" {
		t.Fatalf("TokenFor() = %q", got)
	}

	long := strings.Repeat("a", 200)
	first := TokenFor("infra", long, "uid-1")
	second := TokenFor("infra", long, "uid-2")

	if len(first) > maxTokenLen {
		t.Fatalf("token too long: %d", len(first))
	}
	if first != TokenFor("infra", long, "uid-1") {
		t.Fatal("token is not deterministic")
	}
	if first == second {
		t.Fatal("truncated tokens must be disambiguated by UID")
	}
	if !strings.Contains(first, "~") {
		t.Fatalf("truncated token should carry a hash suffix: %q", first)
	}
}

func TestMarkerRoundTrip(t *testing.T) {
	t.Parallel()

	rule := Rule{Action: ActionAllow, Protocol: ProtocolTCP, ToPorts: []string{"22"}}
	marker := MarkerFor("infra/allow-ssh", rule)
	rendered := marker.String()

	if !strings.HasPrefix(rendered, "HFC:infra/allow-ssh:") {
		t.Fatalf("unexpected marker rendering %q", rendered)
	}

	parsed, ok := ParseMarker(rendered)
	if !ok || parsed != marker {
		t.Fatalf("ParseMarker() = %#v, %v; want %#v", parsed, ok, marker)
	}

	if _, ok := ParseMarker("allow ssh"); ok {
		t.Fatal("unmanaged comment must not parse as a marker")
	}
	if _, ok := ParseMarker("HFC:infra/a:nothex"); ok {
		t.Fatal("non-hex fingerprint must not parse")
	}
}

func TestMarkerWithUserComment(t *testing.T) {
	t.Parallel()

	marker := MarkerFor("infra/a", Rule{Action: ActionAllow, ToPorts: []string{"80"}})
	comment := ComposeComment(marker, "public web")

	parsed, ok := ParseMarker(comment)
	if !ok || parsed != marker {
		t.Fatalf("ParseMarker(%q) = %#v, %v", comment, parsed, ok)
	}
	if !strings.Contains(comment, "public web") {
		t.Fatalf("user comment missing from %q", comment)
	}
}

func TestComposeCommentTruncates(t *testing.T) {
	t.Parallel()

	marker := MarkerFor("infra/a", Rule{Action: ActionAllow})
	comment := ComposeComment(marker, strings.Repeat("é", 300))

	if len(comment) > MaxCommentLen {
		t.Fatalf("comment too long: %d", len(comment))
	}
	if !strings.HasPrefix(comment, marker.String()) {
		t.Fatal("marker must never be truncated")
	}
	if !strings.Contains(comment, "é") {
		t.Fatal("multi-byte characters must not be cut in half")
	}
}
