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
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

const (
	// MarkerPrefix starts every comment owned by the operator.
	MarkerPrefix = "HFC:"

	// fingerprintLen is the number of hex characters of the rule fingerprint.
	fingerprintLen = 12
	// maxTokenLen bounds the "<namespace>/<name>" part so a marker always fits
	// comfortably in a ufw comment.
	maxTokenLen = 100
	// MaxCommentLen is the maximum ufw comment length the operator emits. ufw
	// itself does not document a limit; keeping a tenth of a kilobyte of slack
	// avoids surprises across versions.
	MaxCommentLen = 200

	tokenHashLen = 6
	separator    = " | "
)

// Marker identifies one concrete rule owned by one HostFirewallRule.
type Marker struct {
	Token       string
	Fingerprint string
}

// TokenFor derives the stable token for a HostFirewallRule from its identity.
// When "<namespace>/<name>" is too long it is truncated and disambiguated with a
// hash of the UID, so two long-named CRs can never share a token.
func TokenFor(namespace, name, uid string) string {
	token := namespace + "/" + name
	if len(token) <= maxTokenLen {
		return token
	}

	sum := sha256.Sum256([]byte(uid))
	suffix := "~" + hex.EncodeToString(sum[:])[:tokenHashLen]
	keep := maxTokenLen - len(suffix)
	return token[:keep] + suffix
}

// MarkerFor builds the marker of a concrete rule.
func MarkerFor(token string, r Rule) Marker {
	return Marker{Token: token, Fingerprint: r.Fingerprint()}
}

// String renders the marker as it appears at the start of the ufw comment.
func (m Marker) String() string {
	return MarkerPrefix + m.Token + ":" + m.Fingerprint
}

// ParseMarker extracts a marker from a ufw comment. It returns false for
// comments that are not owned by the operator.
func ParseMarker(comment string) (Marker, bool) {
	// Drop the human readable suffix, if any, before looking for the marker.
	if idx := strings.Index(comment, separator); idx >= 0 {
		comment = comment[:idx]
	}
	comment = strings.TrimSpace(comment)

	rest, ok := strings.CutPrefix(comment, MarkerPrefix)
	if !ok {
		return Marker{}, false
	}

	idx := strings.LastIndexByte(rest, ':')
	if idx <= 0 {
		return Marker{}, false
	}

	token, fingerprint := rest[:idx], rest[idx+1:]
	if len(fingerprint) != fingerprintLen || !isHex(fingerprint) {
		return Marker{}, false
	}

	return Marker{Token: token, Fingerprint: fingerprint}, true
}

// IsOurs reports whether comment belongs to the CR identified by token.
func IsOurs(comment, token string) bool {
	return strings.HasPrefix(comment, MarkerPrefix+token+":")
}

// ComposeComment builds the final ufw comment: the marker first (it must never
// be truncated), then the optional human readable part.
func ComposeComment(m Marker, userComment string) string {
	base := m.String()
	if userComment == "" {
		return base
	}

	// Trim rune-wise so a multi-byte character is never cut in half, while
	// respecting the byte budget.
	allowed := MaxCommentLen - len(base) - len(separator)
	if allowed <= 0 {
		return base
	}

	var builder strings.Builder
	for _, r := range userComment {
		size := utf8.RuneLen(r)
		if builder.Len()+size > allowed {
			break
		}
		builder.WriteRune(r)
	}

	return base + separator + builder.String()
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
