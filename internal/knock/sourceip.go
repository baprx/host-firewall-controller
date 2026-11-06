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

package knock

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// ParseTrustedProxies parses a list of CIDRs into masked prefixes. Empty
// entries are ignored. It returns the first parse error.
func ParseTrustedProxies(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("parse trusted proxy %q: %w", value, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	return prefixes, nil
}

// clientIP returns the address a request originates from. X-Forwarded-For is
// only honoured when the immediate peer is a trusted proxy. Malformed or
// unspecified forwarded entries are rejected instead of falling back to the
// peer address.
func clientIP(r *http.Request, trusted []netip.Prefix) (netip.Addr, error) {
	peer, err := parseRemoteAddr(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	if !isTrusted(peer, trusted) {
		return peer, nil
	}

	headers := r.Header.Values("X-Forwarded-For")
	if len(headers) == 0 {
		return peer, nil
	}

	entries := strings.Split(strings.Join(headers, ","), ",")
	addresses := make([]netip.Addr, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		addr, err := parseClientAddr(entry)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("parse X-Forwarded-For entry %q: %w", entry, err)
		}
		addresses = append(addresses, addr)
	}

	// Walk from the closest proxy towards the client and stop at the first
	// address that is not a trusted proxy. Every entry was validated above, so
	// a malformed or unspecified entry anywhere in the header fails closed.
	for _, addr := range slices.Backward(addresses) {
		if !isTrusted(addr, trusted) {
			return addr, nil
		}
	}

	// Every forwarded address is a trusted proxy: the leftmost entry is the
	// original client.
	return addresses[0], nil
}

// parseRemoteAddr extracts the peer address from RemoteAddr, which is usually
// host:port but may be a bare address.
func parseRemoteAddr(remoteAddr string) (netip.Addr, error) {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}

	addr, err := parseClientAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse remote address %q: %w", remoteAddr, err)
	}

	return addr, nil
}

// parseClientAddr parses and normalizes an address, rejecting unspecified
// values.
func parseClientAddr(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}

	addr = addr.Unmap().WithZone("")
	if addr.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("address %q is unspecified", value)
	}

	return addr, nil
}

// isTrusted reports whether addr belongs to one of the trusted prefixes.
func isTrusted(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}
