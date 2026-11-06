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
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func mustPrefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()

	prefixes, err := ParseTrustedProxies(values)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%v) returned error: %v", values, err)
	}

	return prefixes
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		forwarded  []string
		trusted    []string
		want       string
		wantErr    bool
	}{
		{
			name:       "IPv4 remote address",
			remoteAddr: "203.0.113.9:1234",
			want:       "203.0.113.9",
		},
		{
			name:       "IPv6 remote address",
			remoteAddr: "[2001:db8::1]:443",
			want:       "2001:db8::1",
		},
		{
			name:       "IPv4-mapped IPv6 remote address",
			remoteAddr: "[::ffff:203.0.113.9]:1234",
			want:       "203.0.113.9",
		},
		{
			name:       "remote address without port",
			remoteAddr: "203.0.113.9",
			want:       "203.0.113.9",
		},
		{
			name:       "trusted peer uses forwarded addresses",
			remoteAddr: "203.0.113.9:1234",
			forwarded:  []string{"198.51.100.7, 203.0.113.9"},
			trusted:    []string{"203.0.113.0/24"},
			want:       "198.51.100.7",
		},
		{
			name:       "untrusted peer ignores forwarded addresses",
			remoteAddr: "198.51.100.7:1234",
			forwarded:  []string{"203.0.113.50"},
			trusted:    []string{"203.0.113.0/24"},
			want:       "198.51.100.7",
		},
		{
			name:       "all forwarded addresses trusted returns leftmost",
			remoteAddr: "203.0.113.9:1234",
			forwarded:  []string{"198.51.100.7, 203.0.113.8"},
			trusted:    []string{"203.0.113.0/24", "198.51.100.0/24"},
			want:       "198.51.100.7",
		},
		{
			name:       "zoned forwarded address",
			remoteAddr: "203.0.113.9:1234",
			forwarded:  []string{"2001:db8::1%eth0"},
			trusted:    []string{"203.0.113.0/24"},
			want:       "2001:db8::1",
		},
		{
			name:       "IPv4-mapped forwarded address",
			remoteAddr: "203.0.113.9:1234",
			forwarded:  []string{"::ffff:198.51.100.7"},
			trusted:    []string{"203.0.113.0/24"},
			want:       "198.51.100.7",
		},
		{
			name:       "multiple forwarded headers",
			remoteAddr: "203.0.113.9:1234",
			forwarded:  []string{"198.51.100.7, 203.0.113.8", "10.0.0.1"},
			trusted:    []string{"203.0.113.0/24"},
			want:       "10.0.0.1",
		},
		{
			name:       "unspecified forwarded address",
			remoteAddr: "203.0.113.9:1234",
			forwarded:  []string{"0.0.0.0"},
			trusted:    []string{"203.0.113.0/24"},
			wantErr:    true,
		},
		{
			name:       "malformed forwarded header",
			remoteAddr: "203.0.113.9:1234",
			forwarded:  []string{"not-an-address"},
			trusted:    []string{"203.0.113.0/24"},
			wantErr:    true,
		},
		{
			name:       "malformed entry left of an untrusted address",
			remoteAddr: "203.0.113.9:1234",
			forwarded:  []string{"not-an-address, 198.51.100.7"},
			trusted:    []string{"203.0.113.0/24"},
			wantErr:    true,
		},
		{
			name:       "unspecified entry left of an untrusted address",
			remoteAddr: "203.0.113.9:1234",
			forwarded:  []string{"0.0.0.0, 198.51.100.7"},
			trusted:    []string{"203.0.113.0/24"},
			wantErr:    true,
		},
		{
			name:       "empty forwarded header from trusted peer",
			remoteAddr: "203.0.113.9:1234",
			forwarded:  []string{""},
			trusted:    []string{"203.0.113.0/24"},
			wantErr:    true,
		},
		{
			name:       "unspecified peer",
			remoteAddr: "0.0.0.0:1234",
			wantErr:    true,
		},
		{
			name:       "invalid peer",
			remoteAddr: "not-an-address",
			wantErr:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: test.remoteAddr,
				Header:     http.Header{},
			}
			for _, value := range test.forwarded {
				req.Header.Add("X-Forwarded-For", value)
			}

			got, err := clientIP(req, mustPrefixes(t, test.trusted...))
			if test.wantErr {
				if err == nil {
					t.Fatalf("clientIP() = %v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("clientIP() returned error: %v", err)
			}

			want := netip.MustParseAddr(test.want)
			if got != want {
				t.Fatalf("clientIP() = %v, want %v", got, want)
			}
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		want    []string
		wantErr bool
	}{
		{
			name:   "IPv4 and IPv6 prefixes",
			values: []string{"10.0.0.0/8", "2001:db8::/32"},
			want:   []string{"10.0.0.0/8", "2001:db8::/32"},
		},
		{
			name:   "prefixes are masked",
			values: []string{"10.1.2.3/8"},
			want:   []string{"10.0.0.0/8"},
		},
		{
			name:   "whitespace and empty entries are ignored",
			values: []string{" 10.0.0.0/8 ", "", "   ", "2001:db8::/32"},
			want:   []string{"10.0.0.0/8", "2001:db8::/32"},
		},
		{
			name:   "no entries",
			values: nil,
			want:   []string{},
		},
		{
			name:    "invalid prefix",
			values:  []string{"not-a-cidr"},
			wantErr: true,
		},
		{
			name:    "bare address",
			values:  []string{"10.0.0.1"},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseTrustedProxies(test.values)
			if test.wantErr {
				if err == nil {
					t.Fatalf("ParseTrustedProxies(%v) = %v, want error", test.values, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTrustedProxies(%v) returned error: %v", test.values, err)
			}

			if len(got) != len(test.want) {
				t.Fatalf("ParseTrustedProxies(%v) = %v, want %v", test.values, got, test.want)
			}
			for i, want := range test.want {
				if got[i] != netip.MustParsePrefix(want) {
					t.Fatalf("ParseTrustedProxies(%v)[%d] = %v, want %v", test.values, i, got[i], want)
				}
			}
		})
	}
}

func TestParseTrustedProxiesErrorNamesValue(t *testing.T) {
	_, err := ParseTrustedProxies([]string{"10.0.0.0/8", "not-a-cidr"})
	if err == nil {
		t.Fatal("ParseTrustedProxies() returned no error, want error")
	}
	if !strings.Contains(err.Error(), "not-a-cidr") {
		t.Fatalf("ParseTrustedProxies() error = %q, want it to name the offending value", err)
	}
}
