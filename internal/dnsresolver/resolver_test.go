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

package dnsresolver

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestNormalizeAddrs(t *testing.T) {
	t.Parallel()

	v4 := netip.MustParseAddr("192.0.2.10")
	v6 := netip.MustParseAddr("2001:db8::10")
	mapped := netip.MustParseAddr("::ffff:192.0.2.10")

	got := NormalizeAddrs([]netip.Addr{v6, mapped, v4, {}, v4})
	want := []netip.Addr{v4, v6}

	if !slices.Equal(got, want) {
		t.Fatalf("NormalizeAddrs() = %#v, want %#v", got, want)
	}
}

func TestFakeResolver(t *testing.T) {
	t.Parallel()

	resolver := &FakeResolver{
		Addrs: map[string][]netip.Addr{"web.example.com": {netip.MustParseAddr("192.0.2.10")}},
		Errs:  map[string]error{"bad.example.com": errors.New("NXDOMAIN")},
	}

	addrs, err := resolver.LookupHost(context.Background(), "web.example.com")
	if err != nil || len(addrs) != 1 {
		t.Fatalf("LookupHost() = %#v, %v", addrs, err)
	}

	if _, err := resolver.LookupHost(context.Background(), "bad.example.com"); err == nil {
		t.Fatal("expected the scripted error")
	}

	if resolver.CallCount("web.example.com") != 1 {
		t.Fatalf("CallCount = %d", resolver.CallCount("web.example.com"))
	}
}
