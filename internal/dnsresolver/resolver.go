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

// Package dnsresolver resolves FQDN rule endpoints. It exists so the
// controller can be tested with a fake resolver.
package dnsresolver

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// DefaultTimeout bounds one lookup.
const DefaultTimeout = 10 * time.Second

// Resolver resolves a hostname to a sorted, de-duplicated set of addresses.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]netip.Addr, error)
}

// NetResolver uses the resolver configured on the host (/etc/resolv.conf).
type NetResolver struct {
	Timeout time.Duration
}

// LookupHost implements Resolver.
func (r NetResolver) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	return NormalizeAddrs(addrs), nil
}

// NormalizeAddrs unmaps IPv4-in-IPv6 addresses, drops invalid ones, de-duplicates
// and sorts the result so the desired rule set is stable.
func NormalizeAddrs(addrs []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(addrs))
	out := make([]netip.Addr, 0, len(addrs))

	for _, addr := range addrs {
		addr = addr.Unmap()
		if !addr.IsValid() {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}

	slices.SortFunc(out, func(a, b netip.Addr) int {
		return a.Compare(b)
	})
	return out
}

// FakeResolver is a scripted Resolver for tests.
type FakeResolver struct {
	mu    sync.Mutex
	Addrs map[string][]netip.Addr
	Errs  map[string]error
	Calls map[string]int
}

// LookupHost implements Resolver.
func (f *FakeResolver) LookupHost(_ context.Context, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.Calls == nil {
		f.Calls = map[string]int{}
	}
	f.Calls[host]++

	if err, ok := f.Errs[host]; ok && err != nil {
		return nil, err
	}

	return NormalizeAddrs(f.Addrs[host]), nil
}

// CallCount returns how many times host was looked up.
func (f *FakeResolver) CallCount(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Calls[host]
}
