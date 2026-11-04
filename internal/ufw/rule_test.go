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

const (
	testCIDR     = "10.0.0.0/8"
	testFromArg  = "from"
	testAnyArg   = "any"
	testProtoArg = "proto"
)

func TestArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule Rule
		want []string
	}{
		{
			name: "simple tcp port",
			rule: Rule{Action: ActionAllow, Protocol: ProtocolTCP, ToPorts: []string{"22"}},
			want: []string{string(ActionAllow), testProtoArg, "tcp", "to", testAnyArg, "port", "22"},
		},
		{
			name: "deny from cidr",
			rule: Rule{Action: ActionDeny, From: Endpoint{Address: testCIDR}},
			want: []string{"deny", testFromArg, testCIDR},
		},
		{
			name: "out on interface with destination",
			rule: Rule{
				Action:    ActionAllow,
				Direction: DirectionOut,
				Interface: "eth0",
				Protocol:  ProtocolTCP,
				To:        Endpoint{Address: "192.0.2.1"},
				ToPorts:   []string{"443"},
			},
			want: []string{string(ActionAllow), "out", "on", "eth0", testProtoArg, "tcp", "to", "192.0.2.1", "port", "443"},
		},
		{
			name: "limit with log",
			rule: Rule{Action: ActionLimit, Protocol: ProtocolTCP, ToPorts: []string{"22"}, Log: true},
			want: []string{"limit", "log", testProtoArg, "tcp", "to", testAnyArg, "port", "22"},
		},
		{
			name: "prepend with port list",
			rule: Rule{Action: ActionAllow, Prepend: true, Protocol: ProtocolTCP, ToPorts: []string{"80", "443", "8080:8090"}},
			want: []string{"prepend", string(ActionAllow), testProtoArg, "tcp", "to", testAnyArg, "port", "80,443,8080:8090"},
		},
		{
			name: "any protocol omits proto clause",
			rule: Rule{Action: ActionAllow, Protocol: ProtocolAny, ToPorts: []string{"53"}},
			want: []string{string(ActionAllow), "to", testAnyArg, "port", "53"},
		},
		{
			name: "source port",
			rule: Rule{
				Action:  ActionAllow,
				From:    Endpoint{Address: "198.51.100.0/24", Port: "1024:65535"},
				ToPorts: []string{"5432"},
			},
			want: []string{string(ActionAllow), testFromArg, "198.51.100.0/24", "port", "1024:65535", "to", testAnyArg, "port", "5432"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.rule.Args(); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Args() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rule Rule
		want string
	}{
		{
			name: "short syntax for a simple port",
			rule: Rule{Action: ActionAllow, Protocol: ProtocolTCP, ToPorts: []string{"22"}},
			want: "allow 22/tcp",
		},
		{
			name: "short syntax omits an any protocol",
			rule: Rule{Action: ActionAllow, Protocol: ProtocolAny, ToPorts: []string{"53"}},
			want: "allow 53",
		},
		{
			name: "short syntax with direction out",
			rule: Rule{Action: ActionAllow, Direction: DirectionOut, Protocol: ProtocolUDP, ToPorts: []string{"53"}},
			want: "allow out 53/udp",
		},
		{
			name: "source cidr uses full syntax",
			rule: Rule{Action: ActionDeny, From: Endpoint{Address: testCIDR}},
			want: "deny from 10.0.0.0/8",
		},
		{
			name: "protocol is printed after the endpoints",
			rule: Rule{Action: ActionAllow, Protocol: ProtocolTCP, From: Endpoint{Address: testCIDR}},
			want: "allow from 10.0.0.0/8 proto tcp",
		},
		{
			name: "source port forces full syntax",
			rule: Rule{Action: ActionAllow, From: Endpoint{Port: "1234"}},
			want: "allow from any port 1234",
		},
		{
			name: "interface and destination",
			rule: Rule{
				Action:    ActionAllow,
				Direction: DirectionOut,
				Interface: "eth0",
				Protocol:  ProtocolTCP,
				To:        Endpoint{Address: "192.0.2.1"},
				ToPorts:   []string{"443"},
			},
			want: "allow out on eth0 to 192.0.2.1 port 443 proto tcp",
		},
		{
			name: "generic rule gets to any",
			rule: Rule{Action: ActionAllow},
			want: "allow to any",
		},
		{
			name: "prepend is not part of the persisted command",
			rule: Rule{Action: ActionAllow, Prepend: true, ToPorts: []string{"22"}},
			want: "allow 22",
		},
		{
			name: "log is printed before the endpoints",
			rule: Rule{Action: ActionLimit, Log: true, Protocol: ProtocolTCP, ToPorts: []string{"22"}},
			want: "limit log 22/tcp",
		},
		{
			name: "comment is appended",
			rule: Rule{Action: ActionAllow, ToPorts: []string{"22"}, Comment: "HFC:ns/name:0123456789ab"},
			want: "allow 22 comment 'HFC:ns/name:0123456789ab'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.rule.Command(); got != tt.want {
				t.Fatalf("Command() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMatchKey(t *testing.T) {
	t.Parallel()

	base := Rule{Action: ActionAllow, Protocol: ProtocolTCP, ToPorts: []string{"22"}}
	key := base.MatchKey()

	for name, rule := range map[string]Rule{
		"different action":  {Action: ActionDeny, Protocol: ProtocolTCP, ToPorts: []string{"22"}},
		"with a log":        {Action: ActionAllow, Log: true, Protocol: ProtocolTCP, ToPorts: []string{"22"}},
		"different comment": {Action: ActionAllow, Protocol: ProtocolTCP, ToPorts: []string{"22"}, Comment: "hello"},
		"prepend":           {Action: ActionAllow, Prepend: true, Protocol: ProtocolTCP, ToPorts: []string{"22"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := rule.MatchKey(); got != key {
				t.Fatalf("MatchKey() = %q, want %q", got, key)
			}
		})
	}

	for name, rule := range map[string]Rule{
		"different port":     {Action: ActionAllow, Protocol: ProtocolTCP, ToPorts: []string{"23"}},
		"different protocol": {Action: ActionAllow, Protocol: ProtocolUDP, ToPorts: []string{"22"}},
		"different source":   {Action: ActionAllow, Protocol: ProtocolTCP, From: Endpoint{Address: testCIDR}, ToPorts: []string{"22"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := rule.MatchKey(); got == key {
				t.Fatalf("MatchKey() = %q, must differ from %q", got, key)
			}
		})
	}
}

func TestMatchKeyForArgs(t *testing.T) {
	t.Parallel()

	first, err := SplitArgs("allow 22/tcp comment 'HFC:ns/name:0123456789ab'")
	if err != nil {
		t.Fatal(err)
	}
	second, err := SplitArgs("deny log 22/tcp")
	if err != nil {
		t.Fatal(err)
	}

	if got, want := MatchKeyForArgs(first), MatchKeyForArgs(second); got != want {
		t.Fatalf("MatchKeyForArgs() = %q, want %q", got, want)
	}

	different, err := SplitArgs("allow 23/tcp")
	if err != nil {
		t.Fatal(err)
	}
	if MatchKeyForArgs(first) == MatchKeyForArgs(different) {
		t.Fatal("different ports must have different match keys")
	}
}

func TestFingerprint(t *testing.T) {
	t.Parallel()

	base := Rule{Action: ActionAllow, Protocol: ProtocolTCP, ToPorts: []string{"80", "443"}}

	firstFingerprint := base.Fingerprint()
	if second := base.Fingerprint(); firstFingerprint != second {
		t.Fatalf("fingerprint is not deterministic: %q != %q", firstFingerprint, second)
	}

	reordered := base
	reordered.ToPorts = []string{"443", "80"}
	if base.Fingerprint() != reordered.Fingerprint() {
		t.Fatal("fingerprint must not depend on port order")
	}

	commentOnly := base
	commentOnly.Comment = "HFC:x/y:0123456789ab | hello"
	if base.Fingerprint() != commentOnly.Fingerprint() {
		t.Fatal("fingerprint must not depend on the comment")
	}

	for name, mutate := range map[string]func(Rule) Rule{
		"prepend":   func(r Rule) Rule { r.Prepend = true; return r },
		"log":       func(r Rule) Rule { r.Log = true; return r },
		"ports":     func(r Rule) Rule { r.ToPorts = []string{"80"}; return r },
		"from port": func(r Rule) Rule { r.From.Port = "1234"; return r },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if base.Fingerprint() == mutate(base).Fingerprint() {
				t.Fatalf("fingerprint must change when %s changes", name)
			}
		})
	}
}
