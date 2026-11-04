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

// Package ufw is a pure-Go model of the parts of the ufw command line that the
// operator needs: rule rendering, ownership markers, state parsing and command
// execution. It deliberately has no Kubernetes imports so it can be tested in
// isolation.
package ufw

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
)

// Action is a ufw rule action.
type Action string

const (
	ActionAllow  Action = "allow"
	ActionDeny   Action = "deny"
	ActionReject Action = "reject"
	ActionLimit  Action = "limit"
)

// Direction is the traffic direction a rule applies to.
type Direction string

const (
	DirectionIn  Direction = "in"
	DirectionOut Direction = "out"
)

// Protocol is the layer 4 protocol of a rule.
type Protocol string

const (
	ProtocolAny Protocol = "any"

	anyValue             = string(ProtocolAny)
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// Endpoint is one side of a ufw rule. An empty Address means "any".
type Endpoint struct {
	Address string
	Port    string
}

// Rule is one concrete ufw rule.
type Rule struct {
	Action    Action
	Direction Direction
	Protocol  Protocol
	Interface string
	Log       bool
	Prepend   bool

	From Endpoint
	To   Endpoint
	// ToPorts is the destination port list. When it has more than one entry it
	// is rendered as ufw's comma separated "port 80,443,8080:8090" form.
	ToPorts []string

	// Comment is the full ufw rule comment, including the ownership marker.
	Comment string
}

// Args renders the rule as the argument vector for the ufw binary (without the
// leading "ufw"). Clauses follow the order documented in ufw(8).
func (r Rule) Args() []string {
	args := make([]string, 0, 24)
	if r.Prepend {
		args = append(args, "prepend")
	}
	args = append(args, string(r.Action))

	if r.Direction != "" {
		args = append(args, string(r.Direction))
		if r.Interface != "" {
			args = append(args, "on", r.Interface)
		}
	}

	if r.Log {
		args = append(args, "log")
	}

	if r.Protocol != "" && r.Protocol != ProtocolAny {
		args = append(args, "proto", string(r.Protocol))
	}

	if r.From.Address != "" || r.From.Port != "" {
		args = append(args, "from", orAny(r.From.Address))
		if r.From.Port != "" {
			args = append(args, "port", r.From.Port)
		}
	}

	if r.To.Address != "" || len(r.ToPorts) > 0 || r.To.Port != "" {
		args = append(args, "to", orAny(r.To.Address))
		switch {
		case len(r.ToPorts) > 0:
			args = append(args, "port", strings.Join(r.ToPorts, ","))
		case r.To.Port != "":
			args = append(args, "port", r.To.Port)
		}
	}

	if r.Comment != "" {
		args = append(args, "comment", r.Comment)
	}

	return args
}

func orAny(address string) string {
	if address == "" {
		return string(ProtocolAny)
	}
	return address
}

// Command renders the rule the way ufw's "show added" prints it. ufw uses a
// compact syntax for simple port rules and an extended syntax otherwise. This
// is intentionally a copy of UFWCommandRule.get_command: comparing the result
// with a "show added" line is how the operator detects rules that ufw would
// update in place, regardless of the action, log setting or comment.
func (r Rule) Command() string {
	src := r.From.Address
	dst := r.To.Address
	srcAny := isAnyAddress(src)
	dstAny := isAnyAddress(dst)

	sport := r.From.Port
	if sport == "" {
		sport = anyValue
	}
	dport := r.To.Port
	if len(r.ToPorts) > 0 {
		dport = strings.Join(r.ToPorts, ",")
	}
	if dport == "" {
		dport = anyValue
	}

	protocol := r.Protocol
	if protocol == "" {
		protocol = ProtocolAny
	}
	direction := r.Direction
	if direction == "" {
		direction = DirectionIn
	}

	result := string(r.Action)

	if dstAny && srcAny && sport == anyValue && r.Interface == "" && dport != anyValue {
		// Short syntax.
		if direction == DirectionOut {
			result += " out"
		}
		if r.Log {
			result += " log"
		}
		result += " " + dport
		if protocol != ProtocolAny {
			result += "/" + string(protocol)
		}
	} else {
		// Extended syntax.
		if r.Interface != "" {
			result += " " + string(direction) + " on " + r.Interface
		} else if direction == DirectionOut {
			result += " out"
		}
		if r.Log {
			result += " log"
		}

		for _, endpoint := range []struct {
			loc  string
			port string
			dir  string
		}{
			{src, sport, "from"},
			{dst, dport, "to"},
		} {
			loc := endpoint.loc
			if isAnyAddress(loc) {
				loc = anyValue
			}
			if loc != anyValue || endpoint.port != anyValue {
				result += " " + endpoint.dir + " " + loc
				if endpoint.port != anyValue {
					result += " port " + endpoint.port
				}
			}
		}

		if !strings.Contains(result, " to ") && !strings.Contains(result, " from ") && r.Interface == "" {
			result += " to any"
		}

		if protocol != ProtocolAny {
			result += " proto " + string(protocol)
		}
	}

	if r.Comment != "" {
		result += " comment '" + r.Comment + "'"
	}

	return result
}

// MatchKey is the identity ufw uses when looking for an existing rule. Action,
// logging and the comment are deliberately excluded: ufw replaces an existing
// rule when they differ. Two rules with the same MatchKey can never coexist.
func (r Rule) MatchKey() string {
	args, err := SplitArgs(r.Command())
	if err != nil {
		return ""
	}
	return MatchKeyForArgs(args)
}

// MatchKeyForArgs returns the match key of a ufw command rendered by "show
// added" or by Rule.Command.
func MatchKeyForArgs(args []string) string {
	start := 0
	if len(args) > 0 && args[0] == "prepend" {
		start++
	}
	if start < len(args) {
		start++ // action
	}

	key := make([]string, 0, len(args))
	for _, arg := range args[start:] {
		switch arg {
		case commentToken:
			return strings.Join(key, "\x00")
		case "log", "log-all":
			continue
		default:
			key = append(key, arg)
		}
	}
	return strings.Join(key, "\x00")
}

func isAnyAddress(address string) bool {
	return address == "" || address == "0.0.0.0/0" || address == "::/0"
}

// Fingerprint is a short stable digest of every semantic aspect of the rule.
// The comment is excluded: changing only the human readable part of the comment
// must not force the rule to be recreated. Placement (prepend) is included
// because ufw cannot move an existing rule.
func (r Rule) Fingerprint() string {
	ports := slices.Clone(r.ToPorts)
	slices.Sort(ports)

	canonical := struct {
		Action    Action
		Direction Direction
		Protocol  Protocol
		Interface string
		Log       bool
		Prepend   bool
		FromAddr  string
		FromPort  string
		ToAddr    string
		ToPorts   []string
		ToPort    string
	}{
		Action:    r.Action,
		Direction: r.Direction,
		Protocol:  r.Protocol,
		Interface: r.Interface,
		Log:       r.Log,
		Prepend:   r.Prepend,
		FromAddr:  r.From.Address,
		FromPort:  r.From.Port,
		ToAddr:    r.To.Address,
		ToPorts:   ports,
		ToPort:    r.To.Port,
	}

	payload, _ := json.Marshal(canonical)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])[:fingerprintLen]
}
