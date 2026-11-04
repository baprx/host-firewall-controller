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
	"context"
	"slices"
	"strings"
	"sync"
)

// Response is one scripted answer for FakeRunner.
type Response struct {
	// Match selects the calls this response applies to. A nil Match matches
	// every call.
	Match func(args []string) bool
	Out   string
	Err   error
}

// FakeRunner is a scripted Runner for tests. It records every call.
type FakeRunner struct {
	mu        sync.Mutex
	Responses []Response
	Calls     [][]string
}

// Run implements Runner.
func (f *FakeRunner) Run(_ context.Context, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.Calls = append(f.Calls, append([]string(nil), args...))
	for _, response := range f.Responses {
		if response.Match == nil || response.Match(args) {
			return response.Out, response.Err
		}
	}
	return "", nil
}

// CallsMatching returns the recorded calls containing the given argument
// sequence.
func (f *FakeRunner) CallsMatching(sequence ...string) [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out [][]string
	for _, call := range f.Calls {
		if containsSequence(call, sequence) {
			out = append(out, call)
		}
	}
	return out
}

// Reset forgets all recorded calls.
func (f *FakeRunner) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = nil
}

func containsSequence(haystack, needle []string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ArgsHas reports whether the argument vector contains value as a standalone
// argument.
func ArgsHas(args []string, value string) bool {
	return slices.Contains(args, value)
}

// ArgsString renders an argument vector for logs.
func ArgsString(args []string) string {
	return "ufw " + strings.Join(args, " ")
}
