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

package main

import (
	"testing"
	"time"
)

func TestValidateSweepInterval(t *testing.T) {
	t.Parallel()

	for _, interval := range []time.Duration{0, -time.Second} {
		if err := validateSweepInterval(interval); err == nil {
			t.Fatalf("validateSweepInterval(%s) succeeded, want an error", interval)
		}
	}

	for _, interval := range []time.Duration{time.Nanosecond, time.Second, 5 * time.Minute} {
		if err := validateSweepInterval(interval); err != nil {
			t.Fatalf("validateSweepInterval(%s) = %v, want nil", interval, err)
		}
	}
}
