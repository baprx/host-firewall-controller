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
	"errors"
	"path/filepath"
	"testing"
)

func TestLockIsExclusive(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ufw.lock")

	release, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("first AcquireLock() error = %v", err)
	}

	if _, err := AcquireLock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second AcquireLock() error = %v, want ErrLocked", err)
	}

	if err := release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}

	releaseAgain, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("AcquireLock() after release error = %v", err)
	}
	if err := releaseAgain(); err != nil {
		t.Fatalf("release() error = %v", err)
	}
}
