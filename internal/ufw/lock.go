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
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ErrLocked is returned when another process holds the lock.
var ErrLocked = errors.New("ufw lock is held by another process")

// AcquireLock takes an exclusive, non-blocking flock on path. The returned
// function releases it. The lock is used so a terminating DaemonSet pod and its
// replacement can never interleave ufw invocations.
func AcquireLock(path string) (func() error, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}

	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("flock %s: %w", path, err)
	}

	return func() error {
		if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
			_ = file.Close()
			return fmt.Errorf("unlock %s: %w", path, err)
		}
		return file.Close()
	}, nil
}
