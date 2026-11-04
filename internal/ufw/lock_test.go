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
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
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

func TestAcquireUFWLockIsInheritable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ufw.lock")
	lock, err := acquireUFWLock(path)
	if err != nil {
		t.Fatalf("acquireUFWLock() error = %v", err)
	}
	defer func() { _ = lock.Close() }()

	flags, err := unix.FcntlInt(lock.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD error = %v", err)
	}
	if flags&unix.FD_CLOEXEC != 0 {
		t.Fatalf("lock descriptor has FD_CLOEXEC set")
	}

	// fcntl locks are per-process, so a second acquisition by this process
	// must succeed. UFW relies on this when it locks the same file after exec.
	again, err := acquireUFWLock(path)
	if err != nil {
		t.Fatalf("second acquireUFWLock() error = %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatalf("closing second lock error = %v", err)
	}
}

func TestAcquireUFWLockIsProcessWide(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ufw.lock")
	lock, err := acquireUFWLock(path)
	if err != nil {
		t.Fatalf("acquireUFWLock() error = %v", err)
	}

	run := func() int {
		cmd := exec.Command(os.Args[0], "-test.run=^TestUFWLockHelperProcess$")
		cmd.Env = append(os.Environ(),
			"HFC_UFW_LOCK_HELPER=1",
			"HFC_UFW_LOCK_PATH="+path,
		)
		_ = cmd.Run()
		if cmd.ProcessState == nil {
			t.Fatal("helper process did not run")
		}
		return cmd.ProcessState.ExitCode()
	}

	if code := run(); code != 42 {
		t.Fatalf("helper exit code = %d, want 42 (lock held)", code)
	}

	if err := lock.Close(); err != nil {
		t.Fatalf("closing lock error = %v", err)
	}

	if code := run(); code != 0 {
		t.Fatalf("helper exit code after release = %d, want 0", code)
	}
}

func TestUFWLockHelperProcess(t *testing.T) {
	if os.Getenv("HFC_UFW_LOCK_HELPER") != "1" {
		return
	}

	file, err := os.OpenFile(os.Getenv("HFC_UFW_LOCK_PATH"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		os.Exit(2)
	}
	defer func() { _ = file.Close() }()

	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock); err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EACCES) {
			os.Exit(42)
		}
		os.Exit(2)
	}
	os.Exit(0)
}
