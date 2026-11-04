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
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testHostRoot = "/host"
	testUFWPath  = "/usr/sbin/ufw"
)

func TestChrootRunnerBuildsCommand(t *testing.T) {
	t.Parallel()

	var capturedName string
	var capturedArgs []string

	runner := &ChrootRunner{HostRoot: testHostRoot, UfwPath: testUFWPath, executable: "/manager"}
	runner.newCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedName = name
		capturedArgs = args
		return exec.CommandContext(ctx, "true")
	}

	if _, err := runner.Run(context.Background(), "--force", "delete", "3"); err != nil {
		t.Fatal(err)
	}

	if capturedName != "/manager" {
		t.Fatalf("command = %q, want /manager", capturedName)
	}
	if want := []string{SelfExecCommand, testHostRoot, testUFWPath, "--force", "delete", "3"}; !slices.Equal(capturedArgs, want) {
		t.Fatalf("args = %#v, want %#v", capturedArgs, want)
	}
}

func TestChrootRunnerSetsLocale(t *testing.T) {
	t.Parallel()

	runner := &ChrootRunner{HostRoot: testHostRoot, UfwPath: testUFWPath}
	runner.newCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", `printf '%s' "$LC_ALL"`)
	}

	out, err := runner.Run(context.Background(), "status")
	if err != nil {
		t.Fatal(err)
	}
	if out != "C" {
		t.Fatalf("LC_ALL = %q, want C", out)
	}
}

func TestChrootRunnerReportsStderr(t *testing.T) {
	t.Parallel()

	runner := &ChrootRunner{HostRoot: testHostRoot, UfwPath: testUFWPath}
	runner.newCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "echo 'ERROR: bad rule' >&2; exit 1")
	}

	_, err := runner.Run(context.Background(), "allow", "bogus")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "ERROR: bad rule") {
		t.Fatalf("stderr missing from error: %v", err)
	}
}

func TestChrootRunnerTimeout(t *testing.T) {
	t.Parallel()

	runner := &ChrootRunner{HostRoot: testHostRoot, UfwPath: testUFWPath, Timeout: 50 * time.Millisecond}
	runner.newCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sleep", "5")
	}

	start := time.Now()
	if _, err := runner.Run(context.Background(), "status"); err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("timeout not enforced, took %s", elapsed)
	}
}

func TestFakeRunner(t *testing.T) {
	t.Parallel()

	fake := &FakeRunner{Responses: []Response{
		{Match: func(args []string) bool { return ArgsHas(args, "status") }, Out: "Status: active\n"},
		{Match: func(args []string) bool { return ArgsHas(args, "delete") }, Err: errors.New("boom")},
	}}

	out, err := fake.Run(context.Background(), "status", "numbered")
	if err != nil || out != "Status: active\n" {
		t.Fatalf("unexpected response: %q, %v", out, err)
	}
	if _, err := fake.Run(context.Background(), "--force", "delete", "3"); err == nil {
		t.Fatal("expected the scripted error")
	}

	if got := fake.CallsMatching("delete"); len(got) != 1 {
		t.Fatalf("CallsMatching(delete) = %#v", got)
	}
	if got := fake.CallsMatching("missing"); len(got) != 0 {
		t.Fatalf("unexpected match: %#v", got)
	}
}
