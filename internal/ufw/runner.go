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
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultTimeout bounds one ufw invocation.
const DefaultTimeout = 30 * time.Second

// SelfExecCommand is the hidden argv[1] that turns the manager binary into a
// chroot-and-exec helper. Using ourselves avoids shipping chroot or a shell in
// the container image.
const SelfExecCommand = "__ufw-exec"

// Runner executes a ufw command and returns its standard output.
type Runner interface {
	Run(ctx context.Context, args ...string) (string, error)
}

// ChrootRunner executes the host's own ufw inside the host root. The command is
// run through a re-exec of the manager binary (see ExecChrooted), so the image
// only needs the static manager binary.
type ChrootRunner struct {
	HostRoot string
	UfwPath  string
	Timeout  time.Duration

	// executable overrides os.Executable in tests.
	executable string
	// newCommand is overridden in tests to inspect the built command.
	newCommand func(ctx context.Context, name string, args ...string) *exec.Cmd
}

// Run implements Runner.
func (r *ChrootRunner) Run(ctx context.Context, args ...string) (string, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	executable := r.executable
	if executable == "" {
		var err error
		executable, err = os.Executable()
		if err != nil {
			return "", fmt.Errorf("locate own executable: %w", err)
		}
	}

	newCommand := r.newCommand
	if newCommand == nil {
		newCommand = exec.CommandContext
	}

	commandArgs := append([]string{SelfExecCommand, r.HostRoot, r.UfwPath}, args...)
	cmd := newCommand(ctx, executable, commandArgs...)
	cmd.Env = []string{
		"LC_ALL=C",
		"LANG=C",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin",
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = "no stderr output"
		}
		return stdout.String(), fmt.Errorf("ufw %s: %w: %s", strings.Join(args, " "), err, message)
	}

	return stdout.String(), nil
}

// ExecChrooted is the helper side of ChrootRunner. It chroots into the host
// root and replaces itself with the host ufw. It never returns on success.
func ExecChrooted(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "hfc: __ufw-exec requires a host root and a ufw path")
		os.Exit(127)
	}

	hostRoot, ufwPath := args[0], args[1]
	ufwArgs := args[2:]

	if err := unix.Chroot(hostRoot); err != nil {
		fmt.Fprintf(os.Stderr, "hfc: chroot %s: %v\n", hostRoot, err)
		os.Exit(127)
	}
	if err := unix.Chdir("/"); err != nil {
		fmt.Fprintf(os.Stderr, "hfc: chdir into %s: %v\n", hostRoot, err)
		os.Exit(127)
	}

	env := []string{
		"LC_ALL=C",
		"LANG=C",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin",
	}
	argv := append([]string{ufwPath}, ufwArgs...)
	if err := unix.Exec(ufwPath, argv, env); err != nil {
		fmt.Fprintf(os.Stderr, "hfc: exec %s: %v\n", ufwPath, err)
		os.Exit(127)
	}
}

// Version returns the raw output of "ufw --version".
func Version(ctx context.Context, runner Runner) (string, error) {
	out, err := runner.Run(ctx, "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}
