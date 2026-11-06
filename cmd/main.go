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
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
	"github.com/baprx/host-firewall-controller/internal/controller"
	"github.com/baprx/host-firewall-controller/internal/dnsresolver"
	"github.com/baprx/host-firewall-controller/internal/knock"
	"github.com/baprx/host-firewall-controller/internal/ufw"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	// Hidden chroot-and-exec mode used by ufw.ChrootRunner.
	if len(os.Args) > 1 && os.Args[1] == ufw.SelfExecCommand {
		ufw.ExecChrooted(os.Args[2:])
	}

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var (
		metricsAddr            string
		probeAddr              string
		nodeName               string
		hostRoot               string
		ufwPath                string
		sweepInterval          time.Duration
		defaultRefreshInterval time.Duration
		minRefreshInterval     time.Duration
		maxRulesPerNode        int
		maxRulesPerCR          int
		maxAddresses           int
		dryRun                 bool
		lockPath               string
		knockBindAddress       string
		knockTrustedProxies    string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metrics endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&nodeName, "node-name", os.Getenv("NODE_NAME"),
		"The node this manager runs on. Defaults to $NODE_NAME.")
	flag.StringVar(&hostRoot, "host-root", "/host", "Mount point of the host root filesystem.")
	flag.StringVar(&ufwPath, "ufw-path", "/usr/sbin/ufw", "Path to the ufw binary inside the host root.")
	flag.DurationVar(&sweepInterval, "sweep-interval", 5*time.Minute,
		"How often to prune rules that are no longer desired on this node.")
	flag.DurationVar(&defaultRefreshInterval, "default-refresh-interval", 5*time.Minute,
		"Default hostname refresh interval when a rule does not set one.")
	flag.DurationVar(&minRefreshInterval, "min-refresh-interval", 30*time.Second,
		"Minimum hostname refresh interval.")
	flag.IntVar(&maxRulesPerNode, "max-rules-per-node", 256,
		"Maximum number of rules the operator will manage on one node.")
	flag.IntVar(&maxRulesPerCR, "max-rules-per-cr", 64,
		"Maximum number of concrete rules one HostFirewallRule may expand to on one node.")
	flag.IntVar(&maxAddresses, "max-addresses", 16,
		"Default maximum number of addresses used per hostname.")
	flag.BoolVar(&dryRun, "dry-run", false, "Log ufw commands instead of executing them.")
	flag.StringVar(&lockPath, "lock-path", "",
		"Lock file path. Defaults to <host-root>/run/host-firewall-controller.lock.")
	flag.StringVar(&knockBindAddress, "knock-bind-address", "0",
		"The address the knock endpoint binds to. 0 disables it.")
	flag.StringVar(&knockTrustedProxies, "knock-trusted-proxies", "",
		"Comma-separated CIDRs allowed to set X-Forwarded-For.")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if nodeName == "" {
		setupLog.Error(fmt.Errorf("missing node name"), "--node-name or $NODE_NAME is required")
		os.Exit(1)
	}

	if err := validateSweepInterval(sweepInterval); err != nil {
		setupLog.Error(err, "Invalid --sweep-interval")
		os.Exit(1)
	}

	if lockPath == "" {
		lockPath = filepath.Join(hostRoot, "run", "host-firewall-controller.lock")
	}

	runner := &ufw.ChrootRunner{HostRoot: hostRoot, UfwPath: ufwPath}
	ufwVersion := checkUFW(runner)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         false,
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	reconciler := &controller.HostFirewallRuleReconciler{
		Client:                 mgr.GetClient(),
		Scheme:                 mgr.GetScheme(),
		Recorder:               mgr.GetEventRecorder("host-firewall-controller"),
		NodeName:               nodeName,
		Ufw:                    runner,
		Locker:                 func() (func() error, error) { return ufw.AcquireLock(lockPath) },
		Resolver:               dnsresolver.NetResolver{},
		SweepInterval:          sweepInterval,
		DefaultRefreshInterval: defaultRefreshInterval,
		MinRefreshInterval:     minRefreshInterval,
		MaxRulesPerNode:        maxRulesPerNode,
		MaxRulesPerCR:          maxRulesPerCR,
		MaxAddresses:           maxAddresses,
		UFWVersion:             ufwVersion,
		DryRun:                 dryRun,
	}

	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "hostfirewallrule")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if knockBindAddress != "" && knockBindAddress != "0" {
		trusted, err := knock.ParseTrustedProxies(strings.Split(knockTrustedProxies, ","))
		if err != nil {
			setupLog.Error(err, "Invalid --knock-trusted-proxies")
			os.Exit(1)
		}

		namespace := os.Getenv("POD_NAMESPACE")
		if namespace == "" {
			setupLog.Info("POD_NAMESPACE is empty; knocks that require a token will fail closed", "address", knockBindAddress)
		}

		srv := &knock.Server{
			Client:         mgr.GetClient(),
			Reader:         mgr.GetAPIReader(),
			Namespace:      namespace,
			BindAddress:    knockBindAddress,
			TrustedProxies: trusted,
		}
		if err := mgr.Add(srv); err != nil {
			setupLog.Error(err, "Failed to add knock server")
			os.Exit(1)
		}
		setupLog.Info("Starting knock server", "address", knockBindAddress, "trustedProxies", knockTrustedProxies)
	}

	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		// Run one sweep at startup to prune anything left by a previous pod.
		if err := reconciler.ReconcileSweep(ctx); err != nil {
			setupLog.Error(err, "Initial sweep failed")
		}

		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if err := reconciler.ReconcileSweep(ctx); err != nil {
					setupLog.Error(err, "Sweep failed")
				}
			}
		}
	})); err != nil {
		setupLog.Error(err, "Failed to add sweep runnable")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager", "node", nodeName, "ufwVersion", ufwVersion, "dryRun", dryRun)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}

// validateSweepInterval rejects values that would make time.NewTicker panic.
func validateSweepInterval(interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("--sweep-interval must be positive, got %s", interval)
	}
	return nil
}

// checkUFW fails fast when the host ufw cannot store rule comments, because the
// operator relies on them for ownership.
func checkUFW(runner ufw.Runner) string {
	ctx, cancel := context.WithTimeout(context.Background(), ufw.DefaultTimeout)
	defer cancel()

	version, err := ufw.Version(ctx, runner)
	if err != nil {
		setupLog.Error(err, "ufw is not usable inside the host root; the operator cannot manage rules")
		os.Exit(1)
	}

	if !ufw.SupportsComments(version) {
		setupLog.Error(fmt.Errorf("unsupported ufw version"),
			"ufw 0.36 or newer is required because the operator stores ownership in rule comments",
			"version", version)
		os.Exit(1)
	}

	return version
}
