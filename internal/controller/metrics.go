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

package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	managedRules = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "hfc_managed_rules",
		Help: "Number of ufw rules owned by host-firewall-controller on this node.",
	})
	applyDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "hfc_apply_duration_seconds",
		Help:    "Time spent in one ufw add or delete invocation.",
		Buckets: prometheus.DefBuckets,
	})
	resolutionFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "hfc_resolution_failures_total",
		Help: "Number of failed DNS resolutions. Last known-good addresses are kept.",
	})
	reconcileErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "hfc_reconcile_errors_total",
		Help: "Number of reconciliations that ended in an error.",
	})
)

func init() {
	metrics.Registry.MustRegister(managedRules, applyDuration, resolutionFailures, reconcileErrors)
}
