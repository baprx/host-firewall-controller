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

package knock

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	resultOK           = "ok"
	resultNotFound     = "not_found"
	resultAmbiguous    = "ambiguous"
	resultUnauthorized = "unauthorized"
	resultBadRequest   = "bad_request"
	resultError        = "error"
)

var knockRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "hfc_knock_requests_total",
	Help: "Number of HTTP knock requests handled by the dynamic IP endpoint.",
}, []string{"result"})

func init() {
	metrics.Registry.MustRegister(knockRequests)
}
