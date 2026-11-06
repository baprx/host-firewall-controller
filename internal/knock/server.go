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

// Package knock implements the HTTP endpoint that turns a request path into a
// dynamic grant on a HostFirewallRule.
package knock

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/baprx/host-firewall-controller/api/v1alpha1"
)

const (
	// apiTimeout bounds the Kubernetes API calls made while serving one request.
	apiTimeout = 10 * time.Second
	// shutdownTimeout bounds the graceful shutdown started by Start.
	shutdownTimeout = 10 * time.Second
)

// Server serves the dynamic IP knock endpoint. It is a manager Runnable: Start
// blocks until the context is cancelled and NeedLeaderElection is false so every
// pod runs its own server.
type Server struct {
	Client         client.Client
	Reader         client.Reader
	Namespace      string
	BindAddress    string
	TrustedProxies []netip.Prefix
	Now            func() time.Time
}

// Handler returns the handler that serves every knock path.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.handle)
}

// NeedLeaderElection reports that every pod must run the server.
func (s *Server) NeedLeaderElection() bool {
	return false
}

// Start serves requests until ctx is cancelled. An empty or "0" bind address
// disables the server.
func (s *Server) Start(ctx context.Context) error {
	if s.BindAddress == "" || s.BindAddress == "0" {
		return nil
	}

	server := &http.Server{
		Addr:              s.BindAddress,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errs := make(chan error, 1)
	go func() {
		errs <- server.ListenAndServe()
	}()

	select {
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		if err := <-errs; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// handle resolves the request path to one rule, authorizes it, and records the
// source address as the rule's cluster-wide dynamic grant.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		s.reject(w, r, http.StatusMethodNotAllowed, resultBadRequest,
			"Rejected knock: method not allowed", "method", r.Method)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), apiTimeout)
	defer cancel()

	var list securityv1alpha1.HostFirewallRuleList
	if err := s.Client.List(ctx, &list); err != nil {
		s.reject(w, r, http.StatusInternalServerError, resultError,
			"Failed to list HostFirewallRules", "error", err)
		return
	}

	rule, side, code := s.matchRule(&list, r.URL.Path)
	switch code {
	case http.StatusNotFound:
		s.reject(w, r, http.StatusNotFound, resultNotFound,
			"Rejected knock: no rule matches the path")
		return
	case http.StatusConflict:
		s.reject(w, r, http.StatusConflict, resultAmbiguous,
			"Rejected knock: several rules match the path")
		return
	}

	_, dynamic := rule.Spec.DynamicEndpoint()
	if dynamic == nil {
		// matchRule only returns rules with a dynamic endpoint. Fail closed if
		// that invariant is ever broken.
		s.reject(w, r, http.StatusInternalServerError, resultError,
			"Matched rule has no dynamic endpoint", "rule", rule.Name)
		return
	}

	if code, err := s.authorize(ctx, r, dynamic.TokenSecretRef); code != 0 {
		s.reject(w, r, code, resultForStatus(code), "Rejected knock: token check failed",
			"rule", rule.Name, "error", err)
		return
	}

	addr, err := clientIP(r, s.TrustedProxies)
	if err != nil {
		s.reject(w, r, http.StatusBadRequest, resultBadRequest,
			"Rejected knock: invalid client address", "rule", rule.Name, "error", err)
		return
	}

	if err := s.storeGrant(ctx, rule, side, addr); err != nil {
		s.reject(w, r, http.StatusInternalServerError, resultError,
			"Failed to store dynamic grant", "rule", rule.Name, "error", err)
		return
	}

	knockRequests.WithLabelValues(resultOK).Inc()

	var expiresAt any
	if dynamic.TTL != nil {
		expiresAt = s.now().Add(dynamic.TTL.Duration)
	}
	log.FromContext(r.Context()).Info("Accepted knock",
		"rule", rule.Name,
		"path", dynamic.Path,
		"address", addr.String(),
		"expiresAt", expiresAt,
	)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// matchRule returns the rule bound to path, its dynamic side, and a sentinel
// status code: 200 for exactly one match, 404 for none, 409 for several.
func (s *Server) matchRule(
	list *securityv1alpha1.HostFirewallRuleList,
	path string,
) (*securityv1alpha1.HostFirewallRule, string, int) {
	var (
		matched *securityv1alpha1.HostFirewallRule
		side    string
		count   int
	)

	for i := range list.Items {
		rule := &list.Items[i]
		ruleSide, dynamic := rule.Spec.DynamicEndpoint()
		if dynamic == nil || dynamic.Path != path {
			continue
		}
		count++
		if count == 1 {
			matched = rule
			side = ruleSide
		}
	}

	switch count {
	case 0:
		return nil, "", http.StatusNotFound
	case 1:
		return matched, side, http.StatusOK
	default:
		return nil, "", http.StatusConflict
	}
}

// authorize checks the bearer token required by ref. A nil ref means the path
// alone authorizes the knock. It returns 0 when the request may proceed, 401 for
// a missing or wrong token, and 503 when the Secret cannot be used.
func (s *Server) authorize(
	ctx context.Context,
	r *http.Request,
	ref *securityv1alpha1.SecretKeyRef,
) (int, error) {
	if ref == nil {
		return 0, nil
	}
	if s.Namespace == "" {
		return http.StatusServiceUnavailable, errors.New("operator namespace is not set")
	}
	if s.Reader == nil {
		return http.StatusServiceUnavailable, errors.New("no Secret reader is configured")
	}

	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: s.Namespace, Name: ref.Name}
	if err := s.Reader.Get(ctx, key, secret); err != nil {
		return http.StatusServiceUnavailable, fmt.Errorf("read token Secret: %w", err)
	}

	token := secret.Data[ref.Key]
	if len(token) == 0 {
		return http.StatusServiceUnavailable,
			fmt.Errorf("token Secret %q has no value for key %q", ref.Name, ref.Key)
	}

	presented, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok || subtle.ConstantTimeCompare(presented, token) != 1 {
		return http.StatusUnauthorized, errors.New("missing or invalid bearer token")
	}

	return 0, nil
}

// bearerToken extracts the token from an Authorization: Bearer header.
func bearerToken(header string) ([]byte, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) || len(header) == len(prefix) {
		return nil, false
	}
	return []byte(header[len(prefix):]), true
}

// storeGrant applies status.dynamic under the hfc-dynamic field manager. A new
// knock replaces the previous grant and restarts the TTL.
func (s *Server) storeGrant(
	ctx context.Context,
	rule *securityv1alpha1.HostFirewallRule,
	side string,
	addr netip.Addr,
) error {
	now := s.now()
	_, spec := rule.Spec.DynamicEndpoint()

	grant := &securityv1alpha1.DynamicGrant{
		Path:       spec.Path,
		Side:       side,
		Address:    addr.String(),
		ObservedAt: metav1.NewTime(now),
	}
	if spec.TTL != nil {
		expires := metav1.NewTime(now.Add(spec.TTL.Duration))
		grant.ExpiresAt = &expires
	}

	patch := &securityv1alpha1.HostFirewallRule{
		TypeMeta: metav1.TypeMeta{
			APIVersion: securityv1alpha1.GroupVersion.String(),
			Kind:       "HostFirewallRule",
		},
		ObjectMeta: metav1.ObjectMeta{Name: rule.Name},
		Status:     securityv1alpha1.HostFirewallRuleStatus{Dynamic: grant},
	}

	return s.Client.SubResource("status").Apply(ctx, patch,
		client.FieldOwner(securityv1alpha1.DynamicGrantFieldManager),
		client.ForceOwnership,
	)
}

// reject writes a status code, counts the result, and logs the reason at a low
// verbosity so normal traffic stays quiet. It never logs request credentials.
func (s *Server) reject(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	result, message string,
	keysAndValues ...any,
) {
	knockRequests.WithLabelValues(result).Inc()
	log.FromContext(r.Context()).V(1).Info(message, keysAndValues...)
	http.Error(w, http.StatusText(status), status)
}

// resultForStatus maps an authorization failure to its metric label.
func resultForStatus(status int) string {
	if status == http.StatusUnauthorized {
		return resultUnauthorized
	}
	return resultError
}

// now returns the current time, or the injected clock when set.
func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
