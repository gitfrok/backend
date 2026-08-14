// Package clouddriver is the per-cloud driver seam (SPEC-0039 AC2, ADR-0010, T-0031): the one
// place everything that differs between GKE, EKS and AKS lives — storage classes, keyless
// identity, ingress and load-balancer behaviour.
//
// A new provider is a new driver file that registers itself plus one conformance-matrix row;
// it is never a change to the selection logic here or to any module. The boundary test in
// internal/arch keeps provider-specific dependencies inside this tree the same way invariant 22
// keeps module edges honest.
package clouddriver

import (
	"fmt"
	"sort"
	"strings"
)

// Provider names one supported cloud. Values are stable wire/registry strings, not labels.
type Provider string

const (
	ProviderGKE Provider = "gke"
	ProviderEKS Provider = "eks"
	ProviderAKS Provider = "aks"
)

// Settings carries the per-cloud settings an install supplies. A driver names which of these
// it requires; Select refuses rather than silently defaulting one (SPEC-0039: "no silent
// default that half-works").
type Settings map[string]string

// Driver is one cloud's differences, expressed as facts the data plane and the packaging need.
// Implementations are data, not behaviour that reaches for cloud APIs; the seam is what a real
// SDK-backed implementation would sit behind.
type Driver interface {
	// Provider names the cloud this driver serves.
	Provider() Provider
	// RequiredSettings lists the Settings keys this provider must be given. Select refuses
	// if any is absent or empty.
	RequiredSettings() []string
	// StorageClass is the default storage class the plane's volumes bind to on this cloud.
	StorageClass() string
	// IdentityMode names the keyless workload-identity mechanism (ADR-0010).
	IdentityMode() string
	// IngressClass is the ingress controller class this cloud ships with.
	IngressClass() string
	// LoadBalancerClass is the load-balancer provisioning class, "" where the cloud uses a
	// plain Service of type LoadBalancer with no class.
	LoadBalancerClass() string
	// Capabilities are the data-plane capabilities the agent reports at enrolment; they feed
	// the control-plane registry record and are what the conformance matrix verifies.
	Capabilities() []string
}

// registry is the set of registered drivers. Drivers self-register in their own files, so
// adding a cloud is adding a file — never editing selection.
var registry = map[Provider]Driver{}

// Register adds one driver to the seam. It panics on a duplicate provider: two drivers for one
// cloud is a composition error that must fail loudly at startup, not resolve silently.
func Register(d Driver) {
	if d == nil {
		panic("clouddriver: cannot register a nil driver")
	}
	if _, dup := registry[d.Provider()]; dup {
		panic(fmt.Sprintf("clouddriver: duplicate driver for provider %q", d.Provider()))
	}
	registry[d.Provider()] = d
}

// Providers lists the registered providers in stable order — the rows the conformance matrix
// covers.
func Providers() []Provider {
	out := make([]Provider, 0, len(registry))
	for p := range registry {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Select returns the driver for provider after validating the settings it requires. It refuses
// an unknown provider and any missing required setting — there is no fallback driver and no
// silent default, because a half-configured cloud is an outage dressed as an install.
func Select(provider Provider, settings Settings) (Driver, error) {
	d, ok := registry[provider]
	if !ok {
		return nil, fmt.Errorf("clouddriver: no driver for provider %q (known: %s)",
			provider, strings.Join(providerNames(), ", "))
	}
	var missing []string
	for _, key := range d.RequiredSettings() {
		if strings.TrimSpace(settings[key]) == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("clouddriver: provider %q requires setting %s; refusing to "+
			"install with a silent default", provider, strings.Join(missing, ", "))
	}
	return d, nil
}

func providerNames() []string {
	names := make([]string, 0, len(registry))
	for _, p := range Providers() {
		names = append(names, string(p))
	}
	return names
}
