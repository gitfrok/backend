package clouddriver

import (
	"strings"
	"testing"
)

// TestSelectReturnsRegisteredDrivers covers the three clouds the portability target names
// (ADR-0010): each selects when its required setting is present.
func TestSelectReturnsRegisteredDrivers(t *testing.T) {
	cases := []struct {
		provider Provider
		settings Settings
	}{
		{ProviderGKE, Settings{SettingGKEWorkloadIdentitySA: "dp-sa@tenant.iam"}},
		{ProviderEKS, Settings{SettingEKSIRSARoleArn: "arn:aws:iam::123:role/dp"}},
		{ProviderAKS, Settings{SettingAKSEntraClientID: "00000000-0000-0000-0000-000000000000"}},
	}
	for _, tc := range cases {
		t.Run(string(tc.provider), func(t *testing.T) {
			d, err := Select(tc.provider, tc.settings)
			if err != nil {
				t.Fatalf("Select(%q) = %v, want a driver", tc.provider, err)
			}
			if d.Provider() != tc.provider {
				t.Fatalf("driver provider = %q, want %q", d.Provider(), tc.provider)
			}
			if d.StorageClass() == "" || d.IdentityMode() == "" || d.IngressClass() == "" {
				t.Fatalf("driver %q has an empty per-cloud fact: storage=%q identity=%q ingress=%q",
					tc.provider, d.StorageClass(), d.IdentityMode(), d.IngressClass())
			}
			if len(d.Capabilities()) == 0 {
				t.Fatalf("driver %q reports no capabilities for enrolment", tc.provider)
			}
		})
	}
}

// TestSelectRefusesMissingRequiredSetting is the "no silent default that half-works" case: an
// absent (or blank) required setting is a refusal, not a default.
func TestSelectRefusesMissingRequiredSetting(t *testing.T) {
	cases := []struct {
		provider Provider
		settings Settings
		wantSub  string
	}{
		{ProviderGKE, Settings{}, SettingGKEWorkloadIdentitySA},
		{ProviderGKE, Settings{SettingGKEWorkloadIdentitySA: "   "}, SettingGKEWorkloadIdentitySA},
		{ProviderEKS, Settings{}, SettingEKSIRSARoleArn},
		{ProviderAKS, Settings{}, SettingAKSEntraClientID},
	}
	for _, tc := range cases {
		t.Run(string(tc.provider), func(t *testing.T) {
			d, err := Select(tc.provider, tc.settings)
			if err == nil {
				t.Fatalf("Select(%q, %+v) = %v, want a refusal for missing %q",
					tc.provider, tc.settings, d, tc.wantSub)
			}
			if d != nil {
				t.Fatalf("a refused selection must not return a driver, got %v", d)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("refusal %q does not name the missing setting %q", err, tc.wantSub)
			}
		})
	}
}

// TestSelectRefusesUnknownProvider: there is no fallback driver for a cloud we do not serve.
func TestSelectRefusesUnknownProvider(t *testing.T) {
	d, err := Select("oci", Settings{})
	if err == nil || d != nil {
		t.Fatalf("Select(oci) = %v, %v; want a refusal and no driver", d, err)
	}
}

// TestProvidersListsAllClouds guards the conformance-matrix rows: the seam must expose exactly
// the clouds the portability target fixes, so a dropped registration is visible.
func TestProvidersListsAllClouds(t *testing.T) {
	got := Providers()
	want := []Provider{ProviderAKS, ProviderEKS, ProviderGKE}
	if len(got) != len(want) {
		t.Fatalf("Providers() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Providers()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
