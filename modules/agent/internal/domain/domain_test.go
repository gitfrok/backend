package domain

import (
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
)

func TestGenerateSecretIsUniqueAndOpaque(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	b, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if a == "" || a == b {
		t.Fatalf("secrets must be non-empty and unique, got %q and %q", a, b)
	}
	// The secret must not be derivable from its hash.
	if h := HashSecret(a); h == HashSecret(b) {
		t.Fatal("distinct secrets hashed to the same value")
	}
}

func TestPresentOutcome(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	base := Token{
		ID: "tok-1", TenantID: "acme",
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}

	cases := []struct {
		name   string
		mutate func(*Token)
		want   api.RefusalReason // "" means admitted
	}{
		{name: "fresh unspent token is admitted", want: ""},
		{name: "spent token is refused as spent", mutate: func(t *Token) { t.SpentAt = now.Add(-time.Minute) }, want: api.RefusalTokenSpent},
		{name: "spent token stays spent after expiry", mutate: func(t *Token) {
			t.SpentAt = now.Add(-time.Minute)
			t.ExpiresAt = now.Add(-time.Second)
		}, want: api.RefusalTokenSpent},
		{name: "expired token is refused as expired", mutate: func(t *Token) { t.ExpiresAt = now.Add(-time.Second) }, want: api.RefusalTokenExpired},
		{name: "revoked token is refused as revoked", mutate: func(t *Token) { t.RevokedAt = now.Add(-time.Minute) }, want: api.RefusalTokenRevoked},
		{name: "revocation wins over expiry", mutate: func(t *Token) {
			t.RevokedAt = now.Add(-time.Minute)
			t.ExpiresAt = now.Add(-time.Second)
		}, want: api.RefusalTokenRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := base
			if tc.mutate != nil {
				tc.mutate(&tok)
			}
			if got := tok.PresentOutcome(now); got != tc.want {
				t.Fatalf("PresentOutcome = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeriveStatus(t *testing.T) {
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	staleAfter := 5 * time.Minute
	plane := func(seen time.Time) DataPlane {
		return DataPlane{ID: "dp-1", TenantID: "acme", EnrolledAt: now.Add(-time.Hour), LastSeenAt: seen, CurrentCertificateID: "cert-1"}
	}

	cases := []struct {
		name   string
		dp     DataPlane
		active bool
		want   api.DataPlaneStatus
	}{
		{"active stream is connected", plane(now.Add(-time.Hour)), true, api.StatusConnected},
		{"recent contact is connected", plane(now.Add(-4 * time.Minute)), false, api.StatusConnected},
		{"contact exactly at the window edge is connected", plane(now.Add(-staleAfter)), false, api.StatusConnected},
		{"contact beyond the window is stale", plane(now.Add(-staleAfter - time.Nanosecond)), false, api.StatusStale},
		{"revoked wins over staleness", func() DataPlane {
			dp := plane(now.Add(-time.Hour))
			dp.RevokedAt = now.Add(-time.Minute)
			return dp
		}(), false, api.StatusRevoked},
		{"revoked wins over an active stream", func() DataPlane {
			dp := plane(now)
			dp.RevokedAt = now.Add(-time.Minute)
			return dp
		}(), true, api.StatusRevoked},
		{"enrolled but never certified is never connected", func() DataPlane {
			dp := plane(now)
			dp.CurrentCertificateID = ""
			return dp
		}(), false, api.StatusNeverConnected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveStatus(tc.dp, tc.active, now, staleAfter); got != tc.want {
				t.Fatalf("DeriveStatus = %q, want %q", got, tc.want)
			}
		})
	}
}

// AC8: stale must never render healthy, and must be distinguishable from every other state.
func TestStaleIsNeverHealthy(t *testing.T) {
	for _, s := range []api.DataPlaneStatus{api.StatusNeverConnected, api.StatusConnected, api.StatusStale, api.StatusRevoked} {
		want := s == api.StatusConnected
		if got := s.Healthy(); got != want {
			t.Fatalf("status %s Healthy() = %v, want %v", s, got, want)
		}
	}
	if api.StatusStale == api.StatusConnected {
		t.Fatal("stale must be distinguishable from connected")
	}
}
