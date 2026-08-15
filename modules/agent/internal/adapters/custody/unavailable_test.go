package custody_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/agent/internal/adapters/custody"
)

// TestCustodyOutageIsAvailabilityNotIntegrity is SPEC-0044's
// custody-unavailable test against the fake: when the signer refuses,
// ISSUANCE stops as an availability event — and certificates already issued
// keep validating, because verification never crosses the seam (ADR-0066
// decision 6, SPEC-0044 assumption).
//
// The enrolment half of this surface — a first-issuance failure AFTER the
// token spend, and the claim release that makes retry the recovery — is
// SPEC-0042 AC6's territory, proven by T-0036's service-level chaos tests;
// this test COMPLEMENTS them at the adapter: it proves the signer's refusal
// is what those tests inject, and that the refusal touches nothing already
// issued. Neither proves it alone (SPEC-0044 Test plan).
func TestCustodyOutageIsAvailabilityNotIntegrity(t *testing.T) {
	fake, _, issuer, clk := newTestCA(t, "agent-ca-outage")

	issued, _ := issueOne(t, issuer, clk, 24*time.Hour)
	id := api.Identity{TenantID: "tenant-b", DataPlaneID: "plane-2"}
	if _, err := issuer.Issue(context.Background(), id, clk.Now(), time.Hour, 0); err != nil {
		t.Fatalf("issuance before the outage must succeed: %v", err)
	}

	_, publics, signs := fake.Counts()
	fake.Seal()

	// Issuance is refused, and the refusal names the outage.
	_, err := issuer.Issue(context.Background(), id, clk.Now(), time.Hour, 0)
	if !errors.Is(err, custody.ErrUnavailable) {
		t.Fatalf("Issue during the outage = %v, want ErrUnavailable", err)
	}

	// Already-issued certificates still validate — and validating them made
	// ZERO seam calls: the counts are exactly where they stood at seal time.
	if _, validity, vErr := issuer.VerifyChain([][]byte{leafDEROf(t, issued)}, clk.Now()); vErr != nil || validity != api.ValidNow {
		t.Errorf("issued certificate during the outage = (%v, %v), want (ValidNow, nil)", validity, vErr)
	}
	if gotID, gotExpiry, iErr := issuer.Inspect(leafDEROf(t, issued)); iErr != nil || gotID != testIdentity || !gotExpiry.Equal(issued.ExpiresAt) {
		t.Errorf("Inspect during the outage = (%+v, %v, %v), want the issued identity", gotID, gotExpiry, iErr)
	}
	if _, publicsAfter, signsAfter := fake.Counts(); publicsAfter != publics || signsAfter != signs {
		t.Errorf("verification crossed the seam during the outage (pubs %d->%d, sigs %d->%d)",
			publics, publicsAfter, signs, signsAfter)
	}

	// The outage ends where it began: unseal, and issuance resumes on the
	// SAME reference — the key survived the outage in custody, nothing was
	// re-generated.
	fake.Unseal()
	if _, err := issuer.Issue(context.Background(), id, clk.Now(), time.Hour, 0); err != nil {
		t.Fatalf("issuance after the outage: %v", err)
	}
	if gen, _, _ := fake.Counts(); gen != 1 {
		t.Errorf("the outage re-generated a key (generates=%d) — keys survive custody outages", gen)
	}
}

// TestStagingDuringAnOutageRefuses: rotation cannot advance while custody
// refuses — a Stage that cannot generate the new key is a refusal, not a
// half-open window. The window state that existed before the outage is
// untouched.
func TestStagingDuringAnOutageRefuses(t *testing.T) {
	fake, bundle, issuer, clk, oldCert, _ := stageOverlap(t)
	fake.Seal()

	if _, err := bundle.Stage(context.Background(), "agent-ca-gen3"); !errors.Is(err, custody.ErrUnavailable) {
		t.Fatalf("Stage during the outage = %v, want ErrUnavailable", err)
	}
	roots := bundle.Roots()
	live := 0
	for _, r := range roots {
		if r.RemovedAt.IsZero() {
			live++
		}
	}
	if live != 2 {
		t.Fatalf("outage disturbed the overlap window: %d live roots, want 2", live)
	}
	// And what the window held still validates — outage or not.
	if _, validity, err := issuer.VerifyChain([][]byte{leafDEROf(t, oldCert)}, clk.Now()); err != nil || validity != api.ValidNow {
		t.Errorf("overlap-window certificate during the outage = (%v, %v), want (ValidNow, nil)", validity, err)
	}
}
