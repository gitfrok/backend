package agent

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/backend/modules/agent/internal/adapters/custody"
)

// TestNewCustodyCARequiresSnapshotFile is the fail-fast half of the Wave-3
// C1 fix: an issuer with nowhere to persist the bundle's durable state is a
// composition mistake, refused at construction with a clear error — never
// started half-durable.
func TestNewCustodyCARequiresSnapshotFile(t *testing.T) {
	_, err := NewCustodyCA(CustodyCAConfig{OpenBaoAddress: "https://openbao.test"})
	if err == nil || !strings.Contains(err.Error(), "snapshot file path is required") {
		t.Fatalf("NewCustodyCA without a snapshot path = %v; want the fail-fast refusal", err)
	}
}

// TestNewCustodyCAComposesRestartProof composes the production issuer over
// the CI custody service and proves the restart shape end to end: the first
// composition bootstraps and persists; a kill-and-restart restores the same
// window from disk without asking custody for a new key — the crash-loop the
// Wave-3 C1 finding named.
func TestNewCustodyCAComposesRestartProof(t *testing.T) {
	signer := custody.NewFakeSigner()
	cfg := CustodyCAConfig{
		SnapshotFile: filepath.Join(t.TempDir(), "agent-ca.snapshot"),
		Now:          time.Now,
	}

	first, err := newCustodyCA(cfg, signer)
	if err != nil {
		t.Fatalf("first composition: %v", err)
	}
	if roots := first.Bundle().Roots(); len(roots) != 1 || roots[0].Ref != custody.KeyRef("agent-ca") {
		t.Fatalf("first composition roots = %+v; want the one bootstrapped root", roots)
	}

	second, err := newCustodyCA(cfg, signer)
	if err != nil {
		t.Fatalf("restart composition: %v — a restart against custody that kept its keys must restore, not fail", err)
	}
	if generates, _, _ := signer.Counts(); generates != 1 {
		t.Fatalf("custody saw %d GenerateKey calls across the restart; the restore generates none", generates)
	}
	if roots := second.Bundle().Roots(); len(roots) != 1 || roots[0].Ref != custody.KeyRef("agent-ca") {
		t.Fatalf("restored roots = %+v; want the same bootstrapped root", roots)
	}
}
