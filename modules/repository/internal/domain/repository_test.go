package domain

import "testing"

func TestNewRepositoryRequiresFields(t *testing.T) {
	if _, err := NewRepository("", "r1", "n"); err == nil {
		t.Error("expected error when tenant empty")
	}
	if _, err := NewRepository("t1", "r1", "n"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TenantID scoping is an invariant-1 guard: a repo never answers to another tenant.
func TestBelongsToRejectsCrossTenant(t *testing.T) {
	r, err := NewRepository("t1", "r1", "n")
	if err != nil {
		t.Fatal(err)
	}
	if r.BelongsTo("t2") {
		t.Error("repository leaked across tenants")
	}
	if !r.BelongsTo("t1") {
		t.Error("repository rejected its own tenant")
	}
}
