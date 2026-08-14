package domain

import "testing"

// TestContradiction is the SPEC-0040 AC1/AC2 judgement table: an observed placement
// contradicts a declaration whenever either half differs, and an observation that reports
// no placement contradicts every declaration.
func TestContradiction(t *testing.T) {
	cases := []struct {
		name                          string
		declaredCloud, declaredRegion string
		observedCloud, observedRegion string
		want                          bool
	}{
		{"exact match is no contradiction", "gke", "europe-west1", "gke", "europe-west1", false},
		{"different cloud contradicts", "gke", "europe-west1", "aws", "europe-west1", true},
		{"different region contradicts", "gke", "europe-west1", "gke", "us-east1", true},
		{"both differ contradict", "gke", "europe-west1", "aws", "us-east1", true},
		{"unreported cloud contradicts", "gke", "europe-west1", "", "europe-west1", true},
		{"unreported region contradicts", "gke", "europe-west1", "gke", "", true},
		{"empty observation contradicts any declaration", "gke", "europe-west1", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Contradiction(tc.declaredCloud, tc.declaredRegion, tc.observedCloud, tc.observedRegion); got != tc.want {
				t.Fatalf("Contradiction(%q,%q vs %q,%q) = %v, want %v",
					tc.declaredCloud, tc.declaredRegion, tc.observedCloud, tc.observedRegion, got, tc.want)
			}
		})
	}
}
