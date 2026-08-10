package main

import (
	"testing"
	"time"
)

// The import pace is per-environment configuration, and a plane starts either
// way: an unset or unusable value falls back to the default rather than failing
// the rollout over a throttle.
func TestImportPaceInterval(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{"unset", "", defaultImportPaceInterval},
		{"configured", "500ms", 500 * time.Millisecond},
		{"zero paces nothing", "0s", 0},
		{"unparseable falls back", "sometimes", defaultImportPaceInterval},
		{"negative falls back", "-1s", defaultImportPaceInterval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := importPaceInterval(func(string) string { return tc.raw })
			if got != tc.want {
				t.Fatalf("importPaceInterval(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
