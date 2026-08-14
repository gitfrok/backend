package main

import (
	"time"
)

// residencyReportIntervalEnv is how long a data plane's placement reporting may be
// silent before the evidence pack's residency section renders the silence as a gap
// rather than reading it as compliance (T-0033, SPEC-0040 AC5). Per-environment
// configuration, never compiled in (invariant 13).
const residencyReportIntervalEnv = "GITFROK_RESIDENCY_MAX_REPORT_INTERVAL"

// residencyReportInterval reads the configured silence bound. Unset or unparseable
// means zero — the fail-safe: every obligation interval renders as a gap, so no
// silence is ever read as compliance (SPEC-0040 AC5).
func residencyReportInterval(getenv func(string) string) time.Duration {
	raw := getenv(residencyReportIntervalEnv)
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return 0
	}
	return d
}
