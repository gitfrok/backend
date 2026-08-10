package main

import (
	"time"
)

// importPaceIntervalEnv sets the minimum gap between steps of import work, as a
// Go duration ("250ms", "1s").
//
// Per-environment configuration, never compiled in (invariant 13): how much
// import throughput a plane can spare depends on what else that plane is
// serving. Unset or unparseable means the default below rather than a refusal to
// start — an unpaced import is a load problem an operator can see, whereas a
// plane that will not come up because a throttle is misspelled is an outage.
const importPaceIntervalEnv = "GITFROK_IMPORT_PACE_INTERVAL"

// defaultImportPaceInterval spaces import fetches far enough apart that an
// import cannot saturate a source API or this plane's own request budget, while
// still finishing a few thousand records in minutes rather than hours
// (SPEC-0011 AC21).
const defaultImportPaceInterval = 100 * time.Millisecond

// importPaceInterval reads the configured pace, falling back to the default.
func importPaceInterval(getenv func(string) string) time.Duration {
	raw := getenv(importPaceIntervalEnv)
	if raw == "" {
		return defaultImportPaceInterval
	}
	interval, err := time.ParseDuration(raw)
	if err != nil || interval < 0 {
		return defaultImportPaceInterval
	}
	return interval
}
