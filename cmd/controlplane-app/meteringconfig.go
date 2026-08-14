package main

import (
	"fmt"
	"strconv"

	meteringapi "github.com/gitfrok/backend/modules/metering/api"
)

// The metering context's per-environment configuration (invariant 13): derivation
// parameters and enforcement values are env vars with dev-friendly defaults, never
// compiled-in production values. The defaults are named here and mirrored into
// deploy/MVP-RUNBOOK.md.
//
// Thresholds themselves are per-tenant configuration (SPEC-0041 non-functional);
// the env vars below only seed the defaults a tenant without an override reads.
const (
	// usageGRPCAddrEnv opens the UsageService door the BFF calls when set; an empty
	// value means the control plane serves no usage view.
	usageGRPCAddrEnv = "GITFROK_USAGE_GRPC_ADDR"
	// meteringGapAfterEnv bounds how long a data plane may be silent before the
	// interval after its last recorded window renders as a gap (SPEC-0041 AC3).
	meteringGapAfterEnv = "GITFROK_METERING_GAP_AFTER"
	// meteringDivergenceToleranceEnv is the relative difference above which a data
	// plane's self-report and the control plane's counter become a health finding.
	meteringDivergenceToleranceEnv = "GITFROK_METERING_DIVERGENCE_TOLERANCE"
	// meteringThrottledConcurrencyEnv is the reduced CI concurrency a breached CI
	// dimension produces (SPEC-0041 AC5).
	meteringThrottledConcurrencyEnv = "GITFROK_METERING_THROTTLED_CONCURRENCY"
	// meteringQueueDepthCapEnv caps the queue depth under a CI breach; queued jobs
	// are delayed with a visible cause, never dropped (AC5).
	meteringQueueDepthCapEnv = "GITFROK_METERING_QUEUE_DEPTH_CAP"
	// meteringCIMinutesNotifyEnv / meteringCIMinutesEnvelopeEnv seed the default
	// CI-minutes thresholds tenants without an override read.
	meteringCIMinutesNotifyEnv   = "GITFROK_METERING_CI_MINUTES_NOTIFY"
	meteringCIMinutesEnvelopeEnv = "GITFROK_METERING_CI_MINUTES_ENVELOPE"
)

type meteringConfig struct {
	usageAddr string
	cfg       meteringapi.Config
}

// loadMeteringConfig reads the metering configuration. An unset usage address is a
// valid answer: the door simply does not exist. A malformed value fails the rollout
// rather than starting a metering surface with parameters nobody chose.
func loadMeteringConfig(getenv func(string) string) (meteringConfig, error) {
	out := meteringConfig{usageAddr: getenv(usageGRPCAddrEnv)}

	gapAfter, err := envDuration(getenv, meteringGapAfterEnv, "15m")
	if err != nil {
		return meteringConfig{}, err
	}
	tolerance, err := envFloat(getenv, meteringDivergenceToleranceEnv, 0.05)
	if err != nil {
		return meteringConfig{}, err
	}
	concurrency, err := envInt(getenv, meteringThrottledConcurrencyEnv, 2)
	if err != nil {
		return meteringConfig{}, err
	}
	queueCap, err := envInt(getenv, meteringQueueDepthCapEnv, 50)
	if err != nil {
		return meteringConfig{}, err
	}
	notify, err := envFloat(getenv, meteringCIMinutesNotifyEnv, 8000)
	if err != nil {
		return meteringConfig{}, err
	}
	envelope, err := envFloat(getenv, meteringCIMinutesEnvelopeEnv, 10000)
	if err != nil {
		return meteringConfig{}, err
	}
	// Sanity the composition cannot recover from at request time: a notification
	// threshold at or past the envelope would never fire before breach (AC4).
	if notify >= envelope {
		return meteringConfig{}, fmt.Errorf("%s must be smaller than %s", meteringCIMinutesNotifyEnv, meteringCIMinutesEnvelopeEnv)
	}

	out.cfg = meteringapi.Config{
		GapAfter:             gapAfter,
		DivergenceTolerance:  tolerance,
		ThrottledConcurrency: int32(concurrency),
		QueueDepthCap:        int64(queueCap),
		DefaultThresholds: map[meteringapi.Dimension]meteringapi.Threshold{
			meteringapi.DimensionCIMinutes: {Notify: notify, Envelope: envelope},
		},
	}
	return out, nil
}

func envFloat(getenv func(string) string, name string, fallback float64) (float64, error) {
	raw := getenv(name)
	if raw == "" {
		return fallback, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a number: %w", name, raw, err)
	}
	if f <= 0 {
		return 0, fmt.Errorf("%s=%q must be positive", name, raw)
	}
	return f, nil
}

func envInt(getenv func(string) string, name string, fallback int) (int, error) {
	raw := getenv(name)
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not an integer: %w", name, raw, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s=%q must be positive", name, raw)
	}
	return n, nil
}
