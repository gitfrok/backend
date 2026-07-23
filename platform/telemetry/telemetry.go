// Package telemetry is the metrics/trace seam. No-op baseline (T-0001).
package telemetry

// Counter records a monotonically increasing measurement.
type Counter interface{ Inc() }

type noopCounter struct{}

func (noopCounter) Inc() {}

// NewCounter returns a no-op counter until the telemetry backend is wired.
func NewCounter(string) Counter { return noopCounter{} }
