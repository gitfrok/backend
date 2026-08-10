// Package kedametrics exposes CI dispatch metrics in Prometheus exposition
// format. KEDA uses the queued-depth gauge to scale the runner dispatcher
// (SPEC-0020 AC3).
package kedametrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// Gauge is a minimal Prometheus-style gauge for queued job depth.
type Gauge struct {
	val *atomic.Int64
}

func NewGauge() *Gauge        { return &Gauge{val: &atomic.Int64{}} }
func (g *Gauge) Set(n int64)  { g.val.Store(n) }
func (g *Gauge) Add(n int64)  { g.val.Add(n) }
func (g *Gauge) Value() int64 { return g.val.Load() }

// Handler returns an HTTP handler that emits the queued-depth metric in
// Prometheus text exposition format.
func Handler(gauge *Gauge) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("X-Accel-Expires", "0")
		fmt.Fprintf(w, "# HELP ci_queued_jobs Number of jobs awaiting dispatch.\n")
		fmt.Fprintf(w, "# TYPE ci_queued_jobs gauge\n")
		fmt.Fprintf(w, "ci_queued_jobs %d\n", gauge.Value())
	})
}
