// Package chaos is the reusable kill-and-restart harness for durability proofs
// (T-0036, SPEC-0042 AC1/AC2; built for T-0037 to reuse).
//
// A "plane" is whatever composition a test runs against the database — a
// service plus its stores and pool. Kill models kill -9: the composition is
// discarded with NO graceful shutdown, no flush, no state handoff; only the
// database outlives it. Restart builds a fresh plane over a fresh connection
// to the SAME database. Whatever the restarted plane still knows was durable;
// whatever it lost was process memory — and the specs under test say the
// security-critical half must all be on the durable side.
package chaos

import "github.com/gitfrok/backend/platform/db"

// BuildFunc assembles one fresh plane over one fresh pool. It is called once
// per Start — including the first — so every restart is genuinely new
// process memory over the same durable state.
type BuildFunc[S any] func(dsn string) (plane S, pool *db.Pool, err error)

// Plane is one killable, restartable composition under test.
type Plane[S any] struct {
	dsn   string
	build BuildFunc[S]

	// State is the plane currently alive. Zero value between Kill and
	// Restart; touching it there is a test bug, not a harness feature.
	State S

	pool *db.Pool
}

// New returns a harness over dsn. The plane is not started yet.
func New[S any](dsn string, build BuildFunc[S]) *Plane[S] {
	return &Plane[S]{dsn: dsn, build: build}
}

// Start builds the plane fresh. A second Start without a Kill is a test bug.
func (p *Plane[S]) Start() error {
	state, pool, err := p.build(p.dsn)
	if err != nil {
		return err
	}
	p.State, p.pool = state, pool
	return nil
}

// Kill is kill -9: no graceful shutdown, no close handshake with the plane —
// its in-process state simply stops existing. The pool is closed only because
// a test process cannot leak sockets into the next restart; the database saw
// no orderly drain, which is the point being modelled.
func (p *Plane[S]) Kill() {
	p.State = *new(S)
	if p.pool != nil {
		p.pool.Close()
		p.pool = nil
	}
}

// Restart is Kill then Start: one process death and its successor.
func (p *Plane[S]) Restart() error {
	p.Kill()
	return p.Start()
}
