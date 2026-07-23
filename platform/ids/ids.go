// Package ids issues sortable identifiers (ULID target per contracts). Pure; no infra.
package ids

import "sync/atomic"

var counter atomic.Uint64

// NextSeq returns a monotonic per-process sequence — a placeholder until the ULID
// generator lands (T-0008 wires the real platform). Kept infra-free so domain may use it.
func NextSeq() uint64 { return counter.Add(1) }
