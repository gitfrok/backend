// The input digest (SPEC-0030): a stable, reproducible digest over the canonicalized decision
// input.
//
// An auditor re-derives this digest from the input a decision was made over — the question is
// recorded alongside the answer precisely so "a decision was made" can be strengthened to "a
// decision was made over exactly this input". That only works if the digest is a pure function
// of the input with one documented canonical form, so this file IS the canonicalization and a
// change to what it covers is a spec amendment, not a refactor (SPEC-0030 open question).
package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/gitfrok/backend/modules/policy/api"
)

// digestPrefix names the digest algorithm in the value itself, so a future stronger hash is an
// auditor-visible change rather than a silent re-interpretation of stored values.
const digestPrefix = "sha256:"

// digestOf computes the input digest for one decision.
//
// It covers exactly the input the policy evaluated — the request, field for field — and
// deliberately NOT when the decision was made: the timestamp is metadata about the answer, not
// part of the question, and leaving it out is what makes a dry-run's replayed input re-derive
// the original decision's digest exactly (same question, same digest). The record stores the
// timestamp separately.
//
// The canonical form is JSON with sorted map keys — encoding/json sorts map keys by
// construction, so two equal inputs always marshal to the same bytes regardless of the order a
// caller populated them.
//
// Every field of the request is covered, including the subject's tenant and roles: two
// requests differing in any of them are different decisions (SPEC-0002 AC3's cache-key rule,
// restated for provenance), so the digest must see the difference too.
func digestOf(req api.Request) string {
	ctxAttrs := req.Context
	if ctxAttrs == nil {
		ctxAttrs = map[string]string{}
	}
	roles := req.Subject.Roles
	if roles == nil {
		roles = []string{}
	}
	canonical := map[string]any{
		"tenant_id": req.TenantID,
		"subject": map[string]any{
			"id":        req.Subject.ID,
			"tenant_id": req.Subject.TenantID,
			"roles":     roles,
		},
		"action": req.Action,
		"resource": map[string]any{
			"type": req.Resource.Type,
			"id":   req.Resource.ID,
		},
		"context": ctxAttrs,
	}
	// Error is unreachable for this shape — strings, string slices, string maps and nested
	// maps of the same — and a panic here would be the honest response to a future field that
	// makes it reachable: silently digesting a partial input would be worse.
	b, err := json.Marshal(canonical)
	if err != nil {
		panic("policy: canonical decision input no longer marshals: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return digestPrefix + hex.EncodeToString(sum[:])
}
