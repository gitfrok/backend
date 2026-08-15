package releasebundle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ReconcileDir is the bundle's staged-key ACTUATION seam (T-0041, SPEC-0045
// AC2; the rotation actuation MVP-RUNBOOK §6b named for this wave): the
// desired live key set is DECLARED as files — one *.pub per trusted
// release-signing key, the key ID its filename without the extension — and
// this call converges the bundle toward it:
//
//   - a declared key the bundle does not hold is STAGED (newest declared key
//     last, so signing moves deterministically toward the declared set);
//   - a live key no longer declared is REMOVED, subject to the removal
//     preconditions (the last live key never leaves; the signing key leaves
//     only once a successor has taken signing) — a refused removal changes
//     nothing and is retried on the next reconcile;
//   - an EMPTY declaration removes nothing: an absent directory entry and an
//     intentionally emptied one are indistinguishable by construction, so the
//     safety posture is to treat empty as "no change", never "remove all".
//
// Only PUBLIC keys enter through this seam — every file is parsed the way
// Stage parses one, and a file carrying a private key or unparseable
// material fails the WHOLE reconcile before any state changes (ADR-0044
// custody posture). The directory's entries are read in full first; the
// bundle changes only against a completely readable declaration.
func (b *Bundle) ReconcileDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("releasebundle: reconcile %q: %w", dir, err)
	}
	type declared struct {
		id  string
		pem []byte
	}
	var want []declared
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".pub")
		if id == "" {
			return fmt.Errorf("releasebundle: reconcile %q: %q carries no key ID", dir, e.Name())
		}
		pemBytes, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("releasebundle: reconcile %q: read %q: %w", dir, e.Name(), err)
		}
		if _, err := parsePublicKey(pemBytes); err != nil {
			return fmt.Errorf("releasebundle: reconcile %q: %q: %w", dir, e.Name(), err)
		}
		want = append(want, declared{id: id, pem: pemBytes})
	}
	sort.Slice(want, func(i, j int) bool { return want[i].id < want[j].id })

	// Stage every declared key the bundle does not hold yet, sorted for a
	// deterministic signing successor.
	for _, w := range want {
		b.mu.Lock()
		known := false
		for _, k := range b.keys {
			if k.ID == w.id {
				known = true
				break
			}
		}
		b.mu.Unlock()
		if !known {
			if err := b.Stage(w.id, w.pem); err != nil {
				return fmt.Errorf("releasebundle: reconcile %q: stage %q: %w", dir, w.id, err)
			}
		}
	}

	// Remove every live key no longer declared — unless the declaration is
	// empty (the safety posture above). Refusals are not errors here: the
	// preconditions they enforce outlive one reconcile pass.
	if len(want) == 0 {
		return nil
	}
	declaredIDs := make(map[string]bool, len(want))
	for _, w := range want {
		declaredIDs[w.id] = true
	}
	var stale []string
	for _, k := range b.Keys() {
		if k.RemovedAt.IsZero() && !declaredIDs[k.ID] {
			stale = append(stale, k.ID)
		}
	}
	for _, id := range stale {
		if err := b.RemoveKey(id); err != nil && !errors.Is(err, ErrKeyStillNeeded) {
			return fmt.Errorf("releasebundle: reconcile %q: remove %q: %w", dir, id, err)
		}
	}
	return nil
}
