// Package protection holds Repository/Git's own tenant-scoped projection of
// branch-protection facts.
//
// Code Review owns the rules. Repository/Git needs one fact about them — is this
// exact ref protected — to give the PDP server-derived context before it accepts a
// direct ref update. It gets that fact by consuming BranchProtectionChanged, never
// by reading Code Review's tables and never by calling Code Review on the
// receive-pack path (SPEC-0019 AC7).
//
// It lives beside the transport rather than inside modules/repository on purpose:
// git-storaged is the enforcement point that needs the fact, and the Repository
// module is deliberately held at zero fan-out (ADR-0022, internal/arch).
package protection

import (
	"context"
	"sort"
	"sync"

	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/platform/bus"
)

// Projection answers whether one exact ref is protected, within one tenant.
type Projection struct {
	mu    sync.RWMutex
	rules map[string]codereviewapi.BranchProtection
}

func New() *Projection {
	return &Projection{rules: map[string]codereviewapi.BranchProtection{}}
}

// Subscribe connects the projection to the bus. This is the only route by which
// protection facts enter Repository/Git when Code Review shares the process.
func (p *Projection) Subscribe(events bus.Bus) {
	bus.SubscribeTyped(events, p.onBranchProtectionChanged)
}

// Set installs or replaces the exact-ref rule, mirroring Code Review's
// replace-only semantics (SPEC-0019): there is no unprotect path, and a rule
// requiring zero approvals still protects the ref. It is the cross-process
// counterpart of the BranchProtectionChanged event: when Code Review and
// git-storaged do not share a bus, the rule reaches the node that enforces
// direct pushes through this setter instead.
func (p *Projection) Set(rule codereviewapi.BranchProtection) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules[key(rule.TenantID, rule.RepositoryID, rule.TargetRef)] = rule
}

func (p *Projection) onBranchProtectionChanged(_ context.Context, event codereviewapi.BranchProtectionChanged) error {
	p.Set(codereviewapi.BranchProtection{
		TenantID: event.TenantID, RepositoryID: event.RepositoryID, TargetRef: event.TargetRef,
		RequiredApprovals: event.RequiredApprovals,
	})
	return nil
}

// Protected reports whether the exact ref carries a protection rule in this
// tenant. A rule requiring zero approvals still protects the ref: the count
// governs merges, the existence of the rule governs direct pushes.
func (p *Projection) Protected(tenantID, repositoryID, ref string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.rules[key(tenantID, repositoryID, ref)]
	return ok
}

// ProtectedRefs lists the protected refs in one tenant and repository. The order
// is stable, so the set of refs a push is refused is the same between calls.
func (p *Projection) ProtectedRefs(tenantID, repositoryID string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var refs []string
	for _, rule := range p.rules {
		if rule.TenantID == tenantID && rule.RepositoryID == repositoryID {
			refs = append(refs, rule.TargetRef)
		}
	}
	sort.Strings(refs)
	return refs
}

func key(tenantID, repositoryID, ref string) string {
	return tenantID + "\x00" + repositoryID + "\x00" + ref
}
