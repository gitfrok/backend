package app

import (
	"context"

	"github.com/gitfrok/backend/modules/codereview/api"
	"github.com/gitfrok/backend/platform/audit"
)

// MapDeclaredActor records a tenant admin's assertion that a foreign handle from
// an import belongs to a platform identity (SPEC-0011 AC10/AC22).
//
// It is an assertion and nothing else. Nothing in this path compares emails,
// names, or any other attribute of the handle against a platform user: every
// mapping originates in a decision a named admin made, PDP-authorized, and lands
// with a first-party audit event carrying that admin's identity. An inference
// engine could be added here later and would be exactly the thing ADR-0029 §4
// forbids, so the absence is deliberate rather than unfinished.
//
// The mapping never touches the imported record. An imported record is immutable
// (AC13) and stays ATTESTED_IMPORT; a mapped handle's approval is still an
// imported approval and still satisfies no merge policy (AC23).
func (s *ImportService) MapDeclaredActor(ctx context.Context, req api.MapDeclaredActorRequest) (api.DeclaredActorMapping, error) {
	if !validContext(req.Context) || req.ImportID == "" ||
		req.DeclaredActor == "" || req.SourceInstance == "" || req.MappedActorID == "" {
		return api.DeclaredActorMapping{}, ErrImportDenied
	}

	// The import must exist within this tenant before anything is asserted about
	// it. A mapping for an import in another tenant is refused exactly as a read
	// of it would be, and the refusal says nothing about which of the two it was.
	imp, err := s.store.GetImport(ctx, req.ImportID)
	if err != nil || imp.TenantID != req.TenantID {
		return api.DeclaredActorMapping{}, ErrImportDenied
	}
	// A revoked import's records are gone from every read, so there is nothing
	// left to make a claim about (AC24).
	if imp.State == api.ImportRevoked {
		return api.DeclaredActorMapping{}, ErrImportDenied
	}

	// Owner-only in the policy: asserting who a foreign handle is, is the one act
	// that can make imported history read as ours (governance authz.rego).
	if !s.allowed(ctx, req.Context, "repository.import.map_actor", "import", req.ImportID, map[string]string{
		"source_instance": req.SourceInstance,
	}) {
		return api.DeclaredActorMapping{}, ErrImportDenied
	}

	mapping, err := s.records.PutMapping(ctx, api.DeclaredActorMapping{
		MappingID:      s.newID(),
		TenantID:       imp.TenantID,
		ImportID:       imp.ID,
		DeclaredActor:  req.DeclaredActor,
		SourceInstance: req.SourceInstance,
		ActorID:        req.MappedActorID,
		// The asserting admin comes from the verified context, never from the
		// request: a caller that could name its own asserter could attribute its
		// claim to somebody else.
		AssertedBy: req.Context.ActorID,
		AssertedAt: s.now().UTC(),
	})
	if err != nil {
		return api.DeclaredActorMapping{}, err
	}

	// One first-party audit event per accepted assertion, naming the admin. This
	// is the accountability record: an identity mapping has to stay attributable
	// long after whoever made it has moved on (ADR-0029 §4).
	if err := s.bus.Publish(ctx, audit.DeclaredActorMapped{
		TenantID:       mapping.TenantID,
		ActorID:        mapping.AssertedBy,
		ImportID:       mapping.ImportID,
		DeclaredActor:  mapping.DeclaredActor,
		SourceInstance: mapping.SourceInstance,
		MappedActorID:  mapping.ActorID,
		OccurredAt:     s.now().UTC(),
	}); err != nil {
		return api.DeclaredActorMapping{}, err
	}
	return mapping, nil
}

// ListDeclaredActorMappings returns the mappings asserted for one import within
// the caller's tenant. A revoked import returns none: its records are dropped
// from reads, and a mapping describes a record (SPEC-0011 AC24).
func (s *ImportService) ListDeclaredActorMappings(ctx context.Context, principal api.Context, importID string) ([]api.DeclaredActorMapping, error) {
	if !validContext(principal) || importID == "" {
		return nil, ErrImportDenied
	}
	imp, err := s.store.GetImport(ctx, importID)
	if err != nil || imp.TenantID != principal.TenantID {
		return nil, ErrImportDenied
	}
	if !s.allowed(ctx, principal, "repository.import.read", "import", importID, nil) {
		return nil, ErrImportDenied
	}
	return s.records.ListMappings(ctx, importID)
}
