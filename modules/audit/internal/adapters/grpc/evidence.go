// Package grpc exposes the evidence pack surface over contracts/proto/audit/v1
// (T-0026). It translates between the wire shape and the in-process api, and
// does nothing else: no assembly, no filtering, no authorization here — the
// service decides, the adapter renders (invariant 18's discipline applied to
// Audit's own door).
package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/gitfrok/backend/gen/proto/audit/v1"
	contractsv1 "github.com/gitfrok/backend/gen/proto/contracts/v1"
	"github.com/gitfrok/backend/modules/audit/api"
)

// errUnavailable is the ONE coarse wire shape for every failed pack read,
// mirroring api.ErrPackUnavailable: nonexistent, cross-tenant, unauthorized
// and not-yet-ready are indistinguishable (SPEC-0001, SPEC-0032 AC5).
var errUnavailable = status.Error(codes.PermissionDenied, "audit: evidence pack unavailable")

var errMalformed = status.Error(codes.InvalidArgument, "audit: malformed evidence pack request")

// Server implements auditv1.EvidenceServiceServer over api.PackService.
type Server struct {
	auditv1.UnimplementedEvidenceServiceServer
	svc api.PackService
}

// NewServer wires the adapter over the in-process surface.
func NewServer(svc api.PackService) *Server { return &Server{svc: svc} }

// RequestEvidencePack starts the asynchronous assembly of a pack over one
// closed date range.
func (s *Server) RequestEvidencePack(ctx context.Context, req *auditv1.RequestEvidencePackRequest) (*auditv1.RequestEvidencePackResponse, error) {
	c, err := contextOf(req.GetContext())
	if err != nil {
		return nil, err
	}
	if req.GetRangeFrom() == nil || req.GetRangeTo() == nil {
		return nil, errMalformed
	}
	packID, state, err := s.svc.RequestPack(ctx, c, api.PackRequest{
		RangeFrom:    req.GetRangeFrom().AsTime(),
		RangeTo:      req.GetRangeTo().AsTime(),
		RepositoryID: req.GetRepositoryId(),
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &auditv1.RequestEvidencePackResponse{PackId: packID, State: packStateOf(state)}, nil
}

// GetEvidencePackStatus observes assembly.
func (s *Server) GetEvidencePackStatus(ctx context.Context, req *auditv1.GetEvidencePackStatusRequest) (*auditv1.GetEvidencePackStatusResponse, error) {
	c, err := contextOf(req.GetContext())
	if err != nil {
		return nil, err
	}
	st, err := s.svc.PackStatus(ctx, c, req.GetPackId())
	if err != nil {
		return nil, wireError(err)
	}
	resp := &auditv1.GetEvidencePackStatusResponse{
		State:               packStateOf(st.State),
		FailureReason:       st.FailureReason,
		AppendixRecordCount: st.AppendixRecordCount,
		RepositoryId:        st.RepositoryID,
	}
	if !st.RangeFrom.IsZero() {
		resp.RangeFrom = timestamppb.New(st.RangeFrom)
	}
	if !st.RangeTo.IsZero() {
		resp.RangeTo = timestamppb.New(st.RangeTo)
	}
	for _, ss := range st.SectionCounts {
		resp.Sections = append(resp.Sections, &auditv1.SectionStatus{
			Type:        sectionTypeOf(ss.Type),
			RecordCount: ss.RecordCount,
			Gaps:        gapsOf(ss.Gaps),
		})
	}
	return resp, nil
}

// GetEvidencePack streams a READY pack as its bounded chunk sequence.
func (s *Server) GetEvidencePack(req *auditv1.GetEvidencePackRequest, stream auditv1.EvidenceService_GetEvidencePackServer) error {
	c, err := contextOf(req.GetContext())
	if err != nil {
		return err
	}
	chunks, err := s.svc.GetPack(stream.Context(), c, req.GetPackId())
	if err != nil {
		return wireError(err)
	}
	for _, chunk := range chunks {
		resp := &auditv1.GetEvidencePackResponse{ChunkIndex: chunk.Index, FinalChunk: chunk.Final}
		switch {
		case chunk.Header != nil:
			resp.Content = &auditv1.GetEvidencePackResponse_Header{Header: packOf(*chunk.Header)}
		case chunk.Section != nil:
			resp.Content = &auditv1.GetEvidencePackResponse_Section{Section: sectionOf(*chunk.Section)}
		case chunk.Appendix != nil:
			resp.Content = &auditv1.GetEvidencePackResponse_Appendix{Appendix: appendixOf(*chunk.Appendix)}
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
	return nil
}

// wireError maps the api's two coarse shapes onto the wire. Everything that
// is not a malformed request is the same denial: the wire cannot be the place
// a caller learns to distinguish nonexistent from unauthorized (SPEC-0001).
func wireError(err error) error {
	if errors.Is(err, api.ErrInvalidPackRequest) {
		return errMalformed
	}
	return errUnavailable
}

func contextOf(c *auditv1.EvidenceContext) (api.Context, error) {
	if c == nil || c.GetTenantId() == "" || c.GetActorId() == "" || c.GetRequestId() == "" {
		return api.Context{}, errMalformed
	}
	return api.Context{
		TenantID:   c.GetTenantId(),
		ActorID:    c.GetActorId(),
		ActorRoles: append([]string(nil), c.GetActorRoles()...),
		RequestID:  c.GetRequestId(),
	}, nil
}

func packStateOf(s api.PackState) auditv1.PackState {
	switch s {
	case api.PackPending:
		return auditv1.PackState_PACK_STATE_PENDING
	case api.PackAssembling:
		return auditv1.PackState_PACK_STATE_ASSEMBLING
	case api.PackReady:
		return auditv1.PackState_PACK_STATE_READY
	case api.PackFailed:
		return auditv1.PackState_PACK_STATE_FAILED
	default:
		return auditv1.PackState_PACK_STATE_UNSPECIFIED
	}
}

func sectionTypeOf(t api.SectionType) auditv1.SectionType {
	switch t {
	case api.SectionApprovals:
		return auditv1.SectionType_SECTION_TYPE_APPROVALS
	case api.SectionPolicyDecisions:
		return auditv1.SectionType_SECTION_TYPE_POLICY_DECISIONS
	case api.SectionScanGates:
		return auditv1.SectionType_SECTION_TYPE_SCAN_GATES
	case api.SectionAccessChanges:
		return auditv1.SectionType_SECTION_TYPE_ACCESS_CHANGES
	default:
		return auditv1.SectionType_SECTION_TYPE_UNSPECIFIED
	}
}

func gapReasonOf(r api.GapReason) auditv1.GapReason {
	switch r {
	case api.GapSourceUnavailable:
		return auditv1.GapReason_GAP_REASON_SOURCE_UNAVAILABLE
	case api.GapProjectionLagged:
		return auditv1.GapReason_GAP_REASON_PROJECTION_LAGGED
	case api.GapAssemblyFailed:
		return auditv1.GapReason_GAP_REASON_ASSEMBLY_FAILED
	default:
		return auditv1.GapReason_GAP_REASON_UNSPECIFIED
	}
}

func gapsOf(gaps []api.SectionGap) []*auditv1.SectionGap {
	out := make([]*auditv1.SectionGap, 0, len(gaps))
	for _, g := range gaps {
		out = append(out, &auditv1.SectionGap{
			From:   timestamppb.New(g.From),
			To:     timestamppb.New(g.To),
			Reason: gapReasonOf(g.Reason),
		})
	}
	return out
}

func packOf(p api.Pack) *auditv1.EvidencePack {
	pb := &auditv1.EvidencePack{
		PackId:       p.PackID,
		TenantId:     p.TenantID,
		RepositoryId: p.RepositoryID,
		RequestedBy:  p.RequestedBy,
		DecisionId:   p.DecisionID,
		GeneratedAt:  timestamppb.New(p.GeneratedAt),
		RangeFrom:    timestamppb.New(p.RangeFrom),
		RangeTo:      timestamppb.New(p.RangeTo),
		Appendix:     appendixOf(p.Appendix),
	}
	for _, sec := range p.Sections {
		pb.Sections = append(pb.Sections, sectionOf(sec))
	}
	return pb
}

func sectionOf(s api.Section) *auditv1.ControlSection {
	pb := &auditv1.ControlSection{
		Type:          sectionTypeOf(s.Type),
		Complete:      s.Complete,
		Gaps:          gapsOf(s.Gaps),
		RecordsDigest: s.RecordsDigest,
		Anchors: &auditv1.ChainAnchor{
			FirstSeq:        s.Anchor.FirstSeq,
			LastSeq:         s.Anchor.LastSeq,
			FirstRecordHash: s.Anchor.FirstRecordHash,
			LastRecordHash:  s.Anchor.LastRecordHash,
			PrevRecordHash:  s.Anchor.PrevRecordHash,
		},
	}
	for _, r := range s.Records {
		pb.Records = append(pb.Records, recordOf(r))
	}
	return pb
}

func recordOf(r api.SectionRecord) *auditv1.ControlSectionRecord {
	pb := &auditv1.ControlSectionRecord{
		ChainSeq:   r.ChainSeq,
		RecordHash: r.RecordHash,
		ActorId:    r.ActorID,
		Resource:   r.Resource,
		Action:     string(r.Action),
		Allowed:    r.Allowed,
		OccurredAt: timestamppb.New(r.OccurredAt),
	}
	switch {
	case r.Approval != nil:
		pb.Detail = &auditv1.ControlSectionRecord_Approval{Approval: &auditv1.ApprovalRecord{
			MergeRequestId:   r.Approval.MergeRequestID,
			ProtectionRuleId: r.Approval.ProtectionRuleID,
		}}
	case r.PolicyDecision != nil:
		pb.Detail = &auditv1.ControlSectionRecord_PolicyDecision{PolicyDecision: &auditv1.PolicyDecisionRecord{
			DecisionId:     r.PolicyDecision.DecisionID,
			BundleRevision: r.PolicyDecision.BundleRevision,
			InputDigest:    r.PolicyDecision.InputDigest,
			// ENFORCED is the only value the closed enum admits; setting it
			// explicitly renders the contract's single non-default value
			// rather than relying on the zero default.
			Mode: auditv1.ControlDecisionMode_CONTROL_DECISION_MODE_ENFORCED,
		}}
	case r.ScanGate != nil:
		pb.Detail = &auditv1.ControlSectionRecord_ScanGate{ScanGate: &auditv1.ScanGateRecord{
			MergeRequestId:      r.ScanGate.MergeRequestID,
			ScanId:              r.ScanGate.ScanID,
			ReliedUponTriageIds: append([]string(nil), r.ScanGate.ReliedUponTriageIDs...),
		}}
	case r.AccessChange != nil:
		pb.Detail = &auditv1.ControlSectionRecord_AccessChange{AccessChange: &auditv1.AccessChangeRecord{
			AccessKind:        r.AccessChange.AccessKind,
			TargetPrincipalId: r.AccessChange.TargetPrincipalID,
			GrantId:           r.AccessChange.GrantID,
		}}
	}
	return pb
}

func appendixOf(a api.Appendix) *auditv1.AttestedAppendix {
	pb := &auditv1.AttestedAppendix{Label: a.Label}
	for _, g := range a.Groups {
		group := &auditv1.AttestedImportGroup{
			HistoryImported: &auditv1.HistoryImportedReference{
				EventId:         g.Import.EventID,
				ActorId:         g.Import.ActorID,
				RepositoryId:    g.Import.RepositoryID,
				ImportId:        g.Import.ImportID,
				SourceSystem:    g.Import.SourceSystem,
				SourceInstance:  g.Import.SourceInstance,
				RecordCounts:    g.Import.RecordCounts,
				ManifestDigest:  g.Import.ManifestDigest,
				OccurredAt:      timestamppb.New(g.Import.OccurredAt),
			},
		}
		for _, r := range g.Records {
			group.Records = append(group.Records, &auditv1.AttestedAppendixRecord{
				RecordKind:       r.RecordKind,
				SourceRef:        r.Provenance.SourceRef,
				Payload:          append([]byte(nil), r.Payload...),
				PayloadMediaType: "application/json",
				Provenance: &contractsv1.Provenance{
					Class:          contractsv1.Provenance_CLASS_ATTESTED_IMPORT,
					ImportId:       r.Provenance.ImportID,
					SourceSystem:   r.Provenance.SourceSystem,
					SourceInstance: r.Provenance.SourceInstance,
					SourceRef:      r.Provenance.SourceRef,
					DeclaredActor:  r.Provenance.ForeignHandle,
					DeclaredAt:     timestamppb.New(r.Provenance.DeclaredAt),
					PayloadDigest:  r.Provenance.PayloadDigest,
				},
			})
		}
		pb.Groups = append(pb.Groups, group)
	}
	return pb
}
