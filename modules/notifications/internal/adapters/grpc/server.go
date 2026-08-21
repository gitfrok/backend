// Package grpc adapts the Notifications in-process surface to
// contracts/proto/notifications/v1 (SPEC-0063). It translates shapes only:
// the recipient is derived from the verified principal on the call — never a
// wire field — and every failure is the one coarse denial.
package grpc

import (
	"context"
	"time"

	notificationsv1 "github.com/gitfrok/backend/gen/proto/notifications/v1"
	"github.com/gitfrok/backend/modules/notifications/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/tenancy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server is the gRPC adapter for the notifications read surface.
type Server struct {
	notificationsv1.UnimplementedNotificationServiceServer
	notifications api.Notifications
	pdp           policyapi.DecisionPoint
}

func NewServer(notifications api.Notifications, pdp policyapi.DecisionPoint) *Server {
	return &Server{notifications: notifications, pdp: pdp}
}

// denial is the one refusal this surface returns.
func denial() error {
	return status.Error(codes.PermissionDenied, "notifications unavailable")
}

// caller scopes the call to its verified principal, carried house-style in
// the request's context message: the BFF forwards the session-verified tenant
// and actor (ADR-0045 at the session layer). An incomplete context is a
// coarse denial rather than a partial call.
func caller(ctx context.Context, c *notificationsv1.NotificationContext) (context.Context, api.Context, bool) {
	if c == nil || c.GetTenantId() == "" || c.GetActorId() == "" {
		return ctx, api.Context{}, false
	}
	scoped := tenancy.WithTenant(ctx, tenancy.ID(c.GetTenantId()))
	return scoped, api.Context{TenantID: c.GetTenantId(), ActorID: c.GetActorId()}, true
}

// allowed asks the PDP once per call, deny-by-default (invariant 2).
func (s *Server) allowed(ctx context.Context, c api.Context, action, id string) bool {
	decision, err := s.pdp.Decide(ctx, policyapi.Request{
		TenantID: c.TenantID,
		Subject:  policyapi.Subject{ID: c.ActorID, TenantID: c.TenantID},
		Action:   action,
		Resource: policyapi.Resource{Type: "notification", ID: id},
	})
	return err == nil && decision.Allowed
}

func (s *Server) ListNotifications(ctx context.Context, req *notificationsv1.ListNotificationsRequest) (*notificationsv1.ListNotificationsResponse, error) {
	ctx, c, ok := caller(ctx, req.GetContext())
	if !ok || !s.allowed(ctx, c, "notification.read", "") {
		return nil, denial()
	}
	page, err := s.notifications.List(ctx, api.ListRequest{
		Context:   c,
		PageSize:  int(req.GetPageSize()),
		PageToken: req.GetPageToken(),
	})
	if err != nil {
		return nil, denial()
	}
	out := &notificationsv1.ListNotificationsResponse{NextPageToken: page.NextPageToken}
	for _, n := range page.Notifications {
		out.Notifications = append(out.Notifications, proto(n))
	}
	return out, nil
}

func (s *Server) UnreadCount(ctx context.Context, req *notificationsv1.UnreadCountRequest) (*notificationsv1.UnreadCountResponse, error) {
	ctx, c, ok := caller(ctx, req.GetContext())
	if !ok || !s.allowed(ctx, c, "notification.read", "") {
		return nil, denial()
	}
	n, err := s.notifications.UnreadCount(ctx, c)
	if err != nil {
		return nil, denial()
	}
	return &notificationsv1.UnreadCountResponse{Unread: n}, nil
}

func (s *Server) MarkRead(ctx context.Context, req *notificationsv1.MarkReadRequest) (*notificationsv1.MarkReadResponse, error) {
	ctx, c, ok := caller(ctx, req.GetContext())
	if !ok || !s.allowed(ctx, c, "notification.mark_read", req.GetNotificationId()) {
		return nil, denial()
	}
	n, err := s.notifications.MarkRead(ctx, c, req.GetNotificationId())
	if err != nil {
		return nil, denial()
	}
	return &notificationsv1.MarkReadResponse{Notification: proto(n)}, nil
}

func kindProto(k api.Kind) notificationsv1.NotificationKind {
	switch k {
	case api.KindMergeRequestReadyForReview:
		return notificationsv1.NotificationKind_NOTIFICATION_KIND_MERGE_REQUEST_READY_FOR_REVIEW
	case api.KindReviewSubmitted:
		return notificationsv1.NotificationKind_NOTIFICATION_KIND_REVIEW_SUBMITTED
	case api.KindMergeRequestMerged:
		return notificationsv1.NotificationKind_NOTIFICATION_KIND_MERGE_REQUEST_MERGED
	case api.KindFindingsAttributed:
		return notificationsv1.NotificationKind_NOTIFICATION_KIND_FINDINGS_ATTRIBUTED
	default:
		return notificationsv1.NotificationKind_NOTIFICATION_KIND_UNSPECIFIED
	}
}

func proto(n api.Notification) *notificationsv1.Notification {
	var at *timestamppb.Timestamp
	if !n.OccurredAt.IsZero() && !n.OccurredAt.Equal(time.Time{}) {
		at = timestamppb.New(n.OccurredAt)
	}
	return &notificationsv1.Notification{
		NotificationId: n.ID,
		Kind:           kindProto(n.Kind),
		RepositoryId:   n.RepositoryID,
		MergeRequestId: n.MergeRequestID,
		ActorId:        n.ActorID,
		HeadRevision:   n.HeadRevision,
		OccurredAt:     at,
		Read:           n.Read,
	}
}
