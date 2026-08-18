package grpc_test

import (
	"context"
	"testing"

	policyv1 "github.com/gitfrok/backend/gen/proto/policy/v1"
	"github.com/gitfrok/backend/modules/policy/api"
	policygrpc "github.com/gitfrok/backend/modules/policy/internal/adapters/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SPEC-0055 AC1: the bundle in force, and nothing about its contents.

type revisionPDP struct{ revision string }

func (p revisionPDP) Decide(context.Context, api.Request) (api.Decision, error) {
	return api.Decision{}, nil
}
func (p revisionPDP) Revision() string { return p.revision }

// silentPDP knows no revision — a test double, or a PDP that has not loaded.
type silentPDP struct{}

func (silentPDP) Decide(context.Context, api.Request) (api.Decision, error) {
	return api.Decision{}, nil
}

func TestBundleStatusReportsTheRevisionInForce(t *testing.T) {
	srv := policygrpc.NewServer(revisionPDP{revision: "0.10.0"}, nil)
	got, err := srv.GetBundleStatus(context.Background(), &policyv1.GetBundleStatusRequest{TenantId: "t-1"})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if got.GetBundleRevision() != "0.10.0" {
		t.Fatalf("revision %q", got.GetBundleRevision())
	}
	if got.GetLoadedAt() == "" {
		t.Fatal("no load time")
	}
}

// A PDP that cannot say answers empty rather than inventing a revision. On a
// compliance surface a made-up revision is worse than no answer.
func TestAPDPThatCannotReportItsRevisionAnswersEmpty(t *testing.T) {
	srv := policygrpc.NewServer(silentPDP{}, nil)
	got, err := srv.GetBundleStatus(context.Background(), &policyv1.GetBundleStatusRequest{TenantId: "t-1"})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if got.GetBundleRevision() != "" {
		t.Fatalf("invented a revision: %q", got.GetBundleRevision())
	}
}

func TestBundleStatusRequiresAVerifiedTenant(t *testing.T) {
	srv := policygrpc.NewServer(revisionPDP{revision: "0.10.0"}, nil)
	_, err := srv.GetBundleStatus(context.Background(), &policyv1.GetBundleStatusRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}

// The response carries the revision and the load time, and nothing that could
// hold policy source: the bundle is a platform artifact.
func TestTheResponseCarriesNoPolicySource(t *testing.T) {
	fields := (&policyv1.GetBundleStatusResponse{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		switch name := string(fields.Get(i).Name()); name {
		case "bundle_revision", "loaded_at":
		default:
			t.Fatalf("GetBundleStatusResponse carries %q — the bundle's contents are not a tenant read", name)
		}
	}
}
