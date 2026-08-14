package api_test

import (
	"strings"
	"testing"

	securityv1 "github.com/gitfrok/backend/gen/proto/security/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// SPEC-0027 AC7: "the finding message carries no triage field, proven by a
// contract test." Triage is a resource keyed by the finding identity, never
// a field of the finding message (SPEC-0026, SPEC-0027): that separation is
// what makes "survives a re-scan" true by construction, and putting a
// triage state onto the finding would make the next scan's upsert the thing
// that decides whether a recorded decision still exists.
//
// The test asserts the shape of the GENERATED contract, not of this module's
// Go types: the boundary an additive change would cross is the proto.

// TestFindingCarriesNoTriageField fails the day a triage field is added to
// the Finding message — by name and by type.
func TestFindingCarriesNoTriageField(t *testing.T) {
	fields := messageFields(t, (*securityv1.Finding)(nil).ProtoReflect().Descriptor())
	for name, kind := range fields {
		if strings.Contains(strings.ToUpper(name), "TRIAGE") {
			t.Errorf("contracts Finding message carries field %q — triage is a keyed "+
				"resource, never a field of the finding (SPEC-0027 AC7)", name)
		}
		if strings.Contains(strings.ToUpper(string(kind)), "TRIAGE") {
			t.Errorf("contracts Finding message field %q has triage-typed value %q (SPEC-0027 AC7)", name, kind)
		}
	}
}

// TestTriageRequestCarriesNoServerFacts: no triage request may carry a
// finding's severity, lifecycle, or an allowed flag as input (SPEC-0027).
// Those are server facts; a request that would assert them must have no
// fields to assert them in.
func TestTriageRequestCarriesNoServerFacts(t *testing.T) {
	forbidden := []string{"SEVERITY", "LIFECYCLE", "ALLOWED", "DECISION"}
	for name, msg := range map[string]protoreflect.MessageDescriptor{
		"SetTriageRequest": (*securityv1.SetTriageRequest)(nil).ProtoReflect().Descriptor(),
		"GetTriageRequest": (*securityv1.GetTriageRequest)(nil).ProtoReflect().Descriptor(),
	} {
		for field := range messageFields(t, msg) {
			for _, bad := range forbidden {
				if strings.Contains(strings.ToUpper(field), bad) {
					t.Errorf("contracts %s carries field %q — severity, lifecycle and "+
						"authorization outcomes are server facts, not triage inputs (SPEC-0027)", name, field)
				}
			}
		}
	}
}

// TestTriageRecordIsItsOwnMessage guards the keyed-resource shape: the
// triage record is a message of its own with the identity, scope, state,
// version, and actor fields the spec names — not an extension of Finding.
func TestTriageRecordIsItsOwnMessage(t *testing.T) {
	fields := messageFields(t, (*securityv1.TriageRecord)(nil).ProtoReflect().Descriptor())
	for _, want := range []string{"triage_id", "finding_id", "tenant_id", "repository_id", "state", "version", "actor_id"} {
		if _, ok := fields[want]; !ok {
			t.Errorf("contracts TriageRecord lost field %q — the keyed-resource shape "+
				"is what makes re-scan survival structural (SPEC-0027)", want)
		}
	}
}

func messageFields(t *testing.T, d protoreflect.MessageDescriptor) map[string]string {
	t.Helper()
	out := make(map[string]string)
	fs := d.Fields()
	for i := 0; i < fs.Len(); i++ {
		f := fs.Get(i)
		out[string(f.Name())] = f.Kind().String()
	}
	return out
}
