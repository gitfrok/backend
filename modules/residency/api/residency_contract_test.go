package api_test

import (
	"strings"
	"testing"

	agentv1 "github.com/gitfrok/backend/gen/proto/agent/v1"
	residencyv1 "github.com/gitfrok/backend/gen/proto/residency/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// SPEC-0043 AC6 / ADR-0067: no message in residency/v1 carries a tenant, actor
// or role field. The subject of a declaration is the verified principal on the
// call, never a message field — a request field naming the tenant would be an
// unauthenticated routing claim (ADR-0045). The absence is asserted against the
// COMPILED descriptor, not grepped out of source, so the field cannot reappear
// as a convenience later (mirrors governance/scripts/check-contracts.sh check 7).

// subjectFieldNames are the identifier fragments a subject-carrying field would
// use. Any hit is a regression of AC6's prohibition.
var subjectFieldNames = []string{"TENANT", "ACTOR", "ROLE", "PRINCIPAL", "SUBJECT"}

// TestResidencyContractCarriesNoSubject walks every message residency/v1 declares
// and fails the day any of them grows a tenant, actor or role field.
func TestResidencyContractCarriesNoSubject(t *testing.T) {
	file := (*residencyv1.DeclareResidencyRequest)(nil).ProtoReflect().Descriptor().ParentFile()
	msgs := file.Messages()
	if msgs.Len() == 0 {
		t.Fatal("residency/v1 file descriptor exposes no messages — descriptor walk is broken")
	}
	for i := 0; i < msgs.Len(); i++ {
		msg := msgs.Get(i)
		fields := msg.Fields()
		for j := 0; j < fields.Len(); j++ {
			name := strings.ToUpper(string(fields.Get(j).Name()))
			for _, bad := range subjectFieldNames {
				if strings.Contains(name, bad) {
					t.Errorf("residency/v1 message %s carries subject field %q — the subject is the "+
						"verified principal on the call, never a message field (SPEC-0043 AC6, ADR-0067)",
						msg.Name(), fields.Get(j).Name())
				}
			}
		}
	}
}

// TestResidencyRequestIsCloudRegionOnly pins the wire shape AC6 relies on: the
// declare request carries exactly cloud and region, so there is no field a caller
// could use to claim a tenant, an actor or a role.
func TestResidencyRequestIsCloudRegionOnly(t *testing.T) {
	fields := messageFieldNames(t, (*residencyv1.DeclareResidencyRequest)(nil).ProtoReflect().Descriptor())
	want := map[string]bool{"cloud": true, "region": true}
	if len(fields) != len(want) {
		t.Fatalf("DeclareResidencyRequest fields = %v, want exactly cloud and region", fields)
	}
	for _, f := range fields {
		if !want[f] {
			t.Errorf("DeclareResidencyRequest carries unexpected field %q — the request supplies "+
				"cloud and region only (SPEC-0043 AC6)", f)
		}
	}
}

// TestAgentChannelHasNoDeclarationPath is SPEC-0043 AC5's wire tripwire: no
// message, field or method in agent/v1 can set, mutate or influence a residency
// declaration — the managed data plane only reports witnessed placement facts, it
// never tells the control plane where it is allowed to run (SPEC-0040 AC1,
// ADR-0063 decision 5). The tripwire walks the COMPILED agent/v1 descriptor, so a
// future declaration path added to the agent channel fails the build rather than
// shipping.
func TestAgentChannelHasNoDeclarationPath(t *testing.T) {
	// declarationPathNames are the identifier fragments a residency-declaration
	// path on the agent channel would have to use. Observed placement reporting
	// uses "placement", "cloud" and "region", none of which match.
	declarationPathNames := []string{"RESIDENCY", "DECLARATION"}

	file := (*agentv1.AgentMessage)(nil).ProtoReflect().Descriptor().ParentFile()

	msgs := file.Messages()
	for i := 0; i < msgs.Len(); i++ {
		msg := msgs.Get(i)
		assertNoDeclarationPath(t, "message", string(msg.Name()), declarationPathNames)
		fields := msg.Fields()
		for j := 0; j < fields.Len(); j++ {
			assertNoDeclarationPath(t, "field of "+string(msg.Name()), string(fields.Get(j).Name()), declarationPathNames)
		}
	}

	services := file.Services()
	for i := 0; i < services.Len(); i++ {
		svc := services.Get(i)
		assertNoDeclarationPath(t, "service", string(svc.Name()), declarationPathNames)
		methods := svc.Methods()
		for j := 0; j < methods.Len(); j++ {
			assertNoDeclarationPath(t, "method of "+string(svc.Name()), string(methods.Get(j).Name()), declarationPathNames)
		}
	}
}

func assertNoDeclarationPath(t *testing.T, kind, name string, fragments []string) {
	t.Helper()
	upper := strings.ToUpper(name)
	for _, frag := range fragments {
		if strings.Contains(upper, frag) {
			t.Errorf("agent/v1 %s %q names a residency declaration path — the agent channel only "+
				"reports witnessed placement, it never declares residency (SPEC-0043 AC5, ADR-0063)",
				kind, name)
		}
	}
}

func messageFieldNames(t *testing.T, d protoreflect.MessageDescriptor) []string {
	t.Helper()
	var out []string
	fs := d.Fields()
	for i := 0; i < fs.Len(); i++ {
		out = append(out, string(fs.Get(i).Name()))
	}
	return out
}
