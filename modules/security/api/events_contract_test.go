package api_test

import (
	"reflect"
	"strings"
	"testing"

	securityeventsv1 "github.com/gitfrok/backend/gen/events/security/v1"
	"github.com/gitfrok/backend/modules/security/api"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The Security/Findings parity test, in the shape repository/api's established
// for the event mirror (T-0008 AC3). The in-process events this module
// publishes on the bus are plain Go structs — the api/ surface stays free of
// infrastructure (invariant 20), so it cannot expose generated protobuf types
// directly. That freedom is only safe if the two shapes are held in lockstep,
// which is what makes extraction to Redpanda (ADR-0026) mechanical: the
// publisher swaps bus.Publish for a producer and the payload maps
// field-for-field.
//
// So: for every in-process event, its name must equal the proto message's
// full name, and its fields must correspond one-to-one with the proto
// message's fields. Adding a field to contracts/events without mirroring it
// here fails this test, and vice versa.

// eventPairs binds each in-process event to the contracts/events message it mirrors.
var eventPairs = []struct {
	name     string
	inProc   api.Event
	protoMsg proto.Message
}{
	{"ScanIngested", api.ScanIngested{}, (*securityeventsv1.ScanIngested)(nil)},
	{"FindingOpened", api.FindingOpened{}, (*securityeventsv1.FindingOpened)(nil)},
	{"FindingResolved", api.FindingResolved{}, (*securityeventsv1.FindingResolved)(nil)},
}

// TestEventNameIsTheProtoFullName: the bus routing key and the Redpanda topic
// key are the same string, so a rename in contracts/ cannot silently leave
// the in-process seam behind.
func TestEventNameIsTheProtoFullName(t *testing.T) {
	for _, p := range eventPairs {
		t.Run(p.name, func(t *testing.T) {
			want := string(p.protoMsg.ProtoReflect().Descriptor().FullName())
			if got := p.inProc.EventName(); got != want {
				t.Errorf("EventName() = %q, want the proto full name %q", got, want)
			}
		})
	}
}

// TestEventShapeMirrorsTheContract: field-for-field parity in both directions.
func TestEventShapeMirrorsTheContract(t *testing.T) {
	for _, p := range eventPairs {
		t.Run(p.name, func(t *testing.T) {
			protoFields := protoFieldNames(p.protoMsg.ProtoReflect().Descriptor())
			goFields := goFieldNames(reflect.TypeOf(p.inProc))

			for norm, orig := range protoFields {
				if _, ok := goFields[norm]; !ok {
					t.Errorf("contracts field %q has no counterpart on api.%s — mirror it, or the "+
						"payload stops mapping when this event moves to Redpanda", orig, p.name)
				}
			}
			for norm, orig := range goFields {
				if _, ok := protoFields[norm]; !ok {
					t.Errorf("api.%s has field %q with no counterpart in contracts/events — an "+
						"in-process-only field cannot survive extraction", p.name, orig)
				}
			}
		})
	}
}

// TestEveryEventIsTenantScoped: invariant 1 reaches events too. Every
// contracts/events message carries tenant_id, and the bus refuses to publish
// an event whose tenant is empty, so the in-process mirror must be able to
// answer with it.
func TestEveryEventIsTenantScoped(t *testing.T) {
	for _, p := range eventPairs {
		t.Run(p.name, func(t *testing.T) {
			if _, ok := protoFieldNames(p.protoMsg.ProtoReflect().Descriptor())["TENANTID"]; !ok {
				t.Fatalf("contracts message %s has no tenant_id", p.name)
			}
			withTenant := reflect.New(reflect.TypeOf(p.inProc)).Elem()
			withTenant.FieldByName("TenantID").SetString("t-1")
			if got := withTenant.Interface().(api.Event).Tenant(); got != "t-1" {
				t.Errorf("Tenant() = %q, want it to report TenantID", got)
			}
		})
	}
}

// TestNoEventCarriesProvenanceOrPolicyOutcomes: the contract is explicit —
// events never carry provenance bytes, scanner credentials, source code, or a
// policy allow flag (SPEC-0025). Asserted against the mirror so a future
// field addition fails here rather than leaking on the wire.
func TestNoEventCarriesProvenanceOrPolicyOutcomes(t *testing.T) {
	forbidden := []string{"PROVENANCE", "SECRET", "CREDENTIAL", "TOKEN", "SOURCE", "ALLOWED", "POLICY"}
	for _, p := range eventPairs {
		t.Run(p.name, func(t *testing.T) {
			for norm := range goFieldNames(reflect.TypeOf(p.inProc)) {
				for _, bad := range forbidden {
					if strings.Contains(norm, bad) {
						t.Errorf("api.%s carries field %q — events never carry provenance, "+
							"credentials, source, or a policy outcome (SPEC-0025)", p.name, norm)
					}
				}
			}
		})
	}
}

// protoFieldNames returns the message's fields keyed by normalized name.
func protoFieldNames(d protoreflect.MessageDescriptor) map[string]string {
	out := make(map[string]string)
	fields := d.Fields()
	for i := 0; i < fields.Len(); i++ {
		name := string(fields.Get(i).Name())
		out[normalize(name)] = name
	}
	return out
}

// goFieldNames returns the struct's exported fields keyed by normalized name.
func goFieldNames(t reflect.Type) map[string]string {
	out := make(map[string]string)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.IsExported() {
			out[normalize(f.Name)] = f.Name
		}
	}
	return out
}

// normalize folds proto snake_case and Go CamelCase onto one key, so event_id
// and EventID compare equal without hard-coding an initialism list.
func normalize(s string) string { return strings.ToUpper(strings.ReplaceAll(s, "_", "")) }
