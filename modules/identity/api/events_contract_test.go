package api_test

import (
	"reflect"
	"strings"
	"testing"

	identityeventsv1 "github.com/gitfrok/backend/gen/events/identity/v1"
	"github.com/gitfrok/backend/modules/identity/api"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The Identity&Access auditor grant parity test, in the shape
// repository/api's established for the event mirror (T-0008 AC3), as the
// Security module's events_contract_test.go practices it. The in-process
// events this module publishes on the bus are plain Go structs — the api/
// surface stays free of infrastructure (invariant 20) — and that freedom is
// only safe if the two shapes are held in lockstep: the publisher swaps
// bus.Publish for a producer and the payload maps field-for-field (ADR-0026).
//
// AuditorGrantUsed is deliberately NOT mirrored here: Identity&Access never
// witnesses a pack read — the grant's use is a fact of the evidence read
// path, and the module that serves that read is the one that would announce
// it (T-0027 scope position).

// event is the bus-visible shape every in-process event must satisfy.
type event interface {
	EventName() string
	Tenant() string
}

// eventPairs binds each in-process event to the contracts/events message it mirrors.
var eventPairs = []struct {
	name     string
	inProc   event
	protoMsg proto.Message
}{
	{"AuditorGrantIssued", api.AuditorGrantIssued{}, (*identityeventsv1.AuditorGrantIssued)(nil)},
	{"AuditorGrantRevoked", api.AuditorGrantRevoked{}, (*identityeventsv1.AuditorGrantRevoked)(nil)},
	{"AuditorGrantExpired", api.AuditorGrantExpired{}, (*identityeventsv1.AuditorGrantExpired)(nil)},
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

// TestEveryEventIsTenantScoped: invariant 1 reaches events too.
func TestEveryEventIsTenantScoped(t *testing.T) {
	for _, p := range eventPairs {
		t.Run(p.name, func(t *testing.T) {
			if _, ok := protoFieldNames(p.protoMsg.ProtoReflect().Descriptor())["TENANTID"]; !ok {
				t.Fatalf("contracts message %s has no tenant_id", p.name)
			}
			withTenant := reflect.New(reflect.TypeOf(p.inProc)).Elem()
			withTenant.FieldByName("TenantID").SetString("t-1")
			if got := withTenant.Interface().(event).Tenant(); got != "t-1" {
				t.Errorf("Tenant() = %q, want it to report TenantID", got)
			}
		})
	}
}

// TestNoEventCarriesProvenanceOrPolicyOutcomes: events never carry
// provenance bytes, credentials, source, pack contents, or a policy allow
// flag. Scope and opaque identifiers only (SPEC-0033).
func TestNoEventCarriesProvenanceOrPolicyOutcomes(t *testing.T) {
	forbidden := []string{"PROVENANCE", "SECRET", "CREDENTIAL", "TOKEN", "SOURCE", "ALLOWED", "POLICY", "CONTENT"}
	for _, p := range eventPairs {
		t.Run(p.name, func(t *testing.T) {
			for norm := range goFieldNames(reflect.TypeOf(p.inProc)) {
				for _, bad := range forbidden {
					if strings.Contains(norm, bad) {
						t.Errorf("api.%s carries field %q — events never carry provenance, "+
							"credentials, source, contents, or a policy outcome", p.name, norm)
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

// normalize folds proto snake_case and Go CamelCase onto one key.
func normalize(s string) string { return strings.ToUpper(strings.ReplaceAll(s, "_", "")) }
