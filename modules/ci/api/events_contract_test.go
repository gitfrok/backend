package api_test

import (
	"reflect"
	"strings"
	"testing"

	cieventsv1 "github.com/gitfrok/backend/gen/events/ci/v1"
	"github.com/gitfrok/backend/modules/ci/api"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestCIEventShapesMirrorContracts(t *testing.T) {
	for _, pair := range []struct {
		event   apiEvent
		message proto.Message
	}{
		{api.CIJobQueued{}, (*cieventsv1.CIJobQueued)(nil)},
		{api.CIJobStarted{}, (*cieventsv1.CIJobStarted)(nil)},
		{api.CIJobFinished{}, (*cieventsv1.CIJobFinished)(nil)},
	} {
		if got, want := pair.event.EventName(), string(pair.message.ProtoReflect().Descriptor().FullName()); got != want {
			t.Fatalf("event name = %q, want %q", got, want)
		}
		protoFields, goFields := fieldNames(pair.message.ProtoReflect().Descriptor()), goFieldNames(reflect.TypeOf(pair.event))
		if !reflect.DeepEqual(protoFields, goFields) {
			t.Fatalf("contract fields = %v, api fields = %v", protoFields, goFields)
		}
	}
}

type apiEvent interface {
	EventName() string
	Tenant() string
}

func fieldNames(d protoreflect.MessageDescriptor) map[string]struct{} {
	out := map[string]struct{}{}
	for i := 0; i < d.Fields().Len(); i++ {
		out[normalize(string(d.Fields().Get(i).Name()))] = struct{}{}
	}
	return out
}
func goFieldNames(t reflect.Type) map[string]struct{} {
	out := map[string]struct{}{}
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).IsExported() {
			out[normalize(t.Field(i).Name)] = struct{}{}
		}
	}
	return out
}
func normalize(value string) string { return strings.ToUpper(strings.ReplaceAll(value, "_", "")) }
