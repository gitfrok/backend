package api_test

import (
	"reflect"
	"strings"
	"testing"

	coderevieweventsv1 "github.com/gitfrok/backend/gen/events/codereview/v1"
	"github.com/gitfrok/backend/modules/codereview/api"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The in-process event shapes and the published contract are one document. If
// they drift, a consumer reading the contract is reading something this context
// no longer emits.
func TestCodeReviewEventShapesMirrorContracts(t *testing.T) {
	for _, pair := range []struct {
		event   apiEvent
		message proto.Message
	}{
		{api.MergeRequestOpened{}, (*coderevieweventsv1.MergeRequestOpened)(nil)},
		{api.ReviewSubmitted{}, (*coderevieweventsv1.ReviewSubmitted)(nil)},
		{api.MergeRequestMerged{}, (*coderevieweventsv1.MergeRequestMerged)(nil)},
		{api.BranchProtectionChanged{}, (*coderevieweventsv1.BranchProtectionChanged)(nil)},
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

// Nothing on this surface may carry a policy outcome, an approval count, or
// review text: the events are facts about what happened, not authorization
// results a consumer could act on directly (SPEC-0019, G9).
func TestCodeReviewEventsCarryNoPolicyOutcomeOrReviewText(t *testing.T) {
	for _, event := range []any{
		api.MergeRequestOpened{}, api.ReviewSubmitted{},
		api.MergeRequestMerged{}, api.BranchProtectionChanged{},
	} {
		fields := goFieldNames(reflect.TypeOf(event))
		for _, forbidden := range []string{"ALLOWED", "ALLOW", "DECISION", "APPROVALCOUNT", "VALIDAPPROVALS", "COMMENT", "CREDENTIAL", "TOKEN"} {
			if _, present := fields[forbidden]; present {
				t.Errorf("%T carries %s", event, forbidden)
			}
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
