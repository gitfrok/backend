package app_test

import (
	"os"
	"regexp"
	"testing"

	codereviewapi "github.com/gitfrok/backend/modules/codereview/api"
)

// The security gate's severity threshold has two reviewed sources of truth
// (phase-2 review M11): the Go constant this plane assembles gate facts
// under (codereviewapi.SecurityGateSeverityThreshold) and the reviewed rego
// bundle's security_severity_threshold, which denies a merge whose highest
// attributed severity reaches it (SPEC-0029 AC3,
// governance/policies/gitsaas/authz/authz.rego).
//
// A fully PDP-driven threshold would need a governance contract change and
// is the recorded follow-up; until then THIS parity test is the enforcement:
// any drift between the two sources fails CI rather than silently letting
// the gate facts and the reviewed policy disagree.
func TestSecurityGateSeverityThresholdMatchesReviewedRego(t *testing.T) {
	// From backend/modules/security/internal/app to the repo root is five
	// levels up.
	const regoPath = "../../../../../governance/policies/gitsaas/authz/authz.rego"
	data, err := os.ReadFile(regoPath)
	if err != nil {
		t.Skipf("governance policies not alongside this checkout: %v", err)
	}
	m := regexp.MustCompile(`security_severity_threshold\s*:=\s*"([A-Z]+)"`).FindSubmatch(data)
	if m == nil {
		t.Fatalf("security_severity_threshold not found in the reviewed rego bundle (%s)", regoPath)
	}
	if got := string(m[1]); got != codereviewapi.SecurityGateSeverityThreshold {
		t.Fatalf("threshold drift: the reviewed rego bundle says %q but the findings gate assembles facts under %q — "+
			"reconcile them before merging (SPEC-0029 AC3; recorded follow-up: a PDP-driven threshold needs a "+
			"governance contract change)", got, codereviewapi.SecurityGateSeverityThreshold)
	}
}
