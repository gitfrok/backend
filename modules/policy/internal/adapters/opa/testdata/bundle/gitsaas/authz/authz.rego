# A stand-in for governance/policies, deliberately NOT a copy of it.
#
# These tests exercise the *evaluator* — bundle loading, input mapping, revision reporting, and
# what happens when evaluation goes wrong. The rules' content is governance's to test, and it does
# (`policies/gitsaas/authz/authz_test.rego`). A copy of the real policy here would be a second
# source of truth for something invariant 21 says has exactly one, and it would drift the first
# time governance tightened a rule.
#
# So this fixture keeps only the shape the adapter depends on: the package path, a total `decision`
# document with `allow` and `reason`, and deny-by-default. One trivial grant exists so the adapter's
# allow path is exercised at all.
package gitsaas.authz

default allow := false

allow if {
	input.action == "repo.read"
	some role in input.subject.roles
	role == "reader"
}

default reason := "denied: no policy grants this action"

reason := "allowed: subject holds a role granting this action" if allow

decision := {
	"allow": allow,
	"reason": reason,
}
