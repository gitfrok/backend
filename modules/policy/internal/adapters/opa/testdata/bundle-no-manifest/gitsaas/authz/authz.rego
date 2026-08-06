# A bundle directory with no .manifest, so it carries no revision.
#
# The adapter must refuse this too. An empty revision means every PEP keys its decision cache on
# the empty string, so a policy change invalidates nothing and tightened rules keep not applying
# until each cache's TTL happens to lapse. That failure is silent and looks exactly like the policy
# not having been changed — much worse than refusing to start.
package gitsaas.authz

default allow := false

default reason := "denied"

decision := {
	"allow": allow,
	"reason": reason,
}
