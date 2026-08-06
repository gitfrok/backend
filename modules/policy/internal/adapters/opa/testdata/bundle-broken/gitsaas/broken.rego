# A bundle that does not compile. The adapter must refuse to construct rather than start up and
# deny everything at runtime: a PDP that cannot evaluate is a broken deployment, and failing at
# wiring time makes that visible at rollout instead of as a wave of denials in production.
package gitsaas.broken

allow if {
	this is not rego
