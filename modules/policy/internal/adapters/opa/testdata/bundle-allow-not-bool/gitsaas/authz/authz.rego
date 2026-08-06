# `decision.allow` is the string "true" rather than a bool.
#
# This is the case worth being strict about: "true" is truthy to a careless reader and to several
# languages, and a decision object assembled by hand or by a templating mistake is exactly how a
# non-bool gets there. Reading it through a checked type assertion makes the zero value — false —
# what a malformed document yields.
package gitsaas.authz

default allow := false

decision := {"allow": "true", "reason": "malformed on purpose"}
