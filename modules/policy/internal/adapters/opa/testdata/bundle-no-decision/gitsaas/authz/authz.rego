# A bundle that loads and compiles but defines no `decision` document.
#
# The adapter must report this rather than invent an answer. It is the shape a policy takes if
# someone refactors `decision` away without noticing the adapter queries it, and the failure has to
# be loud: silently treating "no decision" as a denial would leave a broken bundle in production
# behaving exactly like a strict one, until the day it was supposed to allow something.
package gitsaas.authz

default allow := false
