# Present so the loader's test-file exclusion is tested against a real one rather than a
# hypothetical. If the filter regressed, this package would ship inside the bundle the adapter
# builds — and TestBundleExcludesTestFiles asserts it does not.
#
# It also references a rule that does not exist, so a loader that included it would fail to compile
# the bundle rather than merely carry dead weight. The failure is the signal.
package gitsaas.authz_test

import data.gitsaas.authz

test_placeholder if {
	authz.this_rule_does_not_exist
}
