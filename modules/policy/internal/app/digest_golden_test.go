// Test-only file added for the SPEC-0036 Modern Go Guidelines refactor (AC2 permits new
// test-only files; existing tests stay unmodified).
//
// digest.go's canonical output is spec-frozen (SPEC-0030): this golden-vector test pins the
// exact digest bytes for fixed decision inputs so any transformation that touches the
// canonicalization — or a future refactor near it — must prove byte-identity or fail here.
package app

import (
	"strings"
	"testing"

	"github.com/gitfrok/backend/modules/policy/api"
)

func TestDigestGoldenVectors(t *testing.T) {
	cases := []struct {
		name   string
		req    api.Request
		golden string
	}{
		{
			name: "full input with roles and context",
			req: api.Request{
				TenantID: "tenant-golden",
				Subject: api.Subject{
					ID:       "actor-golden",
					TenantID: "tenant-golden",
					Roles:    []string{"developer", "reviewer"},
				},
				Action:   "merge.request.merge",
				Resource: api.Resource{Type: "merge_request", ID: "mr-0001"},
				Context: map[string]string{
					"approvals":        "2",
					"findings.gate":    "true",
					"head_revision":    "deadbeef",
					"required_scopes":  "protected",
					"target_ref":       "refs/heads/main",
					"valid_approvals":  "2",
					"zz_last_key":      "last",
					"aa_first_key":     "first",
					"protection_state": "active",
					"base_revision":    "cafebabe",
				},
			},
			golden: "sha256:7113a0176189488d0858c8c9c7dff3317b7242b282129a2670138ffab4328968",
		},
		{
			name: "nil roles and nil context normalise to empty",
			req: api.Request{
				TenantID: "tenant-golden",
				Subject: api.Subject{
					ID:       "actor-golden",
					TenantID: "tenant-golden",
					Roles:    nil,
				},
				Action:   "repository.read",
				Resource: api.Resource{Type: "repository", ID: "repo-0001"},
				Context:  nil,
			},
			golden: "sha256:80941b0fcff5bc4393a8225e9ab6fd91ec1d858b26e1e54605a6921cb4185f2c",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := digestOf(tc.req)
			if got != tc.golden {
				t.Fatalf("canonical digest drifted (SPEC-0030 is byte-frozen):\n got  %s\n want %s", got, tc.golden)
			}
			if !strings.HasPrefix(got, digestPrefix) {
				t.Fatalf("digest lost its algorithm prefix: %s", got)
			}
		})
	}
}

// TestDigestIndependentOfMapPopulation guards the canonical-form property the digest contract
// documents: encoding/json sorts map keys, so equal inputs digest identically no matter how a
// caller populated the context map. Two maps with the same entries in different insertion
// orders must yield the same digest.
func TestDigestIndependentOfMapPopulation(t *testing.T) {
	base := api.Request{
		TenantID: "tenant-golden",
		Subject:  api.Subject{ID: "actor-golden", TenantID: "tenant-golden", Roles: []string{"developer"}},
		Action:   "merge.request.merge",
		Resource: api.Resource{Type: "merge_request", ID: "mr-0001"},
	}
	a := base
	a.Context = map[string]string{"alpha": "1", "beta": "2", "gamma": "3"}
	b := base
	b.Context = map[string]string{"gamma": "3", "alpha": "1", "beta": "2"}
	if digestOf(a) != digestOf(b) {
		t.Fatalf("digest depends on map population order, canonical form broken")
	}
}
