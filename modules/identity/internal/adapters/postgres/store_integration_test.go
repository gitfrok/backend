package postgres_test

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/identity"
	identityapi "github.com/gitfrok/backend/modules/identity/api"
	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/platform/db"
	"github.com/gitfrok/backend/platform/tenancy"
)

// Run with TEST_DATABASE_URL set to the non-superuser app role against a
// database with the T-0004 and T-0013 migrations applied.
func TestPostgresPATRevocationDeniesNextResolverLookup(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — integration test needs T-0013 identity migration")
	}
	pool, err := db.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	stamp := time.Now().UTC().UnixNano()
	tenantID := fmt.Sprintf("identity-test-%d", stamp)
	actorID := fmt.Sprintf("actor-%d", stamp)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenantID))
	if err := pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO identity.principals (tenant_id, actor_id) VALUES ($1, $2)`, tenantID, actorID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO identity.memberships (tenant_id, actor_id, role) VALUES ($1, $2, 'member')`, tenantID, actorID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	auth := identity.NewPostgres(pool, "test", map[string][]byte{"test": []byte("test-verifier-key")}, allowPDP{})
	lifecycleCtx := identityapi.WithPrincipal(ctx, identityapi.Principal{TenantID: tenantID, ActorID: actorID, Roles: []string{"member"}})
	pat, token, err := auth.IssuePAT(lifecycleCtx, tenantID, actorID, "integration", []string{"repo.read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	principal, ok := auth.AuthenticatePAT(t.Context(), token)
	if !ok || principal.TenantID != tenantID || principal.ActorID != actorID || !reflect.DeepEqual(principal.Roles, []string{"member"}) {
		t.Fatalf("resolved principal=%+v ok=%v", principal, ok)
	}
	if _, err := auth.RevokePAT(lifecycleCtx, tenantID, actorID, pat.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := auth.AuthenticatePAT(t.Context(), token); ok {
		t.Fatal("revoked PAT authenticated through resolver")
	}
}

type allowPDP struct{}

func (allowPDP) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true}, nil
}
