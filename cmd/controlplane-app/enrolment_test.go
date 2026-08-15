package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	agentv1 "github.com/gitfrok/backend/gen/proto/agent/v1"
	"github.com/gitfrok/backend/modules/agent"
	agentapi "github.com/gitfrok/backend/modules/agent/api"
	"github.com/gitfrok/backend/modules/identity"
	"github.com/gitfrok/backend/modules/policy"
	platformaudit "github.com/gitfrok/backend/platform/audit"
	"github.com/gitfrok/backend/platform/bus"
	"github.com/gitfrok/backend/platform/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// The enrolment issuance door's composition proofs (SPEC-0038 AC1): the PDP
// decides the caller's posture from the verified principal's roles, a PAT the
// verifier key cannot authenticate never reaches the PDP, and a successful
// issuance writes the durable token and returns its secret exactly once.

// TestMain self-applies the agent module's enrolment migration when the
// superuser DSN is available, so the durable-door proof does not depend on the
// dev-provision list knowing about it — the same seam the agent module's own
// Postgres suite uses.
func TestMain(m *testing.M) {
	if dsn := os.Getenv("TEST_SUPERUSER_DATABASE_URL"); dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		file := filepath.Join("..", "..", "modules", "agent", "internal", "adapters", "postgres", "migrations", "0001_agent_enrolment.sql")
		if sql, err := os.ReadFile(file); err == nil {
			if pool, err := pgxpool.New(ctx, dsn); err == nil {
				if _, err := pool.Exec(ctx, string(sql)); err != nil {
					fmt.Fprintf(os.Stderr, "controlplane-app enrolment tests: could not self-apply migration: %v\n", err)
				}
				pool.Close()
			}
		}
		cancel()
	}
	os.Exit(m.Run())
}

// enrolVerifierKey is a 32-byte PAT verifier key — the same credential shape
// the residency door's config test uses.
var enrolVerifierKey = []byte("0123456789abcdef0123456789abcdef")

// enrolCfg is the agent surface's per-environment configuration the door's
// tests compose with: the TokenMaxLifetime under test is 24h.
func enrolCfg() agentapi.Config {
	return agentapi.Config{
		CertLifetime:          time.Hour,
		RotationLead:          20 * time.Minute,
		RotationRetryInterval: time.Minute,
		StaleAfter:            5 * time.Minute,
		TokenMaxLifetime:      24 * time.Hour,
		HeartbeatInterval:     30 * time.Second,
		ClockSkewLeeway:       5 * time.Minute,
		Now:                   time.Now,
	}
}

// enrolBearerCtx is one incoming door call carrying the credential the way the
// wire does: an authorization metadata value of "Bearer <token>".
func enrolBearerCtx(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer "+token))
}

// enrolmentBundleDir is the reviewed policy bundle, mounted beside the backend
// in every development checkout and in CI — the same seam the residency
// module's bundle proof uses.
func enrolmentBundleDir() (string, bool) {
	dir := filepath.Join("..", "..", "..", "governance", "policies")
	if _, err := os.Stat(filepath.Join(dir, ".manifest")); err != nil {
		return "", false
	}
	return dir, true
}

// enrolAuditCounts subscribes the bus's audit channel and counts the events the
// door's contract names: one AgentTokenIssued per issuance, one
// PolicyDecisionDenied per PDP refusal, and nothing for a subject the platform
// never verified.
type enrolAuditCounts struct {
	issued int
	denied int
}

func watchEnrolAudit(b bus.Bus) *enrolAuditCounts {
	c := &enrolAuditCounts{}
	b.Subscribe(platformaudit.EventAudit, func(_ context.Context, e bus.Event) error {
		switch e.(type) {
		case platformaudit.AgentTokenIssued:
			c.issued++
		case platformaudit.PolicyDecisionDenied:
			c.denied++
		}
		return nil
	})
	return c
}

// TestEnrolmentDoorConfigIsAllOrNothing is the fail-fast posture the issuance
// door inherits from the residency Declare door (ADR-0006): an unconfigured
// door serves no surface, but an open door without a verifier key fails the
// rollout — a door that cannot verify its caller must never serve a surface
// that mints credentials (SPEC-0038 AC1).
func TestEnrolmentDoorConfigIsAllOrNothing(t *testing.T) {
	getenv := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	// Unconfigured: no door, no error — the health-only plane is unchanged.
	cfg, err := loadEnrolmentDoorConfig(getenv(map[string]string{}))
	if err != nil || cfg.addr != "" || cfg.patKey != nil {
		t.Fatalf("unconfigured door = %+v, %v; want empty, no error", cfg, err)
	}
	// Open door with a proper key: both, as one unit.
	key := "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=" // base64 of 31+ bytes
	cfg, err = loadEnrolmentDoorConfig(getenv(map[string]string{
		enrolmentGRPCAddrEnv: "127.0.0.1:7166", patVerifierKeyEnv: key,
	}))
	if err != nil || cfg.addr != "127.0.0.1:7166" || len(cfg.patKey) < 32 {
		t.Fatalf("configured door = %+v, %v; want addr + >=32-byte key", cfg, err)
	}
	// Open door, missing/short/malformed key: the rollout fails.
	for name, kv := range map[string]string{
		"missing key": "",
		"short key":   "c2hvcnQ=",
		"not base64":  "!!!",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadEnrolmentDoorConfig(getenv(map[string]string{
				enrolmentGRPCAddrEnv: "127.0.0.1:7166", patVerifierKeyEnv: kv,
			})); err == nil {
				t.Fatalf("an open door without a usable verifier key must fail the rollout (%s)", name)
			}
		})
	}
}

// TestEnrolmentDoorPDPDecidesTheVerifiedPosture is the door's behavioral proof
// against the REAL governance bundle (SPEC-0038 AC1, SPEC-0002 AC4): the door
// presents the PAT-verified principal to the PDP action agent.enrolment_token.issue
// and the bundle's answer is the issuance's outcome. Under the merged bundle the
// issuance is an owner grant: an owner-rolled principal is allowed and issues
// exactly one audited token, while member, reader and platform_operator
// principals are refused — one PolicyDecisionDenied each — and an unverified
// caller produces NO decision at all.
func TestEnrolmentDoorPDPDecidesTheVerifiedPosture(t *testing.T) {
	dir, ok := enrolmentBundleDir()
	if !ok {
		t.Skip("governance/policies not checked out beside backend/; the bundle proof needs both repos")
	}
	b := bus.NewInProcess()
	pdp, err := policy.NewOPADecisionPoint(dir, b)
	if err != nil {
		t.Fatalf("the real governance bundle does not load: %v", err)
	}
	counts := watchEnrolAudit(b)
	ca, err := agent.NewDevCA("test-enrolment-door-ca", time.Now)
	if err != nil {
		t.Fatalf("dev ca: %v", err)
	}
	svc := agent.New(pdp, b, ca, enrolCfg(), func(string, ...any) {})
	auth := identity.NewInMemory(enrolVerifierKey, pdp)
	door := agent.NewEnrolmentDoor(svc, auth, nil)

	const tenant = "acme"
	issuePAT := func(actor string, roles []string) string {
		t.Helper()
		_, secret, err := auth.IssuePAT(ownerCtx(tenant), tenant, actor, "door-test", nil, roles, nil)
		if err != nil {
			t.Fatalf("issue PAT for %v: %v", roles, err)
		}
		return secret
	}

	// The owner posture issues: one token, one issuance record, the secret
	// returned exactly once in this response.
	resp, err := door.IssueEnrolmentToken(enrolBearerCtx(issuePAT("op-owner", []string{"owner"})),
		&agentv1.IssueEnrolmentTokenRequest{Lifetime: durationpb.New(time.Hour)})
	if err != nil {
		t.Fatalf("owner issuance through the real bundle: %v", err)
	}
	if resp.GetTokenId() == "" || resp.GetOneTimeToken() == "" {
		t.Fatalf("issuance must return the token's ID and its secret once, got %+v", resp)
	}
	if counts.issued != 1 {
		t.Fatalf("issuance audit records = %d, want exactly 1", counts.issued)
	}

	// The wrong-role postures are the PDP's refusals: each leaves exactly one
	// denial record and mints nothing.
	deniedBefore := counts.denied
	for _, roles := range [][]string{{"member"}, {"reader"}, {"platform_operator"}} {
		_, err := door.IssueEnrolmentToken(enrolBearerCtx(issuePAT("op-x", roles)),
			&agentv1.IssueEnrolmentTokenRequest{Lifetime: durationpb.New(time.Hour)})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("roles %v: err = %v, want the coarse PermissionDenied", roles, err)
		}
	}
	if counts.denied-deniedBefore != 3 {
		t.Fatalf("denial audit records = %d, want exactly 3 — one per refused role", counts.denied-deniedBefore)
	}
	if counts.issued != 1 {
		t.Fatalf("a refused issuance must mint nothing, got %d issued", counts.issued)
	}

	// An unverified caller is refused BEFORE the PDP: no decision is recorded
	// for a subject the platform did not verify, and nothing is minted.
	if _, err := door.IssueEnrolmentToken(context.Background(),
		&agentv1.IssueEnrolmentTokenRequest{Lifetime: durationpb.New(time.Hour)}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unverified call = %v, want the coarse refusal", err)
	}
	if counts.denied != deniedBefore+3 || counts.issued != 1 {
		t.Fatalf("an unverified caller must leave no PDP decision and no token (denied=%d issued=%d)",
			counts.denied, counts.issued)
	}
}

// TestEnrolmentDoorRejectsUnverifiableSignaturesBeforePolicy is the PAT seam's
// proof (ADR-0043): a credential the verifier key cannot authenticate — a
// tampered signature, a key that does not match, or no credential at all — is
// refused with the one coarse shape and never reaches the operator surface, so
// no issuance and no PDP decision exist for it.
func TestEnrolmentDoorRejectsUnverifiableSignaturesBeforePolicy(t *testing.T) {
	b := bus.NewInProcess()
	counts := watchEnrolAudit(b)
	ca, err := agent.NewDevCA("test-enrolment-signature-ca", time.Now)
	if err != nil {
		t.Fatalf("dev ca: %v", err)
	}
	svc := agent.New(allowPDP{}, b, ca, enrolCfg(), func(string, ...any) {})
	auth := identity.NewInMemory(enrolVerifierKey, allowPDP{})
	door := agent.NewEnrolmentDoor(svc, auth, nil)

	const tenant = "acme"
	_, secret, err := auth.IssuePAT(ownerCtx(tenant), tenant, "op-1", "sig-test", nil, []string{"owner"}, nil)
	if err != nil {
		t.Fatalf("issue PAT: %v", err)
	}

	// The intact signature issues.
	if _, err := door.IssueEnrolmentToken(enrolBearerCtx(secret),
		&agentv1.IssueEnrolmentTokenRequest{Lifetime: durationpb.New(time.Hour)}); err != nil {
		t.Fatalf("intact credential: %v", err)
	}
	if counts.issued != 1 {
		t.Fatalf("issuance records = %d, want 1", counts.issued)
	}

	// A tampered signature, a door verifying against ANOTHER key, and an absent
	// credential are all the same coarse refusal BEFORE any policy question —
	// the allowPDP above allows everything, so any reach of the surface would
	// have issued.
	tampered := secret[:len(secret)-1] + "0"
	if tampered == secret {
		tampered = secret[:len(secret)-1] + "1"
	}
	otherKeyDoor := agent.NewEnrolmentDoor(svc, identity.NewInMemory([]byte("fedcba9876543210fedcba9876543210"), allowPDP{}), nil)
	for name, call := range map[string]func() error{
		"tampered signature": func() error {
			_, err := door.IssueEnrolmentToken(enrolBearerCtx(tampered), &agentv1.IssueEnrolmentTokenRequest{})
			return err
		},
		"wrong verifier key": func() error {
			_, err := otherKeyDoor.IssueEnrolmentToken(enrolBearerCtx(secret), &agentv1.IssueEnrolmentTokenRequest{})
			return err
		},
		"no credential": func() error {
			_, err := door.IssueEnrolmentToken(context.Background(), &agentv1.IssueEnrolmentTokenRequest{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if status.Code(call()) != codes.PermissionDenied {
				t.Fatalf("%s must refuse with the coarse PermissionDenied", name)
			}
		})
	}
	if counts.issued != 1 || counts.denied != 0 {
		t.Fatalf("unverifiable credentials must reach neither the surface nor the PDP (issued=%d denied=%d)",
			counts.issued, counts.denied)
	}
}

// TestEnrolmentDoorDurableIssuanceReturnsTokenOnce is the door's durability
// proof against a real Postgres (SPEC-0038 AC1/AC2, ADR-0062): a successful
// issuance writes the token onto the durable agent.enrolment_tokens store — a
// FRESH service over the same pool reads it back — returns the secret in
// exactly this one response, and honors the lifetime bounds: a shorter request
// is kept, zero and beyond-maximum both clamp to the configured maximum.
func TestEnrolmentDoorDurableIssuanceReturnsTokenOnce(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — needs the dev Postgres (port-forward 15432)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	pool, err := db.Open(ctx, dsn)
	cancel()
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	defer pool.Close()

	b := bus.NewInProcess()
	counts := watchEnrolAudit(b)
	ca, err := agent.NewDevCA("test-enrolment-durable-ca", time.Now)
	if err != nil {
		t.Fatalf("dev ca: %v", err)
	}
	stores := agent.NewPostgresStores(pool)
	svc := agent.NewWithStores(allowPDP{}, b, ca, stores, stores, enrolCfg(), func(string, ...any) {})
	auth := identity.NewInMemory(enrolVerifierKey, allowPDP{})
	door := agent.NewEnrolmentDoor(svc, auth, nil)

	tenant := fmt.Sprintf("enrol-door-%d", time.Now().UnixNano()%1_000_000_000)
	_, secret, err := auth.IssuePAT(ownerCtx(tenant), tenant, "op-1", "durable-test", nil, []string{"owner"}, nil)
	if err != nil {
		t.Fatalf("issue PAT: %v", err)
	}

	issue := func(lifetime *durationpb.Duration) (string, string, time.Duration) {
		t.Helper()
		req := &agentv1.IssueEnrolmentTokenRequest{}
		if lifetime != nil {
			req.Lifetime = lifetime
		}
		resp, err := door.IssueEnrolmentToken(enrolBearerCtx(secret), req)
		if err != nil {
			t.Fatalf("durable issuance (lifetime %v): %v", lifetime, err)
		}
		if resp.GetOneTimeToken() == "" || resp.GetTokenId() == "" {
			t.Fatalf("issuance must return the secret and its ID exactly once, got %+v", resp)
		}
		return resp.GetTokenId(), resp.GetOneTimeToken(),
			resp.GetExpiresAt().AsTime().Sub(resp.GetIssuedAt().AsTime())
	}

	// A shorter lifetime is kept as requested.
	id1, secret1, window1 := issue(durationpb.New(time.Hour))
	if window1 != time.Hour {
		t.Fatalf("a 1h request must yield a 1h window, got %v", window1)
	}
	// Zero and beyond-maximum clamp to the configured maximum — a caller can
	// shorten a token but never lengthen it past the bound.
	id2, secret2, window2 := issue(nil)
	if window2 != 24*time.Hour {
		t.Fatalf("an absent lifetime must clamp to the 24h maximum, got %v", window2)
	}
	id3, secret3, window3 := issue(durationpb.New(72 * time.Hour))
	if window3 != 24*time.Hour {
		t.Fatalf("a 72h request must clamp to the 24h maximum, got %v", window3)
	}
	// The secret exists in exactly one response per token: three issuances,
	// three distinct secrets, none ever retrievable again — the store holds
	// only the hash (AC2).
	if secret1 == secret2 || secret1 == secret3 || secret2 == secret3 {
		t.Fatal("each issuance mints its own secret")
	}
	if counts.issued != 3 {
		t.Fatalf("issuance audit records = %d, want exactly 3 — one per act", counts.issued)
	}

	// Durability: a FRESH service composed over the SAME pool reads every
	// issued token back — the state is a property of the platform, not of the
	// process that minted it (ADR-0062).
	freshStores := agent.NewPostgresStores(pool)
	freshSvc := agent.NewWithStores(allowPDP{}, bus.NewInProcess(), ca, freshStores, freshStores, enrolCfg(), func(string, ...any) {})
	fleet, err := freshSvc.Fleet(ownerCtx(tenant), tenant, "op-1")
	if err != nil {
		t.Fatalf("fresh service fleet read: %v", err)
	}
	seen := map[string]bool{}
	for _, row := range fleet {
		if row.TokenID != "" {
			seen[row.TokenID] = true
			if row.Status != agentapi.StatusNeverConnected {
				t.Fatalf("an unspent durable token reads %s, want NEVER_CONNECTED", row.Status)
			}
		}
	}
	for _, id := range []string{id1, id2, id3} {
		if !seen[id] {
			t.Fatalf("token %s was not read back from the durable store by a fresh service", id)
		}
	}
}
