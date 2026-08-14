// Package reportstore persists CI scan reports (SPEC-0037, ADR-0059 Option C).
//
// A scan step's report becomes one durable, tenant-scoped object addressed by
// (tenant, repository, job, attempt, scanner class), with the content digest
// as the final segment so both object tiers can verify it:
//
//	ci-scan-reports/<tenant>/<repository>/<job>/<attempt>/<class>/<sha256>
//
// The package stores bytes and nothing else. It does not parse reports, assert
// identities, or touch findings — the Security context's subscriber does all of
// that, reading through the ci module's aliases (AC3: the report asserts no
// identity).
package reportstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/gitfrok/backend/platform/ids"
	"github.com/gitfrok/backend/platform/objectstore"
)

// rootPrefix is where every scan report lives. It is the prefix the retention
// sweep and the recovery backfill enumerate, so nothing else may be stored
// under it.
const rootPrefix = "ci-scan-reports"

// ErrScanReportNotFound is the coarse answer for any report that is absent —
// including one that exists under a different tenant, which must be
// indistinguishable from one that was never written (SPEC-0001).
var ErrScanReportNotFound = errors.New("reportstore: no such scan report")

// ErrScanReportTooLarge refuses a report that exceeds the configured size
// limit. The refusal is whole: nothing is truncated and nothing is stored
// (SPEC-0037 AC7).
var ErrScanReportTooLarge = errors.New("reportstore: scan report exceeds the size limit")

// Tier is the object tier reports live on. Both objectstore tiers satisfy it.
type Tier interface {
	Put(ctx context.Context, key string, size int64, sha256Hex string, body io.Reader) (int64, error)
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// Ref is one stored report's address.
type Ref struct {
	TenantID     string
	RepositoryID string
	JobID        string
	AttemptID    string
	ScannerClass string
	// Key is the full object key, digest segment included.
	Key string
}

// Store persists and retrieves scan reports on one tier.
type Store struct {
	tier     Tier
	maxBytes int64
	now      func() time.Time
}

// New builds a report store on tier. maxBytes is the write-time size limit
// (AC7) and now is the clock retention ages by.
func New(tier Tier, maxBytes int64, now func() time.Time) (*Store, error) {
	if tier == nil {
		return nil, errors.New("reportstore: a tier is required")
	}
	if maxBytes <= 0 {
		return nil, errors.New("reportstore: the size limit must be positive")
	}
	if now == nil {
		now = time.Now
	}
	return &Store{tier: tier, maxBytes: maxBytes, now: now}, nil
}

// Write persists one report for (tenant, repository, job, attempt, scanner
// class).
//
// It refuses reports over the size limit without truncating them (AC7), and it
// refuses a second report for a class an attempt already has (AC1: one object
// per scanner class per attempt). A write is either fully stored under its
// content digest or not stored at all — the tier's own Put makes that true.
func (s *Store) Write(ctx context.Context, tenantID, repositoryID, jobID, attemptID, scannerClass string, report io.Reader) (Ref, error) {
	if err := validateAddress(tenantID, repositoryID, jobID, attemptID, scannerClass); err != nil {
		return Ref{}, err
	}

	// Read at most maxBytes+1: enough to tell "at the limit" from "over it"
	// without buffering anything unbounded. The refusal is whole — truncating
	// would ingest a report that lies about what the scanner saw (AC7).
	body, err := io.ReadAll(io.LimitReader(report, s.maxBytes+1))
	if err != nil {
		return Ref{}, fmt.Errorf("reportstore: reading the report: %w", err)
	}
	if int64(len(body)) > s.maxBytes {
		return Ref{}, fmt.Errorf("%w: %d bytes, limit %d", ErrScanReportTooLarge, len(body), s.maxBytes)
	}

	classPrefix := s.classPrefix(tenantID, repositoryID, jobID, attemptID, scannerClass)
	existing, err := s.tier.List(ctx, classPrefix)
	if err != nil {
		return Ref{}, fmt.Errorf("reportstore: listing %s: %w", classPrefix, err)
	}
	if len(existing) > 0 {
		return Ref{}, fmt.Errorf("reportstore: %s/%s attempt %s already has a %s report", tenantID, repositoryID, attemptID, scannerClass)
	}

	digest := sha256.Sum256(body)
	key := classPrefix + hex.EncodeToString(digest[:])
	if _, err := s.tier.Put(ctx, key, int64(len(body)), hex.EncodeToString(digest[:]), bytes.NewReader(body)); err != nil {
		return Ref{}, fmt.Errorf("reportstore: storing %s: %w", key, err)
	}
	return Ref{TenantID: tenantID, RepositoryID: repositoryID, JobID: jobID, AttemptID: attemptID, ScannerClass: scannerClass, Key: key}, nil
}

// Read returns one report's bytes, or ErrScanReportNotFound.
func (s *Store) Read(ctx context.Context, tenantID, repositoryID, jobID, attemptID, scannerClass string) ([]byte, error) {
	if err := validateAddress(tenantID, repositoryID, jobID, attemptID, scannerClass); err != nil {
		return nil, err
	}
	keys, err := s.tier.List(ctx, s.classPrefix(tenantID, repositoryID, jobID, attemptID, scannerClass))
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrScanReportNotFound
	}
	body, err := s.readKey(ctx, keys[0])
	if err != nil {
		return nil, err
	}
	return body, nil
}

// AttemptReports lists the reports one attempt has, one per scanner class. An
// attempt that stored no report is an empty list, not an error: that is the
// state the ingest subscriber must treat as a strict no-op (AC4).
func (s *Store) AttemptReports(ctx context.Context, tenantID, repositoryID, jobID, attemptID string) ([]Ref, error) {
	if err := validateIDs(tenantID, repositoryID, jobID, attemptID); err != nil {
		return nil, err
	}
	keys, err := s.tier.List(ctx, s.attemptPrefix(tenantID, repositoryID, jobID, attemptID))
	if err != nil {
		return nil, err
	}
	var refs []Ref
	for _, key := range keys {
		if ref, ok := parseRef(key); ok {
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

// AllRefs enumerates every stored report across tenants. Only the retention
// sweep and the recovery backfill — both plane-internal — may call it.
func (s *Store) AllRefs(ctx context.Context) ([]Ref, error) {
	keys, err := s.tier.List(ctx, rootPrefix+"/")
	if err != nil {
		return nil, err
	}
	var refs []Ref
	for _, key := range keys {
		if ref, ok := parseRef(key); ok {
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

// Sweep deletes reports whose attempt ULID is older than retention, and
// returns how many objects it deleted. It deletes reports only: the findings,
// scans and audit records derived from them are the Security and Audit
// contexts' to keep (AC9). What cannot be aged — an attempt segment that is
// not a ULID — is left for an operator, never guessed at.
func (s *Store) Sweep(ctx context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, errors.New("reportstore: retention must be positive")
	}
	refs, err := s.AllRefs(ctx)
	if err != nil {
		return 0, err
	}
	cutoff := s.now().Add(-retention)
	byAttempt := map[string][]Ref{}
	for _, ref := range refs {
		issued, ok := ids.TimeOf(ref.AttemptID)
		if !ok {
			continue
		}
		if issued.Before(cutoff) {
			byAttempt[ref.AttemptID] = append(byAttempt[ref.AttemptID], ref)
		}
	}
	attempts := make([]string, 0, len(byAttempt))
	for attempt := range byAttempt {
		attempts = append(attempts, attempt)
	}
	slices.Sort(attempts)
	deleted := 0
	for _, attempt := range attempts {
		for _, ref := range byAttempt[attempt] {
			if err := s.tier.Delete(ctx, ref.Key); err != nil {
				return deleted, fmt.Errorf("reportstore: deleting %s: %w", ref.Key, err)
			}
			deleted++
		}
	}
	return deleted, nil
}

func (s *Store) readKey(ctx context.Context, key string) ([]byte, error) {
	body, _, err := s.tier.Get(ctx, key)
	if errors.Is(err, objectstore.ErrNotFound) {
		return nil, ErrScanReportNotFound
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()
	return io.ReadAll(body)
}

// classPrefix names the directory one scanner class's reports live in; the
// digest segment completes the key.
func (s *Store) classPrefix(tenantID, repositoryID, jobID, attemptID, scannerClass string) string {
	return rootPrefix + "/" + tenantID + "/" + repositoryID + "/" + jobID + "/" + attemptID + "/" + scannerClass + "/"
}

func (s *Store) attemptPrefix(tenantID, repositoryID, jobID, attemptID string) string {
	return rootPrefix + "/" + tenantID + "/" + repositoryID + "/" + jobID + "/" + attemptID + "/"
}

// parseRef is the inverse of the key shape. Anything that does not parse is
// skipped by the enumerators rather than guessed at.
func parseRef(key string) (Ref, bool) {
	parts := strings.Split(key, "/")
	if len(parts) != 7 || parts[0] != rootPrefix || parts[6] == "" {
		return Ref{}, false
	}
	return Ref{
		TenantID:     parts[1],
		RepositoryID: parts[2],
		JobID:        parts[3],
		AttemptID:    parts[4],
		ScannerClass: parts[5],
		Key:          key,
	}, true
}

// validateIDs refuses an address whose identifiers cannot safely become key
// segments, before any of them can. Jobs and attempts are ids this platform
// issues and are checked strictly; tenants and repositories are slugs and are
// checked for shape only.
func validateIDs(tenantID, repositoryID, jobID, attemptID string) error {
	if !validSlug(tenantID) {
		return fmt.Errorf("reportstore: %q is not a tenant identifier", tenantID)
	}
	if !validSlug(repositoryID) {
		return fmt.Errorf("reportstore: %q is not a repository identifier", repositoryID)
	}
	if !validULID(jobID) {
		return fmt.Errorf("reportstore: %q is not a job identifier", jobID)
	}
	if !validULID(attemptID) {
		return fmt.Errorf("reportstore: %q is not an attempt identifier", attemptID)
	}
	return nil
}

func validateAddress(tenantID, repositoryID, jobID, attemptID, scannerClass string) error {
	if err := validateIDs(tenantID, repositoryID, jobID, attemptID); err != nil {
		return err
	}
	if !validClass(scannerClass) {
		return fmt.Errorf("reportstore: %q is not a scanner class", scannerClass)
	}
	return nil
}

// validULID accepts exactly the shape ids.NewULID issues: 26 Crockford base32
// characters, strict on case. Jobs and attempts carry the retention clock in
// that prefix, so nothing looser is admitted in their position.
func validULID(s string) bool {
	if len(s) != 26 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'Z' && !strings.ContainsRune("ILOU", rune(c)):
		default:
			return false
		}
	}
	return true
}

// validSlug accepts tenant and repository identifiers: the slug vocabulary the
// tenancy layer issues. The check is shape, not origin — origin is enforced by
// the caller's context — but a segment that could navigate the key space is
// refused outright.
func validSlug(s string) bool {
	if s == "" || len(s) > 64 || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// validClass accepts the scanner vocabulary the Security context's adapters
// declare (lowercase, digits, dashes): "sast", "secrets". A class is caller
// supplied, so anything else is refused rather than carried into a key.
func validClass(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}
