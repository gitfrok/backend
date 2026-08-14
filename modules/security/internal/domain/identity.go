// Package domain is the Security/Findings domain layer. It imports no
// infrastructure (invariant 16): identity derivation is a pure function,
// because SPEC-0024 requires the same input set to yield the same identity on
// any node, in any process, at any time.
package domain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
)

// ScannerClass is the one-of-five scanner classes the normalized model covers
// (SPEC-0024 AC1). Adding a class is an additive value here and in the
// contract; adding a scanner needs no model change (AC6).
type ScannerClass string

const (
	ScannerClassSAST       ScannerClass = "SAST"
	ScannerClassDependency ScannerClass = "DEPENDENCY"
	ScannerClassSecrets    ScannerClass = "SECRETS"
	ScannerClassContainer  ScannerClass = "CONTAINER"
	ScannerClassDAST       ScannerClass = "DAST"
)

// Valid reports whether the class is one of the five.
func (c ScannerClass) Valid() bool {
	switch c {
	case ScannerClassSAST, ScannerClassDependency, ScannerClassSecrets,
		ScannerClassContainer, ScannerClassDAST:
		return true
	}
	return false
}

// Location is the content-derived half of the identity input set (SPEC-0024).
//
// For SAST, secrets, and DAST findings the location is the artifact the
// finding sits in plus the enclosing content that carries it. For dependency
// and container findings the affected component and version stand in place of
// a file location. Identity is invariant to the commit, the scan run, and the
// absolute line number — none of those is representable here, which is the
// point: a field that cannot be supplied cannot leak into the identity.
type Location struct {
	// ArtifactPath is the path, within the repository, of the artifact the
	// finding sits in. It is part of the input set, so a rename yields a new
	// identity (the old finding resolves, the new one opens).
	ArtifactPath string
	// EnclosingContent is the content that carries the finding — the
	// normalized snippet or enclosing symbol the scanner names. It is
	// content-derived, so an unrelated edit elsewhere in the file, which
	// shifts the finding's line without changing this content, cannot move
	// the identity (SPEC-0024 AC2).
	EnclosingContent string
	// Component and ComponentVersion are the dependency/container substitute
	// for a file location.
	Component        string
	ComponentVersion string
}

// Normalize returns the location with its content-derived fields canonicalized
// (surrounding whitespace trimmed, line endings unified). Normalization is the
// adapter's obligation before identity computation; applying it here as well
// makes the domain total — an unnormalized input cannot produce a different
// identity than the same content delivered normalized.
func (l Location) Normalize() Location {
	return Location{
		ArtifactPath:     strings.TrimSpace(l.ArtifactPath),
		EnclosingContent: normalizeContent(l.EnclosingContent),
		Component:        strings.TrimSpace(l.Component),
		ComponentVersion: strings.TrimSpace(l.ComponentVersion),
	}
}

// normalizeContent trims the edges and unifies line endings without touching
// interior content: interior differences still distinguish findings (AC3).
func normalizeContent(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.TrimSpace(s)
}

// IdentityInput is the named input set of SPEC-0024's identity rule, complete
// and closed: tenant, repository, reporting tool (scanner class and tool
// identity), rule, and the content-derived location. The type is the contract
// — adding or removing a field changes every existing identity and is
// therefore a spec amendment, not a refactor. What is absent is as load
// bearing as what is present: no commit, no scan run, no absolute line, no
// tool version, and no provenance can influence the result.
type IdentityInput struct {
	TenantID     string
	RepositoryID string
	ScannerClass ScannerClass
	ToolName     string
	RuleID       string
	Location     Location
}

// IdentityPrefix marks every server-computed finding identity.
const IdentityPrefix = "fnd-"

// Identity computes the finding identity: a deterministic, opaque digest of
// the input set. Deterministic means a pure function of the inputs — no
// clock, no randomness, no environment. Opaque means the digest reveals
// nothing about the inputs: an identity travels through events, cursors, and
// other tenants' adjacent surfaces without leaking finding content.
//
// Implementations choose the hash construction; they may not choose the input
// set (SPEC-0024). The construction here length-prefixes every field, so no
// two distinct input tuples can serialize to the same byte string.
func Identity(in IdentityInput) string {
	in.Location = in.Location.Normalize()

	h := sha256.New()
	for _, field := range []string{
		in.TenantID,
		in.RepositoryID,
		string(in.ScannerClass),
		in.ToolName,
		in.RuleID,
		in.Location.ArtifactPath,
		in.Location.EnclosingContent,
		in.Location.Component,
		in.Location.ComponentVersion,
	} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		h.Write(length[:])
		io.WriteString(h, field)
	}
	return IdentityPrefix + hex.EncodeToString(h.Sum(nil))
}
