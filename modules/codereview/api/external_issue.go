package api

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

// External issue references (SPEC-0059, PR-28's accepted scope, ADR-0074).
//
// This product does not build an issue tracker. A merge request carries POINTERS to
// issues that live in the customer's own tracker, and the design's whole content is
// what it refuses: nothing here fetches, polls, authenticates against or receives a
// webhook from that tracker.
//
// That is why ExternalIssue has no title and no state. A title would have to be
// fetched — making this product a client of a system it does not control, with
// credentials, retries and an outage story — or typed, making it a copy that
// silently diverges from the truth it claims to show. check-contracts' check 18
// asserts that absence against the contract.
//
// A reference is INERT. Merging performs no outbound act and infers no issue state;
// the merge gate does not read these, and nothing here can satisfy a policy.

// ExternalIssue is one reference: which tracker, which issue, and where it is.
type ExternalIssue struct {
	// Tracker is a short label the tenant recognises — "JIRA", "Linear". It is a
	// free string, not an enum: a vocabulary of trackers would need a decision
	// every time a customer used a different one.
	Tracker string
	// IssueKey is what a person says out loud, e.g. PLAT-1421. With Tracker it is
	// the reference's identity.
	IssueKey string
	// URL is absolute and https. It is the only field a reader clicks.
	URL      string
	LinkedBy string
	LinkedAt time.Time
}

// Bounds on a reference. A reference list is a reference list, not a document: each
// field is bounded and so is the count, because an unbounded list on an aggregate is
// a way to make one merge request expensive for everybody who reads it.
const (
	MaxTrackerBytes   = 32
	MaxIssueKeyBytes  = 64
	MaxIssueURLBytes  = 512
	MaxExternalIssues = 25
)

// ErrInvalidExternalIssue reports a reference this product will not store.
//
// It is deliberately distinguishable from ErrDenied: it is about the fields the
// caller just sent, which the caller already knows, so naming it discloses nothing —
// and a form that fails for no stated reason is a worse product than one that says
// which field was wrong.
var ErrInvalidExternalIssue = errors.New("codereview: a reference needs a tracker, an issue key and an https URL")

// ErrTooManyExternalIssues reports a merge request already carrying MaxExternalIssues.
var ErrTooManyExternalIssues = errors.New("codereview: this merge request has as many issue references as it can carry")

// SameAs reports whether two references name the same issue.
//
// Identity is (tracker, issue key) and NOT the URL: the same issue reached by two
// URLs — a short link and a canonical one — is one issue, and treating them as two
// would let a caller fill the list with synonyms.
func (e ExternalIssue) SameAs(other ExternalIssue) bool {
	return strings.EqualFold(e.Tracker, other.Tracker) && e.IssueKey == other.IssueKey
}

// Validate reports whether this reference may be stored.
//
// The URL rule is the one that matters: absolute, and https. This is a link a person
// clicks from inside the product, so a `javascript:`, `data:`, `http:` or relative
// URL is refused here — and refused again at the frontend, because this one is worth
// refusing twice.
func (e ExternalIssue) Validate() error {
	if strings.TrimSpace(e.Tracker) == "" || len(e.Tracker) > MaxTrackerBytes {
		return ErrInvalidExternalIssue
	}
	if strings.TrimSpace(e.IssueKey) == "" || len(e.IssueKey) > MaxIssueKeyBytes {
		return ErrInvalidExternalIssue
	}
	if len(e.URL) > MaxIssueURLBytes {
		return ErrInvalidExternalIssue
	}
	parsed, err := url.Parse(e.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return ErrInvalidExternalIssue
	}
	return nil
}

// LinkExternalIssueRequest references an issue from one merge request.
//
// There is no LinkedBy field: who linked it is the verified caller on the call, and
// a field naming one would be an unauthenticated authorship claim.
type LinkExternalIssueRequest struct {
	Context
	MergeRequestID string
	Tracker        string
	IssueKey       string
	URL            string
}

// UnlinkExternalIssueRequest removes a reference by its identity.
//
// By tracker and key rather than by position: a positional remove is a race between
// two readers of the same merge request, and the loser removes something they were
// not looking at.
type UnlinkExternalIssueRequest struct {
	Context
	MergeRequestID string
	Tracker        string
	IssueKey       string
}
