package domain

import (
	"errors"
	"time"
)

// The settings behaviour of the Repository aggregate (SPEC-0057, ADR-0076).
//
// It is in the domain rather than in the application service because the rules are about what a
// repository IS: a repository with no name is not a repository, a description is bounded prose, and
// an archived repository is one carrying a label — not one that has lost a capability.

// MaxDescriptionBytes bounds the description. The same bound is a CHECK on the column: the domain
// refuses first so the caller gets a reason, and the column refuses last so nothing else can write
// past it.
const MaxDescriptionBytes = 4096

// ErrNameRequired reports a rename to nothing. The registry's non-empty-name CHECK says the same, and
// so does NewRepository: a repository the product cannot name is one no surface can list.
var ErrNameRequired = errors.New("repository: name is required")

// ErrDescriptionTooLong reports a description past MaxDescriptionBytes.
var ErrDescriptionTooLong = errors.New("repository: description is longer than the bound")

// WithSettings returns the repository with its name and description changed, stamped with who
// changed them and when.
//
// It returns a new value rather than mutating: the caller holds the loaded aggregate until the store
// accepts the new one, so a refused write leaves nothing half-applied.
func (r Repository) WithSettings(name, description, actorID string, at time.Time) (Repository, error) {
	if name == "" {
		return Repository{}, ErrNameRequired
	}
	if len(description) > MaxDescriptionBytes {
		return Repository{}, ErrDescriptionTooLong
	}
	if actorID == "" {
		return Repository{}, errors.New("repository: an actor is required to change settings")
	}
	r.Name = name
	r.Description = description
	r.SettingsUpdatedAt = at.UTC()
	r.SettingsUpdatedBy = actorID
	return r, nil
}

// IsArchived reports whether the repository carries the archived label.
//
// It says nothing about what the repository can do. An archived repository still lists, still reads
// and is still writable — see the type comment on ArchivedAt.
func (r Repository) IsArchived() bool { return !r.ArchivedAt.IsZero() }

// WithArchived returns the repository in the archived state asked for, and reports whether that
// changed anything.
//
// The second return is what makes SPEC-0057 AC3 possible: archiving an archived repository is the
// same fact stated twice, so the caller writes no second audit record and does not move the recorded
// instant. Idempotency is decided here, on the aggregate that knows its own state, rather than in an
// adapter comparing rows.
func (r Repository) WithArchived(archived bool, actorID string, at time.Time) (Repository, bool, error) {
	if actorID == "" {
		return Repository{}, false, errors.New("repository: an actor is required to change archival")
	}
	if archived == r.IsArchived() {
		return r, false, nil
	}
	if archived {
		r.ArchivedAt = at.UTC()
	} else {
		r.ArchivedAt = time.Time{}
	}
	r.SettingsUpdatedAt = at.UTC()
	r.SettingsUpdatedBy = actorID
	return r, true, nil
}
