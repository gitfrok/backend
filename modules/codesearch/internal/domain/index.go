// Package domain is the Code Search context's core model. It imports NO infrastructure —
// dependencies point inward (invariant 16).
package domain

import "errors"

// TenantID scopes every entry; there is no un-tenant-scoped index (invariant 1).
type TenantID string

// RepoID identifies an indexed repository within a tenant.
type RepoID string

// ErrNotIndexed reports that nothing is indexed under that tenant and id. It deliberately does not
// distinguish "another tenant has it" from "nobody has it": a caller must not learn that a
// repository it cannot see exists (the shape PR-19 depends on).
var ErrNotIndexed = errors.New("codesearch: not indexed")

// Entry is one indexed repository.
type Entry struct {
	Tenant TenantID
	ID     RepoID
	Name   string
	Refs   map[string]string
}

// Index is the tenant-partitioned set of entries.
type Index struct {
	entries map[TenantID]map[RepoID]Entry
}

// NewIndex builds an empty index.
func NewIndex() *Index {
	return &Index{entries: make(map[TenantID]map[RepoID]Entry)}
}

// Put inserts or replaces an entry.
func (i *Index) Put(e Entry) {
	byRepo, ok := i.entries[e.Tenant]
	if !ok {
		byRepo = make(map[RepoID]Entry)
		i.entries[e.Tenant] = byRepo
	}
	if e.Refs == nil {
		e.Refs = make(map[string]string)
	}
	byRepo[e.ID] = e
}

// Get returns the entry for a tenant's repository.
func (i *Index) Get(t TenantID, id RepoID) (Entry, error) {
	e, ok := i.entries[t][id]
	if !ok {
		return Entry{}, ErrNotIndexed
	}
	return e, nil
}

// SetRef records the sha last seen for a ref. An update for an entry that is not indexed is
// reported, not invented: once these events arrive over Redpanda they can be reordered, and a
// half-populated entry would be worse than none.
func (i *Index) SetRef(t TenantID, id RepoID, ref, sha string) error {
	e, err := i.Get(t, id)
	if err != nil {
		return err
	}
	e.Refs[ref] = sha
	return nil
}
