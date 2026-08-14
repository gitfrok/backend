// Package memory is the Metering context's in-memory persistence adapter.
// A Postgres adapter is future work; the store is a port, so that is a
// composition-line change (invariant 13).
//
// The adapter's one load-bearing property is message-ID dedup (SPEC-0041
// non-functional): a replayed sample — the shape a control-plane restart
// with at-least-once redelivery produces — is recognized and refused, so
// re-derivation from the record set neither double-counts nor loses an
// interval.
package memory

import (
	"context"
	"slices"
	"sync"

	"github.com/gitfrok/backend/modules/metering/api"
	"github.com/gitfrok/backend/modules/metering/internal/domain"
)

// Store is the in-memory implementation of the app layer's Store port.
type Store struct {
	mu          sync.Mutex
	samples     map[string][]domain.Sample
	sampleIDs   map[string]map[string]bool
	reports     map[string][]domain.UsageReport
	reportIDs   map[string]map[string]bool
	divergences map[string][]api.Divergence
	notices     map[string][]api.Notice
	noticeState map[string]map[api.Dimension]api.State
	thresholds  map[string]map[api.Dimension]api.Threshold
	generations map[string]int64
}

// New builds an empty store.
func New() *Store {
	return &Store{
		samples:     make(map[string][]domain.Sample),
		sampleIDs:   make(map[string]map[string]bool),
		reports:     make(map[string][]domain.UsageReport),
		reportIDs:   make(map[string]map[string]bool),
		divergences: make(map[string][]api.Divergence),
		notices:     make(map[string][]api.Notice),
		noticeState: make(map[string]map[api.Dimension]api.State),
		thresholds:  make(map[string]map[api.Dimension]api.Threshold),
		generations: make(map[string]int64),
	}
}

// AddSample records one sample, idempotent per MessageID.
func (s *Store) AddSample(_ context.Context, tenantID string, sample domain.Sample) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := s.sampleIDs[tenantID]
	if seen == nil {
		seen = make(map[string]bool)
		s.sampleIDs[tenantID] = seen
	}
	if seen[sample.MessageID] {
		return false, nil
	}
	seen[sample.MessageID] = true
	s.samples[tenantID] = append(s.samples[tenantID], sample)
	return true, nil
}

// Samples returns the tenant's recorded samples.
func (s *Store) Samples(_ context.Context, tenantID string) ([]domain.Sample, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.samples[tenantID]), nil
}

// AddUsageReport records one self-report, idempotent per MessageID.
func (s *Store) AddUsageReport(_ context.Context, tenantID string, u domain.UsageReport) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := s.reportIDs[tenantID]
	if seen == nil {
		seen = make(map[string]bool)
		s.reportIDs[tenantID] = seen
	}
	if seen[u.MessageID] {
		return false, nil
	}
	seen[u.MessageID] = true
	s.reports[tenantID] = append(s.reports[tenantID], u)
	return true, nil
}

// UsageReports returns the tenant's recorded self-reports.
func (s *Store) UsageReports(_ context.Context, tenantID string) ([]domain.UsageReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reports[tenantID]), nil
}

// RecordDivergence appends one health finding.
func (s *Store) RecordDivergence(_ context.Context, tenantID string, d api.Divergence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.divergences[tenantID] = append(s.divergences[tenantID], d)
	return nil
}

// Divergences returns the tenant's health findings.
func (s *Store) Divergences(_ context.Context, tenantID string) ([]api.Divergence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.divergences[tenantID]), nil
}

// RecordNotice appends one in-product notice.
func (s *Store) RecordNotice(_ context.Context, tenantID string, n api.Notice) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notices[tenantID] = append(s.notices[tenantID], n)
	return nil
}

// Notices returns the tenant's in-product notices.
func (s *Store) Notices(_ context.Context, tenantID string) ([]api.Notice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.notices[tenantID]), nil
}

// NoticeState reads the edge-trigger state for one dimension.
func (s *Store) NoticeState(_ context.Context, tenantID string, d api.Dimension) (api.State, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.noticeState[tenantID][d]
	return st, ok, nil
}

// SetNoticeState records the edge-trigger state for one dimension.
func (s *Store) SetNoticeState(_ context.Context, tenantID string, d api.Dimension, st api.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.noticeState[tenantID] == nil {
		s.noticeState[tenantID] = make(map[api.Dimension]api.State)
	}
	s.noticeState[tenantID][d] = st
	return nil
}

// TenantThresholds reads one tenant's stored overrides.
func (s *Store) TenantThresholds(_ context.Context, tenantID string) (map[api.Dimension]api.Threshold, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.thresholds[tenantID]
	if !ok {
		return nil, false, nil
	}
	out := make(map[api.Dimension]api.Threshold, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out, true, nil
}

// SetTenantThresholds stores one tenant's overrides.
func (s *Store) SetTenantThresholds(_ context.Context, tenantID string, m map[api.Dimension]api.Threshold) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.thresholds[tenantID] = m
	return nil
}

// NextGeneration hands out the next monotonic desired-state generation.
func (s *Store) NextGeneration(_ context.Context, tenantID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generations[tenantID]++
	return s.generations[tenantID], nil
}
