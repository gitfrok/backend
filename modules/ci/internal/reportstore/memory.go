package reportstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/gitfrok/backend/platform/objectstore"
)

// MemoryTier is an in-process Tier for dev environments and tests. It keeps
// the report store composable where no SeaweedFS tier is configured — the dev
// plane's other contexts do the same with their memory stores — and it honors
// the same digest-on-write contract the real tiers do.
type MemoryTier struct {
	mu      sync.Mutex
	objects map[string][]byte
}

// NewMemoryTier returns an empty in-process tier.
func NewMemoryTier() *MemoryTier {
	return &MemoryTier{objects: map[string][]byte{}}
}

// Put verifies the content against sha256Hex before storing it.
func (m *MemoryTier) Put(_ context.Context, key string, size int64, sha256Hex string, body io.Reader) (int64, error) {
	if key == "" || sha256Hex == "" || size < 0 {
		return 0, fmt.Errorf("reportstore: put needs a key, a size and a digest")
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != sha256Hex {
		return int64(len(data)), fmt.Errorf("%w: stored %s, promised %s", objectstore.ErrDigestMismatch, got, sha256Hex)
	}
	m.mu.Lock()
	m.objects[key] = slices.Clone(data)
	m.mu.Unlock()
	return int64(len(data)), nil
}

// Get serves a stored object, or objectstore.ErrNotFound.
func (m *MemoryTier) Get(_ context.Context, key string) (io.ReadCloser, int64, error) {
	m.mu.Lock()
	data, ok := m.objects[key]
	m.mu.Unlock()
	if !ok {
		return nil, 0, objectstore.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), int64(len(data)), nil
}

// Delete removes an object; absence is success, like the real tiers.
func (m *MemoryTier) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	delete(m.objects, key)
	m.mu.Unlock()
	return nil
}

// List returns the sorted keys a prefix holds.
func (m *MemoryTier) List(_ context.Context, prefix string) ([]string, error) {
	if prefix == "" {
		return nil, fmt.Errorf("reportstore: list needs a prefix")
	}
	m.mu.Lock()
	var keys []string
	for key := range m.objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	m.mu.Unlock()
	slices.Sort(keys)
	return keys, nil
}
