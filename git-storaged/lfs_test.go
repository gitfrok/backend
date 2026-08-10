package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const pointerVersion = "version https://git-lfs.github.com/spec/v1"

func oidOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func pointerFor(content string) string {
	return fmt.Sprintf("%s\noid sha256:%s\nsize %d\n", pointerVersion, oidOf(content), len(content))
}

// A pointer file is recognized; ordinary content is not. The second half matters
// more: a permissive parser would report missing objects for files that were never
// in LFS.
func TestParseLFSPointer(t *testing.T) {
	pointer, ok := parseLFSPointer([]byte(pointerFor("large payload")))
	if !ok {
		t.Fatal("a well-formed pointer was not recognized")
	}
	if pointer.oid != oidOf("large payload") || pointer.size != int64(len("large payload")) {
		t.Fatalf("pointer = %+v", pointer)
	}

	for name, content := range map[string]string{
		"empty":           "",
		"ordinary text":   "just a file that mentions oid sha256:deadbeef\n",
		"no version line": "oid sha256:" + oidOf("x") + "\nsize 1\n",
		"wrong hash":      pointerVersion + "\noid sha1:" + strings.Repeat("a", 40) + "\nsize 1\n",
		"malformed oid":   pointerVersion + "\noid sha256:not-hex\nsize 1\n",
		"uppercase oid":   pointerVersion + "\noid sha256:" + strings.ToUpper(oidOf("x")) + "\nsize 1\n",
		"negative size":   pointerVersion + "\noid sha256:" + oidOf("x") + "\nsize -1\n",
		"no oid":          pointerVersion + "\nsize 12\n",
		"oversized":       pointerVersion + "\noid sha256:" + oidOf("x") + "\nsize 1\n" + strings.Repeat("x", maxPointerSize),
		"wrong spec URL":  "version https://example.test/spec/v1\noid sha256:" + oidOf("x") + "\nsize 1\n",
	} {
		if _, ok := parseLFSPointer([]byte(content)); ok {
			t.Errorf("%s was parsed as a pointer", name)
		}
	}
}

// The same OID in two tenants is two objects (SPEC-0023 AC4).
func TestObjectKeyIsTenantScoped(t *testing.T) {
	oid := oidOf("payload")
	a := lfsObjectKey("tenant-a", oid)
	b := lfsObjectKey("tenant-b", oid)
	if a == b {
		t.Fatal("two tenants share one object key")
	}
	if !strings.HasPrefix(a, "lfs/tenant-a/") {
		t.Fatalf("key = %q, want the tenant first", a)
	}
	if !strings.Contains(a, oid) {
		t.Fatalf("key = %q, want it to name the object", a)
	}
}

// Pointers are found wherever they live in the history of the imported refs, not
// only at the tips: an object referenced by an old commit is still needed.
func TestLFSPointersInRefsWalksHistory(t *testing.T) {
	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")

	// An older commit carries the pointer; the tip replaces the file.
	writeFile(t, work, "big.bin", pointerFor("historical payload"))
	mustRunGit(t, work, "add", "big.bin")
	mustRunGit(t, work, "commit", "-m", "add pointer")
	writeFile(t, work, "big.bin", "plain content now\n")
	mustRunGit(t, work, "add", "big.bin")
	mustRunGit(t, work, "commit", "-m", "replace with plain content")

	pointers, err := lfsPointersInRefs(t.Context(), work, []string{"refs/heads/main"})
	if err != nil {
		t.Fatalf("lfsPointersInRefs: %v", err)
	}
	if len(pointers) != 1 || pointers[0].oid != oidOf("historical payload") {
		t.Fatalf("pointers = %+v, want the one from history", pointers)
	}
}

// A repository with no pointers asks nothing of the object tier, so a deployment
// without one can still import.
func TestNoPointersNeedsNoObjectTier(t *testing.T) {
	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	writeFile(t, work, "README.md", "no large files here\n")
	mustRunGit(t, work, "add", "README.md")
	mustRunGit(t, work, "commit", "-m", "initial")

	pointers, err := lfsPointersInRefs(t.Context(), work, []string{"refs/heads/main"})
	if err != nil {
		t.Fatalf("lfsPointersInRefs: %v", err)
	}
	if len(pointers) != 0 {
		t.Fatalf("pointers = %+v, want none", pointers)
	}
}

// The source's LFS endpoint is derived the way a git-lfs client derives it, and
// only from https: an ssh clone URL has no endpoint without asking the server, and
// this client does not guess.
func TestLFSSourceEndpoint(t *testing.T) {
	for source, want := range map[string]string{
		"https://github.com/acme/widgets.git": "https://github.com/acme/widgets.git/info/lfs",
		"https://github.com/acme/widgets":     "https://github.com/acme/widgets.git/info/lfs",
		"https://gitlab.example.com/g/p.git/": "https://gitlab.example.com/g/p.git/info/lfs",
	} {
		got, err := lfsSourceEndpoint(source)
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		if got != want {
			t.Errorf("%s -> %q, want %q", source, got, want)
		}
	}
	for _, source := range []string{
		"ssh://git@github.com/acme/widgets.git",
		"git@github.com:acme/widgets.git",
		"",
	} {
		if _, err := lfsSourceEndpoint(source); err == nil {
			t.Errorf("an endpoint was derived from %q", source)
		}
	}
}

// An error message never echoes the source URL, which is a request secret
// (SPEC-0011 AC22, SPEC-0023 AC8).
func TestEndpointErrorNeverEchoesTheURL(t *testing.T) {
	_, err := lfsSourceEndpoint("ssh://git@secret-host.internal/acme/widgets.git")
	if err == nil {
		t.Fatal("an ssh URL produced an endpoint")
	}
	if strings.Contains(err.Error(), "secret-host.internal") || strings.Contains(err.Error(), "acme") {
		t.Fatalf("error leaked the source URL: %v", err)
	}
}

// memoryObjects is the object tier in memory, recording what was stored and what
// it was stored under.
type memoryObjects struct {
	mu      sync.Mutex
	stored  map[string][]byte
	putErr  error
	statErr error
}

func newMemoryObjects() *memoryObjects {
	return &memoryObjects{stored: map[string][]byte{}}
}

func (m *memoryObjects) Put(_ context.Context, key string, _ int64, sha256Hex string, body io.Reader) (int64, error) {
	if m.putErr != nil {
		return 0, m.putErr
	}
	content, err := io.ReadAll(body)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != sha256Hex {
		return 0, fmt.Errorf("digest mismatch")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stored[key] = content
	return int64(len(content)), nil
}

func (m *memoryObjects) Stat(_ context.Context, key string) (int64, error) {
	if m.statErr != nil {
		return 0, m.statErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	content, ok := m.stored[key]
	if !ok {
		return 0, fmt.Errorf("not stored")
	}
	return int64(len(content)), nil
}

// sourceLFSServer is a source's LFS endpoint: a batch endpoint plus object bytes.
type sourceLFSServer struct {
	objects map[string]string // oid -> content
	// serveOID, when set, is served for every object regardless of what was asked,
	// so a test can make the source lie about its content.
	serveContent string
	batchCalls   int
	token        string
	server       *httptest.Server
}

// client returns an LFS client that trusts this test server's certificate.
func (s *sourceLFSServer) client() *sourceLFSClient {
	c := newSourceLFSClient()
	c.http = s.server.Client()
	return c
}

func newSourceLFSServer(t *testing.T, objects map[string]string) *sourceLFSServer {
	t.Helper()
	source := &sourceLFSServer{objects: objects}
	mux := http.NewServeMux()
	mux.HandleFunc("/acme/widgets.git/info/lfs/objects/batch", func(w http.ResponseWriter, r *http.Request) {
		source.batchCalls++
		source.token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		var request lfsBatchRequest
		_ = json.NewDecoder(r.Body).Decode(&request)
		response := map[string]any{"transfer": "basic", "objects": []map[string]any{}}
		list := []map[string]any{}
		for _, object := range request.Objects {
			content, ok := source.objects[object.OID]
			if !ok {
				list = append(list, map[string]any{
					"oid": object.OID, "size": object.Size,
					"error": map[string]any{"code": 404, "message": "not found"},
				})
				continue
			}
			list = append(list, map[string]any{
				"oid": object.OID, "size": int64(len(content)),
				"actions": map[string]any{"download": map[string]any{
					"href": source.server.URL + "/objects/" + object.OID,
				}},
			})
		}
		response["objects"] = list
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		_ = json.NewEncoder(w).Encode(response)
	})
	mux.HandleFunc("/objects/", func(w http.ResponseWriter, r *http.Request) {
		oid := strings.TrimPrefix(r.URL.Path, "/objects/")
		content, ok := source.objects[oid]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if source.serveContent != "" {
			content = source.serveContent
		}
		_, _ = io.WriteString(w, content)
	})
	// TLS, because an LFS endpoint is only derivable from an https source URL —
	// the client refuses to guess one for any other scheme (SPEC-0023 AC8's
	// neighbour: a source must be reachable over TLS or not at all).
	source.server = httptest.NewTLSServer(mux)
	t.Cleanup(source.server.Close)
	return source
}

// importLFSObjects fetches every referenced object from the source and stores it
// under the tenant's key (SPEC-0023 AC6 — which is SPEC-0011 AC2).
func TestImportFetchesReferencedLFSObjects(t *testing.T) {
	payload := "a large payload that lives in LFS"
	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	writeFile(t, work, "big.bin", pointerFor(payload))
	mustRunGit(t, work, "add", "big.bin")
	mustRunGit(t, work, "commit", "-m", "add pointer")

	source := newSourceLFSServer(t, map[string]string{oidOf(payload): payload})
	objects := newMemoryObjects()
	server := &Server{objects: objects, sourceLFS: source.client()}

	stored, err := server.importLFSObjects(t.Context(),
		repositoryOperation{path: work, tenantID: "tenant-a", repositoryID: "repo-a"},
		[]string{"refs/heads/main"},
		source.server.URL+"/acme/widgets.git", "source-token")
	if err != nil {
		t.Fatalf("importLFSObjects: %v", err)
	}
	if stored != int64(len(payload)) {
		t.Fatalf("stored = %d bytes, want %d", stored, len(payload))
	}
	key := lfsObjectKey("tenant-a", oidOf(payload))
	if got := string(objects.stored[key]); got != payload {
		t.Fatalf("object at %s = %q, want the source's payload", key, got)
	}
	if source.token != "source-token" {
		t.Fatalf("source saw token %q — the import's credential must reach the source and nowhere else", source.token)
	}
}

// A source that cannot produce a referenced object fails the import: a repository
// advertising pointers whose objects are absent must never be reported complete
// (SPEC-0023 AC7).
func TestImportFailsWhenAnObjectCannotBeFetched(t *testing.T) {
	payload := "an object the source has lost"
	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	writeFile(t, work, "big.bin", pointerFor(payload))
	mustRunGit(t, work, "add", "big.bin")
	mustRunGit(t, work, "commit", "-m", "add pointer")

	// The source knows nothing about this OID.
	source := newSourceLFSServer(t, map[string]string{})
	objects := newMemoryObjects()
	server := &Server{objects: objects, sourceLFS: source.client()}

	if _, err := server.importLFSObjects(t.Context(),
		repositoryOperation{path: work, tenantID: "tenant-a", repositoryID: "repo-a"},
		[]string{"refs/heads/main"},
		source.server.URL+"/acme/widgets.git", ""); err == nil {
		t.Fatal("the import succeeded with an object it could not fetch")
	}
	if len(objects.stored) != 0 {
		t.Fatal("a failed LFS phase still stored objects")
	}
}

// A source serving different bytes under an OID is refused: an object must never
// land under a name that lies about its content (SPEC-0023 AC5).
func TestImportRefusesContentThatDoesNotMatchItsOID(t *testing.T) {
	payload := "the promised payload"
	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	writeFile(t, work, "big.bin", pointerFor(payload))
	mustRunGit(t, work, "add", "big.bin")
	mustRunGit(t, work, "commit", "-m", "add pointer")

	source := newSourceLFSServer(t, map[string]string{oidOf(payload): payload})
	source.serveContent = "something else entirely"
	objects := newMemoryObjects()
	server := &Server{objects: objects, sourceLFS: source.client()}

	if _, err := server.importLFSObjects(t.Context(),
		repositoryOperation{path: work, tenantID: "tenant-a", repositoryID: "repo-a"},
		[]string{"refs/heads/main"},
		source.server.URL+"/acme/widgets.git", ""); err == nil {
		t.Fatal("content that did not match its OID was accepted")
	}
}

// A pointer with no object tier configured fails the import rather than landing a
// repository whose large files are missing.
func TestImportWithPointersAndNoObjectTierFails(t *testing.T) {
	payload := "needs a tier"
	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	writeFile(t, work, "big.bin", pointerFor(payload))
	mustRunGit(t, work, "add", "big.bin")
	mustRunGit(t, work, "commit", "-m", "add pointer")

	server := &Server{sourceLFS: newSourceLFSClient()}
	if _, err := server.importLFSObjects(t.Context(),
		repositoryOperation{path: work, tenantID: "tenant-a", repositoryID: "repo-a"},
		[]string{"refs/heads/main"}, "https://source.test/acme/widgets.git", ""); err == nil {
		t.Fatal("an import carrying pointers succeeded with no object tier")
	}
}

// A resumed import does not re-fetch what the first attempt stored (SPEC-0011 AC6).
func TestResumedImportSkipsStoredObjects(t *testing.T) {
	payload := "already here"
	work := t.TempDir()
	mustRunGit(t, work, "init", "--initial-branch=main", work)
	mustRunGit(t, work, "config", "user.email", "dev@gitsaas.test")
	mustRunGit(t, work, "config", "user.name", "GitFrok test")
	writeFile(t, work, "big.bin", pointerFor(payload))
	mustRunGit(t, work, "add", "big.bin")
	mustRunGit(t, work, "commit", "-m", "add pointer")

	source := newSourceLFSServer(t, map[string]string{oidOf(payload): payload})
	objects := newMemoryObjects()
	objects.stored[lfsObjectKey("tenant-a", oidOf(payload))] = []byte(payload)
	server := &Server{objects: objects, sourceLFS: source.client()}

	stored, err := server.importLFSObjects(t.Context(),
		repositoryOperation{path: work, tenantID: "tenant-a", repositoryID: "repo-a"},
		[]string{"refs/heads/main"}, source.server.URL+"/acme/widgets.git", "")
	if err != nil {
		t.Fatalf("importLFSObjects: %v", err)
	}
	if stored != 0 {
		t.Fatalf("stored = %d, want nothing re-fetched", stored)
	}
	if source.batchCalls != 0 {
		t.Fatalf("source batch calls = %d, want none for an object already held", source.batchCalls)
	}
}

// The storage key layout and the front door's must agree; they are written in two
// binaries and only a test can hold them equal.
func TestKeyLayoutMatchesTheFrontDoor(t *testing.T) {
	oid := oidOf("payload")
	// This is the front door's format, duplicated here on purpose: if either side
	// changes, this test fails rather than a client silently reading nothing.
	want := filepath.Join("lfs", "tenant-a", oid[:2], oid)
	if got := lfsObjectKey("tenant-a", oid); got != want {
		t.Fatalf("storage key = %q, front door expects %q", got, want)
	}
}
