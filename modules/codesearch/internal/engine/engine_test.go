package engine_test

import (
	"regexp"
	"testing"

	"github.com/gitfrok/backend/modules/codesearch/internal/engine"
)

// Engine unit tests: query parsing, tokenization, and bounded result caps (T-0028 "unit
// (backend): query parsing — substring, regex, symbol; tokenization of identifiers/camelCase").

func corpus() *engine.Shard {
	return engine.Build("rev-1", []engine.File{
		{Path: "src/user_service.go", Content: []byte("package users\n\nfunc findUserById(id string) *User {\n\treturn repo.getRef(id)\n}\n\ntype User struct {\n\tID string\n}\n")},
		{Path: "src/http_server.go", Content: []byte("package main\n\nfunc startHTTPServer(addr string) error {\n\treturn nil\n}\n")},
		{Path: "bin/blob.bin", Content: []byte("a\x00b")}, // binary: never indexed
	})
}

func TestSubstringFindsAcrossFiles(t *testing.T) {
	s := corpus()
	hits := s.SearchSubstring("findUserById", 10, 0)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	if hits[0].Path != "src/user_service.go" || hits[0].LineStart != 3 || hits[0].LineEnd != 3 {
		t.Fatalf("unexpected hit %+v", hits[0])
	}
	if hits[0].Content != "func findUserById(id string) *User {" {
		t.Fatalf("content = %q", hits[0].Content)
	}
}

func TestSubstringShortQueryFallsBackToScan(t *testing.T) {
	s := corpus()
	// Two runes: no trigram possible, bounded scan still finds the one case-sensitive match.
	hits := s.SearchSubstring("ID", 10, 0)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1 (the ID field; lowercase id is a distinct string)", len(hits))
	}
}

func TestSubstringContextLinesAreBounded(t *testing.T) {
	s := corpus()
	hits := s.SearchSubstring("findUserById", 10, 1)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	h := hits[0]
	if h.LineStart != 2 || h.LineEnd != 4 {
		t.Fatalf("context range = %d..%d, want 2..4", h.LineStart, h.LineEnd)
	}
}

func TestRegexIsEvaluated(t *testing.T) {
	s := corpus()
	hits := s.SearchRegex(regexp.MustCompile(`func start[A-Z]\w+`), 10, 0)
	if len(hits) != 1 || hits[0].Path != "src/http_server.go" {
		t.Fatalf("got %+v", hits)
	}
}

func TestSymbolMatchesIdentifierAndCamelParts(t *testing.T) {
	s := corpus()
	cases := []struct {
		query string
		path  string
	}{
		{"findUserById", "src/user_service.go"}, // exact identifier
		{"User", "src/user_service.go"},         // camel part of findUserById and the type name
		{"HTTPServer", "src/http_server.go"},    // acronym-glued identifier
		{"Server", "src/http_server.go"},        // camel part of startHTTPServer
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			hits := s.SearchSymbol(c.query, 10, 0)
			if len(hits) == 0 {
				t.Fatalf("symbol %q matched nothing", c.query)
			}
			found := false
			for _, h := range hits {
				if h.Path == c.path {
					found = true
				}
			}
			if !found {
				t.Fatalf("symbol %q matched no line in %s: %+v", c.query, c.path, hits)
			}
		})
	}
}

func TestSymbolDoesNotMatchArbitraryText(t *testing.T) {
	s := corpus()
	if hits := s.SearchSymbol("package", 10, 0); len(hits) == 0 {
		// "package" is an identifier run in the corpus, so it is a symbol; this guards the
		// negative case instead: a string that appears in no identifier.
		t.Skip("package is a legitimate identifier in the corpus")
	}
	if hits := s.SearchSymbol("zzzNoSuchSymbol", 10, 0); len(hits) != 0 {
		t.Fatalf("unknown symbol matched: %+v", hits)
	}
}

func TestResultCapBoundsHits(t *testing.T) {
	s := corpus()
	hits := s.SearchSubstring("string", 1, 0)
	if len(hits) != 1 {
		t.Fatalf("limit 1 returned %d hits", len(hits))
	}
}

func TestBinaryContentIsNeverIndexed(t *testing.T) {
	s := corpus()
	if hits := s.SearchSubstring("\x00", 10, 0); len(hits) != 0 {
		t.Fatalf("binary content served: %+v", hits)
	}
	if s.FileCount() != 2 {
		t.Fatalf("FileCount = %d, want 2 (binary file excluded)", s.FileCount())
	}
}

func TestShardReportsRevisionAndSize(t *testing.T) {
	s := corpus()
	if s.Revision() != "rev-1" {
		t.Fatalf("revision = %q", s.Revision())
	}
	if s.SizeBytes() <= 0 {
		t.Fatalf("size = %d, want > 0", s.SizeBytes())
	}
}
