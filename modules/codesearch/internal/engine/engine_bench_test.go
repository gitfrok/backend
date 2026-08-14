// Benchmark-only file added for the SPEC-0036 Modern Go Guidelines refactor: it pins the
// engine's performance profile before and after the idiom transformations. It asserts nothing
// about behavior and is never part of the functional test suite.
//
// testing_b_loop (SPEC-0036 CONDITIONAL, test-file-only): b.Loop() is used for each measured
// loop because it lets the framework handle timer start/stop and iteration calibration, which
// keeps the before/after numbers comparable without manual b.ResetTimer bookkeeping.
package engine

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// benchCorpus builds a deterministic in-memory corpus: 200 files of ~80 lines each, with
// identifiers and content varied by index so trigram, substring, regex and symbol queries all
// have real work to do. Deterministic by construction (no clock, no randomness) so benchmark
// comparisons across commits measure the code, not the input.
func benchCorpus() []File {
	files := make([]File, 0, 200)
	for f := range 200 {
		var b strings.Builder
		fmt.Fprintf(&b, "// file %04d of the benchmark corpus\n", f)
		fmt.Fprintf(&b, "package mod%d\n\n", f%10)
		for l := range 80 {
			fmt.Fprintf(&b, "func handle%dCase%d(input string) string { return input + \"line %d\" }\n", f, l, l)
		}
		files = append(files, File{
			Path:    fmt.Sprintf("mod%d/file%04d.go", f%10, f),
			Content: []byte(b.String()),
		})
	}
	return files
}

// benchShard builds the corpus shard once per benchmark; the search benchmarks measure query
// work only, never index construction.
func benchShard() *Shard {
	return Build("bench-revision", benchCorpus())
}

func BenchmarkBuild(b *testing.B) {
	files := benchCorpus()
	for b.Loop() {
		Build("bench-revision", files)
	}
}

func BenchmarkSearchSubstring(b *testing.B) {
	s := benchShard()
	for b.Loop() {
		s.SearchSubstring("handle12Case34", 50, 2)
	}
}

func BenchmarkSearchRegex(b *testing.B) {
	s := benchShard()
	re := regexp.MustCompile(`handle[0-9]+Case[0-9]+\(input string\)`)
	for b.Loop() {
		s.SearchRegex(re, 50, 2)
	}
}

func BenchmarkSearchSymbol(b *testing.B) {
	s := benchShard()
	for b.Loop() {
		s.SearchSymbol("handle42Case7", 50, 2)
	}
}
