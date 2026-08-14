// Package engine is the Code Search context's in-module index engine (ADR-0014).
//
// Engine choice, documented per the T-0028 brief: ADR-0014 mandates a Zoekt-style dedicated
// trigram index, and the Zoekt Go module was evaluated first. It was rejected for this plane:
// the active module (github.com/sourcegraph/zoekt) adds ~110 transitive module requirements
// (language detection, roaring bitmaps, Prometheus, opentracing, a wasm RE2 runtime and a cloud
// gRPC stack), its builder is disk-bound while this module's shards live in-process and swap
// atomically, and it provides no ctags-free SYMBOL mode — the camelCase-tokenized symbol queries
// SPEC-0034 AC1 requires would need a second layer anyway. This engine is the same shape of
// index — trigram posting lists over line-split content, RE2 for regex — sized to Phase-2 and
// kept behind the same port, so swapping in Zoekt later is an engine change, not a module
// change (SPEC-0034's open question leaves the strategy to implementation, constrained by AC5).
//
// The engine imports no infrastructure: it is pure computation over plain data (invariant 16).
package engine

import (
	"cmp"
	"regexp"
	"slices"
	"strings"
)

// File is one indexable document: an opaque path and its bytes.
type File struct {
	Path    string
	Content []byte
}

// Hit is one match inside one shard. Lines are one-based and inclusive over Content, which is
// the matched line plus whatever context lines the query asked for.
type Hit struct {
	Path      string
	LineStart int
	LineEnd   int
	Content   string
}

// Shard is one repository's immutable index at one revision. It is built whole, then published
// by an atomic swap (SPEC-0034 AC5): no query ever observes a partially built shard.
type Shard struct {
	revision  string
	sizeBytes int64

	files []fileDoc

	// trigrams posts a trigram to the indexes of files whose content contains it. Substring
	// queries narrow to the intersection before scanning lines.
	trigrams map[string][]int
}

type fileDoc struct {
	path string
	// lines is the file split on \n; line i is one-based line i+1.
	lines []string
	// symbols is the identifier table: full identifiers and their camelCase parts, for
	// QUERY_MODE_SYMBOL.
	symbols map[string]struct{}
}

// isText reports whether content should be indexed at all. A NUL byte marks binary content; the
// index never serves bytes it cannot attribute to readable text (and binary scans would only
// waste the fair-use footprint, PRD §6).
func isText(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return false
		}
	}
	return true
}

// Build constructs a shard for one revision from plain documents. Order of the input defines
// nothing: hits are emitted in deterministic path order regardless.
func Build(revision string, files []File) *Shard {
	// Deterministic document order before any posting list is built, so trigram postings and
	// file indexes agree.
	sorted := make([]File, len(files))
	copy(sorted, files)
	slices.SortFunc(sorted, func(a, b File) int { return cmp.Compare(a.Path, b.Path) })

	s := &Shard{revision: revision, trigrams: make(map[string][]int)}
	docs := make([]fileDoc, 0, len(sorted))
	for _, f := range sorted {
		if !isText(f.Content) {
			continue
		}
		doc := fileDoc{path: f.Path, lines: splitLines(string(f.Content)), symbols: make(map[string]struct{})}
		for _, line := range doc.lines {
			for _, id := range identifiers(line) {
				doc.symbols[id] = struct{}{}
				for _, part := range camelParts(id) {
					doc.symbols[part] = struct{}{}
				}
			}
		}
		idx := len(docs)
		docs = append(docs, doc)
		s.sizeBytes += int64(len(f.Content))
		seen := make(map[string]struct{})
		for _, tri := range trigramsOf(strings.Join(doc.lines, "\n")) {
			if _, ok := seen[tri]; ok {
				continue
			}
			seen[tri] = struct{}{}
			s.trigrams[tri] = append(s.trigrams[tri], idx)
		}
	}
	s.files = docs
	return s
}

// Revision is the opaque revision the shard was built at.
func (s *Shard) Revision() string { return s.revision }

// SizeBytes is the indexed content footprint — the per-tenant fair-use measure's raw input
// (SPEC-0034 AC7).
func (s *Shard) SizeBytes() int64 { return s.sizeBytes }

// FileCount is the number of indexed documents.
func (s *Shard) FileCount() int { return len(s.files) }

// SearchSubstring returns case-sensitive substring matches, at most limit hits, each with at most
// ctxLines of context on either side.
func (s *Shard) SearchSubstring(q string, limit, ctxLines int) []Hit {
	if q == "" || limit <= 0 {
		return nil
	}
	var candidates []int
	tris := trigramsOf(q)
	if len(tris) == 0 {
		candidates = s.allFiles()
	} else {
		candidates = s.intersect(tris)
	}
	var out []Hit
	for _, idx := range candidates {
		doc := s.files[idx]
		for i, line := range doc.lines {
			if !strings.Contains(line, q) {
				continue
			}
			out = append(out, s.hit(doc, i, ctxLines))
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// SearchRegex evaluates one compiled RE2 pattern — linear in the scanned text by construction,
// and bounded here by the result cap so a cheap-to-run pattern cannot monopolize the engine
// (SPEC-0035 non-functional).
func (s *Shard) SearchRegex(re *regexp.Regexp, limit, ctxLines int) []Hit {
	if re == nil || limit <= 0 {
		return nil
	}
	var out []Hit
	for idx := range s.files {
		doc := s.files[idx]
		for i, line := range doc.lines {
			if !re.MatchString(line) {
				continue
			}
			out = append(out, s.hit(doc, i, ctxLines))
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// SearchSymbol matches the query against the code-aware symbol table: an exact identifier, an
// exact camelCase part, or a substring of an identifier — so "RefUpdated" finds getRefUpdated
// through its camelCase tokenization and "findUser" finds findUserById (SPEC-0034 AC1).
func (s *Shard) SearchSymbol(q string, limit, ctxLines int) []Hit {
	if q == "" || limit <= 0 {
		return nil
	}
	var out []Hit
	for idx := range s.files {
		doc := s.files[idx]
		if !symbolMatches(doc.symbols, q) {
			continue
		}
		for i, line := range doc.lines {
			if !lineHasSymbol(line, q) {
				continue
			}
			out = append(out, s.hit(doc, i, ctxLines))
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// symbolMatches reports whether any indexed symbol equals q or contains it inside an identifier.
func symbolMatches(symbols map[string]struct{}, q string) bool {
	if _, ok := symbols[q]; ok {
		return true
	}
	for sym := range symbols {
		if strings.Contains(sym, q) {
			return true
		}
	}
	return false
}

// lineHasSymbol reports whether the line carries an identifier that satisfies the symbol query,
// so the emitted hit sits on the line that actually declares or uses the symbol.
func lineHasSymbol(line, q string) bool {
	for _, id := range identifiers(line) {
		if id == q || strings.Contains(id, q) {
			return true
		}
		for _, part := range camelParts(id) {
			if part == q {
				return true
			}
		}
	}
	return false
}

// hit renders one match line with bounded context.
func (s *Shard) hit(doc fileDoc, lineIdx, ctxLines int) Hit {
	n := len(doc.lines)
	lo := lineIdx - ctxLines
	if lo < 0 {
		lo = 0
	}
	hi := lineIdx + ctxLines + 1
	if hi > n {
		hi = n
	}
	return Hit{
		Path:      doc.path,
		LineStart: lo + 1,
		LineEnd:   hi,
		Content:   strings.Join(doc.lines[lo:hi], "\n"),
	}
}

func (s *Shard) allFiles() []int {
	out := make([]int, len(s.files))
	for i := range out {
		out[i] = i
	}
	return out
}

// intersect narrows to the files posting every trigram, in file order. A missing trigram means
// no file can contain the query.
func (s *Shard) intersect(tris []string) []int {
	var best []int
	bestLen := -1
	for _, tri := range tris {
		post := s.trigrams[tri]
		if len(post) == 0 {
			return nil
		}
		if bestLen == -1 || len(post) < bestLen {
			best, bestLen = post, len(post)
		}
	}
	if best == nil {
		return nil
	}
	want := make(map[string]struct{}, len(tris))
	for _, tri := range tris {
		want[tri] = struct{}{}
	}
	counts := make(map[int]int, len(best))
	for _, tri := range tris {
		for _, idx := range s.trigrams[tri] {
			counts[idx]++
		}
	}
	var out []int
	for idx, c := range counts {
		if c == len(want) {
			out = append(out, idx)
		}
	}
	slices.Sort(out)
	return out
}

// splitLines splits content into lines without retaining trailing carriage returns.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}

// trigramsOf returns the distinct trigrams of s. Strings shorter than three runes post no
// trigrams; the caller falls back to a bounded scan.
func trigramsOf(s string) []string {
	r := []rune(s)
	if len(r) < 3 {
		return nil
	}
	seen := make(map[string]struct{}, len(r)-2)
	var out []string
	for i := 0; i+3 <= len(r); i++ {
		tri := string(r[i : i+3])
		if _, ok := seen[tri]; ok {
			continue
		}
		seen[tri] = struct{}{}
		out = append(out, tri)
	}
	return out
}

// identifiers extracts identifier runs: [A-Za-z_][A-Za-z0-9_]*.
func identifiers(line string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range line {
		switch {
		case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			cur.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return out
}

// camelParts splits an identifier at case boundaries: getRefUpdated -> get, Ref, Updated.
// Consecutive capitals stay together until the last one starts a new word (HTTPServer -> HTTP,
// Server). The identifier itself is not included; callers that want it add it.
func camelParts(id string) []string {
	r := []rune(id)
	var parts []string
	start := 0
	for i := 1; i < len(r); i++ {
		prev, cur := r[i-1], r[i]
		breakHere := false
		switch {
		case isLower(prev) && isUpper(cur):
			breakHere = true
		case isUpper(prev) && isUpper(cur) && i+1 < len(r) && isLower(r[i+1]):
			breakHere = true
		case isLetter(prev) && isDigit(cur), isDigit(prev) && isLetter(cur):
			breakHere = true
		}
		if breakHere {
			parts = append(parts, string(r[start:i]))
			start = i
		}
	}
	parts = append(parts, string(r[start:]))
	if len(parts) == 1 {
		return nil
	}
	return parts
}

func isUpper(r rune) bool { return r >= 'A' && r <= 'Z' }
func isLower(r rune) bool { return r >= 'a' && r <= 'z' }
func isDigit(r rune) bool { return r >= '0' && r <= '9' }
func isLetter(r rune) bool {
	return isUpper(r) || isLower(r) || r == '_'
}
