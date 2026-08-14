package security_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	policyapi "github.com/gitfrok/backend/modules/policy/api"
	"github.com/gitfrok/backend/modules/security/api"
	"github.com/gitfrok/backend/modules/security/internal/adapters/scanners"
	"github.com/gitfrok/backend/modules/security/internal/app"
	"github.com/gitfrok/backend/platform/bus"
)

// TestLiveIdentityProof is SPEC-0024 AC7 against the real scanners: seed a
// real git repository with detectable issues, run BOTH real scanner
// binaries twice — with an intermediate unrelated commit between the scans
// — ingest both rounds through the real service, and assert the
// server-computed identities are equal across scans.
//
// It is a live proof, not a fixture replay: it shells out to semgrep and
// gitleaks on PATH and skips only when a binary is genuinely absent.
func TestLiveIdentityProof(t *testing.T) {
	semgrepBin, errS := exec.LookPath("semgrep")
	gitleaksBin, errG := exec.LookPath("gitleaks")
	if errS != nil || errG != nil {
		t.Skipf("live proof needs real scanner binaries on PATH: semgrep=%v gitleaks=%v", errS, errG)
	}

	repo := seedRepo(t)

	// The semgrep ruleset lives outside the scanned tree so it is not
	// itself scanned. It detects the eval() the seed plants.
	rules := filepath.Join(filepath.Dir(repo), "rules.yaml")
	write(t, rules, `rules:
  - id: python-eval-usage
    patterns:
      - pattern: eval(...)
    message: avoid eval
    languages: [python]
    severity: WARNING
`)

	allowAll := allowAllPDP{}
	svc := app.New(app.NewMemoryStore(), allowAll, bus.NewInProcess())

	// Round 1: scan the pristine seed with BOTH tools, ingest.
	round1 := scanRound(t, repo, rules, semgrepBin, gitleaksBin, svc, "round-1")
	if len(round1.reported) == 0 {
		t.Fatalf("round 1 found nothing: the seed must produce findings from both scanners")
	}

	// Intermediate unrelated commit: a new file and a leading comment in the
	// file carrying the eval, so its absolute line number moves and the git
	// history grows; identity must not (SPEC-0024 AC2).
	write(t, filepath.Join(repo, "app.py"), "# unrelated leading comment\ndef handler(req):\n    return eval(req.body)\n")
	write(t, filepath.Join(repo, "notes.md"), "# unrelated change\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-m", "unrelated change")

	// Round 2: scan again with BOTH tools, ingest through the same service.
	round2 := scanRound(t, repo, rules, semgrepBin, gitleaksBin, svc, "round-2")

	// The assertion: round 2 reports EXACTLY the identities round 1 did —
	// no new opens, no resolutions, identities equal across
	// commit/scan-run/line drift.
	if len(round2.reported) != len(round1.reported) {
		t.Fatalf("round 2 reported %d findings (%v), round 1 had %d (%v)",
			len(round2.reported), sortedKeys(round2.reported), len(round1.reported), sortedKeys(round1.reported))
	}
	for key := range round1.reported {
		if _, ok := round2.reported[key]; !ok {
			t.Fatalf("finding %q reported in round 1 vanished in round 2 (%v)", key, sortedKeys(round2.reported))
		}
	}
	// And the service agrees: every reported identity is stored under the
	// SAME finding ID in both rounds.
	if len(round2.stored) != len(round1.stored) {
		t.Fatalf("round 2 stored %d findings, round 1 stored %d", len(round2.stored), len(round1.stored))
	}
	for key, id1 := range round1.stored {
		id2, ok := round2.stored[key]
		if !ok {
			t.Fatalf("finding %q present in round 1 vanished in round 2", key)
		}
		if id1 != id2 {
			t.Fatalf("identity drifted for %q across an unrelated commit: %s != %s", key, id1, id2)
		}
	}

	// And the service agrees: everything is still OPEN, nothing resolved,
	// nothing duplicated.
	page, err := svc.ListFindings(context.Background(), api.ListRequest{Context: ingestContext("proof-req-list")})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Findings) != len(round1.reported) {
		t.Fatalf("expected %d stored findings after both rounds, got %d", len(round1.reported), len(page.Findings))
	}
	for _, f := range page.Findings {
		if f.Lifecycle != api.LifecycleOpen {
			t.Fatalf("finding %s must remain OPEN across identical reports, got %s", f.ID, f.Lifecycle)
		}
		if f.FirstSeenScanID == f.LastSeenScanID {
			t.Fatalf("finding %s: round 2 must have advanced LastSeenScanID", f.ID)
		}
	}
	t.Logf("live proof: %d findings stable across both real scanners and an unrelated commit", len(round1.reported))
}

// roundResult captures one scan round: reported is what the real scanners
// reported this round (the identity set the proof compares); stored maps
// every stored finding's key to its finding ID (identity-to-ID stability).
type roundResult struct {
	reported map[string]struct{}
	stored   map[string]string
}

// scanRound runs both real scanners, parses their native output with the
// module's adapters, ingests through the service, and returns the round's
// reported identity set plus the store's identity-to-finding-ID map.
func scanRound(t *testing.T, repo, rules, semgrepBin, gitleaksBin string, svc *app.Service, round string) roundResult {
	t.Helper()
	res := roundResult{reported: map[string]struct{}{}, stored: map[string]string{}}

	// Semgrep (SAST).
	semgrepReport := run(t, semgrepBin, "scan", "--config", rules, "--json", "--metrics=off", "--quiet", repo)
	semgrepFindings, err := (scanners.Semgrep{Root: repo}).Parse(semgrepReport)
	if err != nil {
		t.Fatalf("%s semgrep parse: %v", round, err)
	}
	ingest(t, svc, repo, round+"-semgrep", api.ScannerClassSAST, "semgrep", semgrepFindings)
	for _, f := range semgrepFindings {
		res.reported["semgrep/"+ruleSuffix(f.RuleID)+"/"+f.Location.ArtifactPath] = struct{}{}
	}
	for _, f := range lastStored(t, svc, round+"-semgrep") {
		res.stored[f.ToolName+"/"+ruleSuffix(f.RuleID)+"/"+f.Location.ArtifactPath] = f.ID
	}

	// Gitleaks (SECRETS). It scans the seeded repo's git history (--source
	// pins it to the seed: without it gitleaks would scan the test's own
	// working directory), so the intermediate commit changes what it walks
	// while the leak's identity must not. The report lands OUTSIDE the
	// scanned tree so the next round does not find the secret inside the
	// previous round's own report.
	reportPath := filepath.Join(filepath.Dir(repo), ".gitleaks-"+round+".json")
	run(t, gitleaksBin, "detect", "--no-banner", "--source", repo, "-f", "json", "--exit-code", "0", "-r", reportPath)
	gitleaksReport := mustRead(t, reportPath)
	gitleaksFindings, err := (scanners.Gitleaks{}).Parse(gitleaksReport)
	if err != nil {
		t.Fatalf("%s gitleaks parse: %v", round, err)
	}
	ingest(t, svc, repo, round+"-gitleaks", api.ScannerClassSecrets, "gitleaks", gitleaksFindings)
	for _, f := range gitleaksFindings {
		res.reported["gitleaks/"+ruleSuffix(f.RuleID)+"/"+f.Location.ArtifactPath] = struct{}{}
	}
	for _, f := range lastStored(t, svc, round+"-gitleaks") {
		res.stored[f.ToolName+"/"+ruleSuffix(f.RuleID)+"/"+f.Location.ArtifactPath] = f.ID
	}

	if round == "round-1" {
		classes := map[string]bool{}
		for key := range res.reported {
			classes[strings.SplitN(key, "/", 2)[0]] = true
		}
		if !classes["semgrep"] || !classes["gitleaks"] {
			t.Fatalf("round 1 must report at least one finding per scanner, got %v", sortedKeys(res.reported))
		}
	}
	return res
}

// ruleSuffix strips semgrep's config-path prefix from rule IDs of locally
// defined rules ("var.folders...rules.python-eval-usage" → the part after
// the last dot), leaving the rule identity the scanner itself chose.
func ruleSuffix(ruleID string) string {
	if i := strings.LastIndex(ruleID, "."); i >= 0 {
		return ruleID[i+1:]
	}
	return ruleID
}

func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// lastStored reads the store's findings back out of the service after the
// scan completed. Both rounds must map every identity to the same finding
// ID — that is the identity-to-ID stability the proof asserts.
func lastStored(t *testing.T, svc *app.Service, round string) []api.Finding {
	t.Helper()
	page, err := svc.ListFindings(context.Background(), api.ListRequest{
		Context: ingestContext("proof-req-" + round),
	})
	if err != nil {
		t.Fatalf("list %s: %v", round, err)
	}
	return page.Findings
}

func ingest(t *testing.T, svc *app.Service, repo, round string, class api.ScannerClass, tool string, findings []api.RawFinding) {
	t.Helper()
	now := time.Now().UTC()
	_, err := svc.IngestScanResults(context.Background(), api.IngestChunk{
		Context:  ingestContext("proof-req-" + round),
		Revision: gitRev(t, repo),
		Scan: api.Scan{
			ScannerClass: class, ToolName: tool, ToolVersion: "live",
			StartedAt: now, EndedAt: now.Add(time.Second),
		},
		Findings:   findings,
		ChunkIndex: 0,
		FinalChunk: true,
	})
	if err != nil {
		t.Fatalf("ingest %s: %v", round, err)
	}
}

func ingestContext(reqID string) api.Context {
	return api.Context{TenantID: "t-live-proof", RepositoryID: "repo-live-proof", ActorID: "actor-proof", RequestID: reqID}
}

// seedRepo builds a real git repository with one SAST-detectable defect and
// one secret, committed.
func seedRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	write(t, filepath.Join(repo, "app.py"), "def handler(req):\n    return eval(req.body)\n")
	write(t, filepath.Join(repo, "creds.txt"), "GITHUB_TOKEN = \"ghp_L1v3Pr00fT0k3nV4lu3XyZ8aB2c\"\n")
	git(t, repo, "init", "-q")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-m", "seed")
	return repo
}

// allowAllPDP stands in for the PDP: the proof is about identity, and every
// ingest still travels the service's full decision path.
type allowAllPDP struct{}

func (allowAllPDP) Decide(context.Context, policyapi.Request) (policyapi.Decision, error) {
	return policyapi.Decision{Allowed: true, DecisionID: "dec-live"}, nil
}

func run(t *testing.T, bin string, args ...string) []byte {
	t.Helper()
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("%s %v: %v\n%s", bin, args, err, ee.Stderr)
		}
		t.Fatalf("%s %v: %v", bin, args, err)
	}
	return out
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=proof", "GIT_AUTHOR_EMAIL=proof@local",
		"GIT_COMMITTER_NAME=proof", "GIT_COMMITTER_EMAIL=proof@local")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func gitRev(t *testing.T, repo string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	return string(out[:len(out)-1])
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
