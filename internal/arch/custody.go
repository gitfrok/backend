package arch

import (
	"os"
	"path/filepath"
	"strings"
)

// SPEC-0044 makes the custody posture an ASSERTION, not a convention: the
// production composition root issues every agent-identity credential through
// the custody service, and fitness keeps it that way (T-0040 AC1, AC3).
//
// The model (ADR-0064, ADR-0066): the control plane holds key REFERENCES and
// signs DIGESTS through the custody seam; private CA material never enters
// the process. Two shapes would silently break that posture, and both are
// scanned out of the control-plane trees:
//
//   - AC1 — constructing a CA from KEY MATERIAL: a private-key parser or a
//     key-pair loader. A production root that parses a key can be fed one
//     from a file path or an env var, which is exactly the posture custody
//     replaces.
//   - AC3 — reaching the DEV CA: the in-process dev CA constructor belongs
//     to dev/test compositions only; a production root that calls it has a
//     key that lives in process memory.
//
// The scan bounds the PRODUCTION COMPOSITION ROOT — the binary that composes
// the shipped control plane: the assertions name what that root may reach,
// not what every module may contain. The dev CA's own issuance surface and
// the rollout context's key-material DETECTION (a bundle refusing a private
// key it finds) both live outside the root and are out of scope by design.

// caKeyMaterialMarkers are the call shapes that construct a CA from private
// key material (SPEC-0044 AC1). The custody seam admits references and
// digests only — no control-plane source may parse a private key or load a
// key pair.
var caKeyMaterialMarkers = []string{
	"x509.ParseECPrivateKey(",
	"x509.ParsePKCS1PrivateKey(",
	"x509.ParsePKCS8PrivateKey(",
	"tls.LoadX509KeyPair(",
	"tls.X509KeyPair(",
}

// devCAMarkers are the call shapes that construct the dev CA (SPEC-0044
// AC3). The dev CA is dev/test custody in exactly the sense the custody
// package describes it: production compositions must never reach it.
var devCAMarkers = []string{
	"NewDevCA(",
}

// CAKeyMaterialViolation is one control-plane source file that constructs a
// CA from private key material.
type CAKeyMaterialViolation struct {
	File   string
	Marker string
}

// CheckNoCAKeyMaterial scans the production composition root's NON-TEST
// sources for private-key parsers and key-pair loaders and returns every
// hit. An empty result is AC1 holding: the production root cannot construct
// a CA from a file path or env, because no key-material construction exists
// in it to call — the custody-backed issuer it composes admits references
// and digests only.
func CheckNoCAKeyMaterial(root string) ([]CAKeyMaterialViolation, error) {
	hits, err := scanControlPlaneMarkers(root, compositionRootTrees, caKeyMaterialMarkers)
	if err != nil {
		return nil, err
	}
	out := make([]CAKeyMaterialViolation, 0, len(hits))
	for _, h := range hits {
		out = append(out, CAKeyMaterialViolation(h))
	}
	return out, nil
}

// DevCAReachViolation is one control-plane source file that constructs the
// dev CA.
type DevCAReachViolation struct {
	File   string
	Marker string
}

// CheckNoDevCAReach scans the PRODUCTION COMPOSITION ROOT's non-test sources
// for the dev CA constructor and returns every hit. An empty result is AC3
// holding: the production root reaches the custody-backed issuer and nothing
// else. The scan bounds the root itself rather than every derived tree:
// modules/agent keeps NewDevCA as the dev/test composition seam (module
// tests and sibling binaries' test compositions construct through it), and
// what AC3 forbids is the production root EVER taking that seam. Test files
// are excluded for the same reason the dial scan excludes them: a test may
// legitimately stand up dev custody, and a test is not part of the shipped
// control plane.
func CheckNoDevCAReach(root string) ([]DevCAReachViolation, error) {
	hits, err := scanControlPlaneMarkers(root, compositionRootTrees, devCAMarkers)
	if err != nil {
		return nil, err
	}
	out := make([]DevCAReachViolation, 0, len(hits))
	for _, h := range hits {
		out = append(out, DevCAReachViolation(h))
	}
	return out, nil
}

// markerHit is one scanned source file holding one marker — the shared walk's
// shape, converted to each assertion's own violation type.
type markerHit struct {
	File   string
	Marker string
}

// compositionRootTrees yields the one tree both custody assertions scan:
// the production composition root itself.
func compositionRootTrees(string) ([]string, error) { return []string{controlPlaneRoot}, nil }

// scanControlPlaneMarkers walks the trees trees() derives, reading their
// non-test sources and reporting every marker hit — the shared walk behind
// both custody assertions, shaped exactly like CheckNoDataPlaneDial's.
func scanControlPlaneMarkers(root string, trees func(string) ([]string, error), markers []string) ([]markerHit, error) {
	treeList, err := trees(root)
	if err != nil {
		return nil, err
	}
	var out []markerHit
	for _, tree := range treeList {
		dir := filepath.Join(root, filepath.FromSlash(tree))
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			text := string(src)
			for _, m := range markers {
				if strings.Contains(text, m) {
					out = append(out, markerHit{File: path, Marker: m})
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
