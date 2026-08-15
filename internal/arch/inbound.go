package arch

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// SPEC-0039 AC4 makes outbound-only an ASSERTION, not a convention: a test must fail if any
// control-plane component dials a data-plane address. This file is that assertion for the
// backend tree.
//
// The model (ADR-0011, ADR-0017): the customer's data plane is unreachable by design. The only
// connection across the boundary is the one the AGENT opens outbound to the control plane; the
// control plane never opens a connection in the other direction, to any data-plane address, for
// any reason. Everything the control plane expresses — desired state, config, reconcile
// commands — rides the agent's own outbound stream. So no control-plane package may contain a
// primitive that dials out: a net.Dial, a gRPC client dial, or an http.Get/Post.
//
// The one legitimate dialer in this repo is the data-plane agent client
// (platform/agentclient), which dials the control plane OUTBOUND. It is deliberately NOT in the
// control-plane trees scanned here — it is the other end of the same outbound-only rule.

// dialMarkers are the call shapes that open an outbound connection to a remote address.
var dialMarkers = []string{
	"net.Dial(", "net.DialTimeout(", "net.DialContext(",
	"grpc.Dial(", "grpc.DialContext(", "grpc.NewClient(",
	"ggrpc.Dial(", "ggrpc.DialContext(", "ggrpc.NewClient(",
	"http.Get(", "http.Post(", "http.PostForm(",
}

// controlPlaneRoot is the composition root that defines what "control plane" means: whatever
// this binary composes runs on the control-plane side of the agent boundary.
const controlPlaneRoot = "cmd/controlplane-app"

// controlPlaneFloor is the minimum scanned set. It exists so the gate still means something
// if the composition root is ever unreadable — but the scanned set is DERIVED from what the
// root imports (controlPlaneTrees), because a hand-maintained list silently narrows as the
// control plane grows: phase 3 added modules/metering and modules/residency to this binary
// and neither was scanned until the derivation landed (phase-3 review M3).
var controlPlaneFloor = []string{
	"modules/rollout",
	"modules/agent",
	controlPlaneRoot,
}

// modulePrefix is how a control-plane module import looks in source.
const modulePrefix = "github.com/gitfrok/backend/modules/"

// controlPlaneTrees returns the trees to scan: the composition root plus every backend module
// it imports, transitively through those modules' own imports. A module that reaches the
// control plane by composition is control-plane code, whoever wrote it.
func controlPlaneTrees(root string) ([]string, error) {
	seen := map[string]bool{}
	for _, t := range controlPlaneFloor {
		seen[t] = true
	}
	queue := []string{controlPlaneRoot}
	for len(queue) > 0 {
		tree := queue[0]
		queue = queue[1:]
		imports, err := moduleImports(filepath.Join(root, filepath.FromSlash(tree)))
		if err != nil {
			return nil, err
		}
		for _, imp := range imports {
			if !seen[imp] {
				seen[imp] = true
				queue = append(queue, imp)
			}
		}
	}
	return slices.Sorted(maps.Keys(seen)), nil
}

// moduleImports reports the backend modules a tree's non-test sources import, as tree paths.
// A tree that is absent from this checkout contributes nothing: fixtures exercise one tree at
// a time, and a renamed tree must not turn the gate into a crash.
func moduleImports(dir string) ([]string, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, nil
	}
	var out []string
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
		for line := range strings.SplitSeq(string(src), "\n") {
			_, after, ok := strings.Cut(line, modulePrefix)
			if !ok {
				continue
			}
			name, _, _ := strings.Cut(after, "/")
			name = strings.Trim(name, "\"`")
			if name != "" {
				out = append(out, "modules/"+name)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// InboundViolation is one control-plane source file that opens an outbound dial — which, from
// the data plane's side, is an inbound path being built toward it.
type InboundViolation struct {
	File   string
	Marker string
}

// CheckNoDataPlaneDial scans the control-plane trees' NON-TEST sources for dial primitives and
// returns every hit. An empty result is the AC4 assertion holding. Test files are excluded for
// the same reason the graph loader excludes them: a test may legitimately stand up a client to
// exercise a server, and a test is not part of the shipped control plane.
func CheckNoDataPlaneDial(root string) ([]InboundViolation, error) {
	trees, err := controlPlaneTrees(root)
	if err != nil {
		return nil, err
	}
	var out []InboundViolation
	for _, tree := range trees {
		dir := filepath.Join(root, filepath.FromSlash(tree))
		// A tree that does not exist in this checkout is skipped, not an error: fixtures
		// exercise one tree at a time, and a renamed tree must not turn the gate into a crash.
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
			for _, m := range dialMarkers {
				if strings.Contains(text, m) {
					out = append(out, InboundViolation{File: path, Marker: m})
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
