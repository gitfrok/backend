package arch

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// SPEC-0002 AC4: "No service performs an inline permission check that bypasses the PDP."
//
// Invariant 2 and ADR-0006 make the PDP the only place authorization is decided. Every other
// invariant in this file is enforced by an import edge, which is a fact — either the edge exists or
// it does not. Authorization logic has no such signature: `if user.Role == "owner"` imports nothing
// and looks like ordinary code.
//
// WHAT THIS IS, STATED HONESTLY. It is a tripwire, not a proof. It catches the two shapes an inline
// check overwhelmingly takes — a function named for an authorization question, and a comparison
// against a role literal — and it cannot catch a sufficiently indirect one. A gate that is
// advertised as complete when it is heuristic is worse than no gate, because the green tick starts
// being read as an assurance nobody checked. So: this raises the cost of writing the obvious form
// by accident and makes the deliberate form require a waiver someone has to justify in review.
//
// The waiver exists for the same reason. A heuristic with no escape hatch gets deleted the first
// time it misfires, and a deleted gate protects nothing — an audited exception is strictly better
// than an unenforced rule.

// RuleInlinePermissionCheck fires on authorization logic outside the Policy context.
const RuleInlinePermissionCheck = "inline-permission-check"

// authzFuncRe matches function names that answer an authorization question.
//
// Anchored and case-sensitive on the noun so that ordinary Go reads clean: `hasPrefix`, `canRetry`
// and `isReady` do not match, while `hasPermission`, `canAccess` and `isAuthorized` do. The verbs
// are the ones a permission check is actually written with; the nouns are what makes it about
// permission rather than about state.
var authzFuncRe = regexp.MustCompile(
	`^(is|has|can|may|check|assert|require|ensure|verify|validate)` +
		`(Admin|Owner|Member|Permission|Permissions|Permitted|Authorized|Authorised|Authz|` +
		`Role|Roles|Access|Allowed|CanWrite|CanRead)`)

// authzRoleLiterals are the role names governance/policies grants against. A comparison against one
// of these outside the Policy context is a decision being made about a role in Go rather than in
// Rego — which is the definition of the thing invariant 2 forbids.
//
// Kept deliberately short and equal to the real vocabulary. Widening it to every plausible role
// word would trade the false negatives this already has for false positives, and a noisy gate gets
// waived everywhere, which is the same as being off.
var authzRoleLiterals = map[string]bool{
	"owner":  true,
	"member": true,
	"reader": true,
}

// authzWaiver is the escape hatch. It must name a reason — a bare marker is a way to silence the
// gate without saying anything, and the reason is the part a reviewer actually assesses.
//
//	//arch:allow-inline-authz <why this is not an authorization decision>
var authzWaiver = regexp.MustCompile(`//arch:allow-inline-authz\s+\S+`)

// policyModuleDir is the one place authorization logic belongs. The rule cannot apply here: this
// module's whole job is to hold the decision, and it names roles and permissions constantly.
const policyModuleDir = "/modules/policy/"

// archPackageDir is this checker's own package, which necessarily contains the very literals and
// names it looks for. Excluding it is not an exemption for product code — nothing ships from here.
const archPackageDir = "/internal/arch/"

// ScanAuthz parses file and reports inline authorization logic (SPEC-0002 AC4).
//
// Separate from Scan because that one reads imports only, which is enough for every rule founded on
// a dependency edge. This one needs expressions, so it pays for a full parse — and only this rule
// does.
func ScanAuthz(fset *token.FileSet, file string) ([]Violation, error) {
	slash := filepath.ToSlash(file)
	if strings.Contains(slash, policyModuleDir) || strings.Contains(slash, archPackageDir) {
		return nil, nil
	}

	f, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	waived := waivedLines(fset, f)
	var vs []Violation

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Name != nil && authzFuncRe.MatchString(node.Name.Name) {
				addAuthzViolation(&vs, fset, file, node.Name.Pos(), waived, "func "+node.Name.Name)
			}
		case *ast.BinaryExpr:
			// Only equality: `role == "owner"` decides something, whereas `sort(roles)` or a
			// map keyed by role name does not.
			if node.Op != token.EQL && node.Op != token.NEQ {
				return true
			}
			for _, side := range []ast.Expr{node.X, node.Y} {
				if lit := roleLiteral(side); lit != "" {
					addAuthzViolation(&vs, fset, file, node.Pos(), waived, "comparison against role "+strconv.Quote(lit))
					break
				}
			}
		}
		return true
	})

	return vs, nil
}

// addAuthzViolation records one hit unless its line carries a waiver.
func addAuthzViolation(vs *[]Violation, fset *token.FileSet, file string, pos token.Pos, waived map[int]bool, what string) {
	if waived[fset.Position(pos).Line] {
		return
	}
	*vs = append(*vs, Violation{File: file, Import: what, Rule: RuleInlinePermissionCheck})
}

// roleLiteral returns the role name if e is a string literal naming one, else "".
func roleLiteral(e ast.Expr) string {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil || !authzRoleLiterals[s] {
		return ""
	}
	return s
}

// waivedLines maps every line a waiver covers.
//
// A waiver covers its own line and the line after it, so both the trailing form and the
// comment-above form work. It does not cover a whole function or file: a waiver should be as
// narrow as the thing it excuses, or it becomes a way to turn the rule off for a region and nobody
// notices the second exception that drifts in under it.
func waivedLines(fset *token.FileSet, f *ast.File) map[int]bool {
	waived := make(map[int]bool)
	for _, group := range f.Comments {
		for _, c := range group.List {
			if !authzWaiver.MatchString(c.Text) {
				continue
			}
			line := fset.Position(c.Pos()).Line
			waived[line] = true
			waived[line+1] = true
		}
	}
	return waived
}
