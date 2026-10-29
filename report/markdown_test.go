package report_test

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/a11y"
	"github.com/plexusone/findingspec/report"
	"github.com/plexusone/findingspec/security"
)

func fixtureSet(t *testing.T) findingspec.FindingSet {
	t.Helper()
	high := security.Vulnerability{
		ID:             "EX-002",
		Title:          "Token audience is not checked",
		Description:    "The verifier accepts any token signed by the issuer, including `id_token` values.\n\n- this line is prose, not a list",
		Type:           security.TypeSAST,
		CWEs:           []string{"CWE-287"},
		Severity:       findingspec.SeverityHigh,
		Exploitability: security.ExploitabilityPOC,
		RootCause: &security.RootCause{
			Summary:        "No audience binding.",
			MissingControl: "Mandatory aud check",
			Components:     []string{"auth/verify.go (Verify)"},
		},
		Impact: &security.Impact{
			Technical: "Cross-client token replay.",
			Product:   "One compromised app reaches every app.",
		},
		Exploit: &security.Exploit{
			Preconditions: []string{"SECRET-PRECONDITION"},
			Scenario:      "SECRET-SCENARIO",
			Reproduction:  "SECRET-REPRODUCTION",
		},
		Location: &findingspec.Location{
			Repo: "example/app", File: "auth/verify.go", Line: 42,
			Snippet: "if aud != \"\" {\n\treturn ok\n}",
		},
		Remediation: &findingspec.Remediation{
			Summary:     "Require an audience.",
			AgentPrompt: "AGENT-PROMPT-TEXT",
			Effort:      "medium",
		},
		Relationships: []findingspec.Relationship{
			{Type: findingspec.RelationshipRelatedTo, Target: "EX-001", Title: "same root cause"},
			{Type: findingspec.RelationshipTrackedBy, Target: "TICKET-9"},
		},
		References: []findingspec.Reference{{Title: "RFC 9068", URL: "https://www.rfc-editor.org/rfc/rfc9068"}},
		Status:     findingspec.StatusOpen,
	}
	low := security.Vulnerability{
		ID:          "EX-001",
		Title:       "Markup *must* stay <literal> for @team & co",
		Description: "1. not a list\n# not a heading",
		Severity:    findingspec.SeverityLow,
		Package:     &security.Package{Name: "example.com/lib", Version: "v1.2.0", Ecosystem: "golang"},
		Fix:         &security.Fix{State: security.FixStateFixed, Versions: []string{"v1.2.1"}},
		CVSS:        &security.CVSS{Version: "3.1", Score: 3.1, Vector: "CVSS:3.1/AV:N"},
		Status:      findingspec.StatusAccepted,
	}
	f1 := high.ToFinding()
	f1.Confidence = findingspec.ConfidenceHigh
	f1.Evidence = []findingspec.Evidence{{Kind: "log", Summary: "probe output", Data: "SECRET-EVIDENCE-DATA"}}
	a := a11y.Issue{
		ID: "A11Y-1", Title: "Image without alt text", Impact: a11y.ImpactSerious,
		Criterion: "1.1.1",
	}
	// Low first so the test can check that the renderer sorts.
	return findingspec.FindingSet{Findings: []findingspec.Finding{low.ToFinding(), a.ToFinding(), f1}}
}

func render(t *testing.T, set findingspec.FindingSet, opts report.Options) string {
	t.Helper()
	out, err := report.MarkdownString(set, opts)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

func TestShareableOmitsAttackDetail(t *testing.T) {
	out := render(t, fixtureSet(t), report.Options{})
	for _, s := range []string{"SECRET-PRECONDITION", "SECRET-SCENARIO", "SECRET-REPRODUCTION", "SECRET-EVIDENCE-DATA", "return ok", "Attack Scenario", "AGENT-PROMPT-TEXT"} {
		if strings.Contains(out, s) {
			t.Errorf("shareable report contains %q", s)
		}
	}
	for _, s := range []string{"**Distribution:** Shareable", "No audience binding", "Require an audience"} {
		if !strings.Contains(out, s) {
			t.Errorf("shareable report missing %q", s)
		}
	}
}

func TestInternalIncludesAttackDetail(t *testing.T) {
	out := render(t, fixtureSet(t), report.Options{Audience: report.AudienceInternal, IncludeAgentPrompts: true})
	for _, s := range []string{"SECRET-PRECONDITION", "SECRET-SCENARIO", "SECRET-REPRODUCTION", "SECRET-EVIDENCE-DATA", "```go\nif aud", "AGENT-PROMPT-TEXT", "**Distribution:** Internal"} {
		if !strings.Contains(out, s) {
			t.Errorf("internal report missing %q", s)
		}
	}
}

func TestInvalidAudience(t *testing.T) {
	if _, err := report.MarkdownString(fixtureSet(t), report.Options{Audience: "public"}); err == nil {
		t.Fatal("expected an error for an unknown audience")
	}
}

func TestOrderingAndInputUnchanged(t *testing.T) {
	set := fixtureSet(t)
	before := set.Findings[0].ID
	out := render(t, set, report.Options{})
	if set.Findings[0].ID != before {
		t.Fatalf("input set reordered: first is %s, want %s", set.Findings[0].ID, before)
	}
	// Serious a11y impact maps to high; ties order by domain, then ID.
	a11yHigh := strings.Index(out, "### A11Y-1:")
	secHigh := strings.Index(out, "### EX-002:")
	low := strings.Index(out, "### EX-001:")
	if a11yHigh < 0 || secHigh < 0 || low < 0 || a11yHigh >= secHigh || secHigh >= low {
		t.Fatalf("findings out of order: a11y=%d high=%d low=%d", a11yHigh, secHigh, low)
	}
	if !strings.Contains(out, "## High Severity") || !strings.Contains(out, "## Low Severity") {
		t.Error("missing severity group headings")
	}
}

func TestSeverityTableListsEveryLevel(t *testing.T) {
	out := render(t, fixtureSet(t), report.Options{})
	for _, row := range []string{"| Critical | 0 | 0 |", "| High | 2 | 2 |", "| Low | 1 | 0 |", "| **Total** | **3** | **2** |"} {
		if !strings.Contains(out, row) {
			t.Errorf("severity table missing row %q", row)
		}
	}
}

func TestEscaping(t *testing.T) {
	out := render(t, fixtureSet(t), report.Options{})
	for _, s := range []string{
		`Markup \*must\* stay \<literal\> for \@team \& co`,
		"`id_token`",            // code span kept
		`\- this line is prose`, // not a list item
		`1\. not a list`,        // not an ordered list
		`\# not a heading`,      // not a heading
		"| Location | example/app `auth/verify.go:42` |",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
}

func TestLinksAndAnchors(t *testing.T) {
	out := render(t, fixtureSet(t), report.Options{})
	for _, s := range []string{
		"### EX-002: Token audience is not checked {#finding-ex-002}",
		"[EX-002](#finding-ex-002)",
		"- Related to: [EX-001](#finding-ex-001) (same root cause)",
		"- Tracked by: TICKET-9",
		"[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
}

func TestDuplicateIDsGetDistinctAnchors(t *testing.T) {
	f := findingspec.Finding{ID: "a b", Domain: findingspec.DomainQE, Title: "x", Severity: findingspec.SeverityLow}
	g := findingspec.Finding{ID: "a-b", Domain: findingspec.DomainQE, Title: "y", Severity: findingspec.SeverityLow}
	out := render(t, findingspec.FindingSet{Findings: []findingspec.Finding{f, g}}, report.Options{})
	if !strings.Contains(out, "{#finding-a-b}") || !strings.Contains(out, "{#finding-a-b-2}") {
		t.Errorf("expected distinct anchors, got:\n%s", out)
	}
}

func TestAttributes(t *testing.T) {
	out := render(t, fixtureSet(t), report.Options{})
	for _, s := range []string{
		"| Category | Security / SAST |",
		"| CWE | CWE-287 |",
		"| Exploitability | Proof of concept |",
		"| Package | `example.com/lib@v1.2.0` (golang) |",
		"| Fixed in | v1.2.1 |",
		"| CVSS | 3.1 (CVSS 3.1) `CVSS:3.1/AV:N` |",
		"| Status | Accepted |",
		"| Rule | 1.1.1 |",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
}

func TestMetadataAndSections(t *testing.T) {
	out := render(t, fixtureSet(t), report.Options{
		Title:          `Review: "Q4"`,
		Authors:        []string{"Security Team"},
		Date:           "2026-10-01",
		Classification: "Confidential",
		Summary:        "Summary **markdown** kept.",
		Sections:       []report.Section{{Title: "Key Themes", Body: "Theme text."}},
		Appendices:     []report.Section{{Title: "Appendix A", Body: "Appendix text."}},
		NoTOC:          true,
	})
	if !strings.HasPrefix(out, "---\ntitle: \"Review: \\\"Q4\\\"\"\n") {
		t.Errorf("unexpected metadata block start:\n%s", out[:min(len(out), 200)])
	}
	if strings.Contains(out, "toc: true") {
		t.Error("NoTOC set but toc requested")
	}
	order := []string{"Summary **markdown** kept.", "# Key Themes", "# Findings Overview", "# Detailed Findings", "# Appendix A"}
	last := -1
	for _, s := range order {
		i := strings.Index(out, s)
		if i <= last {
			t.Fatalf("%q missing or out of order", s)
		}
		last = i
	}
}

func TestCodeBlockFenceOutlastsContent(t *testing.T) {
	v := security.Vulnerability{
		ID: "EX-9", Title: "fence", Severity: findingspec.SeverityLow,
		Location: &findingspec.Location{File: "x.md", Snippet: "````\ninner\n````"},
	}
	out := render(t, findingspec.FindingSet{Findings: []findingspec.Finding{v.ToFinding()}}, report.Options{Audience: report.AudienceInternal})
	if !strings.Contains(out, "`````\n````\ninner\n````\n`````") {
		t.Errorf("fence not longer than content:\n%s", out)
	}
}

func TestEmptySet(t *testing.T) {
	out := render(t, findingspec.FindingSet{}, report.Options{})
	if strings.Contains(out, "# Detailed Findings") || !strings.Contains(out, "This report covers 0 findings") {
		t.Errorf("unexpected empty-set output:\n%s", out)
	}
}

// TestPandocParses checks that pandoc reads the output as intended: header
// identifiers survive and no escaped text turns into raw HTML. It is skipped
// when pandoc is not installed.
func TestPandocParses(t *testing.T) {
	if _, err := exec.LookPath("pandoc"); err != nil {
		t.Skip("pandoc not installed")
	}
	md := render(t, fixtureSet(t), report.Options{Audience: report.AudienceInternal})
	cmd := exec.Command("pandoc", "-f", "markdown", "-t", "json")
	cmd.Stdin = strings.NewReader(md)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("pandoc: %v: %s", err, stderr.String())
	}
	var doc struct {
		Meta map[string]any `json:"meta"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("decode pandoc json: %v", err)
	}
	if _, ok := doc.Meta["title"]; !ok {
		t.Error("pandoc did not read the title metadata")
	}
	ast := stdout.String()
	if !strings.Contains(ast, `"finding-ex-002"`) {
		t.Error("header identifier finding-ex-002 not in pandoc AST")
	}
	if strings.Contains(ast, `"RawInline"`) || strings.Contains(ast, `"RawBlock"`) {
		t.Error("escaped text was parsed as raw HTML or LaTeX")
	}
}
