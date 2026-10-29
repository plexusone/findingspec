# Reports

The `report` package renders a `FindingSet` as a formal Markdown report. The
output is written for [pandoc](https://pandoc.org/), so one source converts to
DOCX, PDF, or HTML.

```go
import "github.com/plexusone/findingspec/report"

md, err := report.MarkdownString(set, report.Options{
    Title:          "Payments Service Security Review",
    Authors:        []string{"Application Security"},
    Date:           "2026-10-23",
    Classification: "Confidential",
    Summary:        "No critical findings. Two high findings affect token handling.",
    Scope:          "Manual review of the payments service at v2.4.0.",
    Sections: []report.Section{
        {Title: "Recommended Remediation Order", Body: "1. Token audience\n2. Webhook signatures"},
    },
})
if err != nil {
    return err
}
if err := os.WriteFile("report.md", []byte(md), 0o600); err != nil {
    return err
}
```

`report.WriteMarkdown(w, set, opts)` writes to any `io.Writer` instead.

Convert with pandoc:

```bash
pandoc report.md -o report.docx --reference-doc=template.docx
pandoc report.md -o report.pdf --pdf-engine=xelatex -V geometry:margin=1in
```

A `--reference-doc` supplies Word styles (fonts, heading colours, table style,
headers and footers), so branding stays out of the renderer.

## Report structure

1. **Metadata block**: title, subtitle, authors, date, classification, and a
   table of contents request.
2. **Distribution notice**: the classification and the audience.
3. **Executive Summary**: `Options.Summary`, total/open/actionable counts, a
   severity table listing every level, and tables by repository and domain
   when the findings span more than one.
4. **Scope and Methodology**: `Options.Scope`.
5. **Author sections**: `Options.Sections`, in order.
6. **Findings Overview**: one row per finding, most severe first, with each ID
   linking to its detailed section.
7. **Detailed Findings**: grouped by severity. Each finding has an attribute
   table (severity, status, confidence, category, CWE/CVE, CVSS,
   exploitability, reachability, package, fix version, component, location,
   source, effort) followed by description, root cause, impact, attack
   scenario, call paths, compensating controls, evidence, affected code,
   remediation, verification, related findings, and references. Empty parts
   are left out.
8. **Appendices**: `Options.Appendices`, in order.

## Audience

| Content | `AudienceShareable` (default) | `AudienceInternal` |
|---------|:----------------------------:|:------------------:|
| Description, root cause, impact, remediation | Yes | Yes |
| Exploit preconditions, scenario, reproduction | No | Yes |
| Evidence summaries and payloads | No | Yes |
| Code snippets (`Location.Snippet`) | No | Yes |
| Remediation agent prompts | Only with `IncludeAgentPrompts` | Only with `IncludeAgentPrompts` |

Use the shareable audience for anything that leaves the team that owns the
findings. Projecting a `security.Vulnerability` with `ToFinding` copies its
`Exploit` into the finding's detail, so the audience setting, not the data, is
what keeps attack steps out of a shared report.

## Text handling

Finding fields such as titles, descriptions, and root-cause summaries are
treated as plain text. Characters that Markdown or pandoc would interpret
(`*`, `_`, `<`, `@`, `$`, `|`, and others) are escaped, and lines that would
start a list, heading, or block quote are guarded. Matched backtick spans such
as `` `ParseToken` `` are kept as inline code, since authors commonly mark
identifiers that way.

`Options.Summary`, `Options.Scope`, and each `Section.Body` are Markdown and
are written as given.

## Non-security domains

Security findings render their `VulnerabilityDetail` (root cause, impact,
CVSS, package, reachability, and so on). Findings in other domains render from
the canonical `Finding` fields, with `RuleID` shown as the rule.
