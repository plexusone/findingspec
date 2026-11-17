# FindingSpec

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![Docs][docs-mkdoc-svg]][docs-mkdoc-url]
[![Visualization][viz-svg]][viz-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/plexusone/findingspec/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/plexusone/findingspec/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/plexusone/findingspec/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/plexusone/findingspec/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/plexusone/findingspec/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/plexusone/findingspec/actions/workflows/go-sast-codeql.yaml
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/plexusone/findingspec
 [docs-godoc-url]: https://pkg.go.dev/github.com/plexusone/findingspec
 [docs-mkdoc-svg]: https://img.shields.io/badge/Go-dev%20guide-blue.svg
 [docs-mkdoc-url]: https://plexusone.dev/findingspec
 [viz-svg]: https://img.shields.io/badge/Go-visualizaton-blue.svg
 [viz-url]: https://mango-dune-07a8b7110.1.azurestaticapps.net/?repo=plexusone%2Ffindingspec
 [loc-svg]: https://tokei.rs/b1/github/plexusone/findingspec
 [repo-url]: https://github.com/plexusone/findingspec
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/plexusone/findingspec/blob/main/LICENSE

`findingspec` is a Go module defining a **domain-neutral model for findings** —
anything that needs attention — across multiple problem domains: security,
accessibility (a11y), internationalization (i18n), quality engineering (qe), and content.

A single canonical `Finding` type carries the fields common to every domain
(identity, severity, status, location, evidence, remediation). Each domain
package defines richer, semantically-typed findings and projects them into a
`Finding` via a `ToFinding` method — so producers keep domain-specific detail
while consumers reason over one uniform representation.

```
import "github.com/plexusone/findingspec"
```

## Model

```
findingspec              canonical Finding, FindingSet, and shared vocabulary
├── security             vulnerabilities & secrets, CVSS/CWE/CVE, residual risk
├── a11y                 WCAG accessibility issues
├── i18n                 internationalization / localization issues
├── qe                   quality-engineering findings (E2E tests, journeys)
├── content              claims, their sources and recordings; narration vs. script
└── report               formal Markdown reports for pandoc (DOCX, PDF, HTML)
```

The core package's only external dependency is the shared
[priority-frameworks](https://github.com/grokify/priority-frameworks) severity
framework, and it does not import any domain package, keeping the shared
vocabulary neutral. Only domain packages and the `report` renderer depend on
the core.

### Shared vocabulary

- **Severity** — `critical`, `high`, `medium`, `low`, `informational` (canonical
  IDs; display names via `Severity.Name()`), backed by the shared
  [priority-frameworks](https://github.com/grokify/priority-frameworks) Severity
  framework for parsing, ordering, and CVSS mapping
- **Status** — `open`, `confirmed`, `remediated`, `accepted`, `false_positive`, `resolved`
- **Confidence** — `high`, `medium`, `low`
- **Location** — code (`File`/`Line`), runtime (`URL`/`Selector`), or a node inside
  a structured document (`Pointer` = RFC 6901 JSON Pointer + `DocFormat`, e.g.
  OpenAPI/Postman), plus `Repo` and `Component`
- **Evidence**, **Remediation** (with an `AgentPrompt` for AI builders), **Reference**

The `security` domain also models **detected secrets** (`security.Secret`) — API
keys, tokens, and private keys — including secrets located inside OpenAPI specs or
Postman collections via `Location.Pointer`, without ever storing the raw value.

## Example

```go
package main

import (
	"fmt"

	"github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/a11y"
	"github.com/plexusone/findingspec/security"
)

func main() {
	set := findingspec.NewFindingSet()

	set.Add(security.Vulnerability{
		ID:       "VULN-1",
		Title:    "SQL injection in search API",
		Severity: findingspec.SeverityHigh,
		CWEs:     []string{"CWE-89"},
	}.ToFinding())

	set.Add(a11y.Issue{
		ID:        "A11Y-1",
		Title:     "Text has insufficient contrast",
		Criterion: "1.4.3",
		Level:     a11y.LevelAA,
		Impact:    a11y.ImpactSerious,
	}.ToFinding())

	set.SortBySeverity()
	fmt.Println(set.CountByDomain()) // map[a11y:1 security:1]
}
```

## Content Findings

The `content` domain records problems with claims and their sources, such as a quotation that is not in its source
or recording, and narration that doesn't say its script.
The claim is the finding's location, so a claim checker can raise findings in a static scan and carry each through
review with the shared status lifecycle: `open`, then `confirmed` or `false_positive`, then `resolved` or `accepted`.

```go
f := content.Issue{
	ID:        "CF-1",
	Rule:      content.RuleQuoteNotFound,
	Title:     "Quotation not found in its source",
	ClaimID:   "claim-founding",
	Statement: "The company was founded in 1929.",
	SourceRef: "src-history",
	Status:    findingspec.StatusOpen,
}.ToFinding()

content.ClaimID(f) // "claim-founding"
```

See [Content](docs/domains/content.md) for the rules.

## Reports

`report.WriteMarkdown` renders a `FindingSet` as a formal report: a pandoc
metadata block, executive summary and severity tables, a linked findings
overview, and a detailed section per finding. Convert it with pandoc:

```bash
pandoc report.md -o report.docx --reference-doc=template.docx
pandoc report.md -o report.pdf --pdf-engine=xelatex
```

The default shareable audience leaves out exploit steps, evidence payloads,
and code snippets; `report.AudienceInternal` includes them. See
[Reports](https://plexusone.github.io/findingspec/reference/report/).

## Documentation

Full documentation is built with MkDocs (Material) from the `docs/` directory
and published at <https://plexusone.github.io/findingspec/>. Build it locally with:

```bash
mkdocs serve   # live preview at http://127.0.0.1:8000
mkdocs build   # render to ./site
```

Specifications live in [`docs/specs/`](docs/specs/) (PRD, TRD, Roadmap).

## Relationship to govex

The security domain's concepts (inherent vs. residual severity, compensating
controls, exceptions, CVSS/CWE/CVE) were first prototyped in
[`github.com/grokify/govex`](https://github.com/grokify/govex). `findingspec`
re-expresses them cleanly against a shared, multi-domain vocabulary and does not
depend on govex.

## License

[MIT](LICENSE)
