# findingspec

`findingspec` is a Go module defining a **domain-neutral model for findings** —
anything that needs attention — across multiple problem domains: security,
accessibility (a11y), internationalization (i18n), and quality engineering (qe).

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
└── qe                   quality-engineering findings (E2E tests, journeys)
```

The core package's only external dependency is the shared
[priority-frameworks](https://github.com/grokify/priority-frameworks) severity
framework, and it does not import any domain package, keeping the shared
vocabulary neutral. Only domain packages depend on the core.

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
