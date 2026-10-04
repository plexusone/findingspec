# findingspec

**A domain-neutral model for findings — anything that needs attention — across
security, accessibility (a11y), internationalization (i18n), and quality
engineering (qe).**

A single canonical [`Finding`](concepts/finding-model.md) type carries the fields
common to every domain (identity, severity, status, location, evidence,
remediation). Each domain package defines richer, semantically-typed findings and
projects them into a `Finding` via a `ToFinding` method — so producers keep
domain-specific detail while consumers reason over one uniform representation.

```go
import "github.com/plexusone/findingspec"
```

## Why

Findings about software are produced by many tools, each with its own schema.
Consumers that want to prioritize, deduplicate, report, or remediate across
domains must integrate each format separately. `findingspec` provides one
representation for "here is something that needs attention," independent of the
tool that found it — while letting each domain keep its own semantic types.

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
framework, and it does not import any domain package — keeping the shared
vocabulary neutral. Only domain packages depend on the core.

## Quick example

```go
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
```

## Next steps

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)
- [Finding Model](concepts/finding-model.md) — the canonical `Finding` and `FindingSet`
- [Severity](concepts/severity.md) — the shared severity vocabulary
- Domains: [Security](domains/security.md) · [a11y](domains/a11y.md) · [i18n](domains/i18n.md) · [qe](domains/qe.md)

## Relationship to govex

The security domain's concepts (inherent vs. residual severity, compensating
controls, exceptions, CVSS/CWE/CVE) were first prototyped in
[`grokify/govex`](https://github.com/grokify/govex). `findingspec` re-expresses
them cleanly against a shared, multi-domain vocabulary and does not depend on
govex.
