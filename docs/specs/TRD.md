# findingspec — Technical Requirements

## Architecture

A library-first Go module with a domain-neutral core package and one package per
domain. The core defines the canonical representation and shared vocabulary;
domain packages depend on the core and never the reverse, avoiding import cycles
and keeping the core lean — its only dependency is the shared
`grokify/priority-frameworks` severity framework.

```
findingspec (core)      Finding, FindingSet, Severity, Status, Confidence,
                        Source, Location, Evidence, Remediation, Reference, Domain
├── security            Vulnerability, CVSS, Control, Exception, Exploitability
├── a11y                Issue, ConformanceLevel, Impact
├── i18n                Issue, Kind
├── qe                  Failure
└── report              WriteMarkdown, Options, Audience (consumer of the core
                        and the security domain; nothing imports it)
```

## Core types

- `Finding` — canonical finding; `Validate()` enforces id, domain, title, severity.
- `FindingSet` — collection with `Domain`, `Severity`, `Open` filters,
  `CountBySeverity`, `CountByDomain`, and `SortBySeverity`.
- `Severity` — canonical level IDs (`critical`/`high`/`medium`/`low`/
  `informational`) delegating to the shared `grokify/priority-frameworks`
  Severity framework for `Rank`, `MoreSevereThan`, `Actionable`, `Name`,
  `ParseSeverity` (ID/name/alias, e.g. "High", "S2"), and `SeverityFromCVSS`
  (canonical CVSS score→level bands).
- `Domain`, `Status`, `Confidence` — closed enumerations with `Valid` checks.
- `Location` — domain-flexible: code (`File`/`Line`/`Column`) or runtime
  (`URL`/`Selector`), plus `Component` and `Snippet`.

## Domain projection contract

Each domain type implements `ToFinding() findingspec.Finding`, setting the
appropriate `Domain`, mapping its domain-specific severity/impact to the shared
`Severity`, and deriving a `RuleID` from its most specific classifier (CWE, WCAG
success criterion, i18n kind, journey/step).

## Security domain

Recreates the residual-risk model prototyped in `grokify/govex` without importing
it: inherent `Severity` vs. `ResidualSeverity`, `Control` (compensating controls
with function, reduced dimensions, and justified CVSS environmental metrics), and
`Exception` (approval state with expiry). `EffectiveSeverity(t)` returns residual
severity only while an exception is approved and unexpired.

## Report rendering

`report.WriteMarkdown(w, set, opts)` renders a `FindingSet` as pandoc-flavoured
Markdown. It reads only the canonical `Finding` plus, for security findings,
the `VulnerabilityDetail` payload; other domains render from the header fields.

- **Structure:** a YAML metadata block (title, subtitle, authors, date,
  classification, toc), a distribution notice, executive summary with a
  severity table covering every level and count tables by repository and
  domain when there is more than one, author-written sections, a findings
  overview whose IDs link to each finding, detailed findings grouped by
  severity, and appendices.
- **Ordering:** a copy of the set is sorted with `SortBySeverity`; the input is
  not modified.
- **Audience:** `AudienceShareable` (default) omits `Exploit`, `Evidence`, and
  `Location.Snippet`; `AudienceInternal` includes them. `Remediation.AgentPrompt`
  is included only when `IncludeAgentPrompts` is set.
- **Escaping:** free-text finding fields are plain text. Inline Markdown,
  pandoc citation (`@`), math (`$`), and raw HTML characters are
  backslash-escaped, line-start block markers are guarded, and matched
  backtick code spans are kept. Author-supplied summary, scope, and section
  bodies are Markdown and written verbatim.
- **Anchors:** each finding heading carries an explicit `{#finding-<id>}`
  identifier, deduplicated when two IDs normalize to the same anchor.
  Relationships whose target is in the set become internal links.
- **Tables:** pipe tables whose separator dash counts set pandoc's relative
  column widths, so long titles wrap within the page in DOCX and PDF.

## Conventions

- JSON tags use camelCase (API/document-format surface).
- Core depends only on the shared `grokify/priority-frameworks` severity
  framework; domain packages avoid additional dependencies where possible.
- Go structs are the source of truth; a JSON Schema is generated from them
  (see ROADMAP).
- `gofmt` and `go vet` clean; unit tests per package.

## Testing

Unit tests cover severity parsing/ordering, finding validation, set
filtering/counting/sorting, CVSS→severity mapping, effective-severity under
exceptions, each domain's `ToFinding` projection, and report rendering
(audience filtering, escaping, ordering, anchors, and a pandoc parse check that
is skipped when pandoc is not installed).
