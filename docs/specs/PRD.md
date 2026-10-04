# findingspec — Product Requirements

## Problem

Findings about software — security vulnerabilities, accessibility violations,
internationalization gaps, failed end-to-end tests — are produced by many
different tools, each with its own schema and vocabulary. Consumers that want to
reason across these domains (prioritize, deduplicate, report, remediate) must
integrate each format separately, and there is no shared way to say "here is
something that needs attention" independent of the tool that found it.

## Goal

Provide a small, dependency-light Go model that represents a **finding** in a
**domain-neutral** way, while letting each domain keep its own semantically-rich
types. One representation should support prioritization, filtering, reporting,
and remediation across security, a11y, i18n, and quality-engineering findings.

## Users

- **Producers** — scanners and assessors (e.g. security scanners, accessibility
  auditors, E2E test runners) that emit findings.
- **Consumers** — dashboards, prioritization engines, and AI remediation agents
  that aggregate findings across domains.

## Requirements

1. A canonical `Finding` type with the fields common to all domains: identity,
   domain, rule, title, description, severity, confidence, status, source,
   location, evidence, remediation, references, tags, and detection time.
2. A shared vocabulary for severity, status, and confidence usable by every
   domain.
3. Domain packages (security, a11y, i18n, qe) with semantic types that project
   into `Finding` via `ToFinding`, without the core depending on any domain.
4. A `FindingSet` with filtering, counting, and severity ordering.
5. Remediation guidance expressible as an instruction for an AI builder.
6. Minimal core dependencies — only the shared priority-frameworks severity
   framework, which supplies the canonical severity vocabulary and ordering.

## Non-goals

- Reproducing every producer's native schema.
- Being a scanning or assessment engine — `findingspec` is a representation, not
  a producer.
- Report rendering, storage, or transport (these belong to consuming systems).

## Success criteria

- A consumer can aggregate findings from at least two domains into one
  `FindingSet` and prioritize them by severity with no domain-specific code.
- Adding a new domain requires only a new package projecting into `Finding`.
