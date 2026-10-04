# Quick Start

This walkthrough builds a mixed-domain `FindingSet`, then prioritizes and
summarizes it.

## 1. Produce findings from domain types

Each domain package defines semantic types with a `ToFinding()` method that
projects into the canonical `findingspec.Finding`:

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

    // A security vulnerability
    set.Add(security.Vulnerability{
        ID:       "VULN-1",
        Title:    "SQL injection in search API",
        Severity: findingspec.SeverityHigh,
        CWEs:     []string{"CWE-89"},
    }.ToFinding())

    // A detected secret inside an OpenAPI document
    set.Add(security.Secret{
        ID:       "SEC-1",
        Title:    "AWS access key in OpenAPI server variable",
        Kind:     security.SecretKindAPIKey,
        Detector: "aws-access-key-id",
        Redacted: "AKIA****************1234",
        Location: &findingspec.Location{
            File:      "openapi.json",
            DocFormat: "openapi",
            Pointer:   "/servers/0/variables/apiKey/default",
        },
    }.ToFinding())

    // An accessibility issue
    set.Add(a11y.Issue{
        ID:        "A11Y-1",
        Title:     "Text has insufficient contrast",
        Criterion: "1.4.3",
        Level:     a11y.LevelAA,
        Impact:    a11y.ImpactSerious,
    }.ToFinding())

    report(set)
}
```

## 2. Prioritize and summarize

`FindingSet` offers filtering, counting, and severity ordering that work
identically across every domain:

```go
func report(set *findingspec.FindingSet) {
    set.SortBySeverity() // most severe first

    fmt.Println("by domain:  ", set.CountByDomain())
    fmt.Println("by severity:", set.CountBySeverity())

    // Only findings that still need attention
    open := set.Open()
    fmt.Printf("%d open findings\n", open.Len())

    // Just the security domain
    for _, f := range set.Domain(findingspec.DomainSecurity).Findings {
        fmt.Printf("[%s] %s — %s\n", f.Severity.Name(), f.RuleID, f.Title)
    }
}
```

## 3. Validate before emitting

`Finding.Validate()` enforces the minimum required fields (ID, a valid domain,
title, and a valid severity):

```go
for _, f := range set.Findings {
    if err := f.Validate(); err != nil {
        log.Fatalf("invalid finding %q: %v", f.ID, err)
    }
}
```

## Where to go next

- [Finding Model](../concepts/finding-model.md) — the full `Finding`/`FindingSet` API
- [Severity](../concepts/severity.md) — parsing, ordering, and CVSS mapping
- [Security](../domains/security.md) · [a11y](../domains/a11y.md) · [i18n](../domains/i18n.md) · [qe](../domains/qe.md)
