# Severity

`findingspec` uses a single canonical severity scale for every domain, backed by
the shared [priority-frameworks](https://github.com/grokify/priority-frameworks)
Severity framework. All parsing, ordering, and CVSS mapping delegate to it, so
severity behaves identically wherever it appears.

## The scale

Ordered most to least severe:

| ID (value) | Name | Actionable |
|------------|------|------------|
| `critical` | Critical | yes |
| `high` | High | yes |
| `medium` | Medium | yes |
| `low` | Low | yes |
| `informational` | Informational | no |

`Severity` values are the lower-case IDs (e.g. JSON serializes as `"critical"`).
Use `Name()` for the display form and `Abbreviation()` for a compact one:

```go
s := findingspec.SeverityCritical
s               // "critical"   (the value / JSON form)
s.Name()        // "Critical"
s.Abbreviation()// "CRIT"
```

Constants: `SeverityCritical`, `SeverityHigh`, `SeverityMedium`, `SeverityLow`,
`SeverityInformational`. `Severities()` returns them in order.

## Ordering and checks

```go
findingspec.SeverityCritical.Rank()                       // 0 (lower = more severe)
findingspec.SeverityHigh.MoreSevereThan(findingspec.SeverityLow) // true
findingspec.SeverityInformational.Actionable()            // false
findingspec.SeverityMedium.Valid()                        // true
```

`FindingSet.SortBySeverity()` and `CountBySeverity()` build directly on `Rank()`.

## Parsing

`ParseSeverity` accepts a level ID, display name, or any alias defined by the
framework (case-sensitive to the framework's entries), returning `false` when
unrecognized:

```go
findingspec.ParseSeverity("High")   // "high", true
findingspec.ParseSeverity("high")   // "high", true
findingspec.ParseSeverity("HIGH")   // "high", true  (alias)
findingspec.ParseSeverity("S2")     // "high", true  (alias)
findingspec.ParseSeverity("bogus")  // "",     false
```

To accept additional spellings (for example "Moderate" for medium), add them as
aliases in the priority-frameworks Severity framework rather than special-casing
them here.

## CVSS mapping

`SeverityFromCVSS` maps a CVSS base score to the canonical severity using the
standard bands (via the framework's CVSS score range). Scores outside 0.0–10.0
map to Informational:

```go
findingspec.SeverityFromCVSS(9.8) // "critical"
findingspec.SeverityFromCVSS(7.5) // "high"
findingspec.SeverityFromCVSS(5.3) // "medium"
findingspec.SeverityFromCVSS(3.1) // "low"
findingspec.SeverityFromCVSS(0.0) // "informational"
```

The `security` domain's `CVSS.Severity()` uses this mapping. CVSS v2 used a
coarser scale; score v2 vectors explicitly rather than relying on these bands.

## Why delegate to priority-frameworks

Severity, priority (P0–P4), MoSCoW, and IETF requirement levels are all the same
shape — an ordered set of named levels — so a shared library owns the vocabulary,
ordering, colors, abbreviations, and cross-framework mapping once. `findingspec`
consumes the Severity framework rather than maintaining its own copy.
