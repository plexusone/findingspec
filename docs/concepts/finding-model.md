# Finding Model

The core `findingspec` package defines the canonical, domain-neutral
representation and the shared vocabulary every domain draws on.

## Finding

`Finding` is the canonical representation of something that needs attention.

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `string` | Stable identifier, unique within its producer |
| `Domain` | `Domain` | Broad area — `security` / `a11y` / `i18n` / `qe` / `compliance` / `observability` |
| `Type` | `string` | Finding class within the domain (`sast`, `sca`, `secret`, `wcag`, `e2e`, `apm`, `cis`, …) |
| `RuleID` | `string` | Domain rule/check id (CWE, WCAG criterion, lint rule, journey/step) |
| `Title` | `string` | Short human-readable summary |
| `Description` | `string` | Detailed explanation |
| `Severity` | `Severity` | Impact on the [shared severity scale](severity.md) |
| `Confidence` | `Confidence` | `high` / `medium` / `low` |
| `Status` | `Status` | Lifecycle state |
| `Source` | `Source` | Producing tool (`Tool`, `Version`, `RuleSet`) |
| `Location` | `*Location` | Where it was observed — see [Location](../reference/location.md) |
| `Evidence` | `[]Evidence` | Supporting artifacts |
| `Remediation` | `*Remediation` | How to fix, incl. an `AgentPrompt` |
| `References` | `[]Reference` | External links |
| `Tags` | `[]string` | Free-form labels |
| `DetectedAt` | `*time.Time` | When observed |
| `Detail` | `json.RawMessage` | Typed per-type subsection (see below) |

### Type and detail — one view, per-type depth

Every finding shares the canonical header above (the single cross-domain view),
and carries its area-specific payload in `Detail` — a typed subsection keyed by
the two-level `Domain` + `Type` taxonomy:

| Domain | Type (examples) | Detail payload |
|--------|-----------------|----------------|
| `security` | `sast` · `dast` · `sca` · `secret` · `container` · `iac` · `cloud-config` · `runtime` · `pentest` | CWE/dataflow · request/response · package/CVE/CVSS/reachability · detector/entropy · image/layer · resource/control · host+agent |
| `compliance` | `cis` · `stig` · `fedramp` · `soc2` · `iso27001` | framework · controlId · result (pass/fail/NA) |
| `a11y` | `wcag` | criterion / level / impact |
| `i18n` | `missing-translation`, … | key / locale |
| `qe` | `e2e` · `functional` | journey / step / expected vs actual |
| `observability` | `apm` · `synthetic` · `rum` · `slo` | service/latency · monitor/uptime · web-vital · SLA target vs actual |

Producers set the detail with `SetDetail`; consumers decode it with the generic
`DetailAs[T]`, keyed on `Type`:

```go
// produce
f.SetDetail(security.SecretDetail{Detector: "aws-access-key-id", Redacted: "AKIA…MPLE"})

// consume
switch f.Type {
case security.TypeSecret:
    d, _ := findingspec.DetailAs[security.SecretDetail](f)
    // d.Detector, d.Redacted, d.Entropy, …
case security.TypeSCA:
    d, _ := findingspec.DetailAs[security.VulnerabilityDetail](f)
    // d.CVEs, d.CVSS, d.Reachable, …
}
```

The header alone drives the unified dashboard (`Summary()`, counts, sorting);
`Detail` gives full area-specific depth when a consumer wants it. This is how one
IR normalizes many scanners (SAST/DAST/SCA/secrets/container/runtime/compliance)
alongside a11y, i18n, QE, and observability — see [Interchange](interchange.md).

### Validation

`Finding.Validate()` enforces the minimum required fields — a non-empty `ID`, a
valid `Domain`, a non-empty `Title`, and a valid `Severity`:

```go
f := security.Vulnerability{ID: "V-1", Title: "…", Severity: findingspec.SeverityHigh}.ToFinding()
if err := f.Validate(); err != nil {
    // handle invalid finding
}
```

## FindingSet

`FindingSet` is a collection with helpers that work identically across domains.

```go
set := findingspec.NewFindingSet(findings...)
set.Add(more...)

set.Len()                       // count
set.Domain(findingspec.DomainSecurity)   // filter → *FindingSet
set.Severity(findingspec.SeverityHigh)   // filter → *FindingSet
set.Open()                      // only statuses that still need attention

set.CountByDomain()             // map[Domain]int
set.CountBySeverity()           // map[Severity]int
set.SortBySeverity()            // in place, most severe first (ties: domain, then ID)
```

Filters return a new `*FindingSet`, so they compose:

```go
critical := set.Domain(findingspec.DomainSecurity).Severity(findingspec.SeverityCritical)
```

## Analytics

A `FindingSet` is the multi-finding JSON IR — it marshals to
`{"findings":[…]}` and round-trips — and it answers the common analytics
questions directly.

Typed counters:

```go
set.Len()               // total number of findings
set.CountBySeverity()   // map[Severity]int
set.CountByDomain()     // map[Domain]int   — findings by type
set.CountByStatus()     // map[Status]int
set.CountBySource()     // map[string]int   — by producing tool (Source.Tool)
set.CountByRepo()       // map[string]int   — by top-level location (Location.Repo)
set.CountByFile()       // map[string]int   — by file (Location.File)
```

Generic group-by for any other dimension (rule, tag, provider, …):

```go
byRule := set.CountBy(func(f findingspec.Finding) string { return f.RuleID })
```

`Summary()` rolls up the common breakdowns in a single pass into one
JSON-serializable object — useful as a dashboard header or an IR envelope
alongside the findings:

```go
sum := set.Summary()
// sum.Total, sum.Open, sum.Actionable,
// sum.BySeverity, sum.ByDomain, sum.ByStatus, sum.ByRepo
json.Marshal(sum)
```

| Field | Meaning |
|-------|---------|
| `Total` | number of findings |
| `Open` | findings whose status still needs attention |
| `Actionable` | findings whose severity is actionable (not Informational) |
| `BySeverity` | count per severity |
| `ByDomain` | count per domain (type) |
| `ByStatus` | count per lifecycle status |
| `ByRepo` | count per top-level location (repo) |

## Domain projection contract

The core never imports a domain package. Instead, each domain type implements:

```go
ToFinding() findingspec.Finding
```

`ToFinding` sets the appropriate `Domain`, maps the domain's own
severity/impact to the shared `Severity`, and derives a `RuleID` from the most
specific classifier available. This keeps the core neutral while letting each
domain carry rich, semantic detail. Adding a new domain is just a new package
that projects into `Finding`.

## Enumerations

- **`Domain`** — `security`, `a11y`, `i18n`, `qe`, `compliance`, `observability`.
  `Domains()` lists them; `Valid()` checks one.
- **`Status`** — `open`, `confirmed`, `remediated`, `accepted`, `false_positive`,
  `resolved`. `Status.Open()` reports whether a finding still needs attention.
- **`Confidence`** — `high`, `medium`, `low` (certainty of a true positive,
  distinct from severity/impact).
- **`Source`** — the producing tool: `Tool`, `Version`, `RuleSet`.
