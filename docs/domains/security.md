# Security

The `security` package defines semantic security findings — vulnerabilities in
code, dependencies, and configuration, and detected secrets — and projects each
into the domain-neutral [`findingspec.Finding`](../concepts/finding-model.md)
with `Domain = security`.

These concepts were first prototyped in
[grokify/govex](https://github.com/grokify/govex) and are re-expressed here
cleanly against the findingspec core vocabulary. This package does **not** import
govex.

Its defining idea is a residual-risk model: the intrinsic weakness carries an
inherent `Severity`, while a separate `ResidualSeverity` captures the risk that
remains after verified compensating controls — so a control reduces residual risk
without ever relabeling the underlying vulnerability.

## Vulnerability

`Vulnerability` is a semantic security finding: a weakness in code, a dependency,
or configuration.

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `string` | Stable identifier |
| `Title` | `string` | Short human-readable summary |
| `Description` | `string` | Detailed explanation |
| `CVEs` | `[]string` | CVE identifiers |
| `CWEs` | `[]string` | CWE identifiers |
| `CVSS` | `*CVSS` | Scoring result — see [CVSS](#cvss) |
| `Severity` | `findingspec.Severity` | Inherent severity of the weakness |
| `ResidualSeverity` | `findingspec.Severity` | Severity remaining after verified controls; only meaningful once an exception is approved and in effect |
| `Exploitability` | `Exploitability` | Maturity of exploitation |
| `Reachable` | `*bool` | Whether the vulnerable code is reachable in this application's configuration |
| `Controls` | `[]Control` | Compensating controls — see [Control](#control-and-exception) |
| `Exception` | `*Exception` | Risk-exception approval state |
| `Component` | `string` | Affected module or dependency |
| `Location` | `*findingspec.Location` | Where it was observed — see [Location](../reference/location.md) |
| `References` | `[]findingspec.Reference` | External links |
| `Remediation` | `*findingspec.Remediation` | How to fix |
| `Status` | `findingspec.Status` | Lifecycle state |
| `Tags` | `[]string` | Free-form labels |
| `DetectedAt` | `*time.Time` | When observed |

### The residual-risk model

`Severity` is the **inherent** severity of the weakness. `ResidualSeverity` is
the severity that **remains** after verified compensating controls, and is only
meaningful once an `Exception` is approved and in effect. A control therefore
lowers residual risk without changing how the underlying vulnerability is graded.

`EffectiveSeverity(t)` returns the severity in effect as of `t`: the residual
severity while an exception is approved and unexpired (and a residual severity is
set), otherwise the inherent severity.

```go
func (v Vulnerability) EffectiveSeverity(t time.Time) findingspec.Severity
```

The `Exception` SLA policy follows from this: the remediation clock runs on
inherent severity until an exception is approved, after which it runs on residual
severity while the approval is in effect.

### Exploitability

`Exploitability` describes the maturity of exploitation:

| Constant | Value | Meaning |
|----------|-------|---------|
| `ExploitabilityNone` | `none` | No known exploit |
| `ExploitabilityPOC` | `poc` | Proof-of-concept exists |
| `ExploitabilityFunctional` | `functional` | Functional exploit available |
| `ExploitabilityActive` | `active` | Observed exploitation in the wild |

### Example

```go
now := time.Now()
expires := now.AddDate(0, 3, 0)
v := security.Vulnerability{
    ID:          "V-1024",
    Title:       "Deserialization of untrusted data in acme-parser",
    Description: "Untrusted input reaches an unsafe deserializer.",
    CVEs:        []string{"CVE-2025-1234"},
    CWEs:        []string{"CWE-502"},
    CVSS:        &security.CVSS{Version: "3.1", Vector: "CVSS:3.1/AV:N/...", Score: 9.8},
    Severity:    findingspec.SeverityCritical,

    // After a verified WAF rule blocks the vector, residual risk drops.
    ResidualSeverity: findingspec.SeverityMedium,
    Exploitability:   security.ExploitabilityActive,
    Controls: []security.Control{{
        ID:            "CTRL-WAF-17",
        Name:          "WAF rule blocking serialized payloads",
        Function:      security.ControlFunctionPreventive,
        Reduces:       []string{security.ReducesLikelihood},
        Effectiveness: "high",
        Verified:      true,
    }},
    Exception: &security.Exception{
        Status:     security.ExceptionStatusApproved,
        ApprovedAt: &now,
        ExpiresAt:  &expires,
    },
    Component:  "acme-parser@1.4.2",
    DetectedAt: &now,
}

v.EffectiveSeverity(now) // "medium" — residual, while the exception is in effect

f := v.ToFinding() // Domain=security, Severity=critical (inherent), RuleID="CWE-502"
```

`ToFinding()` projects the vulnerability into a domain-neutral
`findingspec.Finding` in the security domain. The finding's `Severity` is the
**inherent** severity; residual detail is preserved on the `Vulnerability`. When
`Severity` is unset but a `CVSS` is present, the finding's severity is derived
from `CVSS.Severity()`. `RuleID` is derived from the most specific classifier
available — the first CWE, else the first CVE.

## Analysis, verification, and disclosure

A `Vulnerability` can carry the analysis that turns a report into an actionable
record. These fields live in `Detail`, except `Verification` and
`Relationships`, which belong to the core `Finding`.

| Field | Type | Notes |
|-------|------|-------|
| `RootCause` | `*RootCause` | Why the weakness exists: summary, components, missing control, trust boundary |
| `Impact` | `*Impact` | Technical and product consequence, and the surfaces affected |
| `Exploit` | `*Exploit` | Preconditions, scenario, and reproduction. Sensitive: keep in private stores |
| `Publication` | `*Publication` | Disclosure lifecycle: visibility, state, affected version ranges, GHSA, CVE, OSV, and Go vulnerability IDs |
| `Verification` | `*findingspec.Verification` | How the fix was proven: result, method, and the checks that pass |
| `Relationships` | `[]findingspec.Relationship` | Typed links to threats, controls, requirements, work items, fixes, and tests |

Relationship targets are opaque references (a roadmap item ID, a commit hash, a
URI). findingspec does not resolve them, which keeps the core independent of the
systems it links to.

### Private by default

Findings that describe exploitable weaknesses, especially in releases users may
still run, belong in a private store. `Publication.Visibility` records whether a
sanitized public projection is permitted. Generate a public advisory from the
private record through an explicit review; do not redact the private record in
place, and do not commit the original and sanitize it later.

## Package vulnerabilities (SCA & container)

For dependency (SCA) and container scans, `Vulnerability` carries three extra
fields that describe the affected package and where it lives. These are the
canonical shape that Grype, Trivy, and AWS Inspector all normalize into.

| Type | Fields |
|------|--------|
| `Package` | `Name`, `Version`, `Ecosystem` (npm/pypi/deb/apk/…), `PURL`, `Path`, `Arch` |
| `Fix` | `State` (`FixStateFixed`/`NotFixed`/`WontFix`/`Unknown`), `Versions` |
| `Artifact` | `Image`, `ImageDigest`, `OS`, `Layer` |

Set `Vulnerability.Type` to `TypeSCA` for a plain dependency scan or
`TypeContainer` when an image is present (a non-empty `Artifact.Image`). The
`security.SeverityOrCVSS(label, cvssScore)` helper maps a scanner's severity
label (including below-Low labels like Grype's `Negligible` or Inspector's
`Untriaged`) to the canonical severity, falling back to the CVSS score.

```go
v := security.Vulnerability{
    ID:       "CVE-2024-1234:openssl@1.1.1k",
    Title:    "CVE-2024-1234 in openssl",
    Type:     security.TypeContainer,
    CVEs:     []string{"CVE-2024-1234"},
    CVSS:     &security.CVSS{Version: "3.1", Score: 7.5},
    Severity: security.SeverityOrCVSS("High", 7.5),
    Package:  &security.Package{Name: "openssl", Version: "1.1.1k", Ecosystem: "apk"},
    Fix:      &security.Fix{State: security.FixStateFixed, Versions: []string{"1.1.1w"}},
    Artifact: &security.Artifact{Image: "alpine:3.19", OS: "alpine 3.19"},
}
f := v.ToFinding() // Domain=security, Type=container; Package/Fix/Artifact on Detail
```

See [Interchange & Adapters](../concepts/interchange.md) for the Grype, Trivy, and
Inspector converters that produce this shape.

### Reachability

`Vulnerability` carries two reachability signals — a primary prioritization input
(a reachable vulnerability is exploitable; an unreachable one is usually noise):

- **`Reachable *bool`** — the coarse yes/no some scanners report.
- **`Reachability *Reachability`** — the detailed, call-graph form: `State`
  (`reachable` / `unreachable` / `unknown`), the vulnerable `Symbol`, and example
  call `Paths`. Use `Reachability.IsReachable()` for a quick check.

Analyzers that do call-graph analysis populate the detailed form — the
[govulncheck adapter](../concepts/interchange.md#govulncheck-go-sca-with-reachability)
sets `State=reachable` with the symbol and call path when the vulnerable function
is actually called, and `State=unreachable` when the package is only imported.

## CVSS

`CVSS` holds a Common Vulnerability Scoring System result.

| Field | Type | Notes |
|-------|------|-------|
| `Version` | `string` | CVSS version, e.g. `"3.1"` or `"4.0"` |
| `Vector` | `string` | CVSS vector string |
| `Score` | `float64` | Numeric base score, `0.0`–`10.0` |

```go
func (c CVSS) Severity() findingspec.Severity
```

`Severity()` maps the score to the canonical severity scale, delegating to
[`findingspec.SeverityFromCVSS`](../concepts/severity.md) using the standard CVSS
v3.x / v4.0 bands (Critical ≥9.0, High ≥7.0, Medium ≥4.0, Low ≥0.1,
Informational 0.0). Scores outside `0.0`–`10.0` map to Informational.

```go
c := security.CVSS{Version: "3.1", Score: 7.5}
c.Severity() // "high"
```

CVSS v2 used a different, coarser scale; when scoring v2 vectors, map severity
explicitly rather than relying on this method.

## Control and Exception

`Control` is a compensating control that reduces the residual risk of a
vulnerability. It links the control to the risk dimensions it reduces and,
optionally, the CVSS environmental metrics it justifies.

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `string` | Stable identifier |
| `Name` | `string` | Short name |
| `Description` | `string` | Longer explanation |
| `Function` | `string` | `preventive`, `detective`, or `corrective` |
| `Reduces` | `[]string` | Risk dimensions mitigated: `likelihood`, `impact` |
| `ModifiedMetrics` | `[]string` | CVSS environmental metrics justified, e.g. `"MAV:A"` |
| `Effectiveness` | `string` | Coarse rating: `high`, `medium`, `low` |
| `Verified` | `bool` | Whether the control has been verified |
| `VerifiedMethod` | `string` | How it was verified |
| `LastVerifiedAt` | `*time.Time` | When last verified |
| `Owner` | `string` | Accountable owner |

Control constants:

| Constant | Value |
|----------|-------|
| `ControlFunctionPreventive` | `preventive` |
| `ControlFunctionDetective` | `detective` |
| `ControlFunctionCorrective` | `corrective` |
| `ReducesLikelihood` | `likelihood` |
| `ReducesImpact` | `impact` |

`Exception` records the approval state of a risk exception for a vulnerability.

| Field | Type | Notes |
|-------|------|-------|
| `Status` | `string` | `requested`, `approved`, `rejected`, or `expired` |
| `ApprovedAt` | `*time.Time` | When approved |
| `ApprovedBy` | `string` | Approver |
| `ExpiresAt` | `*time.Time` | When the approval expires |
| `Reference` | `string` | Ticket or record reference |
| `URL` | `string` | Link to the record |

Exception status constants:

| Constant | Value |
|----------|-------|
| `ExceptionStatusRequested` | `requested` |
| `ExceptionStatusApproved` | `approved` |
| `ExceptionStatusRejected` | `rejected` |
| `ExceptionStatusExpired` | `expired` |

```go
func (ex *Exception) IsApprovedAt(t time.Time) bool
```

`IsApprovedAt(t)` reports whether the exception is approved and unexpired as of
`t`. A `nil` receiver reports `false`. This is the gate `EffectiveSeverity` uses
to decide whether residual severity applies.

## Secret

`Secret` is a security finding for a detected credential or secret — for example
an API key, token, password, or private key discovered in source, a config file,
or a structured document such as an OpenAPI spec or Postman collection.

The raw secret value is **never stored** — only a redacted preview in `Redacted`.

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `string` | Stable identifier |
| `Title` | `string` | Short human-readable summary |
| `Description` | `string` | Detailed explanation |
| `Kind` | `SecretKind` | Category of secret |
| `Detector` | `string` | Rule or detector that matched, e.g. `"aws-access-key-id"` |
| `Provider` | `string` | Service the secret belongs to, e.g. `"aws"`, `"stripe"`, `"github"` |
| `Redacted` | `string` | Masked preview, e.g. `"AKIA****…****1234"`. The raw value must not be stored |
| `Entropy` | `float64` | Shannon entropy of the match, when computed |
| `Validation` | `SecretValidation` | Whether the secret was confirmed live |
| `Severity` | `findingspec.Severity` | Impact; defaults to High when unset |
| `Location` | `*findingspec.Location` | Where it was found — see [Location](../reference/location.md) |
| `Remediation` | `*findingspec.Remediation` | How to fix |
| `Status` | `findingspec.Status` | Lifecycle state |
| `DetectedAt` | `*time.Time` | When observed |

`SecretKind` categorizes the secret:

| Constant | Value |
|----------|-------|
| `SecretKindAPIKey` | `api_key` |
| `SecretKindToken` | `token` |
| `SecretKindPassword` | `password` |
| `SecretKindPrivateKey` | `private_key` |
| `SecretKindCertificate` | `certificate` |
| `SecretKindConnectionString` | `connection_string` |
| `SecretKindGeneric` | `generic` |

`SecretValidation` records whether a detected secret was verified against its
provider, when a detector supports validation:

| Constant | Value |
|----------|-------|
| `SecretValidationUnknown` | `unknown` |
| `SecretValidationActive` | `active` |
| `SecretValidationInactive` | `inactive` |

### Locating a secret in a structured document

For a structured document, the exact location is carried on
[`Location`](../reference/location.md) rather than by line and column:

- `Location.File` — the document path
- `Location.DocFormat` — the format, e.g. `"openapi"` or `"postman"`
- `Location.Pointer` — an RFC 6901 JSON Pointer to the offending node

A JSON Pointer is a stable, format-independent locator preferable to line/column
for JSON and YAML documents.

### ToFinding and the redacted snippet

`ToFinding()` projects the secret into a domain-neutral `findingspec.Finding` in
the security domain. `Severity` defaults to `SeverityHigh` when unset, since an
exposed live credential is typically high-impact. `RuleID` is derived from the
most specific classifier — the `Detector`, else the `Kind`.

The finding never carries the raw secret. `ToFinding()` copies `Redacted` into
the finding's `Location.Snippet` (via a **non-mutating copy** of `Location`, only
when `Location` is set and does not already carry a snippet), so a consumer that
only inspects the generic `Finding` still sees the redacted preview. The caller's
original `Location` is left untouched.

### Example: secret in an OpenAPI server variable

```go
s := security.Secret{
    ID:         "SEC-1",
    Title:      "Hard-coded API key in OpenAPI server variable",
    Kind:       security.SecretKindAPIKey,
    Detector:   "generic-api-key",
    Provider:   "acme",
    Redacted:   "sk_live_****…****9f2a",
    Validation: security.SecretValidationActive,
    Location: &findingspec.Location{
        File:      "openapi.yaml",
        DocFormat: "openapi",
        Pointer:   "/servers/0/variables/apiKey/default",
    },
}

f := s.ToFinding() // Severity=high, RuleID="generic-api-key"
f.Location.Snippet // "sk_live_****…****9f2a" — copied from Redacted
```

### Example: secret in a Postman request header

```go
s := security.Secret{
    ID:       "SEC-2",
    Title:    "Bearer token committed in Postman collection",
    Kind:     security.SecretKindToken,
    Detector: "bearer-token",
    Redacted: "Bearer ****…****c1d2",
    Location: &findingspec.Location{
        File:      "collection.postman_collection.json",
        DocFormat: "postman",
        Pointer:   "/item/2/request/header/1/value",
    },
}

f := s.ToFinding() // Severity defaults to high
```

## Related

- [Finding Model](../concepts/finding-model.md) — the canonical, domain-neutral `Finding` these types project into
- [Severity](../concepts/severity.md) — the shared severity scale and CVSS mapping
- [Location](../reference/location.md) — the location fields, including `Pointer` and `DocFormat`
