# Interchange & Adapters

findingspec is designed to be the **neutral normalization hub** for findings:
many tools produce findings in their own formats, findingspec gives them one
canonical representation, and consumers (dashboards, prioritization, ticketing,
export) read that single shape.

```
   producers                      findingspec IR                 consumers
 ┌───────────────┐            ┌──────────────────┐          ┌────────────────┐
 gitleaks, SARIF,  ── ingest ─▶  FindingSet         ── export ▶ SARIF, OCSF,
 Trivy/Grype,       adapters   {findings:[Finding]}  adapters   ASFF, VEX,
 ZAP, AWS Inspector,           header + typed Detail            DefectDojo, POA&M
 axe, OSCAL, OTel  ◀──────────  Summary() analytics  ──────────▶ dashboards
 └───────────────┘            └──────────────────┘          └────────────────┘
```

## Why a new model

Application Security Posture Management tools (Ox, Aikido, DefectDojo, …) all
normalize scanner output internally, but there is **no open, cross-domain
standard** to do it. The existing open formats are each siloed:

- **SARIF** — static analysis (SAST)
- **OCSF / AWS ASFF** — security events/findings
- **OSCAL** — compliance controls
- **VEX** — vulnerability exchange

findingspec spans all of these *and* extends past security into accessibility,
i18n, quality engineering, and observability — with a shared header for the
single-pane view and a typed `Detail` subsection for per-area depth. Those
formats become **import/export adapters**, not the canonical object.

## Ingest adapters

An ingest adapter converts a tool's native output into `findingspec.Finding`s,
typically by building a domain type (e.g. `security.Secret`) and calling
`ToFinding()`. Adapters live under `adapters/<tool>` and depend only on the
tool's stable output shape, keeping the core lean.

### gitleaks (reference adapter)

`adapters/gitleaks` ingests a gitleaks JSON report (secret scanning):

```go
import "github.com/plexusone/findingspec/adapters/gitleaks"

set, err := gitleaks.Parse(reportReader, gitleaks.Options{Repo: "acme/app"})
// set is a *findingspec.FindingSet of security/secret findings
```

Each gitleaks finding becomes a `security.Secret` → `Finding` with
`Domain=security`, `Type=secret`, `Source.Tool="gitleaks"`, provider and kind
inferred from the rule ID, the file/line/repo on `Location`, and the secret
**redacted** (first/last four preserved — the raw value is never stored). The
per-secret detail is available via `DetailAs[security.SecretDetail]`.

### Container & SCA scans — one shape from Grype, Trivy, and AWS Inspector

Dependency (SCA) and container scanners all describe the same thing — a
vulnerability in a package inside an image — so they normalize into a single
canonical shape: a `security.Vulnerability` (→ `Finding` with
`Type` = `sca` or `container`) whose `Detail` carries `Package`, `Fix`, and
`Artifact`:

| Field | Meaning |
|-------|---------|
| `security.Package` | name, version, ecosystem, PURL, path, arch |
| `security.Fix` | state (`fixed`/`not-fixed`/`wont-fix`/`unknown`) + fixing versions |
| `security.Artifact` | image, image digest, OS, layer |

Three converters live in their own tool libraries (which already model each
scanner's native format) and import findingspec:

- **Grype** — `github.com/grokify/gogrype`: `GrypeOutputJSON.Findings(opts)`
- **Trivy** — `github.com/grokify/gotrivy`: `Report.Findings(opts)`
- **AWS Inspector** — `github.com/grokify/awsgo/inspector2util`:
  `Findings.Findings(opts)` (emits one finding per vulnerable package)

Each maps its own severity vocabulary through `security.SeverityOrCVSS` (so
Grype's `Negligible` and Inspector's `Untriaged` land at `informational`), picks a
primary CVSS from that tool's shape, sets `Source.Tool`, and preserves the native
vuln ID (CVE/GHSA/ALAS) as `RuleID`. A consumer then reads any of them uniformly
via `DetailAs[security.VulnerabilityDetail]` — the same code path regardless of
which scanner produced the finding.

This placement follows a simple rule: when a Go library already models a tool's
format (gogrype, gotrivy, inspector2util, pubguard), the conversion lives there
and imports findingspec; for tools without one (gitleaks, axe-core), findingspec
ships a lightweight `adapters/<tool>` package.

### axe-core (accessibility)

`adapters/axe` ingests axe-core JSON results (`axe.run()` output, as emitted by
`@axe-core/cli`, Playwright/axe, and CI reporters):

```go
import "github.com/plexusone/findingspec/adapters/axe"

set, err := axe.Parse(reportReader, axe.Options{IncludeIncomplete: false})
// set is a *findingspec.FindingSet of a11y/wcag findings, one per matched element
```

Each violation node becomes an `a11y.Issue` → `Finding` with `Domain=a11y`,
`Type=wcag`, `Source.Tool="axe-core"`: axe `impact` maps 1:1 to the a11y impact
scale (→ severity), the WCAG criterion and level are parsed from the `wcag…` tags
(`wcag143`→`1.4.3`, `wcag2aa`→`AA`), the node `target` becomes
`Location.Selector` (nested frame targets flattened) and `html` the snippet, and
the `failureSummary` becomes the remediation. `Options.IncludeIncomplete` also
ingests axe's needs-review results at low confidence.

### govulncheck (Go SCA, with reachability)

`adapters/govulncheck` ingests the `govulncheck -json` stream for Go dependency
vulnerabilities:

```go
import "github.com/plexusone/findingspec/adapters/govulncheck"

set, err := govulncheck.Parse(streamReader, govulncheck.Options{})
// set is a *findingspec.FindingSet of security/sca findings
```

Its distinguishing value is **reachability**. govulncheck does call-graph
analysis, so the adapter populates `security.Reachability` — `state`
(`reachable` when the vulnerable symbol is actually called, `unreachable` when the
package is only imported/required, else `unknown`), the vulnerable `symbol`, and
example call `paths`. Reachability is one of the strongest prioritization signals
an ASPM layer can offer: a reachable vulnerability is exploitable; an unreachable
one is usually noise. Consumers can filter on it via
`DetailAs[security.VulnerabilityDetail](f).Reachability`.

```go
d, _ := findingspec.DetailAs[security.VulnerabilityDetail](f)
if d.Reachability.IsReachable() {
    // prioritize: the vulnerable symbol is on a live call path
}
```

Note: many Go OSV entries carry a CVSS vector but no numeric score, so severity
can fall back to Informational — reachability is the primary signal here until a
CVSS vector→score calculator lands (see roadmap).

## Export adapters (planned)

The same IR projects outward — SARIF, OCSF, AWS ASFF, VEX, DefectDojo import, and
POA&M — so findingspec interoperates with existing pipelines rather than
replacing them. See the [roadmap](../specs/ROADMAP.md).

## Relationship to assessments

An ingest run is one **assessment** that produces zero or more findings.
findingspec models the findings; the higher-level assessment artifact (the audit
or scan run, its target, config, and status) is the sibling **assessmentspec**.
A failed compliance control or a breached SLO is a `Finding`
(`domain=compliance` / `domain=observability`) that rolls up under an assessment.
