# findingspec — Roadmap

Themed phases group related roadmap items (RMIs). Phase status is derived from
member RMI statuses. RMI IDs are stable (`RMI-FINDINGSPEC-<NNN>`).

## Phase 1 — Core model

- **RMI-FINDINGSPEC-001** — Canonical `Finding` and shared vocabulary
  (Severity, Status, Confidence, Source, Location, Evidence, Remediation,
  Reference, Domain). *Status: done.*
- **RMI-FINDINGSPEC-002** — `FindingSet` with filtering, counting, and severity
  ordering. *Status: done.*
- **RMI-FINDINGSPEC-003** — Domain projection contract (`ToFinding`) and the
  four domain packages (security, a11y, i18n, qe). *Status: done.*

## Phase 2 — Schema and interchange

- **RMI-FINDINGSPEC-004** — Go-first JSON Schema generation from the core and
  domain types, embedded via `//go:embed`, linted with `schemakit`.
- **RMI-FINDINGSPEC-005** — Round-trip JSON marshal/unmarshal tests and schema
  conformance tests. *(partly done: FindingSet, Detail, and Summary round-trip.)*
- **RMI-FINDINGSPEC-006** — Two-level `Domain` + `Type` taxonomy and a typed
  per-type `Detail` subsection (`SetDetail` / `DetailAs[T]`). *Status: done.*
- **RMI-FINDINGSPEC-013** — Ingest adapters. Done: gitleaks (secrets, in-repo
  `adapters/gitleaks`), axe-core (a11y, in-repo `adapters/axe`), Grype and Trivy
  (SCA/container, in `gogrype`/`gotrivy`), AWS Inspector (container/runtime, in
  `awsgo/inspector2util`). Prioritize open-source / freemium scanners; see the
  planned list below (RMI-016–020).
- **RMI-FINDINGSPEC-016** — SARIF ingest → mostly `security/sast`. One adapter
  unlocks many OSS scanners that emit SARIF (Semgrep, CodeQL, gosec, Bandit,
  Trivy SARIF mode, …); map runs/results/rules/locations, incl. code flows.
  Highest-leverage single adapter. *(OSS)*
- **RMI-FINDINGSPEC-017** — OWASP ZAP ingest → `security/dast`; map alerts
  (risk/confidence, CWE/WASC, URL/param/evidence, request/response). *(OSS)*
- **RMI-FINDINGSPEC-018** — Extend the Trivy adapter (`gotrivy`) beyond vulns to
  its `Misconfigurations` → `security/iac`, `Secrets` → `security/secret`, and
  optionally `Licenses`. *(OSS)*
- **RMI-FINDINGSPEC-019** — govulncheck ingest → `security/sca`, in-repo
  `adapters/govulncheck`. Parses the `govulncheck -json` stream (OSV + findings);
  derives call-graph **reachability** into `security.Reachability` (state +
  vulnerable symbol + example call paths) — a differentiator few scanners
  provide. *Status: done.* Follow-up: a CVSS vector→score calculator so OSV
  entries that carry only a CVSS vector get a numeric severity.
- **RMI-FINDINGSPEC-020** — golangci-lint ingest. Parse `golangci-lint run
  --output.json.path` output and **route by linter**: security linters (gosec,
  and gitleaks via its linter) → `security/sast`/`security/secret`; everything
  else (staticcheck, govet, revive, gofmt, ineffassign, …) → a new
  **`code-quality`** domain with a `lint` type (`Type` = the linter name). The
  decision: code-quality lint is neither security nor QE-test-failure, so it gets
  its own domain rather than overloading `qe`. Adds `DomainCodeQuality` when built.
- Further ingest: OSCAL (compliance), OTel/Datadog (observability).
- **RMI-FINDINGSPEC-015** — Canonical container/SCA model: `security.Package`,
  `Fix`/`FixState`, `Artifact` on `Vulnerability`/`VulnerabilityDetail`, and the
  `SeverityOrCVSS` scanner-severity normalizer. *Status: done.*
- **RMI-FINDINGSPEC-014** — Export adapters: SARIF, OCSF, AWS ASFF, VEX,
  DefectDojo import, and POA&M.

## Phase 3 — Security depth

- **RMI-FINDINGSPEC-007** — Port remaining govex security concepts worth keeping
  (SLA policy on effective severity, risk ratings/matrices) into the security
  domain, cleanly re-expressed.
- **RMI-FINDINGSPEC-008** — CWE/CVE/CVSS helper coverage and validation.
- **RMI-FINDINGSPEC-009** — Deduplication and correlation across producers within
  a domain.

## Phase 4 — Consumption

- **RMI-FINDINGSPEC-010** — Prioritization helpers combining severity,
  confidence, reachability, and exploitability.
- **RMI-FINDINGSPEC-011** — Remediation `AgentPrompt` conventions for AI builders.
- **RMI-FINDINGSPEC-012** — Reference consumer example aggregating multi-domain
  findings into a single prioritized view.
