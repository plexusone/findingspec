# Evidence & Remediation

These supporting types hang off a [Finding](../concepts/finding-model.md) to
explain what was observed, how to fix it, and how sure the producer is. They are
domain-neutral: every domain populates the same shapes.

## Evidence

`Evidence` is a supporting artifact that substantiates a finding — a screenshot,
an HTTP response, a stack trace, or a code excerpt. A `Finding` carries a
`[]Evidence`.

| Field | Type | Notes |
|-------|------|-------|
| `Kind` | `string` | Category, e.g. `"screenshot"`, `"html"`, `"log"`, `"trace"`, `"http-response"`, `"code"` |
| `Summary` | `string` | Short human-readable description |
| `Data` | `string` | Inline content; binary content should be base64 |
| `URI` | `string` | Points to externally-stored evidence when not inlined |
| `MediaType` | `string` | IANA media type of `Data` or the `URI` target, if known |

## Remediation

`Remediation` describes how to resolve a finding. Beyond the human-readable
`Summary` and `Detail`, it carries an `AgentPrompt` — the **"fix with an AI
builder" hook**: an instruction phrased for an AI code builder so the fix can be
applied directly, without a human first translating the finding into a task.

| Field | Type | Notes |
|-------|------|-------|
| `Summary` | `string` | Concise statement of the fix |
| `Detail` | `string` | Optional longer explanation |
| `AgentPrompt` | `string` | Instruction suitable for handing to an AI code builder |
| `Effort` | `string` | Coarse estimate, e.g. `"low"`, `"medium"`, `"high"` |
| `References` | `[]Reference` | External links supporting the remediation |

```go
rem := findingspec.Remediation{
    Summary:     "Move the API key out of the OpenAPI default and into a secret.",
    Detail:      "The server variable's default embeds a live credential that ships to every client.",
    AgentPrompt: "Remove the hardcoded default from servers[0].variables.apiKey and read it from an environment variable at request time, without changing application behavior.",
    Effort:      "low",
    References: []findingspec.Reference{
        {Title: "OpenAPI server variables", URL: "https://spec.openapis.org/oas/latest.html#server-variable-object"},
    },
}
```

## Reference

`Reference` is an external link supporting a finding or its remediation, such as
an advisory, standard, or documentation page.

| Field | Type | Notes |
|-------|------|-------|
| `Title` | `string` | Optional link text |
| `URL` | `string` | The link target |

## Source

`Source` identifies the tool or producer that generated a finding.

| Field | Type | Notes |
|-------|------|-------|
| `Tool` | `string` | Producer name, e.g. `"govex"`, `"agent-a11y"`, `"w3pilot"` |
| `Version` | `string` | Producer version, if known |
| `RuleSet` | `string` | Rule catalog or standard applied, e.g. `"WCAG-2.2"`, `"CWE"`, `"OWASP-ASVS"` |

## Confidence

`Confidence` expresses how certain a producer is that a finding is a true
positive. It is distinct from severity, which measures impact.

| Constant | Value |
|----------|-------|
| `ConfidenceHigh` | `high` |
| `ConfidenceMedium` | `medium` |
| `ConfidenceLow` | `low` |

`Valid()` reports whether a value is one of the three known levels:

```go
findingspec.ConfidenceHigh.Valid() // true
findingspec.Confidence("guess").Valid() // false
```

## Status

`Status` is the lifecycle state of a finding.

| Constant | Value | Still needs attention? |
|----------|-------|------------------------|
| `StatusOpen` | `open` | yes |
| `StatusConfirmed` | `confirmed` | yes |
| `StatusRemediated` | `remediated` | no |
| `StatusAccepted` | `accepted` | no |
| `StatusFalsePositive` | `false_positive` | no |
| `StatusResolved` | `resolved` | no |

`Statuses()` returns all known statuses in a stable order. `Valid()` reports
whether a value is known, and `Open()` reports whether the finding still
requires attention (only `open` and `confirmed` are open):

```go
findingspec.StatusConfirmed.Valid() // true
findingspec.StatusConfirmed.Open()  // true
findingspec.StatusResolved.Open()   // false
```

`FindingSet.Open()` uses `Status.Open()` to filter a set down to the findings
that still need work.

## See also

- [Finding model](../concepts/finding-model.md) — how these types compose into a `Finding`
