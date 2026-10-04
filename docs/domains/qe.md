# Quality Engineering (qe)

The `qe` package defines semantic types for quality-engineering findings — failed
end-to-end tests and broken user journeys — and projects them into the
domain-neutral [`Finding`](../concepts/finding-model.md).

## Failure

`Failure` is a quality-engineering finding: a test assertion or user-journey step
that did not behave as expected.

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `string` | Stable identifier |
| `Title` | `string` | Short human-readable summary |
| `Description` | `string` | Detailed explanation |
| `Journey` | `string` | Identifier of the user journey under test, if any |
| `Step` | `string` | Failing step within the test or journey |
| `Expected` | `string` | Expected value of the assertion |
| `Actual` | `string` | Actual value observed |
| `Severity` | `findingspec.Severity` | Impact; defaults to `High` when unset |
| `Location` | `*findingspec.Location` | Where it was observed — see [Location](../reference/location.md) |
| `Evidence` | `[]findingspec.Evidence` | Supporting artifacts |
| `Remediation` | `*findingspec.Remediation` | How to fix, incl. an `AgentPrompt` |
| `Status` | `findingspec.Status` | Lifecycle state |
| `DetectedAt` | `*time.Time` | When observed |

## Projection to Finding

`ToFinding()` projects the failure into a domain-neutral `findingspec.Finding` in
the `qe` domain:

- sets `Domain` to `findingspec.DomainQE`;
- derives `RuleID` from the journey and step — `journey/step` when both are
  present, otherwise whichever is set;
- defaults `Severity` to `findingspec.SeverityHigh` when unset (a broken journey
  typically blocks users), on the [shared severity scale](../concepts/severity.md);
- adds a `journey:<journey>` tag for a non-empty `Journey`.

```go
failure := qe.Failure{
    ID:       "qe-001",
    Title:    "Checkout fails at payment step",
    Journey:  "checkout",
    Step:     "submit-payment",
    Expected: "order confirmation page",
    Actual:   "HTTP 500",
    Location: &findingspec.Location{
        URL: "https://example.com/checkout/payment",
    },
}

f := failure.ToFinding()
f.Domain   // "qe"
f.RuleID   // "checkout/submit-payment"
f.Severity // "high"  (defaulted)
f.Tags     // ["journey:checkout"]
```

## See also

- [Finding model](../concepts/finding-model.md)
- [Severity](../concepts/severity.md)
- [Location](../reference/location.md)
