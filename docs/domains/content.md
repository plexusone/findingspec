# Content

The `content` package defines semantic types for content findings — problems with the accuracy and attribution of
published content — and projects them into the domain-neutral [`Finding`](../concepts/finding-model.md). A claim
checker produces them: a static scan of claims and their sources, then models and people confirming or dismissing
each finding.

## Issue

`Issue` is a problem with one claim, or with one of the sources it cites.

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `string` | Stable identifier |
| `Rule` | `string` | Rule that raised it, such as `content.quote.notFound` |
| `Title` | `string` | Short human-readable summary |
| `Description` | `string` | Detailed explanation |
| `ClaimID` | `string` | The claim the issue is about |
| `Statement` | `string` | The claim's text |
| `SourceRef` | `string` | The cited source the issue is about, if any |
| `Document` | `string` | The file that holds the claim |
| `Severity` | `findingspec.Severity` | Impact; defaults to `Medium` when unset |
| `Confidence` | `findingspec.Confidence` | How sure the producer is |
| `Evidence` | `[]findingspec.Evidence` | Supporting artifacts |
| `Remediation` | `*findingspec.Remediation` | How to fix, incl. an `AgentPrompt` |
| `Status` | `findingspec.Status` | Lifecycle state |
| `DetectedAt` | `*time.Time` | When found |

## Rules

Common rule IDs; scanners may add their own.

| Rule | Problem |
|------|---------|
| `content.evidence.none` | The claim cites no source |
| `content.source.unknown` | The claim cites a source not in the source list |
| `content.source.unreliable` | The source is a forum, fan site, social media post, AI answer or similar |
| `content.source.unrated` | The source's reliability could not be decided |
| `content.source.unreachable` | The source's text could not be retrieved, so its quotations were not checked |
| `content.quote.missing` | A supporting citation gives no quotation |
| `content.quote.notFound` | The quotation does not appear in the source's text |
| `content.quote.translationMissing` | A quotation in another language has no translation |
| `content.facts.missing` | A date, figure or name in the claim is in no supporting quotation |
| `content.claim.singleSource` | A claim stating dates, figures or quotations rests on one source |
| `content.claim.notAtomic` | The claim states several facts |
| `content.claim.verdict` | A judge found the claim not supported as written |

### Quotations from Recordings

A quotation from a podcast, interview or talk is checked by cutting a clip of the recording around it and comparing
what several speech-to-text engines heard. `content.quote.notFound` applies when the quotation can't be located in
the recording; three more rules cover what the comparison can't settle.

| Rule | Problem |
|------|---------|
| `content.quote.audioDisputed` | The engines disagree on a substantive word: a number, a negation, a name or a term |
| `content.quote.audioMismatch` | The engines agree with each other but not with the quotation; the finding gives what they heard |
| `content.quote.audioUnchecked` | Too few engines produced a transcript, or the clip could not be cut |

Put what each engine heard, and the clip's start and end, in the finding's `Evidence`, so a reviewer can listen to
the same seconds.

## Projection to Finding

`ToFinding()` projects the issue into a `findingspec.Finding` in the `content` domain:

- sets `Domain` to `findingspec.DomainContent`, `Type` to `claim` and `RuleID` to `Rule`;
- uses the claim as the location: `Location.Component` is the claim ID, `Location.File` the document and
  `Location.Snippet` the statement;
- defaults `Severity` to `findingspec.SeverityMedium`;
- adds `claim:<id>` and `source:<ref>` tags.

`content.ClaimID(f)` returns the claim a content finding is about. It returns `""` for findings of another type,
such as narration; content findings with no type are read as claim findings.

## Narration

`NarrationIssue` is a recording, or one segment of it, that doesn't say its script, such as a course lesson's
voice-over.

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `string` | Stable identifier |
| `Rule` | `string` | `content.narration.mismatch` |
| `Title` | `string` | Short human-readable summary |
| `Description` | `string` | Detailed explanation |
| `Document` | `string` | The file that holds the script, such as a slide deck |
| `Segment` | `string` | The part of the script, such as a slide's ID |
| `Expected` | `string` | The script's wording |
| `Heard` | `string` | What the engines heard, when they agree |
| `Recording` | `string` | The audio file checked |
| `Severity`, `Confidence`, `Evidence`, `Remediation`, `Status`, `DetectedAt` | | As for `Issue` |

| Rule | Problem |
|------|---------|
| `content.narration.mismatch` | Words are dropped, added or misheard by every engine |

`ToFinding()` sets `Type` to `narration` and uses the segment as the location: `Location.Component` is the segment
ID, `Location.File` the document and `Location.Snippet` the expected wording. `Heard`, when set, becomes a `transcript`
evidence entry after the issue's own evidence. It adds `segment:<id>` and `recording:<file>` tags. `content.Segment(f)` returns the segment a narration finding is about.

## Status Through a Review Funnel

The shared status lifecycle follows a finding through the stages of a review: a static scan opens it (`open`), a
model or person confirms it (`confirmed`) or dismisses it (`false_positive`), the claim or its citation is fixed
(`resolved`), or a person accepts it as it is (`accepted`), for example a single source judged sufficient.
