// Package content defines semantic types for content findings — problems with
// the accuracy and attribution of published content, such as a claim its
// cited source does not support or a quotation that cannot be found in its
// source — and projects them into the domain-neutral findingspec.Finding.
package content

import (
	"time"

	"github.com/plexusone/findingspec"
)

// Common rule IDs for problems with a claim and its sources. Scanners may
// define their own; these name the problems most claim checks share.
const (
	// RuleNoEvidence: the claim cites no source.
	RuleNoEvidence = "content.evidence.none"
	// RuleSourceUnknown: the claim cites a source that is not in the
	// source list.
	RuleSourceUnknown = "content.source.unknown"
	// RuleSourceUnreliable: the source is of a kind not accepted as
	// reliable, such as a forum, fan site, social media post or AI answer.
	RuleSourceUnreliable = "content.source.unreliable"
	// RuleSourceUnrated: the source's reliability could not be decided.
	RuleSourceUnrated = "content.source.unrated"
	// RuleSourceUnreachable: the source's text could not be retrieved, so
	// its quotations could not be checked.
	RuleSourceUnreachable = "content.source.unreachable"
	// RuleQuoteMissing: a supporting citation gives no quotation.
	RuleQuoteMissing = "content.quote.missing"
	// RuleQuoteNotFound: the quotation does not appear in the source's text.
	RuleQuoteNotFound = "content.quote.notFound"
	// RuleTranslationMissing: a quotation not in the reader's language has
	// no translation, or a translation has no language for its quotation.
	RuleTranslationMissing = "content.quote.translationMissing"
	// RuleFactsMissing: a date, figure or name in the claim does not
	// appear in any supporting quotation.
	RuleFactsMissing = "content.facts.missing"
	// RuleSingleSource: a claim stating dates, figures or quotations rests
	// on one source.
	RuleSingleSource = "content.claim.singleSource"
	// RuleNotAtomic: the claim states several facts, which are easier to
	// check and to disagree about separately.
	RuleNotAtomic = "content.claim.notAtomic"
	// RuleVerdict: a judge found the claim not supported as written, for
	// example contested, unsupported or contradicted.
	RuleVerdict = "content.claim.verdict"
)

// Issue is a content finding: a problem with one claim, or with one of the
// sources it cites.
type Issue struct {
	ID          string `json:"id"`
	Rule        string `json:"rule"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// ClaimID identifies the claim the issue is about.
	ClaimID string `json:"claimId"`
	// Statement is the claim's text, shown as the finding's snippet.
	Statement string `json:"statement,omitempty"`
	// SourceRef identifies the cited source the issue is about, if any.
	SourceRef string `json:"sourceRef,omitempty"`
	// Document is the file that holds the claim, if known.
	Document string `json:"document,omitempty"`
	// Severity is the impact of the issue; defaults to Medium when unset.
	Severity   findingspec.Severity   `json:"severity,omitempty"`
	Confidence findingspec.Confidence `json:"confidence,omitempty"`

	Evidence    []findingspec.Evidence   `json:"evidence,omitempty"`
	Remediation *findingspec.Remediation `json:"remediation,omitempty"`
	Status      findingspec.Status       `json:"status,omitempty"`
	DetectedAt  *time.Time               `json:"detectedAt,omitempty"`
}

// ToFinding projects the issue into a domain-neutral findingspec.Finding in
// the content domain. The claim is the finding's location: Location.Component
// is the claim ID, Location.File the document holding it and
// Location.Snippet its statement. Severity defaults to Medium. The claim and
// source are also tags, "claim:<id>" and "source:<ref>", for filtering.
func (i Issue) ToFinding() findingspec.Finding {
	sev := i.Severity
	if sev == "" {
		sev = findingspec.SeverityMedium
	}
	tags := []string{"claim:" + i.ClaimID}
	if i.SourceRef != "" {
		tags = append(tags, "source:"+i.SourceRef)
	}
	return findingspec.Finding{
		ID:          i.ID,
		Domain:      findingspec.DomainContent,
		Type:        "claim",
		RuleID:      i.Rule,
		Title:       i.Title,
		Description: i.Description,
		Severity:    sev,
		Confidence:  i.Confidence,
		Status:      i.Status,
		Location:    &findingspec.Location{File: i.Document, Component: i.ClaimID, Snippet: i.Statement},
		Evidence:    i.Evidence,
		Remediation: i.Remediation,
		Tags:        tags,
		DetectedAt:  i.DetectedAt,
	}
}

// ClaimID returns the claim a content finding is about, from its location,
// or "" when the finding is not about a claim.
func ClaimID(f findingspec.Finding) string {
	if f.Domain != findingspec.DomainContent || f.Location == nil {
		return ""
	}
	return f.Location.Component
}
