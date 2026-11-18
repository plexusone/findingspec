// Package content defines semantic types for content findings — problems with
// the accuracy and attribution of published content, such as a claim its
// cited source does not support, a quotation that cannot be found in its
// source or recording, or narration that does not say its script — and
// projects them into the domain-neutral findingspec.Finding.
package content

import (
	"strings"
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
	// RuleLessPrecise: the claim is accurate but says less than its
	// sources, leaving out a full name, a date or a figure they give.
	RuleLessPrecise = "content.claim.lessPrecise"
	// RuleSubjectMissing: the claim, or the quotation supporting it, does
	// not name who or what it is about, such as a quotation that begins
	// with a pronoun.
	RuleSubjectMissing = "content.claim.subjectMissing"
	// RuleEvidenceDuplicate: a quotation repeats, or is contained in,
	// another quotation the claim cites from the same source.
	RuleEvidenceDuplicate = "content.evidence.duplicate"
	// RuleEvidenceOffClaim: a supporting quotation bears on no part of the
	// claim, such as a passage left from an earlier wording.
	RuleEvidenceOffClaim = "content.evidence.offClaim"
	// RuleEvidenceStance: a citation's stance, such as disputes, is not
	// what its passage shows.
	RuleEvidenceStance = "content.evidence.stance"
	// RuleReviewNote: a person's note on a claim that no other rule
	// describes.
	RuleReviewNote = "content.review.note"

	// Rules for quotations from recordings, such as podcasts, interviews and
	// talks, checked by comparing what several speech-to-text engines heard
	// in a clip of the recording. RuleQuoteNotFound also applies: the
	// quotation could not be located in the recording.

	// RuleQuoteAudioDisputed: the engines disagree with each other on a
	// substantive word of the quotation, such as a number, a negation, a
	// name or a term, so the recording does not settle the wording.
	RuleQuoteAudioDisputed = "content.quote.audioDisputed"
	// RuleQuoteAudioMismatch: the engines agree with each other but not with
	// the quotation, so the quotation is not what was said. The finding
	// gives the wording the engines heard.
	RuleQuoteAudioMismatch = "content.quote.audioMismatch"
	// RuleQuoteAudioUnchecked: too few engines produced a transcript, or the
	// clip could not be cut, so the quotation was not checked.
	RuleQuoteAudioUnchecked = "content.quote.audioUnchecked"
)

// Rules for narration: recorded or generated speech that should say a
// script, such as a course lesson's voice-over.
const (
	// RuleNarrationMismatch: the recording does not say its script. Words
	// are dropped, added or misheard by every engine.
	RuleNarrationMismatch = "content.narration.mismatch"
)

// Finding types in the content domain.
const (
	// TypeClaim marks findings about a claim or the sources it cites.
	TypeClaim = "claim"
	// TypeNarration marks findings about narration and its script.
	TypeNarration = "narration"
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
		Type:        TypeClaim,
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
// or "" when the finding is not about a claim. Findings with no type are
// treated as claim findings, as earlier versions wrote them.
func ClaimID(f findingspec.Finding) string {
	if f.Domain != findingspec.DomainContent || f.Location == nil {
		return ""
	}
	if f.Type != "" && f.Type != TypeClaim {
		return ""
	}
	return f.Location.Component
}

// NarrationIssue is a problem with narration: a recording, or one segment of
// it, that does not say its script.
type NarrationIssue struct {
	ID          string `json:"id"`
	Rule        string `json:"rule"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Document is the file that holds the script, such as a slide deck.
	Document string `json:"document,omitempty"`
	// Segment identifies the part of the script, such as a slide's ID.
	Segment string `json:"segment"`
	// Expected is the script's wording for the segment.
	Expected string `json:"expected,omitempty"`
	// Heard is what the engines heard, when they agree.
	Heard string `json:"heard,omitempty"`
	// Recording is the audio file checked, if known.
	Recording string `json:"recording,omitempty"`
	// Severity is the impact of the issue; defaults to Medium when unset.
	Severity   findingspec.Severity   `json:"severity,omitempty"`
	Confidence findingspec.Confidence `json:"confidence,omitempty"`

	Evidence    []findingspec.Evidence   `json:"evidence,omitempty"`
	Remediation *findingspec.Remediation `json:"remediation,omitempty"`
	Status      findingspec.Status       `json:"status,omitempty"`
	DetectedAt  *time.Time               `json:"detectedAt,omitempty"`
}

// ToFinding projects the narration issue into a findingspec.Finding in the
// content domain with type "narration". The segment is the location:
// Location.Component is the segment ID, Location.File the script's document
// and Location.Snippet the expected wording. Heard, when set, is added to
// the evidence as a "transcript" entry, after a copy of the issue's own
// evidence. Severity defaults to Medium. The segment and recording are also
// tags, "segment:<id>" and "recording:<file>".
func (i NarrationIssue) ToFinding() findingspec.Finding {
	sev := i.Severity
	if sev == "" {
		sev = findingspec.SeverityMedium
	}
	tags := []string{"segment:" + i.Segment}
	if i.Recording != "" {
		tags = append(tags, "recording:"+i.Recording)
	}
	evidence := i.Evidence
	if i.Heard != "" {
		// A new slice, so the caller's evidence is never modified.
		evidence = append(append([]findingspec.Evidence(nil), i.Evidence...),
			findingspec.Evidence{Kind: "transcript", Summary: "Heard: " + i.Heard})
	}
	return findingspec.Finding{
		ID:          i.ID,
		Domain:      findingspec.DomainContent,
		Type:        TypeNarration,
		RuleID:      i.Rule,
		Title:       i.Title,
		Description: i.Description,
		Severity:    sev,
		Confidence:  i.Confidence,
		Status:      i.Status,
		Location:    &findingspec.Location{File: i.Document, Component: i.Segment, Snippet: i.Expected},
		Evidence:    evidence,
		Remediation: i.Remediation,
		Tags:        tags,
		DetectedAt:  i.DetectedAt,
	}
}

// Segment returns the narration segment a content finding is about, or ""
// when the finding is not about narration.
func Segment(f findingspec.Finding) string {
	if f.Domain != findingspec.DomainContent || f.Type != TypeNarration || f.Location == nil {
		return ""
	}
	return f.Location.Component
}

// FindingID builds a stable finding ID from the producer's prefix, the
// finding's subject and its rule: "<prefix>-<subject>-<rule suffix>", where
// the suffix is the rule's last segment, such as
// FindingID("CF", "claim-founding", RuleLessPrecise) =
// "CF-claim-founding-lessPrecise". The same finding gets the same ID every
// time it is raised, so decisions about it stay attached across review
// rounds, and producers with different prefixes never collide when their
// findings are merged. The subject is a claim ID for claim findings and a
// segment ID for narration findings.
func FindingID(prefix, subject, rule string) string {
	suffix := rule
	if i := strings.LastIndex(rule, "."); i >= 0 {
		suffix = rule[i+1:]
	}
	parts := make([]string, 0, 3)
	for _, p := range []string{prefix, subject, suffix} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, "-")
}
