package findingspec

import (
	"encoding/json"
	"errors"
	"time"
)

// Finding is the canonical, domain-neutral representation of something that
// needs attention. Domain packages (security, a11y, i18n, qe) produce their own
// semantic types and project them into a Finding via a ToFinding method.
type Finding struct {
	// ID is a stable identifier for this finding, unique within its producer.
	ID string `json:"id"`
	// Domain is the broad problem space this finding belongs to.
	Domain Domain `json:"domain"`
	// Type is the finding class within the domain — the scanner or test kind,
	// e.g. "sast", "sca", "secret", "container", "wcag", "e2e", "apm", "cis".
	// Together with Domain it forms the two-level type taxonomy and, when set,
	// tells a consumer how to decode Detail.
	Type string `json:"type,omitempty"`
	// RuleID identifies the domain rule or check that produced the finding,
	// e.g. a CWE ID, a WCAG success criterion, or a lint rule name.
	RuleID string `json:"ruleId,omitempty"`
	// Title is a short human-readable summary.
	Title string `json:"title"`
	// Description explains the finding in detail.
	Description string `json:"description,omitempty"`
	// Severity is the impact of the finding on the shared severity scale.
	Severity Severity `json:"severity"`
	// Confidence expresses certainty that the finding is a true positive.
	Confidence Confidence `json:"confidence,omitempty"`
	// Status is the lifecycle state of the finding.
	Status Status `json:"status,omitempty"`
	// Source identifies the producing tool.
	Source Source `json:"source,omitempty"`
	// Location is where the finding was observed.
	Location *Location `json:"location,omitempty"`
	// Evidence holds supporting artifacts.
	Evidence []Evidence `json:"evidence,omitempty"`
	// Remediation describes how to fix the finding.
	Remediation *Remediation `json:"remediation,omitempty"`
	// References links to external material.
	References []Reference `json:"references,omitempty"`
	// Tags are free-form labels for filtering and grouping.
	Tags []string `json:"tags,omitempty"`
	// DetectedAt is when the finding was observed.
	DetectedAt *time.Time `json:"detectedAt,omitempty"`
	// Detail is the typed, per-type subsection carrying the domain- and
	// type-specific payload (e.g. package/CVE/CVSS for an SCA finding, or
	// detector/entropy for a secret). It is opaque at the core layer; decode it
	// with DetailAs once Type is known. Set it with SetDetail.
	Detail json.RawMessage `json:"detail,omitempty"`
}

// SetDetail marshals v into the finding's Detail subsection. Passing nil clears
// it.
func (f *Finding) SetDetail(v any) error {
	if v == nil {
		f.Detail = nil
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f.Detail = b
	return nil
}

// DetailAs decodes a finding's Detail subsection into a value of type T, using
// the finding's Type as the discriminator the caller keys on. It returns the
// zero value of T when Detail is empty.
func DetailAs[T any](f Finding) (T, error) {
	var out T
	if len(f.Detail) == 0 {
		return out, nil
	}
	err := json.Unmarshal(f.Detail, &out)
	return out, err
}

// Validate reports whether the finding carries the minimum required fields: an
// ID, a valid domain, a title, and a valid severity.
func (f Finding) Validate() error {
	if f.ID == "" {
		return errors.New("findingspec: finding ID is required")
	}
	if !f.Domain.Valid() {
		return errors.New("findingspec: finding domain is invalid")
	}
	if f.Title == "" {
		return errors.New("findingspec: finding title is required")
	}
	if !f.Severity.Valid() {
		return errors.New("findingspec: finding severity is invalid")
	}
	return nil
}
