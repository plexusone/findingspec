// Package qe defines semantic types for quality-engineering findings — failed
// end-to-end tests and broken user journeys — and projects them into the
// domain-neutral findingspec.Finding.
package qe

import (
	"time"

	"github.com/plexusone/findingspec"
)

// Failure is a quality-engineering finding: a test assertion or user-journey
// step that did not behave as expected.
type Failure struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Journey is the identifier of the user journey under test, if any.
	Journey string `json:"journey,omitempty"`
	// Step is the failing step within the test or journey.
	Step string `json:"step,omitempty"`
	// Expected and Actual capture the assertion mismatch.
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	// Severity is the impact of the failure; defaults to High when unset,
	// since a broken journey typically blocks users.
	Severity findingspec.Severity `json:"severity,omitempty"`

	Location    *findingspec.Location    `json:"location,omitempty"`
	Evidence    []findingspec.Evidence   `json:"evidence,omitempty"`
	Remediation *findingspec.Remediation `json:"remediation,omitempty"`
	Status      findingspec.Status       `json:"status,omitempty"`
	DetectedAt  *time.Time               `json:"detectedAt,omitempty"`
}

// ToFinding projects the failure into a domain-neutral findingspec.Finding in
// the qe domain. When Severity is unset it defaults to High. The journey and
// step identify the finding's RuleID.
func (f Failure) ToFinding() findingspec.Finding {
	sev := f.Severity
	if sev == "" {
		sev = findingspec.SeverityHigh
	}
	ruleID := f.Journey
	if f.Step != "" {
		if ruleID != "" {
			ruleID += "/" + f.Step
		} else {
			ruleID = f.Step
		}
	}
	var tags []string
	if f.Journey != "" {
		tags = append(tags, "journey:"+f.Journey)
	}
	return findingspec.Finding{
		ID:          f.ID,
		Domain:      findingspec.DomainQE,
		RuleID:      ruleID,
		Title:       f.Title,
		Description: f.Description,
		Severity:    sev,
		Status:      f.Status,
		Location:    f.Location,
		Evidence:    f.Evidence,
		Remediation: f.Remediation,
		Tags:        tags,
		DetectedAt:  f.DetectedAt,
	}
}
