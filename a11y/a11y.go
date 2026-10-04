// Package a11y defines semantic types for accessibility findings tied to WCAG
// success criteria and projects them into the domain-neutral findingspec.Finding.
package a11y

import (
	"time"

	"github.com/plexusone/findingspec"
)

// ConformanceLevel is a WCAG conformance level.
type ConformanceLevel string

const (
	LevelA   ConformanceLevel = "A"
	LevelAA  ConformanceLevel = "AA"
	LevelAAA ConformanceLevel = "AAA"
)

// Impact is the user-facing impact of an accessibility issue, following the
// common minor/moderate/serious/critical scale used by tools such as axe-core.
type Impact string

const (
	ImpactMinor    Impact = "minor"
	ImpactModerate Impact = "moderate"
	ImpactSerious  Impact = "serious"
	ImpactCritical Impact = "critical"
)

// Severity maps an accessibility Impact to the shared severity scale.
func (i Impact) Severity() findingspec.Severity {
	switch i {
	case ImpactCritical:
		return findingspec.SeverityCritical
	case ImpactSerious:
		return findingspec.SeverityHigh
	case ImpactModerate:
		return findingspec.SeverityMedium
	case ImpactMinor:
		return findingspec.SeverityLow
	default:
		return findingspec.SeverityInformational
	}
}

// Issue is an accessibility finding for a specific WCAG success criterion at a
// location in a rendered page.
type Issue struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Criterion is the WCAG success-criterion identifier, e.g. "1.4.3".
	Criterion string `json:"criterion,omitempty"`
	// Level is the WCAG conformance level of the criterion.
	Level ConformanceLevel `json:"level,omitempty"`
	// Impact is the severity of the issue for users.
	Impact Impact `json:"impact,omitempty"`
	// HelpURL points to guidance for resolving the issue.
	HelpURL string `json:"helpUrl,omitempty"`
	// Rule is the checker's rule identifier (e.g. axe-core's "color-contrast"),
	// distinct from the WCAG criterion. Optional.
	Rule string `json:"rule,omitempty"`

	Location    *findingspec.Location    `json:"location,omitempty"`
	Remediation *findingspec.Remediation `json:"remediation,omitempty"`
	Status      findingspec.Status       `json:"status,omitempty"`
	DetectedAt  *time.Time               `json:"detectedAt,omitempty"`
}

// ToFinding projects the issue into a domain-neutral findingspec.Finding in the
// a11y domain, mapping WCAG impact to severity and the success criterion to the
// finding's RuleID.
func (i Issue) ToFinding() findingspec.Finding {
	var refs []findingspec.Reference
	if i.HelpURL != "" {
		refs = append(refs, findingspec.Reference{Title: "WCAG guidance", URL: i.HelpURL})
	}
	ruleID := i.Criterion
	if i.Level != "" && ruleID != "" {
		ruleID = "WCAG " + ruleID + " (" + string(i.Level) + ")"
	}
	var tags []string
	if i.Rule != "" {
		tags = append(tags, "rule:"+i.Rule)
	}
	f := findingspec.Finding{
		ID:          i.ID,
		Domain:      findingspec.DomainA11y,
		Type:        TypeWCAG,
		RuleID:      ruleID,
		Title:       i.Title,
		Description: i.Description,
		Severity:    i.Impact.Severity(),
		Status:      i.Status,
		Location:    i.Location,
		Remediation: i.Remediation,
		References:  refs,
		Tags:        tags,
		DetectedAt:  i.DetectedAt,
	}
	_ = f.SetDetail(Detail{
		Criterion: i.Criterion,
		Level:     i.Level,
		Impact:    i.Impact,
		Rule:      i.Rule,
		HelpURL:   i.HelpURL,
	})
	return f
}

// TypeWCAG is the a11y finding type: a WCAG success-criterion issue. It is set
// as findingspec.Finding.Type by Issue.ToFinding.
const TypeWCAG = "wcag"

// Detail is the per-type Detail payload for an a11y finding
// (findingspec.Finding.Type == TypeWCAG).
type Detail struct {
	Criterion string           `json:"criterion,omitempty"`
	Level     ConformanceLevel `json:"level,omitempty"`
	Impact    Impact           `json:"impact,omitempty"`
	Rule      string           `json:"rule,omitempty"`
	HelpURL   string           `json:"helpUrl,omitempty"`
}
