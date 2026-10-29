package report

import "fmt"

// Audience selects how much attack detail a report carries.
type Audience string

const (
	// AudienceShareable omits exploit preconditions, scenarios and
	// reproduction steps, evidence payloads, and code snippets. It is the
	// default.
	AudienceShareable Audience = "shareable"
	// AudienceInternal includes every field, including exploit detail.
	AudienceInternal Audience = "internal"
)

// Valid reports whether a is a known audience.
func (a Audience) Valid() bool {
	switch a {
	case AudienceShareable, AudienceInternal:
		return true
	default:
		return false
	}
}

// Section is an author-written report section. Body is Markdown and is
// written verbatim.
type Section struct {
	Title string
	Body  string
}

// Options configures a rendered report.
type Options struct {
	// Title is the report title. Defaults to "Findings Report".
	Title string
	// Subtitle is an optional subtitle, e.g. the system under review.
	Subtitle string
	// Authors are listed in the metadata block.
	Authors []string
	// Date is free text, e.g. "2026-10-23" or "October 2026".
	Date string
	// Classification is a handling label, e.g. "Confidential".
	Classification string
	// Audience selects how much attack detail is included. Defaults to
	// AudienceShareable.
	Audience Audience

	// Summary is the executive summary in Markdown, written verbatim before
	// the severity tables.
	Summary string
	// Scope describes scope and methodology in Markdown.
	Scope string
	// Sections are written after the scope and before the findings
	// overview, e.g. key themes or a recommended fix order.
	Sections []Section
	// Appendices are written after the detailed findings.
	Appendices []Section

	// IncludeAgentPrompts adds each finding's Remediation.AgentPrompt.
	IncludeAgentPrompts bool
	// NoTOC disables the table of contents requested in the metadata block.
	NoTOC bool
}

func (o Options) withDefaults() (Options, error) {
	if o.Title == "" {
		o.Title = "Findings Report"
	}
	if o.Audience == "" {
		o.Audience = AudienceShareable
	}
	if !o.Audience.Valid() {
		return o, fmt.Errorf("report: invalid audience %q", o.Audience)
	}
	return o, nil
}

func (o Options) internal() bool { return o.Audience == AudienceInternal }
