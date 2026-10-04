package security

import (
	"time"

	"github.com/plexusone/findingspec"
)

// DisclosureKind categorizes the kind of unintended information exposure a
// Disclosure records. Unlike Secret (a credential) or Vulnerability (a
// weakness), a Disclosure is information that policy prohibits publishing
// regardless of whether it grants access to anything.
type DisclosureKind string

const (
	// DisclosureKindEntity is a restricted entity reference — a customer,
	// partner, reporter name, or internal codename — that policy prohibits
	// disclosing, typically matched against a curated term list.
	DisclosureKindEntity DisclosureKind = "entity"
	// DisclosureKindLocalPath is a local filesystem or user-identity leak,
	// e.g. a username embedded in an absolute path, or an absolute local
	// path in a config file that should be relative or environment-derived.
	DisclosureKindLocalPath DisclosureKind = "local_path"
)

// Disclosure is a security finding for unintended exposure of information
// that policy prohibits publishing, found in source, a config file, or a
// structured document such as an OpenAPI spec or Postman collection.
//
// The offending text is never stored in full; only a redacted preview. The
// exact location within a structured document is carried on
// Location.Pointer (a JSON Pointer) together with Location.DocFormat, the
// same as Secret.
type Disclosure struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`

	// Kind categorizes the disclosure.
	Kind DisclosureKind `json:"kind,omitempty"`
	// Category further classifies the disclosure within its Kind, e.g.
	// "customer", "partner", "codename" for DisclosureKindEntity.
	Category string `json:"category,omitempty"`
	// Detector is the rule or pattern that matched, e.g. a policy entity
	// rule ID or "path-local-home".
	Detector string `json:"detector,omitempty"`
	// Redacted is a masked preview of the offending text, e.g. "A*******p".
	// The raw value must not be stored here.
	Redacted string `json:"redacted,omitempty"`

	// Severity is the impact; defaults to High when unset.
	Severity findingspec.Severity `json:"severity,omitempty"`

	// Location is where the disclosure was found. For a structured document,
	// set Location.File, Location.DocFormat (e.g. "openapi", "postman"), and
	// Location.Pointer (an RFC 6901 JSON Pointer to the offending node).
	Location    *findingspec.Location    `json:"location,omitempty"`
	Remediation *findingspec.Remediation `json:"remediation,omitempty"`
	Status      findingspec.Status       `json:"status,omitempty"`
	Tags        []string                 `json:"tags,omitempty"`
	DetectedAt  *time.Time               `json:"detectedAt,omitempty"`
}

// ruleID returns the most specific classifier for the disclosure: the
// detector, else the category, else the kind.
func (d Disclosure) ruleID() string {
	if d.Detector != "" {
		return d.Detector
	}
	if d.Category != "" {
		return d.Category
	}
	return string(d.Kind)
}

// ToFinding projects the disclosure into a domain-neutral findingspec.Finding
// in the security domain. Severity defaults to High when unset. The finding
// never carries the raw offending text — only the redacted preview and its
// location.
func (d Disclosure) ToFinding() findingspec.Finding {
	sev := d.Severity
	if sev == "" {
		sev = findingspec.SeverityHigh
	}
	tags := append([]string{"disclosure"}, d.Tags...)
	if d.Kind != "" {
		tags = append(tags, string(d.Kind))
	}
	if d.Category != "" {
		tags = append(tags, "category:"+d.Category)
	}
	return findingspec.Finding{
		ID:          d.ID,
		Domain:      findingspec.DomainSecurity,
		RuleID:      d.ruleID(),
		Title:       d.Title,
		Description: d.Description,
		Severity:    sev,
		Status:      d.Status,
		Location:    withSnippet(d.Location, d.Redacted),
		Remediation: d.Remediation,
		Tags:        tags,
		DetectedAt:  d.DetectedAt,
	}
}
