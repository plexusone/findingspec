package security

import "time"

// Visibility is who may see a finding's full record.
type Visibility string

const (
	// VisibilityPrivate restricts the record to the security team.
	VisibilityPrivate Visibility = "private"
	// VisibilityPublicSanitized permits a reviewed, sanitized projection.
	VisibilityPublicSanitized Visibility = "public_sanitized"
)

// PublicationState is a finding's position in the disclosure lifecycle.
type PublicationState string

const (
	// PublicationUnpublished means no advisory has been issued.
	PublicationUnpublished PublicationState = "unpublished"
	// PublicationDraft means an advisory is being prepared.
	PublicationDraft PublicationState = "draft"
	// PublicationPublished means an advisory is public.
	PublicationPublished PublicationState = "published"
	// PublicationNotRequired means the finding does not merit an advisory.
	PublicationNotRequired PublicationState = "not_required"
)

// VersionRange is a span of releases affected by a weakness. Introduced is the
// first affected version and Fixed the first version that is not; either may
// be empty when unknown or unbounded.
type VersionRange struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Publication tracks how a finding is disclosed downstream. Findings are
// private by default; a public artifact is generated from the private record
// through an explicit review, never by redacting in place.
type Publication struct {
	// Visibility controls what may be published.
	Visibility Visibility `json:"visibility,omitempty"`
	// State is the disclosure lifecycle state.
	State PublicationState `json:"state,omitempty"`
	// Approved records that a disclosure review has signed off.
	Approved bool `json:"approved,omitempty"`
	// Module is the affected module or package path.
	Module string `json:"module,omitempty"`
	// Symbols lists the vulnerable exported symbols, when known.
	Symbols []string `json:"symbols,omitempty"`
	// Affected lists the affected version ranges.
	Affected []VersionRange `json:"affected,omitempty"`
	// GHSA is the GitHub Security Advisory ID.
	GHSA string `json:"ghsa,omitempty"`
	// CVE is the assigned CVE ID.
	CVE string `json:"cve,omitempty"`
	// OSV is the OSV record ID.
	OSV string `json:"osv,omitempty"`
	// GoVuln is the Go vulnerability database ID (GO-YYYY-NNNN).
	GoVuln string `json:"goVuln,omitempty"`
	// PublishedAt is when the advisory became public.
	PublishedAt *time.Time `json:"publishedAt,omitempty"`
}
