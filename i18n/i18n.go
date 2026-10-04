// Package i18n defines semantic types for internationalization and localization
// findings and projects them into the domain-neutral findingspec.Finding.
package i18n

import (
	"time"

	"github.com/plexusone/findingspec"
)

// Kind categorizes an internationalization issue.
type Kind string

const (
	// KindMissingTranslation is a message key with no translation for a locale.
	KindMissingTranslation Kind = "missing_translation"
	// KindHardcodedString is user-facing text that is not externalized for
	// translation.
	KindHardcodedString Kind = "hardcoded_string"
	// KindInvalidPlaceholder is a translation whose placeholders do not match
	// the source string.
	KindInvalidPlaceholder Kind = "invalid_placeholder"
	// KindUntranslatedFormat is a locale-specific formatting problem (dates,
	// numbers, currency, pluralization).
	KindUntranslatedFormat Kind = "untranslated_format"
)

// Issue is an internationalization finding.
type Issue struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Kind categorizes the issue.
	Kind Kind `json:"kind,omitempty"`
	// Key is the affected message key, when applicable.
	Key string `json:"key,omitempty"`
	// Locale is the affected locale (BCP 47), when applicable.
	Locale string `json:"locale,omitempty"`
	// Severity is the impact of the issue; defaults to Medium when unset.
	Severity findingspec.Severity `json:"severity,omitempty"`

	Location    *findingspec.Location    `json:"location,omitempty"`
	Remediation *findingspec.Remediation `json:"remediation,omitempty"`
	Status      findingspec.Status       `json:"status,omitempty"`
	DetectedAt  *time.Time               `json:"detectedAt,omitempty"`
}

// ToFinding projects the issue into a domain-neutral findingspec.Finding in the
// i18n domain. When Severity is unset it defaults to Medium.
func (i Issue) ToFinding() findingspec.Finding {
	sev := i.Severity
	if sev == "" {
		sev = findingspec.SeverityMedium
	}
	var tags []string
	if i.Locale != "" {
		tags = append(tags, "locale:"+i.Locale)
	}
	return findingspec.Finding{
		ID:          i.ID,
		Domain:      findingspec.DomainI18n,
		RuleID:      string(i.Kind),
		Title:       i.Title,
		Description: i.Description,
		Severity:    sev,
		Status:      i.Status,
		Location:    i.Location,
		Remediation: i.Remediation,
		Tags:        tags,
		DetectedAt:  i.DetectedAt,
	}
}
