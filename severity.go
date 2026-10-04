package findingspec

import pf "github.com/grokify/priority-frameworks"

// Severity is a severity level identifier drawn from the canonical
// priority-frameworks Severity framework: Critical, High, Medium, Low,
// Informational. Values are the framework's lower-case level IDs; use Name for
// the display form.
type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
)

// severityFramework is the canonical severity framework; all severity parsing,
// ordering, and CVSS mapping delegate to it.
var (
	severityFramework = pf.Severity()
	cvssScoreRange    = pf.CVSSScoreRange()
)

// Severities returns all severities ordered from most to least severe.
func Severities() []Severity {
	levels := severityFramework.Levels
	out := make([]Severity, len(levels))
	for i, l := range levels {
		out[i] = Severity(l.ID)
	}
	return out
}

// Valid reports whether s is a known severity level.
func (s Severity) Valid() bool {
	return severityFramework.IndexOf(string(s)) >= 0
}

// Rank returns the ordering rank of s (lower is more severe). Unknown
// severities rank after all known ones.
func (s Severity) Rank() int {
	if idx := severityFramework.IndexOf(string(s)); idx >= 0 {
		return idx
	}
	return len(severityFramework.Levels)
}

// MoreSevereThan reports whether s is strictly more severe than other.
func (s Severity) MoreSevereThan(other Severity) bool {
	return severityFramework.Compare(string(s), string(other)) > 0
}

// Actionable reports whether items at this severity require action.
// Informational is not actionable.
func (s Severity) Actionable() bool {
	if l := severityFramework.Parse(string(s)); l != nil {
		return l.Actionable
	}
	return false
}

// Name returns the canonical display name for the severity, e.g. "Critical".
// It returns the raw value if the severity is unknown.
func (s Severity) Name() string {
	if l := severityFramework.Parse(string(s)); l != nil {
		return l.Name
	}
	return string(s)
}

// Abbreviation returns a short display form (e.g. "CRIT" for critical),
// for a caller that wants a compact rendering (e.g. a text-report column)
// instead of Name's full form. It returns the raw value if the severity is
// unknown.
func (s Severity) Abbreviation() string {
	if abbr := severityFramework.AbbreviationFor(string(s)); abbr != "" {
		return abbr
	}
	return string(s)
}

// ParseSeverity normalizes a severity string — a level ID, display name, or
// alias (e.g. "High", "high", "HIGH", "S2") — to a canonical Severity. It
// returns false if the value is not recognized.
func ParseSeverity(s string) (Severity, bool) {
	if l := severityFramework.Parse(s); l != nil {
		return Severity(l.ID), true
	}
	return "", false
}

// SeverityFromCVSS maps a CVSS base score (0.0–10.0) to the canonical severity
// using the standard CVSS bands (Critical ≥9.0, High ≥7.0, Medium ≥4.0,
// Low ≥0.1, Informational 0.0). Scores outside 0.0–10.0 map to Informational.
func SeverityFromCVSS(score float64) Severity {
	if l, err := cvssScoreRange.LevelFromScore(score); err == nil && l != nil {
		return Severity(l.ID)
	}
	return SeverityInformational
}
