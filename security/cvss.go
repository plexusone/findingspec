package security

import "github.com/plexusone/findingspec"

// CVSS holds a Common Vulnerability Scoring System result.
type CVSS struct {
	// Version is the CVSS version, e.g. "3.1" or "4.0".
	Version string `json:"version,omitempty"`
	// Vector is the CVSS vector string.
	Vector string `json:"vector,omitempty"`
	// Score is the numeric base score in the range 0.0–10.0.
	Score float64 `json:"score"`
}

// Severity maps the CVSS score to the canonical severity scale using the
// standard CVSS v3.x / v4.0 bands (see findingspec.SeverityFromCVSS). Scores
// outside 0.0–10.0 map to Informational.
//
// CVSS v2 used a different, coarser scale; callers scoring v2 vectors should map
// severity explicitly rather than rely on this method.
func (c CVSS) Severity() findingspec.Severity {
	return findingspec.SeverityFromCVSS(c.Score)
}
