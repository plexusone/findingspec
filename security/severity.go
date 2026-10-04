package security

import "github.com/plexusone/findingspec"

// ParseScannerSeverity maps a scanner's severity label to the canonical
// findingspec.Severity. It accepts the standard levels and their aliases
// (Critical/High/Medium/Low/Informational, "S2", etc. via findingspec), and maps
// any unrecognized or below-Low label — Grype's "Negligible", Inspector's
// "Untriaged", "Unknown", "None", or empty — to Informational, so every scanner
// finding lands in a canonical bucket.
func ParseScannerSeverity(s string) findingspec.Severity {
	if sev, ok := findingspec.ParseSeverity(s); ok {
		return sev
	}
	return findingspec.SeverityInformational
}

// SeverityOrCVSS returns the canonical severity for a scanner label, falling
// back to the CVSS-derived severity when the label is unrecognized and a CVSS
// base score is available (score > 0).
func SeverityOrCVSS(label string, cvssScore float64) findingspec.Severity {
	if sev, ok := findingspec.ParseSeverity(label); ok {
		return sev
	}
	if cvssScore > 0 {
		return findingspec.SeverityFromCVSS(cvssScore)
	}
	return findingspec.SeverityInformational
}
