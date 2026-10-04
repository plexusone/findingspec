package findingspec

// Domain identifies the problem space a [Finding] belongs to. Each domain has a
// corresponding package in this module that defines its semantic finding types.
type Domain string

const (
	// DomainSecurity covers vulnerabilities, misconfigurations, and other
	// security weaknesses.
	DomainSecurity Domain = "security"
	// DomainA11y covers accessibility (WCAG) conformance issues.
	DomainA11y Domain = "a11y"
	// DomainI18n covers internationalization and localization issues.
	DomainI18n Domain = "i18n"
	// DomainQE covers quality-engineering findings such as failed end-to-end
	// tests or broken user journeys.
	DomainQE Domain = "qe"
	// DomainCompliance covers control-conformance findings against a framework
	// (e.g. CIS, STIG, FedRAMP, SOC 2, ISO 27001). A failed control is a
	// finding; the overall audit or scan run that produced it is a higher-level
	// assessment (see assessmentspec).
	DomainCompliance Domain = "compliance"
	// DomainObservability covers runtime findings such as SLO/SLA violations,
	// error-rate or latency regressions, and failing web vitals, derived from
	// APM, synthetic monitoring, or RUM signals.
	DomainObservability Domain = "observability"
)

// Domains returns all known domains in a stable order.
func Domains() []Domain {
	return []Domain{
		DomainSecurity, DomainA11y, DomainI18n, DomainQE,
		DomainCompliance, DomainObservability,
	}
}

// Valid reports whether d is a known domain.
func (d Domain) Valid() bool {
	switch d {
	case DomainSecurity, DomainA11y, DomainI18n, DomainQE,
		DomainCompliance, DomainObservability:
		return true
	default:
		return false
	}
}
