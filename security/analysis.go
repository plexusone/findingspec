package security

// RootCause explains why a weakness exists, bridging the discoverer's report
// and the engineer's fix.
type RootCause struct {
	// Summary states the underlying defect in one or two sentences.
	Summary string `json:"summary"`
	// Components lists the code paths, modules, or configuration involved.
	Components []string `json:"components,omitempty"`
	// MissingControl names the check or protection that was absent or wrong.
	MissingControl string `json:"missingControl,omitempty"`
	// TrustBoundary names the boundary the weakness crosses, if any.
	TrustBoundary string `json:"trustBoundary,omitempty"`
}

// Impact describes the consequence of a weakness beyond its technical class.
type Impact struct {
	// Technical is the effect on confidentiality, integrity, or availability.
	Technical string `json:"technical,omitempty"`
	// Product is the effect on product behavior, users, tenants, or
	// permissions, stated in terms of the intended behavior it breaks.
	Product string `json:"product,omitempty"`
	// Surfaces lists the product surfaces, APIs, or workflows affected.
	Surfaces []string `json:"surfaces,omitempty"`
}

// Exploit describes how a weakness can be abused. It is sensitive: producers
// keep it in private stores and never project it into public artifacts.
type Exploit struct {
	// Preconditions are the attacker capabilities and system state required.
	Preconditions []string `json:"preconditions,omitempty"`
	// Scenario narrates the attack at a level suited to triage.
	Scenario string `json:"scenario,omitempty"`
	// Reproduction gives the steps or test that demonstrate the weakness.
	Reproduction string `json:"reproduction,omitempty"`
}
