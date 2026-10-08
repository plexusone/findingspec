package findingspec

// RelationshipType names how a finding relates to another artifact.
type RelationshipType string

const (
	// RelationshipRealizesThreat links a finding to a modeled threat it makes
	// real (e.g. a threat-model scenario).
	RelationshipRealizesThreat RelationshipType = "realizes_threat"
	// RelationshipViolatesControl links a finding to a control it defeats or
	// that is missing.
	RelationshipViolatesControl RelationshipType = "violates_control"
	// RelationshipAffectsRequirement links a finding to a product requirement
	// whose intended behavior it breaks.
	RelationshipAffectsRequirement RelationshipType = "affects_requirement"
	// RelationshipTrackedBy links a finding to the work item that resolves it
	// (e.g. a roadmap item or initiative).
	RelationshipTrackedBy RelationshipType = "tracked_by"
	// RelationshipFixedBy links a finding to the change that fixes it (e.g. a
	// commit or pull request).
	RelationshipFixedBy RelationshipType = "fixed_by"
	// RelationshipVerifiedBy links a finding to a test or check that proves
	// the fix.
	RelationshipVerifiedBy RelationshipType = "verified_by"
	// RelationshipDuplicates marks a finding as a duplicate of another.
	RelationshipDuplicates RelationshipType = "duplicates"
	// RelationshipRelatedTo is a general association.
	RelationshipRelatedTo RelationshipType = "related_to"
)

// Relationship is a typed link from a finding to another artifact. The target
// is an opaque, producer-defined reference (a finding ID, a commit hash, a
// roadmap item ID, or a URI); findingspec does not resolve it, so the core
// stays free of dependencies on the systems it links to.
type Relationship struct {
	// Type is the nature of the link.
	Type RelationshipType `json:"type"`
	// Target identifies the linked artifact.
	Target string `json:"target"`
	// Title is an optional human-readable label for the target.
	Title string `json:"title,omitempty"`
}
