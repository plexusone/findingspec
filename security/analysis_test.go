package security

import (
	"encoding/json"
	"testing"

	"github.com/plexusone/findingspec"
)

func TestToFindingCarriesAnalysisAndLifecycle(t *testing.T) {
	v := Vulnerability{
		ID:       "SEC-1",
		Title:    "Missing authorization on list endpoint",
		Severity: findingspec.SeverityHigh,
		CWEs:     []string{"CWE-862"},
		Type:     TypeSAST,
		RootCause: &RootCause{
			Summary:        "Handler returns records without checking the caller's permission",
			Components:     []string{"api/list.go"},
			MissingControl: "object-level authorization",
		},
		Impact: &Impact{Product: "One tenant can read another's records", Surfaces: []string{"GET /records"}},
		Publication: &Publication{
			Visibility: VisibilityPrivate,
			State:      PublicationUnpublished,
			Module:     "example.com/mod",
			Affected:   []VersionRange{{Introduced: "v0.1.0", Fixed: "v0.2.0"}},
		},
		Verification: &findingspec.Verification{
			Result: findingspec.VerificationPassed,
			Checks: []string{"TestListRequiresPermission"},
		},
		Relationships: []findingspec.Relationship{
			{Type: findingspec.RelationshipFixedBy, Target: "abc1234"},
		},
	}
	f := v.ToFinding()
	if err := f.Validate(); err != nil {
		t.Fatalf("invalid finding: %v", err)
	}
	if f.Verification == nil || f.Verification.Result != findingspec.VerificationPassed {
		t.Errorf("verification not projected: %+v", f.Verification)
	}
	if len(f.Relationships) != 1 || f.Relationships[0].Target != "abc1234" {
		t.Errorf("relationships not projected: %+v", f.Relationships)
	}

	// Detail survives a JSON round trip, which is how stores read it back.
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back findingspec.Finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	d, err := findingspec.DetailAs[VulnerabilityDetail](back)
	if err != nil {
		t.Fatalf("DetailAs: %v", err)
	}
	if d.RootCause == nil || d.RootCause.MissingControl != "object-level authorization" {
		t.Errorf("root cause lost: %+v", d.RootCause)
	}
	if d.Publication == nil || d.Publication.Affected[0].Fixed != "v0.2.0" {
		t.Errorf("publication lost: %+v", d.Publication)
	}
}
