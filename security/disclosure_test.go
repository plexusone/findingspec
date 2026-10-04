package security

import (
	"testing"

	"github.com/plexusone/findingspec"
)

func TestDisclosureToFinding_Entity(t *testing.T) {
	d := Disclosure{
		ID:       "DISC-1",
		Title:    "Restricted customer name in README",
		Kind:     DisclosureKindEntity,
		Category: "customer",
		Detector: "customer-acme",
		Redacted: "A*******p",
		Location: &findingspec.Location{
			File: "README.md",
			Line: 3,
		},
	}
	f := d.ToFinding()
	if err := f.Validate(); err != nil {
		t.Fatalf("invalid finding: %v", err)
	}
	if f.Domain != findingspec.DomainSecurity {
		t.Errorf("domain = %q; want security", f.Domain)
	}
	if f.Severity != findingspec.SeverityHigh {
		t.Errorf("default severity = %q; want High", f.Severity)
	}
	if f.RuleID != "customer-acme" {
		t.Errorf("ruleID = %q; want detector", f.RuleID)
	}
	var hasKindTag, hasCategoryTag bool
	for _, tg := range f.Tags {
		if tg == "entity" {
			hasKindTag = true
		}
		if tg == "category:customer" {
			hasCategoryTag = true
		}
	}
	if !hasKindTag || !hasCategoryTag {
		t.Errorf("expected entity/category tags; got %v", f.Tags)
	}
}

func TestDisclosureToFinding_LocalPathInStructuredDoc(t *testing.T) {
	d := Disclosure{
		ID:       "DISC-2",
		Title:    "Local username in Postman collection variable",
		Kind:     DisclosureKindLocalPath,
		Detector: "path-local-home",
		Severity: findingspec.SeverityCritical,
		Location: &findingspec.Location{
			File:      "collection.postman_collection.json",
			DocFormat: "postman",
			Pointer:   "/variable/3/value",
		},
	}
	f := d.ToFinding()
	if f.Severity != findingspec.SeverityCritical {
		t.Errorf("severity = %q; want Critical", f.Severity)
	}
	if f.Location.Pointer != "/variable/3/value" || f.Location.DocFormat != "postman" {
		t.Errorf("location pointer/format not carried: %+v", f.Location)
	}
}
