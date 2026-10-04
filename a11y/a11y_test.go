package a11y

import (
	"testing"

	"github.com/plexusone/findingspec"
)

func TestImpactSeverity(t *testing.T) {
	cases := map[Impact]findingspec.Severity{
		ImpactCritical: findingspec.SeverityCritical,
		ImpactSerious:  findingspec.SeverityHigh,
		ImpactModerate: findingspec.SeverityMedium,
		ImpactMinor:    findingspec.SeverityLow,
		"":             findingspec.SeverityInformational,
	}
	for impact, want := range cases {
		if got := impact.Severity(); got != want {
			t.Errorf("Impact(%q).Severity() = %q; want %q", impact, got, want)
		}
	}
}

func TestIssueToFinding(t *testing.T) {
	i := Issue{
		ID:        "A-1",
		Title:     "Text has insufficient contrast",
		Criterion: "1.4.3",
		Level:     LevelAA,
		Impact:    ImpactSerious,
		Location:  &findingspec.Location{URL: "https://example.com", Selector: "p.muted"},
	}
	f := i.ToFinding()
	if err := f.Validate(); err != nil {
		t.Fatalf("invalid finding: %v", err)
	}
	if f.Domain != findingspec.DomainA11y {
		t.Errorf("domain = %q; want a11y", f.Domain)
	}
	if f.Severity != findingspec.SeverityHigh {
		t.Errorf("severity = %q; want High", f.Severity)
	}
	if f.RuleID != "WCAG 1.4.3 (AA)" {
		t.Errorf("ruleID = %q", f.RuleID)
	}
}
