package i18n

import (
	"testing"

	"github.com/plexusone/findingspec"
)

func TestIssueToFinding(t *testing.T) {
	i := Issue{
		ID:     "I18N-1",
		Title:  "Missing translation for home.title",
		Kind:   KindMissingTranslation,
		Key:    "home.title",
		Locale: "fr",
	}
	f := i.ToFinding()
	if err := f.Validate(); err != nil {
		t.Fatalf("invalid finding: %v", err)
	}
	if f.Domain != findingspec.DomainI18n {
		t.Errorf("domain = %q; want i18n", f.Domain)
	}
	if f.Severity != findingspec.SeverityMedium { // default when unset
		t.Errorf("severity = %q; want medium (default)", f.Severity)
	}
	if f.RuleID != string(KindMissingTranslation) {
		t.Errorf("ruleID = %q; want %q", f.RuleID, KindMissingTranslation)
	}
	found := false
	for _, tg := range f.Tags {
		if tg == "locale:fr" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected locale:fr tag; got %v", f.Tags)
	}
}

func TestIssueToFindingSeverityOverride(t *testing.T) {
	i := Issue{ID: "I18N-2", Title: "hardcoded string", Kind: KindHardcodedString, Severity: findingspec.SeverityLow}
	if got := i.ToFinding().Severity; got != findingspec.SeverityLow {
		t.Errorf("severity = %q; want low", got)
	}
}
