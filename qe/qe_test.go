package qe

import (
	"testing"

	"github.com/plexusone/findingspec"
)

func TestFailureToFinding(t *testing.T) {
	f := Failure{
		ID:       "QE-1",
		Title:    "Checkout fails on mobile",
		Journey:  "signup-to-purchase",
		Step:     "checkout",
		Expected: "order confirmation",
		Actual:   "500 error",
	}
	fin := f.ToFinding()
	if err := fin.Validate(); err != nil {
		t.Fatalf("invalid finding: %v", err)
	}
	if fin.Domain != findingspec.DomainQE {
		t.Errorf("domain = %q; want qe", fin.Domain)
	}
	if fin.Severity != findingspec.SeverityHigh {
		t.Errorf("default severity = %q; want High", fin.Severity)
	}
	if fin.RuleID != "signup-to-purchase/checkout" {
		t.Errorf("ruleID = %q", fin.RuleID)
	}
}
