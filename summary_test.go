package findingspec

import (
	"encoding/json"
	"testing"
)

func sampleSet() *FindingSet {
	return NewFindingSet(
		Finding{ID: "1", Domain: DomainSecurity, Title: "a", Severity: SeverityCritical, Status: StatusOpen, Location: &Location{Repo: "app", File: "main.go"}},
		Finding{ID: "2", Domain: DomainSecurity, Title: "b", Severity: SeverityLow, Status: StatusResolved, Location: &Location{Repo: "app", File: "db.go"}},
		Finding{ID: "3", Domain: DomainA11y, Title: "c", Severity: SeverityInformational, Status: StatusOpen, Location: &Location{Repo: "web"}},
		Finding{ID: "4", Domain: DomainQE, Title: "d", Severity: SeverityHigh, Status: StatusConfirmed},
	)
}

func TestFindingSetSummary(t *testing.T) {
	s := sampleSet()
	sum := s.Summary()

	if sum.Total != 4 {
		t.Errorf("Total = %d; want 4", sum.Total)
	}
	if sum.Open != 3 { // open, open, confirmed (resolved is not open)
		t.Errorf("Open = %d; want 3", sum.Open)
	}
	if sum.Actionable != 3 { // critical, low, high (informational not actionable)
		t.Errorf("Actionable = %d; want 3", sum.Actionable)
	}
	if sum.BySeverity[SeverityCritical] != 1 || sum.BySeverity[SeverityInformational] != 1 {
		t.Errorf("BySeverity = %v", sum.BySeverity)
	}
	if sum.ByDomain[DomainSecurity] != 2 {
		t.Errorf("ByDomain[security] = %d; want 2", sum.ByDomain[DomainSecurity])
	}
	if sum.ByRepo["app"] != 2 || sum.ByRepo["web"] != 1 || sum.ByRepo[""] != 1 {
		t.Errorf("ByRepo = %v", sum.ByRepo)
	}

	// Summary must round-trip through JSON (it is part of the IR surface).
	if _, err := json.Marshal(sum); err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
}

func TestFindingSetCountHelpers(t *testing.T) {
	s := sampleSet()
	if got := s.CountByFile()["main.go"]; got != 1 {
		t.Errorf("CountByFile[main.go] = %d; want 1", got)
	}
	if got := s.CountByStatus()[StatusOpen]; got != 2 {
		t.Errorf("CountByStatus[open] = %d; want 2", got)
	}
	// generic CountBy over an arbitrary dimension (domain as string here)
	byDomain := s.CountBy(func(f Finding) string { return string(f.Domain) })
	if byDomain["security"] != 2 {
		t.Errorf("CountBy(domain)[security] = %d; want 2", byDomain["security"])
	}
}

func TestFindingSetJSONIR(t *testing.T) {
	// The whole set serializes as one JSON IR: {"findings":[...]}.
	b, err := json.Marshal(sampleSet())
	if err != nil {
		t.Fatalf("marshal set: %v", err)
	}
	var back FindingSet
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal set: %v", err)
	}
	if back.Len() != 4 {
		t.Errorf("round-trip Len = %d; want 4", back.Len())
	}
}
