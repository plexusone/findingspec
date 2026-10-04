package findingspec

import "testing"

func TestFindingValidate(t *testing.T) {
	tests := []struct {
		name    string
		finding Finding
		wantErr bool
	}{
		{
			name:    "valid",
			finding: Finding{ID: "F-1", Domain: DomainSecurity, Title: "SQL injection", Severity: SeverityHigh},
		},
		{name: "missing ID", finding: Finding{Domain: DomainSecurity, Title: "x", Severity: SeverityLow}, wantErr: true},
		{name: "bad domain", finding: Finding{ID: "F-2", Domain: "bogus", Title: "x", Severity: SeverityLow}, wantErr: true},
		{name: "missing title", finding: Finding{ID: "F-3", Domain: DomainA11y, Severity: SeverityLow}, wantErr: true},
		{name: "bad severity", finding: Finding{ID: "F-4", Domain: DomainQE, Title: "x", Severity: "sev"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.finding.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"critical": SeverityCritical, "HIGH": SeverityHigh, "Medium": SeverityMedium,
		"low": SeverityLow, "Informational": SeverityInformational, "S2": SeverityHigh,
	}
	for in, want := range cases {
		got, ok := ParseSeverity(in)
		if !ok || got != want {
			t.Errorf("ParseSeverity(%q) = %q,%v; want %q", in, got, ok, want)
		}
	}
	if _, ok := ParseSeverity("bogus"); ok {
		t.Error("ParseSeverity(bogus) = ok; want !ok")
	}
}

func TestFindingSetSortAndCount(t *testing.T) {
	s := NewFindingSet(
		Finding{ID: "a", Domain: DomainSecurity, Title: "a", Severity: SeverityLow},
		Finding{ID: "b", Domain: DomainA11y, Title: "b", Severity: SeverityCritical},
		Finding{ID: "c", Domain: DomainSecurity, Title: "c", Severity: SeverityMedium},
	)
	s.SortBySeverity()
	if s.Findings[0].Severity != SeverityCritical {
		t.Fatalf("SortBySeverity: first = %q; want Critical", s.Findings[0].Severity)
	}
	if got := s.CountByDomain()[DomainSecurity]; got != 2 {
		t.Errorf("CountByDomain[security] = %d; want 2", got)
	}
	if got := s.Domain(DomainA11y).Len(); got != 1 {
		t.Errorf("Domain(a11y).Len() = %d; want 1", got)
	}
}
