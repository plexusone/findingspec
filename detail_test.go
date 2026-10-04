package findingspec

import (
	"encoding/json"
	"testing"
)

type demoDetail struct {
	Package string `json:"package"`
	Fixed   string `json:"fixed"`
}

func TestDetailRoundTrip(t *testing.T) {
	f := Finding{ID: "1", Domain: DomainSecurity, Type: "sca", Title: "vuln dep", Severity: SeverityHigh}
	if err := f.SetDetail(demoDetail{Package: "left-pad@1.0.0", Fixed: "1.0.1"}); err != nil {
		t.Fatalf("SetDetail: %v", err)
	}

	// Detail survives a JSON round-trip of the whole finding.
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got, err := DetailAs[demoDetail](back)
	if err != nil {
		t.Fatalf("DetailAs: %v", err)
	}
	if got.Package != "left-pad@1.0.0" || got.Fixed != "1.0.1" {
		t.Errorf("round-trip detail = %+v", got)
	}
}

func TestDetailEmpty(t *testing.T) {
	f := Finding{ID: "1", Domain: DomainSecurity, Title: "t", Severity: SeverityLow}
	got, err := DetailAs[demoDetail](f)
	if err != nil {
		t.Fatalf("DetailAs on empty: %v", err)
	}
	if (got != demoDetail{}) {
		t.Errorf("empty detail should give zero value, got %+v", got)
	}
	// SetDetail(nil) clears.
	f.Detail = json.RawMessage(`{"package":"x"}`)
	if err := f.SetDetail(nil); err != nil {
		t.Fatal(err)
	}
	if f.Detail != nil {
		t.Errorf("SetDetail(nil) should clear Detail, got %s", f.Detail)
	}
}
