package govulncheck

import (
	"strings"
	"testing"

	findingspec "github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/security"
)

// sampleStream is a govulncheck -json stream: concatenated single-key objects.
const sampleStream = `
{"osv":{"id":"GO-2023-1234","summary":"HTTP/2 rapid reset in x/net","details":"A flaw in HTTP/2.","aliases":["CVE-2023-44487","GHSA-qppj"],"references":[{"type":"FIX","url":"https://go.dev/cl/1"}],"affected":[{"package":{"ecosystem":"Go","name":"golang.org/x/net"}}],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}}
{"finding":{"osv":"GO-2023-1234","fixed_version":"v0.17.0","trace":[{"module":"golang.org/x/net","version":"v0.10.0","package":"golang.org/x/net/http2","function":"processHeaders"},{"module":"example.com/app","package":"example.com/app","function":"serve"},{"module":"example.com/app","package":"example.com/app","function":"main"}]}}
{"osv":{"id":"GO-2022-0999","summary":"Imported but not called","affected":[{"package":{"ecosystem":"Go","name":"example.com/lib"}}]}}
{"finding":{"osv":"GO-2022-0999","fixed_version":"v1.2.0","trace":[{"module":"example.com/lib","version":"v1.0.0","package":"example.com/lib/foo"}]}}
`

func TestParse(t *testing.T) {
	set, err := Parse(strings.NewReader(sampleStream), Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d; want 2", set.Len())
	}

	for _, f := range set.Findings {
		if err := f.Validate(); err != nil {
			t.Fatalf("invalid finding: %v", err)
		}
		if f.Domain != findingspec.DomainSecurity || f.Type != security.TypeSCA {
			t.Errorf("domain/type = %s/%s; want security/sca", f.Domain, f.Type)
		}
		if f.Source.Tool != "govulncheck" {
			t.Errorf("source = %q; want govulncheck", f.Source.Tool)
		}
	}

	// Finding 1: reachable (called).
	called := set.Findings[0]
	if called.RuleID != "GO-2023-1234" {
		t.Errorf("ruleID = %q", called.RuleID)
	}
	d, err := findingspec.DetailAs[security.VulnerabilityDetail](called)
	if err != nil {
		t.Fatalf("DetailAs: %v", err)
	}
	if d.Reachable == nil || !*d.Reachable {
		t.Errorf("Reachable = %v; want true", d.Reachable)
	}
	if d.Reachability == nil || d.Reachability.State != security.ReachabilityReachable {
		t.Fatalf("reachability = %+v; want reachable", d.Reachability)
	}
	if d.Reachability.Symbol != "golang.org/x/net/http2.processHeaders" {
		t.Errorf("symbol = %q", d.Reachability.Symbol)
	}
	if len(d.Reachability.Paths) == 0 || !strings.Contains(d.Reachability.Paths[0], "processHeaders") {
		t.Errorf("paths = %v", d.Reachability.Paths)
	}
	if d.Package == nil || d.Package.Ecosystem != "go" || d.Package.Name != "golang.org/x/net/http2" {
		t.Errorf("package = %+v", d.Package)
	}
	if d.Fix == nil || len(d.Fix.Versions) != 1 || d.Fix.Versions[0] != "v0.17.0" {
		t.Errorf("fix = %+v", d.Fix)
	}
	hasCVE := false
	for _, c := range d.CVEs {
		if c == "CVE-2023-44487" {
			hasCVE = true
		}
	}
	if !hasCVE {
		t.Errorf("CVEs = %v; want CVE-2023-44487", d.CVEs)
	}

	// Finding 2: imported but not called → unreachable.
	notCalled := set.Findings[1]
	d2, _ := findingspec.DetailAs[security.VulnerabilityDetail](notCalled)
	if d2.Reachable == nil || *d2.Reachable {
		t.Errorf("Reachable = %v; want false", d2.Reachable)
	}
	if d2.Reachability == nil || d2.Reachability.State != security.ReachabilityUnreachable {
		t.Errorf("reachability = %+v; want unreachable", d2.Reachability)
	}
}
