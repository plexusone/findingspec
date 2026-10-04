// Package govulncheck ingests `govulncheck -json` output and normalizes it into
// findingspec Findings (security domain, type "sca"). Its distinguishing value is
// call-graph reachability: govulncheck reports whether a vulnerable symbol is
// actually called, which populates security.Reachability — a primary
// prioritization signal. It depends only on govulncheck's stable JSON shape.
package govulncheck

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	findingspec "github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/security"
)

// message is one object in the govulncheck JSON stream (a concatenation of
// single-key objects, not an array).
type message struct {
	OSV     *OSVEntry `json:"osv"`
	Finding *Finding  `json:"finding"`
}

// Finding is a govulncheck finding: an OSV id and a call/import trace.
type Finding struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []Frame `json:"trace"`
}

// Frame is one entry in a finding's trace. A frame with a Function indicates a
// call-level (reachable) finding; module/package-only frames indicate the
// package is required/imported but not called.
type Frame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
}

// OSVEntry is the subset of the OSV record govulncheck emits.
type OSVEntry struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Aliases    []string       `json:"aliases"`
	References []OSVReference `json:"references"`
	Affected   []OSVAffected  `json:"affected"`
	Severity   []OSVSeverity  `json:"severity"`
}

type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// OSVSeverity carries a CVSS vector (Score is the vector string, per OSV schema).
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVAffected struct {
	Package OSVPackage `json:"package"`
}

type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Options configures conversion.
type Options struct {
	// MaxPaths caps the number of example call paths recorded per vulnerability
	// (default 3).
	MaxPaths int
}

// Parse decodes a govulncheck JSON stream and returns a normalized FindingSet,
// one finding per vulnerability (OSV id).
func Parse(r io.Reader, opts Options) (*findingspec.FindingSet, error) {
	if opts.MaxPaths == 0 {
		opts.MaxPaths = 3
	}
	dec := json.NewDecoder(r)
	osvs := map[string]*OSVEntry{}
	byOSV := map[string][]Finding{}
	var order []string
	for {
		var m message
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("govulncheck: decode: %w", err)
		}
		switch {
		case m.OSV != nil:
			osvs[m.OSV.ID] = m.OSV
		case m.Finding != nil:
			if _, ok := byOSV[m.Finding.OSV]; !ok {
				order = append(order, m.Finding.OSV)
			}
			byOSV[m.Finding.OSV] = append(byOSV[m.Finding.OSV], *m.Finding)
		}
	}
	set := findingspec.NewFindingSet()
	for _, id := range order {
		set.Add(toFinding(id, osvs[id], byOSV[id], opts))
	}
	return set, nil
}

func toFinding(id string, osv *OSVEntry, findings []Finding, opts Options) findingspec.Finding {
	affected := affectedModules(osv)
	reach := reachability(findings, affected, opts.MaxPaths)
	pkg, fixed := packageAndFix(findings, affected)

	reachable := reach.IsReachable()
	cvss := cvssFromOSV(osv)

	vuln := security.Vulnerability{
		ID:           id + ":" + pkg.Name,
		Type:         security.TypeSCA,
		Title:        title(id, osv),
		Description:  osvDetails(osv),
		CVEs:         cveAliases(osv),
		CVSS:         cvss,
		Severity:     security.SeverityOrCVSS("", cvssScore(cvss)),
		Reachable:    &reachable,
		Reachability: reach,
		Package:      pkg,
		Fix:          fixFor(fixed),
		Component:    pkg.Name + "@" + pkg.Version,
		References:   references(id, osv),
	}
	f := vuln.ToFinding()
	f.RuleID = id
	f.Source = findingspec.Source{Tool: "govulncheck", RuleSet: "Go vulnerability database"}
	return f
}

// reachability determines whether the vulnerable symbol is called, across all of
// an OSV's findings (govulncheck may emit several at different levels).
func reachability(findings []Finding, affected map[string]bool, maxPaths int) *security.Reachability {
	r := &security.Reachability{State: security.ReachabilityUnknown}
	imported := false
	for _, f := range findings {
		if traceHasFunction(f.Trace) {
			r.State = security.ReachabilityReachable
			if r.Symbol == "" {
				r.Symbol = vulnSymbol(f.Trace, affected)
			}
			if p := renderPath(f.Trace); p != "" && len(r.Paths) < maxPaths {
				r.Paths = append(r.Paths, p)
			}
		} else if traceImported(f.Trace) {
			imported = true
		}
	}
	if r.State != security.ReachabilityReachable {
		if imported {
			r.State = security.ReachabilityUnreachable
		}
	}
	return r
}

func traceHasFunction(trace []Frame) bool {
	for _, fr := range trace {
		if fr.Function != "" {
			return true
		}
	}
	return false
}

func traceImported(trace []Frame) bool {
	for _, fr := range trace {
		if fr.Package != "" {
			return true
		}
	}
	return false
}

// vulnSymbol returns the vulnerable symbol: the first function-level frame in an
// affected module, else the first function-level frame.
func vulnSymbol(trace []Frame, affected map[string]bool) string {
	var fallback string
	for _, fr := range trace {
		if fr.Function == "" {
			continue
		}
		sym := frameSymbol(fr)
		if affected[fr.Module] {
			return sym
		}
		if fallback == "" {
			fallback = sym
		}
	}
	return fallback
}

func frameSymbol(fr Frame) string {
	name := fr.Function
	if fr.Receiver != "" {
		name = fr.Receiver + "." + name
	}
	if fr.Package != "" {
		return fr.Package + "." + name
	}
	return name
}

// renderPath renders the function-level frames of a trace as "a → b → c".
func renderPath(trace []Frame) string {
	var parts []string
	for _, fr := range trace {
		if fr.Function != "" {
			parts = append(parts, frameSymbol(fr))
		}
	}
	return strings.Join(parts, " → ")
}

func affectedModules(osv *OSVEntry) map[string]bool {
	m := map[string]bool{}
	if osv == nil {
		return m
	}
	for _, a := range osv.Affected {
		if a.Package.Name != "" {
			m[a.Package.Name] = true
		}
	}
	return m
}

// packageAndFix picks the vulnerable package (module) and a fixed version from
// the findings' traces.
func packageAndFix(findings []Finding, affected map[string]bool) (*security.Package, string) {
	pkg := &security.Package{Ecosystem: "go"}
	fixed := ""
	for _, f := range findings {
		if fixed == "" && f.FixedVersion != "" {
			fixed = f.FixedVersion
		}
		for _, fr := range f.Trace {
			if !affected[fr.Module] {
				continue
			}
			if pkg.Name == "" && fr.Package != "" {
				pkg.Name = fr.Package
			}
			if pkg.Version == "" && fr.Version != "" {
				pkg.Version = fr.Version
			}
			if fr.Module != "" && fr.Version != "" {
				pkg.PURL = "pkg:golang/" + fr.Module + "@" + fr.Version
			}
		}
	}
	if pkg.Name == "" {
		// fall back to the first affected module name.
		for name := range affected {
			pkg.Name = name
			break
		}
	}
	return pkg, fixed
}

func fixFor(fixed string) *security.Fix {
	if fixed == "" {
		return nil
	}
	return &security.Fix{State: security.FixStateFixed, Versions: []string{fixed}}
}

func title(id string, osv *OSVEntry) string {
	if osv != nil && osv.Summary != "" {
		return osv.Summary
	}
	return id
}

func osvDetails(osv *OSVEntry) string {
	if osv != nil {
		return osv.Details
	}
	return ""
}

func cveAliases(osv *OSVEntry) []string {
	if osv == nil {
		return nil
	}
	var cves []string
	for _, a := range osv.Aliases {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			cves = append(cves, a)
		}
	}
	return cves
}

func references(id string, osv *OSVEntry) []findingspec.Reference {
	refs := []findingspec.Reference{{Title: "Go vulnerability database", URL: "https://pkg.go.dev/vuln/" + id}}
	if osv != nil {
		for _, r := range osv.References {
			if r.URL != "" {
				refs = append(refs, findingspec.Reference{URL: r.URL})
			}
		}
	}
	return refs
}

// cvssFromOSV records the CVSS vector when the OSV carries one. The score is not
// computed from the vector (that needs a CVSS calculator — see roadmap), so
// Score stays 0 and severity falls back to Informational; reachability is the
// primary prioritization signal for govulncheck findings.
func cvssFromOSV(osv *OSVEntry) *security.CVSS {
	if osv == nil {
		return nil
	}
	for _, s := range osv.Severity {
		if s.Score == "" {
			continue
		}
		version := ""
		switch s.Type {
		case "CVSS_V4":
			version = "4.0"
		case "CVSS_V3":
			version = "3.x"
		case "CVSS_V2":
			version = "2.0"
		}
		return &security.CVSS{Version: version, Vector: s.Score}
	}
	return nil
}

func cvssScore(c *security.CVSS) float64 {
	if c == nil {
		return 0
	}
	return c.Score
}
