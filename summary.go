package findingspec

// Summary is a computed, JSON-serializable analytics rollup for a FindingSet.
// It answers the common questions at a glance — how many findings, and how they
// break down by severity, domain (type), status, and top-level location (repo) —
// without the caller assembling each map. For dimensions not covered here, use
// FindingSet.CountBy.
type Summary struct {
	// Total is the number of findings.
	Total int `json:"total"`
	// Open is the number of findings whose status still needs attention.
	Open int `json:"open"`
	// Actionable is the number of findings whose severity is actionable
	// (i.e. not Informational).
	Actionable int `json:"actionable"`
	// BySeverity counts findings per severity.
	BySeverity map[Severity]int `json:"bySeverity,omitempty"`
	// ByDomain counts findings per domain (the finding "type").
	ByDomain map[Domain]int `json:"byDomain,omitempty"`
	// ByStatus counts findings per lifecycle status.
	ByStatus map[Status]int `json:"byStatus,omitempty"`
	// ByRepo counts findings per top-level location (Location.Repo).
	ByRepo map[string]int `json:"byRepo,omitempty"`
}

// Summary computes an analytics rollup over the set in a single pass.
func (s *FindingSet) Summary() Summary {
	out := Summary{
		Total:      len(s.Findings),
		BySeverity: map[Severity]int{},
		ByDomain:   map[Domain]int{},
		ByStatus:   map[Status]int{},
		ByRepo:     map[string]int{},
	}
	for _, f := range s.Findings {
		out.BySeverity[f.Severity]++
		out.ByDomain[f.Domain]++
		out.ByStatus[f.Status]++
		repo := ""
		if f.Location != nil {
			repo = f.Location.Repo
		}
		out.ByRepo[repo]++
		if f.Status.Open() {
			out.Open++
		}
		if f.Severity.Actionable() {
			out.Actionable++
		}
	}
	return out
}
