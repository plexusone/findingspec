package findingspec

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// FindingSet is a collection of findings with convenience helpers for
// filtering, counting, and ordering across domains.
type FindingSet struct {
	Findings []Finding `json:"findings"`
}

// NewFindingSet returns a FindingSet containing the provided findings.
func NewFindingSet(findings ...Finding) *FindingSet {
	return &FindingSet{Findings: findings}
}

// Add appends findings to the set.
func (s *FindingSet) Add(findings ...Finding) {
	s.Findings = append(s.Findings, findings...)
}

// ErrDuplicateID is returned by Merge when two findings share an ID.
var ErrDuplicateID = errors.New("findingspec: duplicate finding ID")

// Merge combines the findings of several sets, in order, into a new set,
// for example the findings that several tools wrote about the same work.
// IDs must be unique across the sets: two findings with the same non-empty
// ID make Merge fail with ErrDuplicateID, naming each repeated ID, since
// each producer should build IDs that cannot collide with another's. Nil
// sets are skipped.
func Merge(sets ...*FindingSet) (*FindingSet, error) {
	out := NewFindingSet()
	seen := map[string]bool{}
	var dups []string
	for _, s := range sets {
		if s == nil {
			continue
		}
		for _, f := range s.Findings {
			if f.ID != "" && seen[f.ID] {
				dups = append(dups, f.ID)
			}
			seen[f.ID] = true
			out.Add(f)
		}
	}
	if len(dups) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrDuplicateID, strings.Join(dups, ", "))
	}
	return out, nil
}

// Len returns the number of findings in the set.
func (s *FindingSet) Len() int { return len(s.Findings) }

// Domain returns a new set containing only findings in the given domain.
func (s *FindingSet) Domain(d Domain) *FindingSet {
	return s.filter(func(f Finding) bool { return f.Domain == d })
}

// Severity returns a new set containing only findings of the given severity.
func (s *FindingSet) Severity(sev Severity) *FindingSet {
	return s.filter(func(f Finding) bool { return f.Severity == sev })
}

// Open returns a new set containing only findings whose status still requires
// attention.
func (s *FindingSet) Open() *FindingSet {
	return s.filter(func(f Finding) bool { return f.Status.Open() })
}

func (s *FindingSet) filter(keep func(Finding) bool) *FindingSet {
	out := &FindingSet{}
	for _, f := range s.Findings {
		if keep(f) {
			out.Findings = append(out.Findings, f)
		}
	}
	return out
}

// CountBySeverity returns the number of findings at each severity.
func (s *FindingSet) CountBySeverity() map[Severity]int {
	counts := map[Severity]int{}
	for _, f := range s.Findings {
		counts[f.Severity]++
	}
	return counts
}

// CountByDomain returns the number of findings in each domain.
func (s *FindingSet) CountByDomain() map[Domain]int {
	counts := map[Domain]int{}
	for _, f := range s.Findings {
		counts[f.Domain]++
	}
	return counts
}

// CountByStatus returns the number of findings in each status.
func (s *FindingSet) CountByStatus() map[Status]int {
	counts := map[Status]int{}
	for _, f := range s.Findings {
		counts[f.Status]++
	}
	return counts
}

// CountBy groups findings by a caller-provided key function, returning the count
// per distinct key. It is the general form behind the typed CountBy* helpers;
// use it for any dimension that lacks a dedicated helper, e.g. by rule:
//
//	set.CountBy(func(f findingspec.Finding) string { return f.RuleID })
func (s *FindingSet) CountBy(key func(Finding) string) map[string]int {
	counts := map[string]int{}
	for _, f := range s.Findings {
		counts[key(f)]++
	}
	return counts
}

// CountBySource returns the number of findings per producing tool
// (Source.Tool). Findings with no tool are counted under "".
func (s *FindingSet) CountBySource() map[string]int {
	return s.CountBy(func(f Finding) string { return f.Source.Tool })
}

// CountByRepo returns the number of findings per top-level location — the
// repository or workspace (Location.Repo). Findings without a location or repo
// are counted under "".
func (s *FindingSet) CountByRepo() map[string]int {
	return s.CountBy(func(f Finding) string {
		if f.Location == nil {
			return ""
		}
		return f.Location.Repo
	})
}

// CountByFile returns the number of findings per file (Location.File). Findings
// without a location or file are counted under "".
func (s *FindingSet) CountByFile() map[string]int {
	return s.CountBy(func(f Finding) string {
		if f.Location == nil {
			return ""
		}
		return f.Location.File
	})
}

// SortBySeverity orders the findings in place from most to least severe, with
// ties broken by domain then ID for stable output.
func (s *FindingSet) SortBySeverity() {
	sort.SliceStable(s.Findings, func(i, j int) bool {
		a, b := s.Findings[i], s.Findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		return a.ID < b.ID
	})
}
