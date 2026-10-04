// Package axe ingests axe-core accessibility results (the JSON produced by
// axe.run(), as emitted by @axe-core/cli, Playwright/axe, CI reporters, etc.)
// and normalizes them into findingspec Findings (a11y domain, type "wcag"). It
// depends only on axe-core's stable JSON shape, not on any library.
package axe

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	findingspec "github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/a11y"
)

// Results is the top level of an axe-core run (axe.run() output).
type Results struct {
	URL        string      `json:"url"`
	Timestamp  string      `json:"timestamp"`
	Violations []Violation `json:"violations"`
	Incomplete []Violation `json:"incomplete"`
}

// Violation is one failed (or, under Incomplete, needs-review) axe rule.
type Violation struct {
	ID          string   `json:"id"`     // axe rule id, e.g. "color-contrast"
	Impact      string   `json:"impact"` // minor|moderate|serious|critical
	Tags        []string `json:"tags"`   // e.g. wcag2aa, wcag143, best-practice
	Description string   `json:"description"`
	Help        string   `json:"help"`
	HelpURL     string   `json:"helpUrl"`
	Nodes       []Node   `json:"nodes"`
}

// Node is one element instance a rule matched.
type Node struct {
	Target         []any  `json:"target"` // CSS selector(s); may nest for frames
	HTML           string `json:"html"`
	FailureSummary string `json:"failureSummary"`
	Impact         string `json:"impact"`
}

// Options configures normalization.
type Options struct {
	// IncludeIncomplete also ingests axe's "incomplete" (needs-review) results,
	// marked with confidence low and an "axe:incomplete" tag.
	IncludeIncomplete bool
}

// Parse decodes axe-core JSON results from r and returns a normalized
// FindingSet.
func Parse(r io.Reader, opts Options) (*findingspec.FindingSet, error) {
	var res Results
	if err := json.NewDecoder(r).Decode(&res); err != nil {
		return nil, fmt.Errorf("axe: decode results: %w", err)
	}
	return res.Findings(opts), nil
}

// Findings converts axe results into a findingspec.FindingSet, one finding per
// matched element (violation × node).
func (res Results) Findings(opts Options) *findingspec.FindingSet {
	set := findingspec.NewFindingSet()
	for _, v := range res.Violations {
		for _, n := range v.Nodes {
			set.Add(toFinding(res, v, n))
		}
	}
	if opts.IncludeIncomplete {
		for _, v := range res.Incomplete {
			for _, n := range v.Nodes {
				f := toFinding(res, v, n)
				f.Confidence = findingspec.ConfidenceLow
				f.Tags = append(f.Tags, "axe:incomplete")
				set.Add(f)
			}
		}
	}
	return set
}

func toFinding(res Results, v Violation, n Node) findingspec.Finding {
	impact := n.Impact
	if impact == "" {
		impact = v.Impact
	}
	sel := selector(n.Target)
	issue := a11y.Issue{
		ID:          fmt.Sprintf("%s|%s", v.ID, sel),
		Title:       v.Help,
		Description: v.Description,
		Criterion:   criterionFromTags(v.Tags),
		Level:       levelFromTags(v.Tags),
		Impact:      a11y.Impact(impact),
		HelpURL:     v.HelpURL,
		Rule:        v.ID,
		Location: &findingspec.Location{
			URL:      res.URL,
			Selector: sel,
			Snippet:  n.HTML,
		},
	}
	if n.FailureSummary != "" {
		issue.Remediation = &findingspec.Remediation{Summary: n.FailureSummary}
	}
	f := issue.ToFinding()
	f.Source = findingspec.Source{Tool: "axe-core", RuleSet: "WCAG"}
	return f
}

var wcagCriterionTag = regexp.MustCompile(`^wcag(\d{3,})$`)

// criterionFromTags extracts a WCAG success-criterion number from axe tags:
// "wcag143" → "1.4.3", "wcag1410" → "1.4.10". Level tags like "wcag2aa"
// (which contain letters) are ignored here.
func criterionFromTags(tags []string) string {
	for _, t := range tags {
		if m := wcagCriterionTag.FindStringSubmatch(t); m != nil {
			d := m[1]
			return fmt.Sprintf("%c.%c.%s", d[0], d[1], d[2:])
		}
	}
	return ""
}

// levelFromTags derives the WCAG conformance level from axe version tags
// ("wcag2a"/"wcag21aa"/"wcag2aaa"/…).
func levelFromTags(tags []string) a11y.ConformanceLevel {
	has := func(suffixes ...string) bool {
		for _, t := range tags {
			if !strings.HasPrefix(t, "wcag2") {
				continue
			}
			for _, s := range suffixes {
				if strings.HasSuffix(t, s) {
					return true
				}
			}
		}
		return false
	}
	switch {
	case has("aaa"):
		return a11y.LevelAAA
	case has("aa"):
		return a11y.LevelAA
	case has("a"):
		return a11y.LevelA
	default:
		return ""
	}
}

// selector flattens an axe target (strings, possibly nested for frames) into a
// single descriptive selector string.
func selector(target []any) string {
	var parts []string
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			parts = append(parts, t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	for _, e := range target {
		walk(e)
	}
	return strings.Join(parts, " ")
}
