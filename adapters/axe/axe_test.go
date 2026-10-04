package axe

import (
	"strings"
	"testing"

	findingspec "github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/a11y"
)

const sampleReport = `{
  "url": "https://example.com/",
  "timestamp": "2026-09-29T10:00:00.000Z",
  "violations": [
    {
      "id": "color-contrast",
      "impact": "serious",
      "tags": ["cat.color", "wcag2aa", "wcag143"],
      "description": "Ensures the contrast between foreground and background colors meets WCAG 2 AA thresholds",
      "help": "Elements must meet minimum color contrast ratio thresholds",
      "helpUrl": "https://dequeuniversity.com/rules/axe/4.9/color-contrast",
      "nodes": [
        { "target": ["main > p.muted"], "html": "<p class=\"muted\">hi</p>", "failureSummary": "Fix any of the following: contrast 2.1", "impact": "serious" },
        { "target": ["footer span"], "html": "<span>x</span>", "failureSummary": "Fix contrast", "impact": "serious" }
      ]
    },
    {
      "id": "image-alt",
      "impact": "critical",
      "tags": ["wcag2a", "wcag111"],
      "description": "Ensures <img> elements have alternate text",
      "help": "Images must have alternate text",
      "helpUrl": "https://dequeuniversity.com/rules/axe/4.9/image-alt",
      "nodes": [
        { "target": [["#frame"], "img.hero"], "html": "<img class=\"hero\">", "failureSummary": "Add alt", "impact": "critical" }
      ]
    }
  ],
  "incomplete": [
    { "id": "aria-hidden-focus", "impact": "serious", "tags": ["wcag2a", "wcag412"], "help": "ARIA hidden focus",
      "nodes": [ { "target": ["button.x"], "html": "<button>", "failureSummary": "review", "impact": "serious" } ] }
  ]
}`

func TestFindings(t *testing.T) {
	set, err := Parse(strings.NewReader(sampleReport), Options{})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.Len() != 3 { // 2 color-contrast nodes + 1 image-alt node (incomplete excluded)
		t.Fatalf("Len = %d; want 3", set.Len())
	}

	for _, f := range set.Findings {
		if err := f.Validate(); err != nil {
			t.Fatalf("invalid finding: %v", err)
		}
		if f.Domain != findingspec.DomainA11y || f.Type != a11y.TypeWCAG {
			t.Errorf("domain/type = %s/%s; want a11y/wcag", f.Domain, f.Type)
		}
		if f.Source.Tool != "axe-core" {
			t.Errorf("source = %q; want axe-core", f.Source.Tool)
		}
		if f.Location.URL != "https://example.com/" {
			t.Errorf("url = %q", f.Location.URL)
		}
	}

	first := set.Findings[0]
	if first.Severity != findingspec.SeverityHigh { // serious → High
		t.Errorf("severity = %q; want high", first.Severity)
	}
	if first.RuleID != "WCAG 1.4.3 (AA)" {
		t.Errorf("ruleID = %q; want WCAG 1.4.3 (AA)", first.RuleID)
	}
	if first.Location.Selector != "main > p.muted" {
		t.Errorf("selector = %q", first.Location.Selector)
	}
	d, err := findingspec.DetailAs[a11y.Detail](first)
	if err != nil {
		t.Fatalf("DetailAs: %v", err)
	}
	if d.Criterion != "1.4.3" || d.Level != a11y.LevelAA || d.Rule != "color-contrast" {
		t.Errorf("detail = %+v", d)
	}

	// image-alt: critical → Critical, criterion 1.1.1 level A, nested frame selector flattened
	var imageAlt *findingspec.Finding
	for i := range set.Findings {
		if strings.HasPrefix(set.Findings[i].ID, "image-alt") {
			imageAlt = &set.Findings[i]
		}
	}
	if imageAlt == nil {
		t.Fatal("image-alt finding missing")
	}
	if imageAlt.Severity != findingspec.SeverityCritical {
		t.Errorf("image-alt severity = %q; want critical", imageAlt.Severity)
	}
	if imageAlt.RuleID != "WCAG 1.1.1 (A)" {
		t.Errorf("image-alt ruleID = %q", imageAlt.RuleID)
	}
	if imageAlt.Location.Selector != "#frame img.hero" {
		t.Errorf("nested selector = %q; want '#frame img.hero'", imageAlt.Location.Selector)
	}
}

func TestIncludeIncomplete(t *testing.T) {
	set, err := Parse(strings.NewReader(sampleReport), Options{IncludeIncomplete: true})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.Len() != 4 { // + 1 incomplete
		t.Fatalf("Len = %d; want 4", set.Len())
	}
	// the incomplete finding is low confidence + tagged
	var inc *findingspec.Finding
	for i := range set.Findings {
		if strings.HasPrefix(set.Findings[i].ID, "aria-hidden-focus") {
			inc = &set.Findings[i]
		}
	}
	if inc == nil {
		t.Fatal("incomplete finding missing")
	}
	if inc.Confidence != findingspec.ConfidenceLow {
		t.Errorf("confidence = %q; want low", inc.Confidence)
	}
	found := false
	for _, tg := range inc.Tags {
		if tg == "axe:incomplete" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected axe:incomplete tag; got %v", inc.Tags)
	}
}
