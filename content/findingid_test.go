package content_test

import (
	"testing"

	"github.com/plexusone/findingspec/content"
)

func TestFindingID(t *testing.T) {
	cases := []struct{ prefix, subject, rule, want string }{
		{"CF", "claim-founding", content.RuleLessPrecise, "CF-claim-founding-lessPrecise"},
		{"AV", "claim-q3", content.RuleQuoteAudioDisputed, "AV-claim-q3-audioDisputed"},
		{"NR", "lesson-1-slide-4", content.RuleNarrationMismatch, "NR-lesson-1-slide-4-mismatch"},
		{"CF", "", content.RuleReviewNote, "CF-note"},
	}
	for _, c := range cases {
		if got := content.FindingID(c.prefix, c.subject, c.rule); got != c.want {
			t.Errorf("FindingID(%q, %q, %q) = %q, want %q", c.prefix, c.subject, c.rule, got, c.want)
		}
	}
}
