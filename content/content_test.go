package content_test

import (
	"strings"
	"testing"

	"github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/content"
)

func TestIssueToFinding(t *testing.T) {
	f := content.Issue{
		ID: "CF-1", Rule: content.RuleQuoteNotFound, Title: "Quotation not found in its source",
		ClaimID: "claim-founding", Statement: "The company was founded in 1929.", SourceRef: "src-history",
		Document: "claims/company.json", Status: findingspec.StatusOpen,
		Remediation: &findingspec.Remediation{Summary: "Quote the source exactly.", AgentPrompt: "Find the passage."},
	}.ToFinding()

	if f.Domain != findingspec.DomainContent || f.RuleID != content.RuleQuoteNotFound || f.Severity != findingspec.SeverityMedium {
		t.Errorf("finding = %+v", f)
	}
	if f.Location == nil || f.Location.Component != "claim-founding" || f.Location.File != "claims/company.json" ||
		f.Location.Snippet == "" {
		t.Errorf("location = %+v", f.Location)
	}
	if len(f.Tags) != 2 || f.Tags[0] != "claim:claim-founding" || f.Tags[1] != "source:src-history" {
		t.Errorf("tags = %v", f.Tags)
	}
	if got := content.ClaimID(f); got != "claim-founding" {
		t.Errorf("ClaimID = %q", got)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestClaimIDOtherDomain(t *testing.T) {
	f := findingspec.Finding{Domain: findingspec.DomainQE, Location: &findingspec.Location{Component: "x"}}
	if got := content.ClaimID(f); got != "" {
		t.Errorf("ClaimID of a qe finding = %q, want empty", got)
	}
}

func TestContentDomainValid(t *testing.T) {
	if !findingspec.DomainContent.Valid() {
		t.Error("content domain is not valid")
	}
}

func TestAudioQuoteRules(t *testing.T) {
	f := content.Issue{
		ID: "CF-2", Rule: content.RuleQuoteAudioMismatch, Title: "Quotation differs from the recording",
		ClaimID: "claim-agentic", Statement: "AI assisted gentle coding", SourceRef: "src-aws-podcast-753",
		Evidence: []findingspec.Evidence{{Kind: "transcript", Summary: "deepgram, elevenlabs and openai heard: AI assisted agentic coding", URI: "checks/round-1/audio.json"}},
	}.ToFinding()
	if f.RuleID != "content.quote.audioMismatch" || f.Type != content.TypeClaim || content.ClaimID(f) != "claim-agentic" {
		t.Errorf("finding = %+v", f)
	}
	for _, r := range []string{content.RuleQuoteAudioDisputed, content.RuleQuoteAudioMismatch, content.RuleQuoteAudioUnchecked, content.RuleNarrationMismatch} {
		if !strings.HasPrefix(r, "content.") {
			t.Errorf("rule %q lacks the content prefix", r)
		}
	}
}

func TestNarrationIssueToFinding(t *testing.T) {
	f := content.NarrationIssue{
		ID: "NAR-1", Rule: content.RuleNarrationMismatch, Title: "Narration drops a word",
		Document: "sections/02/deck/index.html", Segment: "utm-tags", Expected: "Tag every link with UTM parameters.",
		Heard: "Tag every link with parameters.", Recording: "audio/utm-tags.mp3",
	}.ToFinding()
	if f.Domain != findingspec.DomainContent || f.Type != content.TypeNarration || f.Severity != findingspec.SeverityMedium {
		t.Errorf("finding = %+v", f)
	}
	if content.Segment(f) != "utm-tags" {
		t.Errorf("Segment = %q", content.Segment(f))
	}
	if content.ClaimID(f) != "" {
		t.Errorf("ClaimID of a narration finding = %q, want empty", content.ClaimID(f))
	}
	if len(f.Tags) != 2 || f.Tags[0] != "segment:utm-tags" || f.Tags[1] != "recording:audio/utm-tags.mp3" {
		t.Errorf("tags = %v", f.Tags)
	}
}

func TestClaimIDUntypedFinding(t *testing.T) {
	f := findingspec.Finding{Domain: findingspec.DomainContent, Location: &findingspec.Location{Component: "claim-x"}}
	if content.ClaimID(f) != "claim-x" {
		t.Errorf("an untyped content finding should still give its claim")
	}
}
