package gitleaks

import (
	"strings"
	"testing"

	"github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/security"
)

const sampleReport = `[
  {
    "Description": "AWS Access Key",
    "StartLine": 12,
    "StartColumn": 5,
    "Match": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "File": "config/prod.env",
    "Commit": "a1b2c3d4e5f6",
    "Entropy": 3.65,
    "Date": "2026-09-20T10:00:00Z",
    "Tags": ["key", "AWS"],
    "RuleID": "aws-access-token",
    "Fingerprint": "a1b2c3d4:config/prod.env:aws-access-token:12"
  },
  {
    "Description": "Generic API Key",
    "StartLine": 3,
    "File": "src/client.go",
    "Secret": "sk_live_abcd1234efgh5678",
    "Entropy": 4.1,
    "RuleID": "generic-api-key"
  }
]`

func TestParse(t *testing.T) {
	set, err := Parse(strings.NewReader(sampleReport), Options{Repo: "acme/app"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d; want 2", set.Len())
	}

	// Every finding normalizes to a valid security/secret finding.
	for _, f := range set.Findings {
		if err := f.Validate(); err != nil {
			t.Fatalf("invalid finding: %v", err)
		}
		if f.Domain != findingspec.DomainSecurity || f.Type != security.TypeSecret {
			t.Errorf("domain/type = %s/%s; want security/secret", f.Domain, f.Type)
		}
		if f.Source.Tool != "gitleaks" {
			t.Errorf("source tool = %q; want gitleaks", f.Source.Tool)
		}
		if f.Location.Repo != "acme/app" {
			t.Errorf("repo = %q; want acme/app", f.Location.Repo)
		}
	}

	first := set.Findings[0]
	if first.ID != "a1b2c3d4:config/prod.env:aws-access-token:12" {
		t.Errorf("ID = %q; want fingerprint", first.ID)
	}
	if first.DetectedAt == nil {
		t.Error("DetectedAt should be parsed from Date")
	}
	// Provider + kind inferred from the rule ID.
	detail, err := findingspec.DetailAs[security.SecretDetail](first)
	if err != nil {
		t.Fatalf("DetailAs: %v", err)
	}
	if detail.Provider != "aws" {
		t.Errorf("provider = %q; want aws", detail.Provider)
	}
	if detail.Kind != security.SecretKindAPIKey {
		t.Errorf("kind = %q; want api_key", detail.Kind)
	}
	// The raw secret must never survive; only the redacted preview.
	if strings.Contains(detail.Redacted, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("raw secret leaked into Redacted: %q", detail.Redacted)
	}
	if !strings.HasPrefix(detail.Redacted, "AKIA") || !strings.HasSuffix(detail.Redacted, "MPLE") {
		t.Errorf("redaction should keep first/last 4: %q", detail.Redacted)
	}
	// commit tag added
	foundCommit := false
	for _, tg := range first.Tags {
		if tg == "commit:a1b2c3d4e5f6" {
			foundCommit = true
		}
	}
	if !foundCommit {
		t.Errorf("expected commit tag; got %v", first.Tags)
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"short":                "*****",
		"AKIAIOSFODNN7EXAMPLE": "AKIA" + strings.Repeat("*", 12) + "MPLE",
	}
	for in, want := range cases {
		if got := redact(in); got != want {
			t.Errorf("redact(%q) = %q; want %q", in, got, want)
		}
	}
}
