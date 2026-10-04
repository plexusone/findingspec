package security

import (
	"strings"
	"testing"

	"github.com/plexusone/findingspec"
)

func TestSecretToFinding_OpenAPI(t *testing.T) {
	s := Secret{
		ID:       "SEC-1",
		Title:    "AWS access key in OpenAPI server variable",
		Kind:     SecretKindAPIKey,
		Detector: "aws-access-key-id",
		Provider: "aws",
		Redacted: "AKIA****************1234",
		Location: &findingspec.Location{
			File:      "openapi.json",
			DocFormat: "openapi",
			Pointer:   "/servers/0/variables/apiKey/default",
		},
	}
	f := s.ToFinding()
	if err := f.Validate(); err != nil {
		t.Fatalf("invalid finding: %v", err)
	}
	if f.Domain != findingspec.DomainSecurity {
		t.Errorf("domain = %q; want security", f.Domain)
	}
	if f.Severity != findingspec.SeverityHigh {
		t.Errorf("default severity = %q; want High", f.Severity)
	}
	if f.RuleID != "aws-access-key-id" {
		t.Errorf("ruleID = %q; want detector", f.RuleID)
	}
	if f.Location.Pointer != "/servers/0/variables/apiKey/default" || f.Location.DocFormat != "openapi" {
		t.Errorf("location pointer/format not carried: %+v", f.Location)
	}
	// The raw secret must never appear; only the redacted preview.
	if !strings.Contains(f.Location.Pointer, "/servers/0") {
		t.Errorf("expected JSON Pointer to the node")
	}
	hasSecretTag := false
	for _, tg := range f.Tags {
		if tg == "secret" {
			hasSecretTag = true
		}
	}
	if !hasSecretTag {
		t.Errorf("expected 'secret' tag; got %v", f.Tags)
	}
}

func TestSecretToFinding_RedactedCopiedToSnippet(t *testing.T) {
	loc := &findingspec.Location{File: "config.go", Line: 12}
	s := Secret{
		ID:       "SEC-3",
		Title:    "AWS access key",
		Redacted: "AKIA****************1234",
		Location: loc,
	}
	f := s.ToFinding()
	if f.Location.Snippet != "AKIA****************1234" {
		t.Errorf("Location.Snippet = %q; want the redacted preview", f.Location.Snippet)
	}
	if loc.Snippet != "" {
		t.Errorf("original Location must not be mutated, got Snippet = %q", loc.Snippet)
	}
}

func TestSecretToFinding_Postman(t *testing.T) {
	s := Secret{
		ID:         "SEC-2",
		Title:      "Bearer token in Postman header",
		Kind:       SecretKindToken,
		Detector:   "generic-bearer-token",
		Validation: SecretValidationActive,
		Severity:   findingspec.SeverityCritical,
		Location: &findingspec.Location{
			File:      "collection.postman_collection.json",
			DocFormat: "postman",
			Pointer:   "/item/2/request/header/1/value",
		},
	}
	f := s.ToFinding()
	if f.Severity != findingspec.SeverityCritical {
		t.Errorf("severity = %q; want Critical", f.Severity)
	}
	foundValidated := false
	for _, tg := range f.Tags {
		if tg == "validated:active" {
			foundValidated = true
		}
	}
	if !foundValidated {
		t.Errorf("expected 'validated:active' tag; got %v", f.Tags)
	}
}
