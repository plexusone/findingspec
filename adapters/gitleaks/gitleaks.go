// Package gitleaks ingests gitleaks JSON report output and normalizes it into
// findingspec Findings (security domain, type "secret"). It is a reference
// adapter: it depends only on the gitleaks report's stable JSON shape, not on the
// gitleaks library, so importing it stays lightweight.
package gitleaks

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/security"
)

// Finding mirrors a single entry in a gitleaks JSON report (gitleaks v8). Only
// the fields used for normalization are declared; unknown fields are ignored.
type Finding struct {
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	StartColumn int      `json:"StartColumn"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Date        string   `json:"Date"`
	Tags        []string `json:"Tags"`
	RuleID      string   `json:"RuleID"`
	Fingerprint string   `json:"Fingerprint"`
}

// Options configures normalization.
type Options struct {
	// Repo sets Location.Repo on every finding, for multi-repo sweeps. Optional.
	Repo string
}

// Parse decodes a gitleaks JSON report (a top-level array of findings) from r
// and returns a normalized FindingSet.
func Parse(r io.Reader, opts Options) (*findingspec.FindingSet, error) {
	var raw []Finding
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("gitleaks: decode report: %w", err)
	}
	set := findingspec.NewFindingSet()
	for _, gl := range raw {
		set.Add(ToFinding(gl, opts))
	}
	return set, nil
}

// ToFinding normalizes a single gitleaks finding into a findingspec.Finding.
func ToFinding(gl Finding, opts Options) findingspec.Finding {
	sec := security.Secret{
		ID:          findingID(gl),
		Title:       title(gl),
		Description: gl.Description,
		Kind:        inferKind(gl.RuleID),
		Detector:    gl.RuleID,
		Provider:    inferProvider(gl.RuleID),
		Redacted:    redact(secretValue(gl)),
		Entropy:     gl.Entropy,
		Location: &findingspec.Location{
			Repo:   opts.Repo,
			File:   gl.File,
			Line:   gl.StartLine,
			Column: gl.StartColumn,
		},
	}
	f := sec.ToFinding()
	f.Source = findingspec.Source{Tool: "gitleaks", RuleSet: "gitleaks"}
	f.Tags = append(f.Tags, gl.Tags...)
	if gl.Commit != "" {
		f.Tags = append(f.Tags, "commit:"+gl.Commit)
	}
	if t, err := time.Parse(time.RFC3339, gl.Date); err == nil {
		f.DetectedAt = &t
	}
	return f
}

func findingID(gl Finding) string {
	if gl.Fingerprint != "" {
		return gl.Fingerprint
	}
	return fmt.Sprintf("%s:%s:%d", gl.RuleID, gl.File, gl.StartLine)
}

func title(gl Finding) string {
	if gl.Description != "" {
		return gl.Description
	}
	if gl.RuleID != "" {
		return "Secret detected: " + gl.RuleID
	}
	return "Secret detected"
}

// secretValue prefers the captured Secret, falling back to the broader Match.
func secretValue(gl Finding) string {
	if gl.Secret != "" {
		return gl.Secret
	}
	return gl.Match
}

// redact masks a secret, preserving the first and last 4 characters as a hint.
// Values of 8 characters or fewer are fully masked. The raw value is never
// emitted.
func redact(s string) string {
	s = strings.TrimSpace(s)
	n := len(s)
	switch {
	case n == 0:
		return ""
	case n <= 8:
		return strings.Repeat("*", n)
	default:
		stars := n - 8
		if stars > 16 {
			stars = 16
		}
		return s[:4] + strings.Repeat("*", stars) + s[n-4:]
	}
}

// inferKind maps a gitleaks rule ID to a SecretKind by keyword.
func inferKind(ruleID string) security.SecretKind {
	r := strings.ToLower(ruleID)
	switch {
	case strings.Contains(r, "private-key"), strings.Contains(r, "private_key"),
		strings.Contains(r, "-pem"), strings.Contains(r, "rsa"):
		return security.SecretKindPrivateKey
	case strings.Contains(r, "password"), strings.Contains(r, "passwd"):
		return security.SecretKindPassword
	case strings.Contains(r, "api"), strings.Contains(r, "key"),
		strings.Contains(r, "secret"), strings.Contains(r, "access"):
		return security.SecretKindAPIKey
	case strings.Contains(r, "token"):
		return security.SecretKindToken
	default:
		return security.SecretKindGeneric
	}
}

// knownProviders are recognized rule-ID prefixes mapped to a provider tag.
var knownProviders = map[string]bool{
	"aws": true, "gcp": true, "azure": true, "github": true, "gitlab": true,
	"slack": true, "stripe": true, "twilio": true, "sendgrid": true,
	"square": true, "shopify": true, "openai": true, "anthropic": true,
	"datadog": true, "npm": true, "pypi": true, "digitalocean": true,
}

// inferProvider extracts a provider from a gitleaks rule ID's leading token
// (e.g. "aws-access-token" → "aws"), returning "" when not recognized.
func inferProvider(ruleID string) string {
	prefix, _, found := strings.Cut(strings.ToLower(ruleID), "-")
	if found && knownProviders[prefix] {
		return prefix
	}
	return ""
}
