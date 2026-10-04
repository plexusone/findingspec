package security

import (
	"time"

	"github.com/plexusone/findingspec"
)

// SecretKind categorizes a detected secret.
type SecretKind string

const (
	SecretKindAPIKey           SecretKind = "api_key"
	SecretKindToken            SecretKind = "token"
	SecretKindPassword         SecretKind = "password"
	SecretKindPrivateKey       SecretKind = "private_key"
	SecretKindCertificate      SecretKind = "certificate"
	SecretKindConnectionString SecretKind = "connection_string"
	SecretKindGeneric          SecretKind = "generic"
)

// SecretValidation records whether a detected secret was verified against its
// provider (i.e. confirmed live), when a detector supports validation.
type SecretValidation string

const (
	SecretValidationUnknown  SecretValidation = "unknown"
	SecretValidationActive   SecretValidation = "active"
	SecretValidationInactive SecretValidation = "inactive"
)

// Secret is a security finding for a detected credential or secret — for
// example an API key, token, password, or private key discovered in source, a
// config file, or a structured document such as an OpenAPI spec or Postman
// collection.
//
// The raw secret value is never stored; only a redacted preview. The exact
// location within a structured document is carried on Location.Pointer (a JSON
// Pointer) together with Location.DocFormat.
type Secret struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`

	// Kind categorizes the secret.
	Kind SecretKind `json:"kind,omitempty"`
	// Detector is the rule or detector that matched, e.g. "aws-access-key-id"
	// or "stripe-secret-key".
	Detector string `json:"detector,omitempty"`
	// Provider is the service the secret belongs to, e.g. "aws", "stripe",
	// "github", when known.
	Provider string `json:"provider,omitempty"`
	// Redacted is a masked preview of the secret, e.g. "AKIA****…****1234".
	// The raw value must not be stored here.
	Redacted string `json:"redacted,omitempty"`
	// Entropy is the Shannon entropy of the match, when computed.
	Entropy float64 `json:"entropy,omitempty"`
	// Validation records whether the secret was confirmed live.
	Validation SecretValidation `json:"validation,omitempty"`

	// Severity is the impact; defaults to High when unset, since an exposed
	// live credential is typically high-impact.
	Severity findingspec.Severity `json:"severity,omitempty"`

	// Location is where the secret was found. For a structured document, set
	// Location.File, Location.DocFormat (e.g. "openapi", "postman"), and
	// Location.Pointer (an RFC 6901 JSON Pointer to the offending node).
	Location    *findingspec.Location    `json:"location,omitempty"`
	Remediation *findingspec.Remediation `json:"remediation,omitempty"`
	Status      findingspec.Status       `json:"status,omitempty"`
	DetectedAt  *time.Time               `json:"detectedAt,omitempty"`
}

// ruleID returns the most specific classifier for the secret: the detector,
// else the kind.
func (s Secret) ruleID() string {
	if s.Detector != "" {
		return s.Detector
	}
	return string(s.Kind)
}

// ToFinding projects the secret into a domain-neutral findingspec.Finding in the
// security domain. Severity defaults to High when unset. The finding never
// carries the raw secret — only the redacted preview and its location.
// Redacted is copied into a copy of Location's Snippet field when Location is
// set and does not already carry one, so a consumer that only looks at the
// generic Finding still sees the redacted preview.
func (s Secret) ToFinding() findingspec.Finding {
	sev := s.Severity
	if sev == "" {
		sev = findingspec.SeverityHigh
	}
	tags := []string{"secret"}
	if s.Kind != "" {
		tags = append(tags, string(s.Kind))
	}
	if s.Provider != "" {
		tags = append(tags, "provider:"+s.Provider)
	}
	if s.Validation == SecretValidationActive {
		tags = append(tags, "validated:active")
	}
	f := findingspec.Finding{
		ID:          s.ID,
		Domain:      findingspec.DomainSecurity,
		Type:        TypeSecret,
		RuleID:      s.ruleID(),
		Title:       s.Title,
		Description: s.Description,
		Severity:    sev,
		Status:      s.Status,
		Location:    withSnippet(s.Location, s.Redacted),
		Remediation: s.Remediation,
		Tags:        tags,
		DetectedAt:  s.DetectedAt,
	}
	// Detail carries the secret-specific payload (never the raw value).
	_ = f.SetDetail(SecretDetail{
		Kind:       s.Kind,
		Detector:   s.Detector,
		Provider:   s.Provider,
		Redacted:   s.Redacted,
		Entropy:    s.Entropy,
		Validation: s.Validation,
	})
	return f
}

// SecretDetail is the per-type Detail payload for a secret finding
// (findingspec.Finding.Type == TypeSecret). It holds the secret-specific fields
// not already promoted to the canonical header; it never contains the raw
// secret, only the redacted preview.
type SecretDetail struct {
	Kind       SecretKind       `json:"kind,omitempty"`
	Detector   string           `json:"detector,omitempty"`
	Provider   string           `json:"provider,omitempty"`
	Redacted   string           `json:"redacted,omitempty"`
	Entropy    float64          `json:"entropy,omitempty"`
	Validation SecretValidation `json:"validation,omitempty"`
}

// withSnippet returns a copy of loc with Snippet set to redacted, when loc is
// non-nil and does not already carry a Snippet — never mutating the
// caller's original Location. Returns nil unchanged.
func withSnippet(loc *findingspec.Location, redacted string) *findingspec.Location {
	if loc == nil || redacted == "" || loc.Snippet != "" {
		return loc
	}
	cp := *loc
	cp.Snippet = redacted
	return &cp
}
