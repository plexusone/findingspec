package findingspec

// Source identifies the tool or producer that generated a finding.
type Source struct {
	// Tool is the producer name, e.g. "govex", "agent-a11y", "w3pilot".
	Tool string `json:"tool"`
	// Version is the producer version, if known.
	Version string `json:"version,omitempty"`
	// RuleSet names the rule catalog or standard the producer applied, e.g.
	// "WCAG-2.2", "CWE", "OWASP-ASVS".
	RuleSet string `json:"ruleSet,omitempty"`
}
