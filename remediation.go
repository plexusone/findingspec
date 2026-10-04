package findingspec

// Remediation describes how to resolve a finding. It carries both a
// human-readable summary and an optional AgentPrompt — an instruction phrased
// for an AI builder to apply the fix directly.
type Remediation struct {
	// Summary is a concise statement of the fix.
	Summary string `json:"summary"`
	// Detail is an optional longer explanation.
	Detail string `json:"detail,omitempty"`
	// AgentPrompt is an instruction suitable for handing to an AI code builder
	// (e.g. "fix this without changing application behavior").
	AgentPrompt string `json:"agentPrompt,omitempty"`
	// Effort is a coarse estimate, e.g. "low", "medium", "high".
	Effort string `json:"effort,omitempty"`
	// References supports the remediation with external links.
	References []Reference `json:"references,omitempty"`
}
