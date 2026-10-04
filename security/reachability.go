package security

// ReachabilityState describes whether a vulnerable symbol is actually reachable
// from the scanned application's own code, per call-graph analysis.
type ReachabilityState string

const (
	// ReachabilityReachable means the vulnerable symbol is called (in the call
	// graph) — the vulnerability is exploitable and should be prioritized.
	ReachabilityReachable ReachabilityState = "reachable"
	// ReachabilityUnreachable means the vulnerable package is present (imported
	// or required) but its vulnerable symbol is never called — usually
	// deprioritizable noise.
	ReachabilityUnreachable ReachabilityState = "unreachable"
	// ReachabilityUnknown means reachability was not determined (no call-graph
	// analysis was performed).
	ReachabilityUnknown ReachabilityState = "unknown"
)

// Reachability captures call-graph reachability for a vulnerability — a primary
// prioritization signal: a reachable vulnerability is exploitable, while an
// unreachable one is typically noise. It is populated by analyzers that perform
// call-graph analysis (e.g. govulncheck); most scanners leave it nil.
type Reachability struct {
	// State is the reachability determination.
	State ReachabilityState `json:"state,omitempty"`
	// Symbol is the vulnerable symbol in question, e.g.
	// "golang.org/x/net/http2.processHeaders".
	Symbol string `json:"symbol,omitempty"`
	// Paths are example call chains from an application entry point to the
	// vulnerable symbol, each rendered as "entry → … → symbol".
	Paths []string `json:"paths,omitempty"`
}

// IsReachable reports whether the state is reachable. A nil receiver is not
// reachable.
func (r *Reachability) IsReachable() bool {
	return r != nil && r.State == ReachabilityReachable
}
