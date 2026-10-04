package findingspec

// Evidence is a supporting artifact that substantiates a finding, such as a
// screenshot, an HTTP response, a stack trace, or a code excerpt.
type Evidence struct {
	// Kind categorizes the evidence, e.g. "screenshot", "html", "log",
	// "trace", "http-response", "code".
	Kind string `json:"kind"`
	// Summary is a short human-readable description of the evidence.
	Summary string `json:"summary,omitempty"`
	// Data holds inline evidence content; binary content should be base64.
	Data string `json:"data,omitempty"`
	// URI points to externally-stored evidence when it is not inlined.
	URI string `json:"uri,omitempty"`
	// MediaType is the IANA media type of Data or the URI target, if known.
	MediaType string `json:"mediaType,omitempty"`
}
