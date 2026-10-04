package findingspec

// Location describes where a finding was observed. Its fields are intentionally
// domain-flexible: a code-level finding (security, i18n) typically uses File and
// Line, while a runtime UI finding (a11y, qe) typically uses URL and Selector.
// Component names the logical module or capability regardless of representation.
type Location struct {
	// Repo identifies the repository or workspace a finding belongs to, when
	// a producer scans more than one (e.g. a multi-repo sweep, or a monorepo
	// workspace) — a path, URL, or module name, at the producer's discretion.
	// Empty when a producer only ever scans a single, implicit repository.
	Repo string `json:"repo,omitempty"`
	// File is a repository-relative source path.
	File string `json:"file,omitempty"`
	// Line is a 1-indexed line number within File.
	Line int `json:"line,omitempty"`
	// Column is a 1-indexed column within Line.
	Column int `json:"column,omitempty"`
	// URL is the address of the page or endpoint where the finding was observed.
	URL string `json:"url,omitempty"`
	// Selector is a CSS or XPath selector identifying a DOM element.
	Selector string `json:"selector,omitempty"`
	// Component is a logical component, module, or capability name.
	Component string `json:"component,omitempty"`
	// Pointer is an RFC 6901 JSON Pointer identifying a node within a structured
	// document (JSON/YAML), e.g. "/servers/0/variables/apiKey/default" in an
	// OpenAPI document or "/item/2/request/header/1/value" in a Postman
	// collection. It is a stable, format-independent locator preferable to
	// Line/Column for structured files.
	Pointer string `json:"pointer,omitempty"`
	// DocFormat names the structured-document format the File and Pointer refer
	// to, when relevant, e.g. "openapi", "postman", "json", "yaml".
	DocFormat string `json:"docFormat,omitempty"`
	// Snippet is a short excerpt of the offending code or markup.
	Snippet string `json:"snippet,omitempty"`
}

// Empty reports whether the location carries no information.
func (l Location) Empty() bool {
	return l == Location{}
}
