package findingspec

// Reference is an external link supporting a finding or its remediation, such as
// an advisory, standard, or documentation page.
type Reference struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url"`
}
