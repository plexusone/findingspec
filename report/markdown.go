package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/plexusone/findingspec"
	"github.com/plexusone/findingspec/security"
)

// WriteMarkdown renders set as a pandoc-flavoured Markdown report. The set is
// not modified; findings are ordered by severity, then domain, then ID.
func WriteMarkdown(w io.Writer, set findingspec.FindingSet, opts Options) error {
	opts, err := opts.withDefaults()
	if err != nil {
		return err
	}
	sorted := findingspec.FindingSet{Findings: append([]findingspec.Finding(nil), set.Findings...)}
	sorted.SortBySeverity()

	r := &renderer{opts: opts, set: &sorted, anchors: map[string]string{}}
	r.assignAnchors()
	if err := r.metadata(); err != nil {
		return err
	}
	r.executiveSummary()
	r.authorSection("Scope and Methodology", opts.Scope)
	for _, s := range opts.Sections {
		r.authorSection(s.Title, s.Body)
	}
	r.overview()
	if err := r.details(); err != nil {
		return err
	}
	for _, s := range opts.Appendices {
		r.authorSection(s.Title, s.Body)
	}
	_, err = io.WriteString(w, r.b.String())
	return err
}

// MarkdownString renders set to a string. See WriteMarkdown.
func MarkdownString(set findingspec.FindingSet, opts Options) (string, error) {
	var b strings.Builder
	if err := WriteMarkdown(&b, set, opts); err != nil {
		return "", err
	}
	return b.String(), nil
}

type renderer struct {
	opts    Options
	set     *findingspec.FindingSet
	anchors map[string]string // finding ID -> header identifier
	b       strings.Builder
}

func (r *renderer) line(parts ...string) {
	for _, p := range parts {
		r.b.WriteString(p)
	}
	r.b.WriteByte('\n')
}

func (r *renderer) para(s string) {
	if strings.TrimSpace(s) == "" {
		return
	}
	r.line(s)
	r.line()
}

func (r *renderer) assignAnchors() {
	used := map[string]bool{}
	for _, f := range r.set.Findings {
		if _, ok := r.anchors[f.ID]; ok {
			continue
		}
		a := anchor(f.ID)
		for n := 2; used[a]; n++ {
			a = anchor(f.ID) + "-" + strconv.Itoa(n)
		}
		used[a] = true
		r.anchors[f.ID] = a
	}
}

func (r *renderer) metadata() error {
	o := r.opts
	r.line("---")
	fields := []struct{ key, val string }{
		{"title", o.Title},
		{"subtitle", o.Subtitle},
		{"date", o.Date},
		{"classification", o.Classification},
	}
	for _, f := range fields {
		if f.val == "" {
			continue
		}
		q, err := yamlString(f.val)
		if err != nil {
			return err
		}
		r.line(f.key, ": ", q)
		if f.key == "title" && len(o.Authors) > 0 {
			r.line("author:")
			for _, a := range o.Authors {
				qa, err := yamlString(a)
				if err != nil {
					return err
				}
				r.line("  - ", qa)
			}
		}
	}
	if !o.NoTOC {
		r.line("toc: true")
		r.line("toc-depth: 3")
	}
	r.line("---")
	r.line()

	var notice []string
	if o.Classification != "" {
		notice = append(notice, "**Classification:** "+escapeInline(o.Classification))
	}
	if o.internal() {
		notice = append(notice, "**Distribution:** Internal. This report includes exploit detail and must not be shared outside the owning team.")
	} else {
		notice = append(notice, "**Distribution:** Shareable. Exploit detail, evidence payloads, and code snippets are omitted.")
	}
	r.para(strings.Join(notice, "\\\n"))
	return nil
}

func (r *renderer) authorSection(title, body string) {
	if strings.TrimSpace(body) == "" {
		return
	}
	if title == "" {
		title = "Notes"
	}
	r.line("# ", escapeInline(title))
	r.line()
	r.para(strings.TrimSpace(body))
}

func (r *renderer) executiveSummary() {
	sum := r.set.Summary()
	r.line("# Executive Summary")
	r.line()
	r.para(strings.TrimSpace(r.opts.Summary))
	r.para(fmt.Sprintf("This report covers %d %s: %d open and %d actionable.",
		sum.Total, plural(sum.Total, "finding", "findings"), sum.Open, sum.Actionable))

	openBySev := r.set.Open().CountBySeverity()
	r.line("| Severity | Findings | Open |")
	r.line("|:---------|---------:|-----:|")
	for _, sev := range severitiesInOrder(sum.BySeverity) {
		r.line("| ", severityLabel(sev), " | ", strconv.Itoa(sum.BySeverity[sev]), " | ", strconv.Itoa(openBySev[sev]), " |")
	}
	r.line("| **Total** | **", strconv.Itoa(sum.Total), "** | **", strconv.Itoa(sum.Open), "** |")
	r.line()
	r.line(": Findings by severity")
	r.line()

	r.countTable("Repository", "Findings by repository", sum.ByRepo)
	byDomain := map[string]int{}
	for d, n := range sum.ByDomain {
		byDomain[string(d)] = n
	}
	r.countTable("Domain", "Findings by domain", byDomain)
}

// countTable writes a count table when the findings span more than one key.
func (r *renderer) countTable(header, caption string, counts map[string]int) {
	if len(counts) < 2 {
		return
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	r.line("| ", header, " | Findings |")
	r.line("|:", strings.Repeat("-", len(header)), "|---------:|")
	for _, k := range keys {
		label := escapeInline(k)
		if k == "" {
			label = "(unspecified)"
		}
		r.line("| ", label, " | ", strconv.Itoa(counts[k]), " |")
	}
	r.line()
	r.line(": ", caption)
	r.line()
}

func (r *renderer) overview() {
	if r.set.Len() == 0 {
		return
	}
	withRepo := false
	for _, f := range r.set.Findings {
		if f.Location != nil && f.Location.Repo != "" {
			withRepo = true
			break
		}
	}
	r.line("# Findings Overview")
	r.line()
	// Dash counts set pandoc's relative column widths.
	if withRepo {
		r.line("| ID | Title | Severity | Status | Repository |")
		r.line("|:------------------|:------------------------------------|:-------------|:---------|:----------------|")
	} else {
		r.line("| ID | Title | Severity | Status |")
		r.line("|:------------------|:---------------------------------------------|:-------------|:---------|")
	}
	for _, f := range r.set.Findings {
		cells := []string{
			"[" + escapeInline(f.ID) + "](#" + r.anchors[f.ID] + ")",
			escapeInline(f.Title),
			severityLabel(f.Severity),
			statusLabel(f.Status),
		}
		if withRepo {
			repo := ""
			if f.Location != nil {
				repo = escapeInline(f.Location.Repo)
			}
			cells = append(cells, repo)
		}
		r.line("| ", strings.Join(cells, " | "), " |")
	}
	r.line()
	r.line(": All findings, most severe first")
	r.line()
}

func (r *renderer) details() error {
	if r.set.Len() == 0 {
		return nil
	}
	r.line("# Detailed Findings")
	r.line()
	var current findingspec.Severity
	for i, f := range r.set.Findings {
		if i == 0 || f.Severity != current {
			current = f.Severity
			r.line("## ", severityLabel(current), " Severity")
			r.line()
		}
		if err := r.finding(f); err != nil {
			return fmt.Errorf("report: finding %s: %w", f.ID, err)
		}
	}
	return nil
}

func (r *renderer) finding(f findingspec.Finding) error {
	var vd *security.VulnerabilityDetail
	if f.Domain == findingspec.DomainSecurity && len(f.Detail) > 0 {
		d, err := findingspec.DetailAs[security.VulnerabilityDetail](f)
		if err != nil {
			return err
		}
		vd = &d
	}

	r.line("### ", escapeInline(f.ID), ": ", escapeInline(f.Title), " {#", r.anchors[f.ID], "}")
	r.line()
	r.attributes(f, vd)

	r.subsection("Description")
	r.para(escapeText(f.Description))

	if vd != nil {
		r.rootCause(vd.RootCause)
		r.impact(vd.Impact)
		if r.opts.internal() {
			r.exploit(vd.Exploit)
		}
		r.reachabilityPaths(vd.Reachability)
		r.controls(vd.Controls, vd.Exception)
	}
	if r.opts.internal() {
		r.evidence(f.Evidence)
		r.snippet(f.Location)
	}
	r.remediation(f.Remediation)
	r.verification(f.Verification)
	r.related(f.Relationships)
	r.references(f.References)
	return nil
}

func (r *renderer) subsection(title string) {
	r.line("#### ", title)
	r.line()
}

type attr struct{ name, value string }

func (r *renderer) attributes(f findingspec.Finding, vd *security.VulnerabilityDetail) {
	sev := severityLabel(f.Severity)
	if vd != nil && vd.ResidualSeverity != "" && vd.ResidualSeverity != f.Severity {
		sev += " (residual: " + severityLabel(vd.ResidualSeverity) + ")"
	}
	attrs := []attr{
		{"Severity", sev},
		{"Status", statusLabel(f.Status)},
		{"Confidence", humanize(string(f.Confidence))},
		{"Category", category(f)},
	}
	if vd != nil {
		attrs = append(attrs,
			attr{"CWE", escapeInline(strings.Join(vd.CWEs, ", "))},
			attr{"CVE", escapeInline(strings.Join(vd.CVEs, ", "))},
			attr{"CVSS", cvssLabel(vd.CVSS)},
			attr{"Exploitability", exploitabilityLabel(vd.Exploitability)},
			attr{"Reachability", reachabilityLabel(vd.Reachability, vd.Reachable)},
			attr{"Package", packageLabel(vd.Package)},
			attr{"Fixed in", fixLabel(vd.Fix)},
			attr{"Component", codeSpan(vd.Component)},
		)
	} else {
		attrs = append(attrs, attr{"Rule", escapeInline(f.RuleID)})
	}
	attrs = append(attrs,
		attr{"Location", locationLabel(f.Location)},
		attr{"Detected by", sourceLabel(f.Source)},
		attr{"Detected", dateLabel(f.DetectedAt)},
	)
	if f.Remediation != nil {
		attrs = append(attrs, attr{"Effort", humanize(f.Remediation.Effort)})
	}

	r.line("| Attribute | Value |")
	r.line("|:-------------|:--------------------------------------------------|")
	for _, a := range attrs {
		if a.value != "" {
			r.line("| ", a.name, " | ", a.value, " |")
		}
	}
	r.line()
}

func (r *renderer) rootCause(rc *security.RootCause) {
	if rc == nil {
		return
	}
	r.subsection("Root Cause")
	r.para(escapeText(rc.Summary))
	r.labeled("Missing control", rc.MissingControl)
	r.labeled("Trust boundary", rc.TrustBoundary)
	r.list("Affected components", rc.Components)
}

func (r *renderer) impact(im *security.Impact) {
	if im == nil || (im.Technical == "" && im.Product == "" && len(im.Surfaces) == 0) {
		return
	}
	r.subsection("Impact")
	r.labeled("Technical impact", im.Technical)
	r.labeled("Business impact", im.Product)
	r.list("Affected surfaces", im.Surfaces)
}

func (r *renderer) exploit(ex *security.Exploit) {
	if ex == nil || (len(ex.Preconditions) == 0 && ex.Scenario == "" && ex.Reproduction == "") {
		return
	}
	r.subsection("Attack Scenario")
	r.list("Preconditions", ex.Preconditions)
	r.labeled("Scenario", ex.Scenario)
	r.labeled("Reproduction", ex.Reproduction)
}

func (r *renderer) reachabilityPaths(re *security.Reachability) {
	if re == nil || len(re.Paths) == 0 {
		return
	}
	r.subsection("Call Paths")
	for _, p := range re.Paths {
		r.line("- ", codeSpan(p))
	}
	r.line()
}

func (r *renderer) controls(cs []security.Control, ex *security.Exception) {
	if len(cs) == 0 && ex == nil {
		return
	}
	r.subsection("Compensating Controls")
	for _, c := range cs {
		item := "**" + escapeInline(c.Name) + "**"
		if c.Description != "" {
			item += ": " + escapeInline(c.Description)
		}
		if c.Verified {
			item += " *(verified)*"
		}
		r.line("- ", item)
	}
	if len(cs) > 0 {
		r.line()
	}
	if ex != nil {
		parts := []string{"Status: " + humanize(ex.Status)}
		if ex.ApprovedBy != "" {
			parts = append(parts, "approved by "+escapeInline(ex.ApprovedBy))
		}
		if ex.ExpiresAt != nil {
			parts = append(parts, "expires "+ex.ExpiresAt.Format(time.DateOnly))
		}
		if ex.Reference != "" {
			parts = append(parts, "reference "+escapeInline(ex.Reference))
		}
		r.para("**Risk exception:** " + strings.Join(parts, "; ") + ".")
	}
}

func (r *renderer) evidence(ev []findingspec.Evidence) {
	if len(ev) == 0 {
		return
	}
	r.subsection("Evidence")
	for _, e := range ev {
		head := "**" + escapeInline(humanize(e.Kind)) + "**"
		if e.Summary != "" {
			head += ": " + escapeInline(e.Summary)
		}
		if e.URI != "" {
			head += " (<" + linkURL(e.URI) + ">)"
		}
		r.para(head)
		if e.Data != "" {
			r.para(codeBlock(e.Data, ""))
		}
	}
}

func (r *renderer) snippet(loc *findingspec.Location) {
	if loc == nil || strings.TrimSpace(loc.Snippet) == "" {
		return
	}
	r.subsection("Affected Code")
	r.para(codeBlock(loc.Snippet, langForFile(loc.File)))
}

func (r *renderer) remediation(rem *findingspec.Remediation) {
	if rem == nil {
		return
	}
	r.subsection("Remediation")
	r.para(escapeText(rem.Summary))
	r.para(escapeText(rem.Detail))
	if r.opts.IncludeAgentPrompts && rem.AgentPrompt != "" {
		r.labeled("Agent prompt", rem.AgentPrompt)
	}
	if len(rem.References) > 0 {
		r.line("**Remediation references:**")
		r.line()
		for _, ref := range rem.References {
			r.line("- ", referenceLink(ref))
		}
		r.line()
	}
}

func (r *renderer) verification(v *findingspec.Verification) {
	if v == nil {
		return
	}
	r.subsection("Verification")
	head := "**Result:** " + humanize(string(v.Result))
	if v.Method != "" {
		head += "; method: " + escapeInline(v.Method)
	}
	if v.VerifiedAt != nil {
		head += "; verified " + v.VerifiedAt.Format(time.DateOnly)
	}
	r.para(head)
	r.para(escapeText(v.Summary))
	r.list("Checks", v.Checks)
}

func (r *renderer) related(rels []findingspec.Relationship) {
	if len(rels) == 0 {
		return
	}
	r.subsection("Related Findings")
	for _, rel := range rels {
		target := escapeInline(rel.Target)
		if a, ok := r.anchors[rel.Target]; ok {
			target = "[" + target + "](#" + a + ")"
		}
		item := humanize(string(rel.Type)) + ": " + target
		if rel.Title != "" {
			item += " (" + escapeInline(rel.Title) + ")"
		}
		r.line("- ", item)
	}
	r.line()
}

func (r *renderer) references(refs []findingspec.Reference) {
	if len(refs) == 0 {
		return
	}
	r.subsection("References")
	for _, ref := range refs {
		r.line("- ", referenceLink(ref))
	}
	r.line()
}

// labeled writes a paragraph led by a bold label.
func (r *renderer) labeled(label, text string) {
	if strings.TrimSpace(text) == "" {
		return
	}
	r.para("**" + label + ":** " + escapeText(text))
}

// list writes a bold label followed by a bullet list.
func (r *renderer) list(label string, items []string) {
	if len(items) == 0 {
		return
	}
	r.line("**", label, ":**")
	r.line()
	for _, it := range items {
		r.line("- ", escapeInline(it))
	}
	r.line()
}

func referenceLink(ref findingspec.Reference) string {
	title := ref.Title
	if title == "" {
		title = ref.URL
	}
	if ref.URL == "" {
		return escapeInline(title)
	}
	return "[" + escapeInline(title) + "](" + linkURL(ref.URL) + ")"
}

// severitiesInOrder returns every canonical severity, most severe first,
// followed by any non-canonical severities present in counts.
func severitiesInOrder(counts map[findingspec.Severity]int) []findingspec.Severity {
	out := findingspec.Severities()
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rank() < out[j].Rank() })
	known := map[findingspec.Severity]bool{}
	for _, s := range out {
		known[s] = true
	}
	var extra []findingspec.Severity
	for s := range counts {
		if !known[s] {
			extra = append(extra, s)
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i] < extra[j] })
	return append(out, extra...)
}

func severityLabel(s findingspec.Severity) string {
	if s == "" {
		return "Unrated"
	}
	if s.Valid() {
		return s.Name()
	}
	return escapeInline(string(s))
}

func statusLabel(s findingspec.Status) string {
	if s == "" {
		return "Open"
	}
	return humanize(string(s))
}

func category(f findingspec.Finding) string {
	c := humanize(string(f.Domain))
	switch {
	case f.Type == "":
	case f.Domain == findingspec.DomainSecurity:
		// Security types are acronyms: sca, sast, dast, iac.
		c += " / " + escapeInline(strings.ToUpper(f.Type))
	default:
		c += " / " + escapeInline(humanize(f.Type))
	}
	return c
}

func exploitabilityLabel(e security.Exploitability) string {
	switch e {
	case "":
		return ""
	case security.ExploitabilityNone:
		return "No known exploit"
	case security.ExploitabilityPOC:
		return "Proof of concept"
	case security.ExploitabilityFunctional:
		return "Functional exploit"
	case security.ExploitabilityActive:
		return "Exploited in the wild"
	default:
		return humanize(string(e))
	}
}

func reachabilityLabel(re *security.Reachability, reachable *bool) string {
	if re != nil && re.State != "" {
		s := humanize(string(re.State))
		if re.Symbol != "" {
			s += " via " + codeSpan(re.Symbol)
		}
		return s
	}
	if reachable != nil {
		if *reachable {
			return "Reachable"
		}
		return "Unreachable"
	}
	return ""
}

func cvssLabel(c *security.CVSS) string {
	if c == nil {
		return ""
	}
	s := strconv.FormatFloat(c.Score, 'f', 1, 64)
	if c.Version != "" {
		s += " (CVSS " + escapeInline(c.Version) + ")"
	}
	if c.Vector != "" {
		s += " " + codeSpan(c.Vector)
	}
	return s
}

func packageLabel(p *security.Package) string {
	if p == nil || p.Name == "" {
		return ""
	}
	s := p.Name
	if p.Version != "" {
		s += "@" + p.Version
	}
	out := codeSpan(s)
	if p.Ecosystem != "" {
		out += " (" + escapeInline(p.Ecosystem) + ")"
	}
	return out
}

func fixLabel(f *security.Fix) string {
	if f == nil {
		return ""
	}
	if len(f.Versions) > 0 {
		return escapeInline(strings.Join(f.Versions, ", "))
	}
	if f.State != "" && f.State != security.FixStateFixed {
		return humanize(string(f.State))
	}
	return ""
}

func locationLabel(loc *findingspec.Location) string {
	if loc == nil {
		return ""
	}
	var parts []string
	if loc.Repo != "" {
		parts = append(parts, escapeInline(loc.Repo))
	}
	if loc.File != "" {
		file := loc.File
		if loc.Line > 0 {
			file += ":" + strconv.Itoa(loc.Line)
			if loc.Column > 0 {
				file += ":" + strconv.Itoa(loc.Column)
			}
		}
		parts = append(parts, codeSpan(file))
	}
	if loc.URL != "" {
		parts = append(parts, "<"+linkURL(loc.URL)+">")
	}
	if loc.Selector != "" {
		parts = append(parts, codeSpan(loc.Selector))
	}
	if loc.Pointer != "" {
		parts = append(parts, codeSpan(loc.Pointer))
	}
	if loc.Component != "" && len(parts) == 0 {
		parts = append(parts, escapeInline(loc.Component))
	}
	return strings.Join(parts, " ")
}

func sourceLabel(s findingspec.Source) string {
	if s.Tool == "" {
		return ""
	}
	out := escapeInline(s.Tool)
	if s.Version != "" {
		out += " " + escapeInline(s.Version)
	}
	return out
}

func dateLabel(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.Format(time.DateOnly)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
