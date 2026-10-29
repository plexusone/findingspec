// Package report renders a findingspec.FindingSet as a formal, human-readable
// report.
//
// The Markdown output targets pandoc, so one source converts to DOCX, PDF, or
// HTML:
//
//	pandoc report.md -o report.docx --reference-doc=template.docx
//	pandoc report.md -o report.pdf --pdf-engine=xelatex
//
// It begins with a pandoc YAML metadata block (title, subtitle, author, date,
// classification, toc) and uses explicit header identifiers ({#id}) so
// overview rows link to each finding's section.
//
// Reports are written for an Audience. AudienceShareable, the default, leaves
// out attack detail: exploit preconditions, scenarios and reproduction steps,
// evidence payloads, and code snippets. AudienceInternal includes them and
// should stay with the team that owns the findings.
//
// Free-text finding fields (titles, descriptions, root cause, impact, ...) are
// treated as plain text and escaped, so characters such as *, _, < and @ in
// a description render literally. The one exception is a matched backtick
// code span, such as `ParseToken`, which is kept as inline code. Options.Summary, Options.Scope and the
// Body of each Section are author-supplied Markdown and are written verbatim.
package report
