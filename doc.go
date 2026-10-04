// Package findingspec defines a domain-neutral model for representing a
// finding — anything that needs attention — across multiple problem domains:
// security, accessibility (a11y), internationalization (i18n), and quality
// engineering (qe).
//
// The canonical [Finding] type carries the fields common to every domain
// (identity, severity, status, location, evidence, remediation). Domain
// packages under this module (security, a11y, i18n, qe) define richer,
// semantically-typed findings and project them into a [Finding] via a
// ToFinding method, so producers keep domain-specific detail while consumers
// can reason over a single, uniform representation.
//
// The core package's only external dependency is the shared priority-frameworks
// severity framework (github.com/grokify/priority-frameworks); it does not
// import any domain package, keeping the shared vocabulary neutral.
package findingspec
