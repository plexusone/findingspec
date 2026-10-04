// Package security defines semantic types for security findings —
// vulnerabilities in code, dependencies, and configuration — and projects them
// into the domain-neutral findingspec.Finding.
//
// The model separates inherent severity (the intrinsic weakness) from residual
// severity (the risk that remains after verified compensating controls), so a
// control reduces residual risk without relabeling the underlying vulnerability.
// These concepts were first prototyped in github.com/grokify/govex; this package
// re-expresses them cleanly against the findingspec core vocabulary and does not
// depend on govex.
package security
