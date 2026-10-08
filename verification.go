package findingspec

import "time"

// VerificationResult is the outcome of verifying a remediation.
type VerificationResult string

const (
	// VerificationPassed means the fix was shown to work.
	VerificationPassed VerificationResult = "passed"
	// VerificationFailed means the issue still reproduces.
	VerificationFailed VerificationResult = "failed"
	// VerificationPending means verification has not yet been performed.
	VerificationPending VerificationResult = "pending"
)

// Verification records how a remediation was proven, so closing a finding
// rests on evidence rather than assertion.
type Verification struct {
	// Result is the outcome.
	Result VerificationResult `json:"result"`
	// Method summarizes how the fix was verified, e.g. "regression test",
	// "retest", "manual review".
	Method string `json:"method,omitempty"`
	// Checks names the tests or checks that prove the fix.
	Checks []string `json:"checks,omitempty"`
	// Summary describes what was verified.
	Summary string `json:"summary,omitempty"`
	// VerifiedAt is when verification was performed.
	VerifiedAt *time.Time `json:"verifiedAt,omitempty"`
}
