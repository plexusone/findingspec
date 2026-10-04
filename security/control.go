package security

import "time"

// Control functions describe how a compensating control acts on risk.
const (
	ControlFunctionPreventive = "preventive"
	ControlFunctionDetective  = "detective"
	ControlFunctionCorrective = "corrective"
)

// Risk dimensions a control can reduce.
const (
	ReducesLikelihood = "likelihood"
	ReducesImpact     = "impact"
)

// Control is a compensating control that reduces the residual risk of a
// vulnerability. It links the control to the risk dimensions it reduces and,
// optionally, the CVSS environmental metrics it justifies.
type Control struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Function is preventive, detective, or corrective.
	Function string `json:"function,omitempty"`
	// Reduces lists the risk dimensions this control mitigates (likelihood,
	// impact).
	Reduces []string `json:"reduces,omitempty"`
	// ModifiedMetrics lists CVSS environmental metrics this control justifies,
	// e.g. "MAV:A".
	ModifiedMetrics []string `json:"modifiedMetrics,omitempty"`
	// Effectiveness is a coarse rating: high, medium, or low.
	Effectiveness  string     `json:"effectiveness,omitempty"`
	Verified       bool       `json:"verified,omitempty"`
	VerifiedMethod string     `json:"verifiedMethod,omitempty"`
	LastVerifiedAt *time.Time `json:"lastVerifiedAt,omitempty"`
	Owner          string     `json:"owner,omitempty"`
}

// Exception statuses.
const (
	ExceptionStatusRequested = "requested"
	ExceptionStatusApproved  = "approved"
	ExceptionStatusRejected  = "rejected"
	ExceptionStatusExpired   = "expired"
)

// Exception records the approval state of a risk exception for a vulnerability.
// SLA policy: the remediation clock runs on inherent severity until an exception
// is approved, after which it runs on residual severity while the approval is in
// effect.
type Exception struct {
	Status     string     `json:"status,omitempty"`
	ApprovedAt *time.Time `json:"approvedAt,omitempty"`
	ApprovedBy string     `json:"approvedBy,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	Reference  string     `json:"reference,omitempty"`
	URL        string     `json:"url,omitempty"`
}

// IsApprovedAt reports whether the exception is approved and unexpired as of t.
// A nil receiver reports false.
func (ex *Exception) IsApprovedAt(t time.Time) bool {
	if ex == nil || ex.Status != ExceptionStatusApproved {
		return false
	}
	if ex.ExpiresAt != nil && !t.Before(*ex.ExpiresAt) {
		return false
	}
	return true
}
