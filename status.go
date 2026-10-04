package findingspec

// Status is the lifecycle state of a [Finding].
type Status string

const (
	// StatusOpen is a newly-reported finding awaiting triage.
	StatusOpen Status = "open"
	// StatusConfirmed is a finding verified as a true positive.
	StatusConfirmed Status = "confirmed"
	// StatusRemediated is a finding whose fix has been applied.
	StatusRemediated Status = "remediated"
	// StatusAccepted is a finding whose risk has been formally accepted.
	StatusAccepted Status = "accepted"
	// StatusFalsePositive is a finding determined not to be a real issue.
	StatusFalsePositive Status = "false_positive"
	// StatusResolved is a finding confirmed fixed after re-assessment.
	StatusResolved Status = "resolved"
)

// Statuses returns all known statuses in a stable order.
func Statuses() []Status {
	return []Status{
		StatusOpen, StatusConfirmed, StatusRemediated,
		StatusAccepted, StatusFalsePositive, StatusResolved,
	}
}

// Valid reports whether s is a known status.
func (s Status) Valid() bool {
	switch s {
	case StatusOpen, StatusConfirmed, StatusRemediated,
		StatusAccepted, StatusFalsePositive, StatusResolved:
		return true
	default:
		return false
	}
}

// Open reports whether the finding still requires attention. A finding is open
// unless it has been explicitly closed (remediated, resolved, accepted, or
// dismissed as a false positive); an unset or unknown status is treated as open,
// so freshly-detected findings count as needing attention by default.
func (s Status) Open() bool {
	switch s {
	case StatusRemediated, StatusResolved, StatusAccepted, StatusFalsePositive:
		return false
	default:
		return true
	}
}
