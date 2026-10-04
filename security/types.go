package security

// Finding types within the security domain — the second level of the
// findingspec Domain+Type taxonomy. A producer or adapter sets one of these as
// findingspec.Finding.Type so consumers know how to read Detail.
const (
	// TypeSAST is a static application security testing finding (code analysis).
	TypeSAST = "sast"
	// TypeDAST is a dynamic application security testing finding (running app).
	TypeDAST = "dast"
	// TypeSCA is a software composition analysis finding (dependency vuln).
	TypeSCA = "sca"
	// TypeSecret is a detected secret or credential.
	TypeSecret = "secret"
	// TypeContainer is a container image scan finding.
	TypeContainer = "container"
	// TypeIaC is an infrastructure-as-code scan finding.
	TypeIaC = "iac"
	// TypeCloudConfig is a cloud posture / configuration finding (CSPM).
	TypeCloudConfig = "cloud-config"
	// TypeRuntime is a runtime host/workload finding (e.g. AWS Inspector,
	// endpoint agents).
	TypeRuntime = "runtime"
	// TypePentest is a penetration-test finding.
	TypePentest = "pentest"
)
