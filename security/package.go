package security

// Package identifies a software package (dependency or OS package) that a
// vulnerability affects. It is the canonical package shape that SCA and
// container scanners (Grype, Trivy, AWS Inspector, …) normalize into.
type Package struct {
	// Name is the package name (e.g. "log4j-core", "openssl", "lodash").
	Name string `json:"name,omitempty"`
	// Version is the installed version.
	Version string `json:"version,omitempty"`
	// Ecosystem is the package ecosystem / type, e.g. "npm", "pypi", "gem",
	// "maven", "golang", "apk", "deb", "rpm".
	Ecosystem string `json:"ecosystem,omitempty"`
	// PURL is the package URL (purl spec), when available.
	PURL string `json:"purl,omitempty"`
	// Path is the file path where the package was found within the artifact.
	Path string `json:"path,omitempty"`
	// Arch is the package architecture (e.g. "x86_64"), for OS packages.
	Arch string `json:"arch,omitempty"`
}

// FixState describes remediation availability for a package vulnerability.
type FixState string

const (
	FixStateFixed    FixState = "fixed"
	FixStateNotFixed FixState = "not-fixed"
	FixStateWontFix  FixState = "wont-fix"
	FixStateUnknown  FixState = "unknown"
)

// Fix describes how a package vulnerability is remediated.
type Fix struct {
	// State is the remediation state.
	State FixState `json:"state,omitempty"`
	// Versions are the package versions that resolve the vulnerability.
	Versions []string `json:"versions,omitempty"`
}

// Artifact is the scanned image or filesystem the vulnerable package was found
// in. A non-empty Image indicates a container scan (type "container") rather
// than a plain dependency scan (type "sca").
type Artifact struct {
	// Image is the container image reference (e.g. "alpine:3.19",
	// "123.dkr.ecr.us-east-1.amazonaws.com/app:sha-abc").
	Image string `json:"image,omitempty"`
	// ImageDigest is the image digest (e.g. "sha256:…").
	ImageDigest string `json:"imageDigest,omitempty"`
	// OS is the operating system / distro of the image (e.g. "alpine 3.19",
	// "amazon linux 2").
	OS string `json:"os,omitempty"`
	// Layer is the image layer (diffID or layer digest) the package came from.
	Layer string `json:"layer,omitempty"`
}
