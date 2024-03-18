// Package models defines the structures and functions used to determine if a
// SBOM package is affected by a OSV.DEV vulnerabity.
package models

// Ecosystem defines the type of language the package and vulnerabity belong to
type Ecosystem string

// Define the Ecosystem constants for all of the different packages
const (
	EcosystemGo            Ecosystem = "Go"
	EcosystemNPM           Ecosystem = "npm"
	EcosystemOSSFuzz       Ecosystem = "OSS-Fuzz"
	EcosystemPyPI          Ecosystem = "PyPI"
	EcosystemRubyGems      Ecosystem = "RubyGems"
	EcosystemCratesIO      Ecosystem = "crates.io"
	EcosystemPackagist     Ecosystem = "Packagist"
	EcosystemMaven         Ecosystem = "Maven"
	EcosystemNuGet         Ecosystem = "NuGet"
	EcosystemLinux         Ecosystem = "Linux"
	EcosystemDebian        Ecosystem = "Debian"
	EcosystemAlpine        Ecosystem = "Alpine"
	EcosystemHex           Ecosystem = "Hex"
	EcosystemAndroid       Ecosystem = "Android"
	EcosystemGitHubActions Ecosystem = "GitHub Actions"
	EcosystemPub           Ecosystem = "Pub"
	EcosystemConanCenter   Ecosystem = "ConanCenter"
	EcosystemRockyLinux    Ecosystem = "Rocky Linux"
	EcosystemAlmaLinux     Ecosystem = "AlmaLinux"
	EcosystemBitnami       Ecosystem = "Bitnami"
	EcosystemPhotonOS      Ecosystem = "Photon OS"
	EcosystemCRAN          Ecosystem = "CRAN"
	EcosystemBioconductor  Ecosystem = "Bioconductor"
	EcosystemSwiftURL      Ecosystem = "SwiftURL"
)

// Ecosystems defines a list of all the ecosystems
var Ecosystems = []Ecosystem{
	EcosystemGo,
	EcosystemNPM,
	EcosystemOSSFuzz,
	EcosystemPyPI,
	EcosystemRubyGems,
	EcosystemCratesIO,
	EcosystemPackagist,
	EcosystemMaven,
	EcosystemNuGet,
	EcosystemLinux,
	EcosystemDebian,
	EcosystemAlpine,
	EcosystemHex,
	EcosystemAndroid,
	EcosystemGitHubActions,
	EcosystemPub,
	EcosystemConanCenter,
	EcosystemRockyLinux,
	EcosystemAlmaLinux,
	EcosystemBitnami,
	EcosystemPhotonOS,
	EcosystemCRAN,
	EcosystemBioconductor,
	EcosystemSwiftURL,
}

// Constants for the different ecosystems
const (
	AlpineEcosystem   Ecosystem = "Alpine"
	DebianEcosystem   Ecosystem = "Debian"
	CargoEcosystem    Ecosystem = "crates.io"
	ComposerEcosystem Ecosystem = "Packagist"
	ConanEcosystem    Ecosystem = "ConanCenter"
	BundlerEcosystem  Ecosystem = "RubyGems"
	GoEcosystem       Ecosystem = "Go"
	MavenEcosystem    Ecosystem = "Maven"
	MixEcosystem      Ecosystem = "Hex"
	NpmEcosystem      Ecosystem = "npm"
	NuGetEcosystem    Ecosystem = "NuGet"
	PubEcosystem      Ecosystem = "Pub"
	PipEcosystem      Ecosystem = "PyPI"
)

// KnownEcosystems returns the list of currently supported ecosystems
func KnownEcosystems() []Ecosystem {
	return []Ecosystem{
		NpmEcosystem,
		NuGetEcosystem,
		CargoEcosystem,
		BundlerEcosystem,
		ComposerEcosystem,
		GoEcosystem,
		MixEcosystem,
		MavenEcosystem,
		PipEcosystem,
		PubEcosystem,
		ConanEcosystem,
		// Disabled temporarily,
		// see https://github.com/google/osv-scanner/pull/128 discussion for additional context
		// AlpineEcosystem,
	}
}

// used like so: purlEcosystems[PkgURL.Type][PkgURL.Namespace]
// * means it should match any namespace string
var purlEcosystems = map[string]map[string]Ecosystem{
	"apk":      {"alpine": EcosystemAlpine},
	"cargo":    {"*": EcosystemCratesIO},
	"deb":      {"debian": EcosystemDebian},
	"hex":      {"*": EcosystemHex},
	"golang":   {"*": EcosystemGo},
	"maven":    {"*": EcosystemMaven},
	"nuget":    {"*": EcosystemNuGet},
	"npm":      {"*": EcosystemNPM},
	"composer": {"*": EcosystemPackagist},
	"generic":  {"*": EcosystemOSSFuzz},
	"pypi":     {"*": EcosystemPyPI},
	"gem":      {"*": EcosystemRubyGems},
}

// PackageInfo defines Specific package information
type PackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Commit    string `json:"commit"`
}

// SeverityType defines the CVSS format (V2 vs V3)
type SeverityType string

// Constants defining the CVSS V2 vs V3 format
const (
	SeverityCVSSV2 SeverityType = "CVSS_V2"
	SeverityCVSSV3 SeverityType = "CVSS_V3"
)

// RangeType defines what type of range search should be used
type RangeType string

// Constants defining the different range types
const (
	RangeSemVer    RangeType = "SEMVER"
	RangeEcosystem RangeType = "ECOSYSTEM"
	RangeGit       RangeType = "GIT"
)

// ReferenceType defines the backing evidence for the CVE
type ReferenceType string

// Constants defining the different reference types
const (
	ReferenceAdvisory   ReferenceType = "ADVISORY"
	ReferenceArticle    ReferenceType = "ARTICLE"
	ReferenceDetection  ReferenceType = "DETECTION"
	ReferenceDiscussion ReferenceType = "DISCUSSION"
	ReferenceReport     ReferenceType = "REPORT"
	ReferenceFix        ReferenceType = "FIX"
	ReferenceIntroduced ReferenceType = "INTRODUCED"
	ReferencePackage    ReferenceType = "PACKAGE"
	ReferenceEvidence   ReferenceType = "EVIDENCE"
	ReferenceWeb        ReferenceType = "WEB"
)

// CreditType defines the person that gets credit for finding the CVE
type CreditType string

// Constants defining the different entities that can get credit
const (
	CreditFinder               CreditType = "FINDER"
	CreditReporter             CreditType = "REPORTER"
	CreditAnalyst              CreditType = "ANALYST"
	CreditCoordinator          CreditType = "COORDINATOR"
	CreditRemediationDeveloper CreditType = "REMEDIATION_DEVELOPER" //nolint:gosec
	CreditRemediationReviewer  CreditType = "REMEDIATION_REVIEWER"  //nolint:gosec
	CreditRemediationVerifier  CreditType = "REMEDIATION_VERIFIER"  //nolint:gosec
	CreditTool                 CreditType = "TOOL"
	CreditSponsor              CreditType = "SPONSOR"
	CreditOther                CreditType = "OTHER"
)

// PackageDetails defines the package name, version and ecosystem for a SBOM package
type PackageDetails struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Commit    string    `json:"commit,omitempty"`
	Ecosystem Ecosystem `json:"ecosystem,omitempty"`
	CompareAs Ecosystem `json:"compareAs,omitempty"`
}
