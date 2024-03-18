// Package models defines the structures and functions used to determine if a
// SBOM package is affected by a OSV.DEV vulnerabity.
package models

import (
	"errors"
	"fmt"
)

// ErrUnsupportedEcosystem defines the unsupported ecosystem error
var ErrUnsupportedEcosystem = errors.New("unsupported ecosystem")

// MustParse parses the version string based on the ecosystem and panics if it fails to parse
func MustParse(str string, ecosystem Ecosystem) Version {
	v, err := Parse(str, ecosystem)

	if err != nil {
		panic(err)
	}

	return v
}

// Parse chooses the correct parser based on the ecosystem
func Parse(str string, ecosystem Ecosystem) (Version, error) {
	//nolint:exhaustive // Using strings to specify ecosystem instead of lockfile types
	switch ecosystem {
	case "npm":
		return parseSemverVersion(str), nil
	case "crates.io":
		return parseSemverVersion(str), nil
	case "Debian":
		return parseDebianVersion(str), nil
	case "RubyGems":
		return parseRubyGemsVersion(str), nil
	case "NuGet":
		return parseNuGetVersion(str), nil
	case "Packagist":
		return parsePackagistVersion(str), nil
	case "Go":
		return parseSemverVersion(str), nil
	case "Hex":
		return parseSemverVersion(str), nil
	case "Maven":
		return parseMavenVersion(str), nil
	case "PyPI":
		return parsePyPIVersion(str), nil
	case "Pub":
		return parseSemverVersion(str), nil
	case "ConanCenter":
		return parseSemverVersion(str), nil
	case "Alpine":
		return parseSemverVersion(str), nil
	}

	return nil, fmt.Errorf("%w %s", ErrUnsupportedEcosystem, ecosystem)
}
