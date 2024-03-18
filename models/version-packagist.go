// Package models defines the structures and functions used to determine if a
// SBOM package is affected by a OSV.DEV vulnerabity.
package models

import (
	"strconv"
	"strings"
)

func canonicalizePackagistVersion(v string) string {
	// todo: decide how to handle this - without it, we're 1:1 with the native
	//   PHP version_compare function, but composer removes it; arguably this
	//   should be done before the version is passed in (by the dev), except
	//   the ecosystem is named "Packagist" not "php version_compare", though
	//   packagist itself doesn't seem to enforce this (its composer that does
	//   the trimming...)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")

	v = MustCompile(`[-_+]`).ReplaceAllString(v, ".")
	v = MustCompile(`([^\d.])(\d)`).ReplaceAllString(v, "$1.$2")
	v = MustCompile(`(\d)([^\d.])`).ReplaceAllString(v, "$1.$2")

	return v
}

func weighPackagistBuildCharacter(str string) int {
	if strings.HasPrefix(str, "RC") {
		return 3
	}

	specials := []string{"dev", "a", "b", "rc", "#", "p"}

	for i, special := range specials {
		if strings.HasPrefix(str, special) {
			return i
		}
	}

	return 0
}

func comparePackagistSpecialVersions(a, b string) int {
	av := weighPackagistBuildCharacter(a)
	bv := weighPackagistBuildCharacter(b)

	if av > bv {
		return 1
	} else if av < bv {
		return -1
	}

	return 0
}

func comparePackagistComponents(a, b []string) int {
	min := minInt(len(a), len(b))

	var compare int

	for i := 0; i < min; i++ {
		ai, aIsNumber := convertToBigInt(a[i])
		bi, bIsNumber := convertToBigInt(b[i])

		switch {
		case aIsNumber && bIsNumber:
			compare = ai.Cmp(bi)
		case !aIsNumber && !bIsNumber:
			compare = comparePackagistSpecialVersions(a[i], b[i])
		case aIsNumber:
			compare = comparePackagistSpecialVersions("#", b[i])
		default:
			compare = comparePackagistSpecialVersions(a[i], "#")
		}

		if compare != 0 {
			if compare > 0 {
				return 1
			}

			return -1
		}
	}

	if len(a) > len(b) {
		next := a[len(b)]

		if _, err := strconv.Atoi(next); err == nil {
			return 1
		}

		return comparePackagistComponents(a[len(b):], []string{"#"})
	}

	if len(a) < len(b) {
		next := b[len(a)]

		if _, err := strconv.Atoi(next); err == nil {
			return -1
		}

		return comparePackagistComponents([]string{"#"}, b[len(a):])
	}

	return 0
}

// PackagistVersion defines a Packagist Version string
type PackagistVersion struct {
	Original   string
	Components []string
}

func parsePackagistVersion(str string) PackagistVersion {
	return PackagistVersion{
		str,
		strings.Split(canonicalizePackagistVersion(str), "."),
	}
}

// Compare Packagist Version structs
func (v PackagistVersion) Compare(w PackagistVersion) int {
	return comparePackagistComponents(v.Components, w.Components)
}

// CompareStr Packagist Version strings
func (v PackagistVersion) CompareStr(str string) int {
	return v.Compare(parsePackagistVersion(str))
}
