// Package models defines the structures and functions used to determine if a
// SBOM package is affected by a OSV.DEV vulnerabity.
package models

import "strings"

// NuGetVersion defines a Nuget Version String
type NuGetVersion struct {
	SemverLikeVersion
}

// Compare Nuget Version structs
func (v NuGetVersion) Compare(w NuGetVersion) int {
	if diff := v.Components.Cmp(w.Components); diff != 0 {
		return diff
	}

	return compareBuildComponents(strings.ToLower(v.Build), strings.ToLower(w.Build))
}

// CompareStr Nuget Version strings
func (v NuGetVersion) CompareStr(str string) int {
	return v.Compare(parseNuGetVersion(str))
}

func parseNuGetVersion(str string) NuGetVersion {
	return NuGetVersion{ParseSemverLikeVersion(str, 4)}
}
