// Package models defines the structures and functions used to determine if a
// SBOM package is affected by a OSV.DEV vulnerabity.
package models

import (
	"fmt"
	"math/big"
	"regexp"
	"sync"
)

var cache sync.Map

// MustCompile compiles a regex and caches it for later
func MustCompile(exp string) *regexp.Regexp {
	compiled, ok := cache.Load(exp)
	if !ok {
		compiled, _ = cache.LoadOrStore(exp, regexp.MustCompile(exp))
	}

	return compiled.(*regexp.Regexp)
}

// Version deinfes the interface to the CompareStr func
type Version interface {
	// CompareStr returns an integer representing the sort order of the given string
	// when parsed as the concrete Version relative to the subject Version.
	//
	// The result will be 0 if v == w, -1 if v < w, or +1 if v > w.
	CompareStr(str string) int
}

// Components defines a list of IDs
type Components []*big.Int

// Fetch returns the component based on the index
func (components *Components) Fetch(n int) *big.Int {
	if len(*components) <= n {
		return big.NewInt(0)
	}

	return (*components)[n]
}

// Cmp detemines if the Component is in the list of Components
func (components *Components) Cmp(b Components) int {
	numberOfComponents := max(len(*components), len(b))

	for i := 0; i < numberOfComponents; i++ {
		diff := components.Fetch(i).Cmp(b.Fetch(i))

		if diff != 0 {
			return diff
		}
	}

	return 0
}

func convertToBigIntOrPanic(str string) *big.Int {
	if num, isNumber := convertToBigInt(str); isNumber {
		return num
	}

	panic(fmt.Sprintf("failed to convert %s to a number", str))
}

func convertToBigInt(str string) (*big.Int, bool) {
	i, ok := new(big.Int).SetString(str, 10)

	return i, ok
}

func fetch(slice []string, i int, def string) string {
	if len(slice) <= i {
		return def
	}

	return slice[i]
}
