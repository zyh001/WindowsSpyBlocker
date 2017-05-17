package stringsu

import (
	"strings"
	"unicode"
)

// Make a string's first character uppercase
func UcFirst(str string) string {
	for i, v := range str {
		return string(unicode.ToUpper(v)) + str[i+1:]
	}
	return ""
}

// Strip spaces from a string
func StripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}

// Remove extra spaces from a string
func RemoveExtraSpaces(str string) string {
	return strings.Join(strings.Fields(str), " ")
}

// Check if a slice contains a string
func InSlice(needle string, slice []string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}
	_, ok := set[needle]
	return ok
}
