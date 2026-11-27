package safeioc

import "strings"

// Deobfuscate returns the live form of the defanged indicator s. It turns
// "[scheme]:" back into "scheme:", "[.]" into ".", "[@]" into "@" and "[:]"
// into ":", and restores the legacy schemes "hxxp:" and "hxxps:" to
// "http:" and "https:", keeping their case ("HXXPS:" becomes "HTTPS:"). A
// legacy name is only restored where it stands as a scheme, so
// "/hxxp-guide" in a path is kept as it is.
//
// The whole of s is treated as one indicator. To restore only the
// indicators inside free text, and leave text such as the regular
// expression "[0-9]+[.][0-9]+" alone, use [DeobfuscateText].
//
// The result is a live indicator: write it only where it will not be
// rendered as a link or fetched.
func Deobfuscate(s string) string {
	if strings.IndexByte(s, '[') < 0 && !containsLegacyName(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if hasTokenAt(s, i) {
			b.WriteByte(s[i+1])
			i += 3
			continue
		}
		if schemeEnd, sepEnd, ok := matchBracketedScheme(s, i); ok {
			b.WriteString(s[i+1 : schemeEnd])
			b.WriteByte(':')
			i = sepEnd
			continue
		}
		if m := matchLegacyScheme(s, i); m > 0 {
			for _, c := range []byte(s[i : i+m]) {
				switch c {
				case 'x':
					c = 't'
				case 'X':
					c = 'T'
				}
				b.WriteByte(c)
			}
			i += m
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// IsObfuscated reports whether s contains a Safe-IOC token: "[.]", "[@]",
// "[:]", a bracketed scheme such as "[https]:", or a legacy "hxxp:" or
// "hxxps:" scheme. It is true exactly when Deobfuscate would change s.
//
// A string can be obfuscated and still be partly live:
// "[https]://evil.example" has a defanged scheme but a live host. To check
// that an indicator is completely defanged, compare it with its
// Obfuscate result.
func IsObfuscated(s string) bool {
	for i := 0; i < len(s); i++ {
		if hasTokenAt(s, i) || matchLegacyScheme(s, i) > 0 {
			return true
		}
		if _, _, ok := matchBracketedScheme(s, i); ok {
			return true
		}
	}
	return false
}

// containsLegacyName reports whether s contains "hxxp" in any case.
func containsLegacyName(s string) bool {
	for i := 0; i+4 <= len(s); i++ {
		if (s[i] == 'h' || s[i] == 'H') && strings.EqualFold(s[i:i+4], "hxxp") {
			return true
		}
	}
	return false
}
