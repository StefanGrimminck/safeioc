// Package safeioc implements the Safe-IOC obfuscation format defined in
// draft-grimminck-safe-ioc-sharing.
//
// Obfuscate transforms a raw indicator (URL, IP address, email, or domain)
// into a form that cannot be auto-linked or accidentally activated, while
// remaining human-readable and fully reversible. Deobfuscate reverses the
// transformation and also accepts the legacy "hxxp"/"hxxps" tokens.
//
// The transformation is idempotent: Obfuscate(Obfuscate(x)) == Obfuscate(x).
package safeioc

import (
	"net/netip"
	"strings"
)

// Obfuscate returns the canonical Safe-IOC form of s.
//
// The algorithm follows the four steps in draft-grimminck-safe-ioc-sharing:
//
//	Step 1 - wrap the URI scheme in square brackets.
//	Step 2 - replace "@" in the userinfo with "[@]".
//	Step 3 - replace "." in the host with "[.]"; inside an IPv6 literal
//	         replace ":" with "[:]" and embedded IPv4 dots with "[.]".
//	Step 4 - obfuscate recognizable nested indicators in Path/Query/Fragment.
func Obfuscate(s string) string {
	if s == "" {
		return s
	}

	var b strings.Builder
	b.Grow(len(s) + 32)

	n := len(s)
	i := 0

	if s[0] != '[' {
		// Step 3 (bare IPv6): must be checked before scheme because bare
		// IPv6 starting with alpha hex digits (e.g. "fe80::") would
		// otherwise match the scheme rule.
		if m := matchBareIPv6(s, 0); m > 0 {
			writeObfuscatedIPv6(&b, s[:m])
			i = m
		} else if sLen, sepLen, ok := matchScheme(s, 0); ok && acceptAtTop(s[:sLen], sepLen) {
			// Step 1: wrap scheme. Case is preserved verbatim so that the
			// transformation is reversible byte-for-byte.
			b.WriteByte('[')
			b.WriteString(s[:sLen])
			b.WriteByte(']')
			b.WriteString(s[sLen : sLen+sepLen])
			// Steps 2+3: authority; Step 4 tail handled below.
			i = processAuthority(&b, s, sLen+sepLen, n, sepLen == 3, sepLen == 3)
		}
	}

	if i == 0 {
		// No leading scheme or bare IPv6: try to parse authority from pos 0
		// (handles bare domains, bare IPv4, and bracketed IPv6 literals).
		i = processAuthority(&b, s, 0, n, true, true)
	}

	// Step 4: scan the tail for nested indicators.
	scanTail(&b, s, i, n)
	return b.String()
}

// Deobfuscate reverses Safe-IOC obfuscation. It also converts the legacy
// "hxxp"/"hxxps" tokens so that older threat-intelligence feeds round-trip
// correctly.
func Deobfuscate(s string) string {
	s = deobfuscateSchemes(s)
	s = strings.ReplaceAll(s, "hxxps", "https")
	s = strings.ReplaceAll(s, "hxxp", "http")
	s = strings.ReplaceAll(s, "[.]", ".")
	s = strings.ReplaceAll(s, "[:]", ":")
	s = strings.ReplaceAll(s, "[@]", "@")
	return s
}

// acceptAtTop rejects the pattern "dotted.name:" (bare colon without "//")
// because that is a "host:port" pair, not a URI scheme.
func acceptAtTop(scheme string, sepLen int) bool {
	return sepLen == 3 || !strings.ContainsRune(scheme, '.')
}

// processAuthority scans the authority region of a URI starting at pos.
// For hierarchical URIs (hier=true) it stops at the first '/', '?', or '#'.
// For opaque URIs it stops at '?' or '#' and also detects nested schemes.
// Steps 2 and 3 are applied here.
func processAuthority(b *strings.Builder, s string, pos, end int, hier, tryBareIPv6 bool) int {
	i := pos
	for i < end {
		c := s[i]
		if c == '?' || c == '#' {
			break
		}
		if hier && c == '/' {
			break
		}

		// Already-obfuscated tokens are opaque (idempotency guarantee).
		if i+3 <= end {
			tok := s[i : i+3]
			if tok == "[.]" || tok == "[:]" || tok == "[@]" {
				b.WriteString(tok)
				i += 3
				continue
			}
		}

		if c == '[' {
			if endB := findMatchingBracket(s, i); endB != -1 && endB < end {
				inner := s[i+1 : endB]
				switch {
				case containsObfuscationTokens(inner):
					// Already obfuscated IP-literal; emit verbatim.
					b.WriteString(s[i : endB+1])
				case looksLikeRawIPv6(inner):
					// Step 3: obfuscate colons (and embedded IPv4 dots)
					// inside the IP-literal; preserve outer brackets.
					b.WriteByte('[')
					writeObfuscatedIPv6(b, inner)
					b.WriteByte(']')
				default:
					b.WriteString(s[i : endB+1])
				}
				i = endB + 1
				continue
			}
		}

		if tryBareIPv6 && i == pos {
			if m := matchBareIPv6(s, i); m > 0 {
				writeObfuscatedIPv6(b, s[i:i+m])
				i += m
				continue
			}
		}

		// In opaque URI bodies, look for nested indicators before applying
		// the default dot/at replacement.
		if !hier && atBoundary(s, i) {
			if consumed, ok := tryNestedIndicator(b, s, i, end); ok {
				i = consumed
				continue
			}
		}

		switch c {
		case '@':
			b.WriteString("[@]") // Step 2
		case '.':
			b.WriteString("[.]") // Step 3
		default:
			b.WriteByte(c)
		}
		i++
	}
	return i
}

// scanTail walks s[pos:end] applying Step 4: obfuscating any nested URI,
// mailto, email, or IPv4 literal in place. Non-indicator bytes pass through
// verbatim.
func scanTail(b *strings.Builder, s string, pos, end int) {
	i := pos
	for i < end {
		if atBoundary(s, i) {
			if consumed, ok := tryNestedIndicator(b, s, i, end); ok {
				i = consumed
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
}

// tryNestedIndicator attempts to match a nested hierarchical URL, a mailto
// URI followed by a valid email, a bare email address, or a bare IPv4
// address at pos. Returns the new position and true on a match.
func tryNestedIndicator(b *strings.Builder, s string, pos, end int) (int, bool) {
	if sLen, sepLen, ok := matchScheme(s, pos); ok {
		scheme := s[pos : pos+sLen]
		if sepLen == 3 {
			b.WriteByte('[')
			b.WriteString(scheme)
			b.WriteByte(']')
			b.WriteString("://")
			return processAuthority(b, s, pos+sLen+sepLen, end, true, false), true
		}
		if sepLen == 1 && sLen == 6 && strings.EqualFold(scheme, "mailto") {
			if matchEmail(s, pos+7) > 0 {
				b.WriteByte('[')
				b.WriteString(scheme)
				b.WriteByte(']')
				b.WriteByte(':')
				return processAuthority(b, s, pos+7, end, false, false), true
			}
		}
	}
	// Don't detect bare IPv6 when preceded by '[' (inside a bracket literal)
	// or '%' (inside a percent-encoded sequence such as %5B).
	if pos == 0 || (s[pos-1] != '[' && s[pos-1] != '%') {
		if m := matchBareIPv6(s, pos); m > 0 {
			writeObfuscatedIPv6(b, s[pos:pos+m])
			return pos + m, true
		}
	}
	if m := matchEmail(s, pos); m > 0 {
		writeObfuscatedAtDot(b, s[pos:pos+m])
		return pos + m, true
	}
	if m := matchIPv4(s, pos); m > 0 {
		writeObfuscatedAtDot(b, s[pos:pos+m])
		return pos + m, true
	}
	return pos, false
}

// deobfuscateSchemes rewrites "[scheme]:" back to "scheme:".
func deobfuscateSchemes(s string) string {
	if !strings.Contains(s, "[") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i, n := 0, len(s)
	for i < n {
		if s[i] == '[' {
			if schemeEnd, sepEnd, ok := matchBracketedScheme(s, i); ok {
				b.WriteString(s[i+1 : schemeEnd])
				b.WriteByte(':')
				i = sepEnd
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func matchBracketedScheme(s string, pos int) (schemeEnd, sepEnd int, ok bool) {
	n := len(s)
	if pos+3 >= n || s[pos] != '[' {
		return 0, 0, false
	}
	j := pos + 1
	if !isAlpha(s[j]) {
		return 0, 0, false
	}
	j++
	for j < n {
		c := s[j]
		if isAlpha(c) || isDigit(c) || c == '+' || c == '-' || c == '.' {
			j++
			continue
		}
		break
	}
	if j >= n || s[j] != ']' {
		return 0, 0, false
	}
	if j+1 >= n || s[j+1] != ':' {
		return 0, 0, false
	}
	return j, j + 2, true
}

// atBoundary reports whether pos is preceded by a non-word character.
func atBoundary(s string, pos int) bool {
	if pos == 0 {
		return true
	}
	c := s[pos-1]
	return !(isAlpha(c) || isDigit(c) || c == '_')
}

// matchScheme matches ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ( "://" / ":" )
// and returns the scheme length, separator length, and whether a match was found.
func matchScheme(s string, pos int) (schemeLen, sepLen int, ok bool) {
	n := len(s)
	if pos >= n || !isAlpha(s[pos]) {
		return 0, 0, false
	}
	i := pos + 1
	for i < n {
		c := s[i]
		if !(isAlpha(c) || isDigit(c) || c == '+' || c == '-' || c == '.') {
			break
		}
		i++
	}
	if i >= n || s[i] != ':' {
		return 0, 0, false
	}
	if i+3 <= n && s[i+1] == '/' && s[i+2] == '/' {
		return i - pos, 3, true
	}
	return i - pos, 1, true
}

// matchBareIPv6 returns the length of the bare IPv6 address at pos, or 0.
// Validation is delegated to net/netip (RFC 4291 + RFC 9844 zone IDs).
func matchBareIPv6(s string, pos int) int {
	n := len(s)
	i := pos
	colons := 0
	for i < n {
		c := s[i]
		if isHexDigit(c) || c == '.' {
			i++
			continue
		}
		if c == ':' {
			colons++
			i++
			continue
		}
		break
	}
	if colons < 2 {
		return 0
	}
	end := i
	// Accept an optional bare zone identifier (e.g. %eth0).
	if end < n && s[end] == '%' {
		j := end + 1
		for j < n {
			c := s[j]
			if isAlpha(c) || isDigit(c) || c == '_' || c == '.' || c == '-' {
				j++
				continue
			}
			break
		}
		if j > end+1 {
			end = j
		}
	}

	for tryEnd := end; tryEnd >= pos+2; tryEnd-- {
		if strings.Count(s[pos:tryEnd], ":") < 2 {
			break
		}
		if tryEnd < n && isHexDigit(s[tryEnd]) {
			continue
		}
		if addr, err := netip.ParseAddr(s[pos:tryEnd]); err == nil && addr.Is6() {
			return tryEnd - pos
		}
	}
	return 0
}

// matchEmail matches a bare email address (practical subset of RFC 5322) at pos.
func matchEmail(s string, pos int) int {
	n := len(s)
	i := pos
	for i < n {
		c := s[i]
		if isAlpha(c) || isDigit(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-' {
			i++
			continue
		}
		break
	}
	if i == pos || i >= n || s[i] != '@' {
		return 0
	}
	i++

	labels := 0
	for {
		if i >= n || !(isAlpha(s[i]) || isDigit(s[i])) {
			break
		}
		i++
		for i < n {
			c := s[i]
			if isAlpha(c) || isDigit(c) || c == '-' {
				i++
				continue
			}
			break
		}
		if s[i-1] == '-' {
			return 0
		}
		labels++
		if i < n && s[i] == '.' {
			i++
			continue
		}
		break
	}
	if labels < 2 {
		return 0
	}
	if i < n {
		c := s[i]
		if isAlpha(c) || isDigit(c) || c == '_' {
			return 0
		}
	}
	return i - pos
}

// matchIPv4 matches a dotted-quad at pos with a trailing word boundary.
func matchIPv4(s string, pos int) int {
	n := len(s)
	i := pos
	for octet := 0; octet < 4; octet++ {
		if i >= n || !isDigit(s[i]) {
			return 0
		}
		j := i + 1
		for j < n && j-i < 3 && isDigit(s[j]) {
			j++
		}
		i = j
		if octet < 3 {
			if i >= n || s[i] != '.' {
				return 0
			}
			i++
		}
	}
	if i < n {
		c := s[i]
		if isAlpha(c) || isDigit(c) || c == '.' || c == '_' {
			return 0
		}
	}
	return i - pos
}

// findMatchingBracket finds the ']' that closes the '[' at pos, treating
// [.], [:], and [@] as atomic tokens so they are not misinterpreted as
// nested brackets.
func findMatchingBracket(s string, pos int) int {
	depth := 1
	i := pos + 1
	for i < len(s) {
		if i+3 <= len(s) {
			tok := s[i : i+3]
			if tok == "[.]" || tok == "[:]" || tok == "[@]" {
				i += 3
				continue
			}
		}
		switch s[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return -1
}

func containsObfuscationTokens(s string) bool {
	return strings.Contains(s, "[.]") ||
		strings.Contains(s, "[:]") ||
		strings.Contains(s, "[@]")
}

func looksLikeRawIPv6(s string) bool {
	if s == "" || !strings.Contains(s, ":") {
		return false
	}
	addr := s
	if idx := strings.Index(s, "%25"); idx != -1 {
		addr = s[:idx]
		zone := s[idx+3:]
		if zone == "" {
			return false
		}
		for i := 0; i < len(zone); i++ {
			c := zone[i]
			if !isAlphaNum(c) && c != '.' && c != '-' && c != '_' && c != '~' {
				return false
			}
		}
	}
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if !isHexDigit(c) && c != ':' && c != '.' {
			return false
		}
	}
	return true
}

func writeObfuscatedIPv6(b *strings.Builder, s string) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ':':
			b.WriteString("[:]")
		case '.':
			b.WriteString("[.]")
		default:
			b.WriteByte(s[i])
		}
	}
}

// writeObfuscatedAtDot emits s with '.' replaced by "[.]" and '@' by "[@]".
func writeObfuscatedAtDot(b *strings.Builder, s string) {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.':
			b.WriteString("[.]")
		case '@':
			b.WriteString("[@]")
		default:
			b.WriteByte(s[i])
		}
	}
}


func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}

func isAlpha(c byte) bool  { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isAlphaNum(c byte) bool { return isAlpha(c) || isDigit(c) }
