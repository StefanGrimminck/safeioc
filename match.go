package safeioc

import (
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits on the parts of an indicator. They are far above what a real
// indicator needs (RFC 5321 limits a local part to 64 octets, RFC 1035 a
// domain name to 253, and an IPv6 address is at most 45 characters), and
// they bound the work a recognizer does from one position where it cannot
// remember a run it has already read.
const (
	maxScheme = 256
	maxIPv6   = 128
	maxLocal  = 256
	maxDomain = 1024
)

// matchScheme matches a URI scheme and its separator at pos,
// ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) followed by "://" or ":", and
// returns the length of each.
func matchScheme(s string, pos int) (schemeLen, sepLen int, ok bool) {
	n := len(s)
	if pos >= n || !isAlpha(s[pos]) {
		return 0, 0, false
	}
	i := pos + 1
	for i < n && i-pos < maxScheme && isSchemeChar(s[i]) {
		i++
	}
	if i >= n || s[i] != ':' {
		return 0, 0, false
	}
	if strings.HasPrefix(s[i:], "://") {
		return i - pos, 3, true
	}
	return i - pos, 1, true
}

// matchBracketedScheme matches an obfuscated "[scheme]:" at pos. schemeEnd is
// the position of the closing "]" and sepEnd the position after the ":".
func matchBracketedScheme(s string, pos int) (schemeEnd, sepEnd int, ok bool) {
	n := len(s)
	if pos+3 >= n || s[pos] != '[' || !isAlpha(s[pos+1]) {
		return 0, 0, false
	}
	j := pos + 2
	for j < n && j-pos < maxScheme && isSchemeChar(s[j]) {
		j++
	}
	if j+1 >= n || s[j] != ']' || s[j+1] != ':' {
		return 0, 0, false
	}
	return j, j + 2, true
}

// matchLegacyScheme matches "hxxp" or "hxxps" at pos where it stands as a
// URI scheme: not preceded by a scheme character, and followed by ":" or
// by the obfuscated "[:]". The match is case-insensitive, as ABNF strings
// are (RFC 5234 Section 2.3). It returns the length of the name, or 0.
func matchLegacyScheme(s string, pos int) int {
	if pos+4 > len(s) || !strings.EqualFold(s[pos:pos+4], "hxxp") {
		return 0
	}
	if pos > 0 && isSchemeChar(s[pos-1]) {
		return 0
	}
	m := 4
	if pos+m < len(s) && (s[pos+m] == 's' || s[pos+m] == 'S') {
		m = 5
	}
	if rest := s[pos+m:]; strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, "[:]") {
		return m
	}
	return 0
}

// matchIPv4 matches a dotted-quad IPv4 address at pos that is not part of
// a longer word or name. A full stop that ends a sentence may follow it.
// With obfuscated, a dot may also be written "[.]", as long as one is.
func matchIPv4(s string, pos int, obfuscated bool) int {
	i, tokens := pos, 0
	for octet := 0; octet < 4; octet++ {
		if octet > 0 {
			dot := dotLen(s, i, obfuscated)
			if dot == 0 {
				return 0
			}
			if dot == 3 {
				tokens++
			}
			i += dot
		}
		if i = octetEnd(s, i); i < 0 {
			return 0
		}
	}
	if obfuscated && tokens == 0 {
		return 0
	}
	// "192.0.2.1a", "192.0.2.1.5" and "192.0.2.1@x" are something longer.
	// A non-ASCII letter may follow: Chinese and Japanese text puts no
	// space after an address ("198.51.100.7的").
	if i < len(s) && (s[i] == '@' || s[i] == '-' || isAlphaNum(s[i])) {
		return 0
	}
	if dot := dotLen(s, i, obfuscated); dot > 0 && i+dot < len(s) && labelCharLen(s, i+dot) > 0 {
		return 0
	}
	return i - pos
}

// dotLen returns the length of the dot at i: 1 for ".", 3 for "[.]" when
// obfuscated is true, or 0.
func dotLen(s string, i int, obfuscated bool) int {
	switch {
	case i < len(s) && s[i] == '.':
		return 1
	case obfuscated && hasTokenAt(s, i) && s[i+1] == '.':
		return 3
	}
	return 0
}

// octetEnd returns the end of the decimal number from 0 to 255 at i, or
// -1.
func octetEnd(s string, i int) int {
	j, val := i, 0
	for j < len(s) && j-i < 3 && isDigit(s[j]) {
		val = val*10 + int(s[j]-'0')
		j++
	}
	if j == i || val > 255 {
		return -1
	}
	return j
}

// matchIPv6 matches a bare IPv6 address at pos (RFC 4291), with an
// optional "%zone" (RFC 4007), and returns its length. A full stop that
// ends a sentence is not taken as part of it.
func matchIPv6(s string, pos int) int {
	i, colons := pos, 0
	for i < len(s) && i-pos <= maxIPv6 && (isHexDigit(s[i]) || s[i] == '.' || s[i] == ':') {
		if s[i] == ':' {
			colons++
		}
		i++
	}
	if colons < 2 || i-pos > maxIPv6 {
		return 0
	}
	end := zoneEnd(s, i, false)
	if end == i {
		for end > pos && s[end-1] == '.' {
			end--
		}
	}
	if addr, err := netip.ParseAddr(s[pos:end]); err != nil || !addr.Is6() {
		return 0
	}
	return end - pos
}

// zoneEnd returns the end of the "%zone" of an IPv6 address at i, not
// counting a final full stop, or i if there is none. With obfuscated, the
// zone may contain "[.]".
func zoneEnd(s string, i int, obfuscated bool) int {
	if i >= len(s) || s[i] != '%' {
		return i
	}
	j := i + 1
	for j < len(s) && j-i <= 3*maxIPv6 {
		if dot := dotLen(s, j, obfuscated); dot == 3 {
			j += dot
		} else if isZoneChar(s[j]) {
			j++
		} else {
			break
		}
	}
	for j > i+1 && s[j-1] == '.' {
		j--
	}
	if j == i+1 {
		return i
	}
	return j
}

// isIPLiteral reports whether s, the inside of "[...]", is an IPv6
// address, raw or obfuscated, with an optional "%25zone" or "%zone".
func isIPLiteral(s string) bool {
	raw := s
	if containsTokens(s) {
		raw = Deobfuscate(s)
	}
	addr := raw
	if i := strings.IndexByte(raw, '%'); i >= 0 {
		zone := strings.TrimPrefix(raw[i+1:], "25")
		if zone == "" {
			return false
		}
		for j := 0; j < len(zone); j++ {
			if !isZoneChar(zone[j]) && zone[j] != '~' {
				return false
			}
		}
		addr = raw[:i] + "%" + zone
	}
	ip, err := netip.ParseAddr(addr)
	return err == nil && ip.Is6()
}

// A scanner recognizes indicators in s at positions given in increasing
// order. It remembers runs of s that it has already found hold no
// indicator, so that no byte is read more than a constant number of times
// and scanning all of s takes linear time.
type scanner struct {
	s        string
	closing  map[int]int // the "]" closing each "[", once computed
	localEnd int         // no email address starts before this position
	nameEnd  int         // no domain name with a known TLD starts before this position
}

// closingBracket returns the position of the "]" that closes the "[" at
// pos, reading the tokens "[.]", "[:]" and "[@]" as single characters, or
// -1.
func (sc *scanner) closingBracket(pos int) int {
	if sc.closing == nil {
		sc.closing = make(map[int]int)
		var open []int
		for i := 0; i < len(sc.s); i++ {
			switch {
			case hasTokenAt(sc.s, i):
				i += 2
			case sc.s[i] == '[':
				open = append(open, i)
			case sc.s[i] == ']' && len(open) > 0:
				sc.closing[open[len(open)-1]] = i
				open = open[:len(open)-1]
			}
		}
	}
	if c, ok := sc.closing[pos]; ok {
		return c
	}
	return -1
}

// email matches an email address at pos: the dot-atom form of RFC 5322
// in which addresses are written, extended to UTF-8 local parts and
// domain names (RFC 6531, RFC 5890). It returns its length, or 0.
func (sc *scanner) email(pos int) int {
	if pos < sc.localEnd {
		return 0
	}
	s := sc.s
	at := pos
	for at < len(s) {
		l := localCharLen(s, at)
		if l == 0 {
			break
		}
		at += l
	}
	if at > pos && at-pos <= maxLocal && at < len(s) && s[at] == '@' {
		if host, _ := matchHostName(s, at+1, false); host > 0 {
			return at + 1 + host - pos
		}
	}
	sc.localEnd = at // every later start up to at reads the same run
	return 0
}

// domain matches a domain name at pos whose last label is a known
// top-level domain, and returns its length, or 0. It also matches a
// obfuscated name such as "evil[.]example", so that free text can be
// obfuscated more than once.
func (sc *scanner) domain(pos int) int {
	s := sc.s
	if pos < sc.nameEnd || s[pos] == '-' || labelCharLen(s, pos) == 0 {
		return 0
	}
	end, last, labels := scanHostName(s, pos, true)
	if labels >= 2 && end-pos <= maxDomain && isTLD(s[last:end]) && (end == len(s) || s[end] != '@') {
		return end - pos
	}
	sc.nameEnd = end // every later start up to end has the same last label
	return 0
}

// matchHostName matches two or more labels joined by "." at pos, or by
// "[.]" too when obfuscated is true, and returns the length of the match and
// the start of the last label.
func matchHostName(s string, pos int, obfuscated bool) (length, last int) {
	end, last, labels := scanHostName(s, pos, obfuscated)
	if labels < 2 || end-pos > 3*maxDomain {
		return 0, 0
	}
	return end - pos, last
}

// scanHostName reads labels joined by "." (or "[.]" when obfuscated is true)
// from pos. It returns where they end, which is before any final dot, the
// start of the last label, and the number of labels.
func scanHostName(s string, pos int, obfuscated bool) (end, last, labels int) {
	n := len(s)
	i := pos
	for i < n {
		start := i
		for i < n {
			l := labelCharLen(s, i)
			if l == 0 {
				break
			}
			i += l
		}
		if i == start {
			break
		}
		labels++
		last, end = start, i
		switch {
		case i+1 < n && s[i] == '.' && labelCharLen(s, i+1) > 0:
			i++
			continue
		case obfuscated && hasTokenAt(s, i) && s[i+1] == '.' && i+3 < n && labelCharLen(s, i+3) > 0:
			i += 3
			continue
		}
		break
	}
	if labels == 0 {
		end = pos
	}
	return end, last, labels
}

// atBoundary reports whether an indicator can start at pos: at the start
// of s, or after any byte that is not an ASCII letter or digit. An
// underscore is a boundary ("_evil.example_" in Markdown), and so is a
// non-ASCII character, because Chinese and Japanese text puts no space
// before an address. A position inside a UTF-8 sequence is not.
func atBoundary(s string, pos int) bool {
	if pos == 0 {
		return true
	}
	if s[pos]&0xC0 == 0x80 {
		return false
	}
	return !isAlphaNum(s[pos-1])
}

// hasTokenAt reports whether one of "[.]", "[:]" or "[@]" starts at pos.
func hasTokenAt(s string, pos int) bool {
	return pos >= 0 && pos+3 <= len(s) && s[pos] == '[' && s[pos+2] == ']' && isTokenChar(s[pos+1])
}

// containsTokens reports whether s contains "[.]", "[:]" or "[@]".
func containsTokens(s string) bool {
	return strings.Contains(s, "[.]") || strings.Contains(s, "[:]") || strings.Contains(s, "[@]")
}

// labelCharLen returns the length in bytes of the domain label character
// at i, an ASCII letter, digit or hyphen or a Unicode letter, digit or
// mark, or 0. Unicode punctuation, such as a curly quote, ends a label.
func labelCharLen(s string, i int) int {
	if c := s[i]; c < utf8.RuneSelf {
		if isAlphaNum(c) || c == '-' {
			return 1
		}
		return 0
	}
	r, size := utf8.DecodeRuneInString(s[i:])
	if r != utf8.RuneError && (unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r)) {
		return size
	}
	return 0
}

// localCharLen returns the length in bytes of the email local-part
// character at i, or 0: a label character, ".", "_", "%" or "+".
func localCharLen(s string, i int) int {
	switch s[i] {
	case '.', '_', '%', '+':
		return 1
	}
	return labelCharLen(s, i)
}

func isAlpha(c byte) bool      { return (c|0x20) >= 'a' && (c|0x20) <= 'z' }
func isDigit(c byte) bool      { return c >= '0' && c <= '9' }
func isAlphaNum(c byte) bool   { return isAlpha(c) || isDigit(c) }
func isHexDigit(c byte) bool   { return isDigit(c) || ((c|0x20) >= 'a' && (c|0x20) <= 'f') }
func isTokenChar(c byte) bool  { return c == '.' || c == ':' || c == '@' }
func isZoneChar(c byte) bool   { return isAlphaNum(c) || c == '_' || c == '.' || c == '-' }
func isSchemeChar(c byte) bool { return isAlphaNum(c) || c == '+' || c == '-' || c == '.' }

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}
