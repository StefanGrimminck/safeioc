package safeioc

import "strings"

// ObfuscateText obfuscates every indicator it finds in the free text s and
// leaves the rest of s unchanged.
//
//	ObfuscateText("Payload at https://evil.example/x.bin, C2 is 198.51.100.7.")
//	// Payload at [https]://evil[.]example/x.bin, C2 is 198[.]51[.]100[.]7.
//
// It recognizes URLs with a "scheme://" (and "mailto:" URLs), email
// addresses, IPv4 and IPv6 addresses, and domain names whose last label
// is a known top-level domain. Each one is obfuscated with [Obfuscate].
// Punctuation around an indicator, such as the full stop that ends a
// sentence or the brackets around a URL, is not taken as part of it.
//
// Already-obfuscated indicators are left as they are, so ObfuscateText can
// be applied to its own output. [DeobfuscateText] reverses it.
func ObfuscateText(s string) string {
	sc := scanner{s: s}
	return replaceSpans(s, sc.liveSpan, safeForm)
}

// DeobfuscateText restores every obfuscated indicator it finds in the free
// text s and leaves the rest of s unchanged. Only complete indicators are
// restored, as Section 11.3 of the draft asks: in a regular expression such
// as "[0-9]+[.][0-9]+", the "[.]" is not part of an obfuscated address and is
// kept. An obfuscated domain name is restored when its last label is a known
// top-level domain, the rule ObfuscateText uses to find it.
//
// The result contains live indicators: write it only where it will not be
// rendered as links or fetched.
func DeobfuscateText(s string) string {
	if strings.IndexByte(s, '[') < 0 && !containsLegacyName(s) {
		return s
	}
	ds := safeScanner{s: s, nextToken: -1}
	return replaceSpans(s, ds.span, Deobfuscate)
}

// replaceSpans returns s with every span that find reports replaced by
// its transform. It calls find at each word boundary, in increasing order,
// and skips past each span it reports. If no span changes, it returns s
// without copying it.
func replaceSpans(s string, find func(pos int) (end int, ok bool), transform func(string) string) string {
	var b strings.Builder
	done := 0 // s[:done] has been written to b
	for i := 0; i < len(s); {
		if !atBoundary(s, i) {
			i++
			continue
		}
		end, ok := find(i)
		if !ok {
			i++
			continue
		}
		if out := transform(s[i:end]); out != s[i:end] {
			if b.Len() == 0 {
				b.Grow(len(s) + len(s)/4)
			}
			b.WriteString(s[done:i])
			b.WriteString(out)
			done = end
		}
		i = end
	}
	if done == 0 {
		return s
	}
	b.WriteString(s[done:])
	return b.String()
}

// liveSpan reports whether an indicator, live or already obfuscated, starts
// at pos in free text, and where it ends.
func (sc *scanner) liveSpan(pos int) (int, bool) {
	s := sc.s
	if s[pos] == '[' {
		return sc.bracketSpan(pos)
	}
	if end, ok := uriSpan(s, pos); ok {
		return end, true
	}
	// "::" alone is the unspecified address, but in prose it is far more
	// often a scope operator ("Foo :: Bar"), so a digit is required.
	if m := matchIPv6(s, pos); m > 2 && (pos+m == len(s) || !isAlphaNum(s[pos+m])) {
		return trimSpan(s, pos, hostTailEnd(s, pos+m), pos+m), true
	}
	// An address starting with "." or "+" is taken from its first letter
	// or digit, where DeobfuscateText starts looking.
	if isHostStart(s[pos]) {
		if m := sc.email(pos); m > 0 {
			return pos + m, true
		}
	}
	m := matchIPv4(s, pos, false)
	if m == 0 {
		m = sc.domain(pos)
	}
	if m == 0 {
		return 0, false
	}
	return trimSpan(s, pos, hostTailEnd(s, pos+m), pos+m), true
}

// bracketSpan reports whether an obfuscated URI or an IPv6 literal starts at
// the "[" at pos, and where it ends.
func (sc *scanner) bracketSpan(pos int) (int, bool) {
	s := sc.s
	if _, sepEnd, ok := matchBracketedScheme(s, pos); ok && sepEnd < len(s) && isURLChar(s[sepEnd]) {
		return trimSpan(s, pos, urlEnd(s, sepEnd), sepEnd), true
	}
	if closing := sc.closingBracket(pos); closing > pos+1 && isIPLiteral(s[pos+1:closing]) {
		return trimSpan(s, pos, hostTailEnd(s, closing+1), closing+1), true
	}
	return 0, false
}

// uriSpan reports whether a URI with "scheme://", or a "mailto:" URI,
// starts at pos, and where it ends.
func uriSpan(s string, pos int) (int, bool) {
	sLen, sepLen, ok := matchScheme(s, pos)
	if !ok {
		return 0, false
	}
	sep := pos + sLen + sepLen
	if sep >= len(s) || !isURLChar(s[sep]) || (sepLen != 3 && !strings.EqualFold(s[pos:pos+sLen], "mailto")) {
		return 0, false
	}
	return trimSpan(s, pos, urlEnd(s, sep), sep), true
}

// A safeScanner finds obfuscated indicators in free text. Its two cached
// positions only move forward, so scanning a text takes linear time.
type safeScanner struct {
	s         string
	runEnd    int // end of the run of URL characters measured last
	nextToken int // position of the next "[.]", "[:]" or "[@]"; -1 if not yet known
	hostEnd   int // no obfuscated host name starts before this position
	run       hostRun
}

// span reports whether an obfuscated indicator starts at pos and where it
// ends. Positions must be given in increasing order.
func (f *safeScanner) span(pos int) (int, bool) {
	s := f.s
	if schemeEnd, sepEnd, ok := matchBracketedScheme(s, pos); ok && sepEnd < len(s) && isURLChar(s[sepEnd]) {
		// "[INFO]:started" in a log is not an obfuscated URI. Accept
		// "[scheme]://", "[mailto]:", and an opaque URI that holds a
		// token, as in "[urn]:example:a[.]b".
		run := f.urlRunEnd(sepEnd)
		if !strings.HasPrefix(s[sepEnd:], "//") && !strings.EqualFold(s[pos+1:schemeEnd], "mailto") && f.tokenAfter(sepEnd) >= run {
			return 0, false
		}
		return trimSpan(s, pos, run, sepEnd), true
	}
	if m := matchLegacyScheme(s, pos); m > 0 {
		sep := pos + m + 1
		if s[pos+m] == '[' {
			sep += 2 // "[:]"
		}
		if sep < len(s) && isURLChar(s[sep]) {
			return trimSpan(s, pos, f.urlRunEnd(sep), sep), true
		}
		return 0, false
	}
	// A host takes its port and path with it, as in ObfuscateText, so that
	// indicators Obfuscate obfuscated in the path are restored too.
	m := matchObfuscatedIPv6(s, pos)
	if m == 0 {
		m = matchIPv4(s, pos, true)
	}
	if m > 0 {
		return trimSpan(s, pos, hostTailEnd(s, pos+m), pos+m), true
	}
	return f.hostSpan(pos)
}

// hostSpan reports whether an obfuscated email address or domain name starts
// at pos, and where it ends.
func (f *safeScanner) hostSpan(pos int) (int, bool) {
	s := f.s
	if pos < f.hostEnd || !isHostStart(s[pos]) {
		return 0, false
	}
	if pos >= f.run.read {
		f.run = readHostRun(s, pos)
	}
	if f.run.lastToken < pos {
		f.hostEnd = f.run.read // no token follows in this run
		return 0, false
	}
	if f.run.lastAt >= pos {
		return f.run.end, true // an email address has no port or path
	}
	// A host name is label characters joined by "[.]": "_", "%" and "+"
	// belong to email local parts, so "_evil[.]example_" (Markdown
	// emphasis) and "evil[.]example_x" end before the underscore, as they
	// do in ObfuscateText.
	end, last, labels := scanHostName(s, pos, true)
	if labels == 0 {
		return 0, false
	}
	if labels < 2 || !containsTokens(s[pos:end]) || !isTLD(s[last:end]) {
		// Every later start up to end reads the rest of the same name and
		// fails the same way. "log[.]txt" is not an indicator.
		f.hostEnd = end
		return 0, false
	}
	return trimSpan(s, pos, hostTailEnd(s, end), end), true
}

// A hostRun is a run of host characters and "[.]" and "[@]" tokens in
// free text, such as "first[.]last[@]evil[.]example".
type hostRun struct {
	read      int // where reading stopped
	end       int // the position after the last host character
	lastToken int // the last token before end, or -1
	lastAt    int // the last "[@]" before end, or -1
}

// readHostRun reads the host run that starts at pos. A token right after
// "+" ends the run, so that "\w+[.]x" in a regular expression is not
// read as a host. Every later start in the run reads the same run to the
// same end, so DeobfuscateText reads each run once.
func readHostRun(s string, pos int) hostRun {
	r := hostRun{lastToken: -1, lastAt: -1}
	token, at := -1, -1
	i := pos
	for i < len(s) {
		if l := localCharLen(s, i); l > 0 && s[i] != '.' {
			i += l
			r.end, r.lastToken, r.lastAt = i, token, at
			continue
		}
		if i > pos && hasTokenAt(s, i) && s[i+1] != ':' && (s[i-1] != '+' || hasTokenAt(s, i-3)) {
			token = i
			if s[i+1] == '@' {
				at = i
			}
			i += 3
			continue
		}
		break
	}
	r.read = i
	return r
}

// urlRunEnd returns the end of the run of URL characters that contains
// pos.
func (f *safeScanner) urlRunEnd(pos int) int {
	if pos >= f.runEnd {
		f.runEnd = urlEnd(f.s, pos)
	}
	return f.runEnd
}

// tokenAfter returns the position of the first token at or after pos, or
// len(s).
func (f *safeScanner) tokenAfter(pos int) int {
	if f.nextToken < pos {
		f.nextToken = len(f.s)
		for i := pos; i+3 <= len(f.s); i++ {
			if hasTokenAt(f.s, i) {
				f.nextToken = i
				break
			}
		}
	}
	return f.nextToken
}

// matchObfuscatedIPv6 matches an obfuscated IPv6 address at pos, such as
// "2001[:]db8[:][:]1" or "[:][:]ffff[:]192[.]0[.]2[.]1", with an optional
// zone, and returns its length.
func matchObfuscatedIPv6(s string, pos int) int {
	i, colons := pos, 0
	for i < len(s) && i-pos <= 3*maxIPv6 {
		if isHexDigit(s[i]) {
			i++
			continue
		}
		if !hasTokenAt(s, i) || s[i+1] == '@' {
			break
		}
		if s[i+1] == ':' {
			colons++
		}
		i += 3
	}
	if colons < 2 || (i < len(s) && isAlphaNum(s[i])) {
		return 0
	}
	if ip := Deobfuscate(s[pos:i]); matchIPv6(ip, 0) != len(ip) {
		return 0
	}
	return zoneEnd(s, i, true) - pos
}

// isHostStart reports whether a host name or email address can start
// with c in free text.
func isHostStart(c byte) bool {
	return isAlphaNum(c) || c == '_' || c == '%' || c >= 0x80
}

// isURLChar reports whether c can be part of a URL written in free text.
// The bytes of non-ASCII characters count, so IRIs stay in one piece.
func isURLChar(c byte) bool {
	if c <= ' ' || c == 0x7f {
		return false
	}
	switch c {
	case '"', '<', '>', '`', '{', '}', '|', '^':
		return false
	}
	return true
}

// urlEnd returns the end of the run of URL characters starting at pos.
func urlEnd(s string, pos int) int {
	for pos < len(s) && isURLChar(s[pos]) {
		pos++
	}
	return pos
}

// hostTailEnd extends a host that ends at pos over a following ":port"
// and a path, query or fragment.
func hostTailEnd(s string, pos int) int {
	n := len(s)
	if pos < n && s[pos] == ':' {
		j := pos + 1
		for j < n && isDigit(s[j]) {
			j++
		}
		if j == pos+1 {
			return pos
		}
		pos = j
	}
	if pos < n && (s[pos] == '/' || s[pos] == '?' || s[pos] == '#') {
		// Without a scheme, a comma or semicolon more likely separates the
		// next indicator in a list ("192.0.2.0/24,evil.example") than
		// continues the path.
		for pos < n && isURLChar(s[pos]) && s[pos] != ',' && s[pos] != ';' {
			pos++
		}
	}
	return pos
}

// trimSpan drops the punctuation of the surrounding text from the end of
// the span s[start:end]: sentence punctuation, quotes, and closing
// brackets with no opening partner in the span. A "::" that ends an IPv6
// address and the "]" of a token are kept. It never trims below floor.
func trimSpan(s string, start, end, floor int) int {
	span := s[start:end]
	parens := strings.Count(span, "(") - strings.Count(span, ")")
	squares := strings.Count(span, "[") - strings.Count(span, "]")
	for end > floor {
		switch s[end-1] {
		case ':':
			if end-2 >= start && s[end-2] == ':' {
				return end
			}
		case '.', ',', ';', '!', '?', '\'', '*':
		case ')':
			if parens >= 0 {
				return end
			}
			parens++
		case ']':
			if squares >= 0 || hasTokenAt(s, end-3) {
				return end
			}
			squares++
		default:
			return end
		}
		end--
	}
	return end
}
