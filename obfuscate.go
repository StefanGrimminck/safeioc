package safeioc

import "strings"

// Obfuscate returns the obfuscated (Safe-IOC) form of the indicator s: a URL
// or other URI, a domain name, an IPv4 or IPv6 address (optionally with a
// port or CIDR prefix length), or an email address.
//
//	Obfuscate("https://evil.example/a?u=http://198.51.100.7/")
//	// [https]://evil[.]example/a?u=[http]://198[.]51[.]100[.]7/
//
// It applies the four steps of the draft in order:
//
//  1. wrap the URI scheme in brackets ("https" becomes "[https]");
//  2. replace the "@" before the host with "[@]";
//  3. replace "." in the host with "[.]", and inside an IPv6 address
//     replace ":" with "[:]" as well;
//  4. obfuscate URLs, email addresses and IP addresses nested in the path,
//     query or fragment, leaving every other character there unchanged.
//
// Leading and trailing whitespace is kept as it is. Tokens that are
// already obfuscated are left alone, so Obfuscate can be applied to its own
// output. To obfuscate the indicators inside free text, use [ObfuscateText];
// Obfuscate does so itself when s starts with a character no indicator
// starts with, such as a quote, a parenthesis or "/".
func Obfuscate(s string) string {
	lead, core, trail := splitSpace(s)
	switch {
	case core == "":
		return s
	case !startsLikeIndicator(core):
		// "(https://x)", "<https://x>", "//x/y": the canonical steps would
		// leave what follows live, so find the indicators in it instead.
		core = ObfuscateText(core)
	default:
		core = safeForm(core)
	}
	if lead == "" && trail == "" {
		return core
	}
	return lead + core + trail
}

// startsLikeIndicator reports whether an indicator can start where s
// starts: with a scheme, host, address, email local part or an obfuscated
// "[" token. A non-ASCII character counts only if it is a letter or digit,
// so a byte order mark or a no-break space is read as text.
func startsLikeIndicator(s string) bool {
	switch s[0] {
	case '[', ':', '.', '@', '%', '_', '+', '-':
		return true
	}
	return labelCharLen(s, 0) > 0
}

// splitSpace splits s into its leading ASCII whitespace, the rest, and its
// trailing ASCII whitespace.
func splitSpace(s string) (lead, core, trail string) {
	i, j := 0, len(s)
	for i < j && isSpace(s[i]) {
		i++
	}
	for j > i && isSpace(s[j-1]) {
		j--
	}
	return s[:i], s[i:j], s[j:]
}

// obfuscate applies the canonical transformation to the non-empty indicator
// s.
func safeForm(s string) string {
	d := safeWriter{s: s, sc: scanner{s: s}}
	d.b.Grow(len(s) + len(s)/2)
	d.tail(d.head(), len(s))
	return d.b.String()
}

// A safeWriter writes the obfuscated form of s to b, left to right.
type safeWriter struct {
	s  string
	sc scanner
	b  strings.Builder
}

// An authorityKind says which characters of an authority Steps 2 and 3
// bracket.
type authorityKind uint8

const (
	// hostAuthority is the authority of a hierarchical URI, or a bare host
	// or email address: every "@" is bracketed, and "." only in the host,
	// after the last "@" (Section 4.3 of the draft).
	hostAuthority authorityKind = iota
	// opaqueBody is the body of a URI such as "mailto:" or "urn:", in which
	// every "@" and "." is bracketed (Section 4.3 of the draft).
	opaqueBody
)

// head obfuscates the start of the indicator, Steps 1 to 3, and returns
// where its path, query or fragment begins.
func (d *safeWriter) head() int {
	s := d.s
	// A bare IPv6 address first: "fe80::1" would also match as a scheme.
	if m := matchIPv6(s, 0); m > 0 {
		writeBracketed(&d.b, s[:m], ".:")
		return d.authority(m, len(s), hostAuthority)
	}
	// "evil.example:443" is a host and port; a scheme has no dot unless
	// it is followed by "//".
	if sLen, sepLen, ok := matchScheme(s, 0); ok && (sepLen == 3 || strings.IndexByte(s[:sLen], '.') < 0) {
		sep := sLen + sepLen
		d.wrapScheme(0, sLen, sep)
		return d.afterScheme(sep, len(s), sepLen == 3)
	}
	if _, sepEnd, ok := matchBracketedScheme(s, 0); ok {
		return d.wrapped(0, sepEnd, len(s))
	}
	return d.authority(0, len(s), hostAuthority)
}

// afterScheme obfuscates the authority of a hierarchical URI, whose "//" ends
// at pos, or the body of an opaque one, and returns where it ends. An
// authority may be a bare IPv6 address, as in "http://2001:db8::1/".
func (d *safeWriter) afterScheme(pos, end int, hierarchical bool) int {
	if !hierarchical {
		return d.authority(pos, end, opaqueBody)
	}
	if m := matchIPv6(d.s, pos); m > 0 && pos+m <= end {
		writeBracketed(&d.b, d.s[pos:pos+m], ".:")
		pos += m
	}
	return d.authority(pos, end, hostAuthority)
}

// authority applies Steps 2 and 3 from pos up to end and returns where it
// stopped. A host authority ends at "/", "?" or "#", or where a second URI
// is joined on without a path ("a.example,https://b"). An opaque body ends
// at "?" or "#", and nested indicators in it are obfuscated as in Step 4.
func (d *safeWriter) authority(pos, end int, kind authorityKind) int {
	s := d.s
	hostStart := pos
	if kind == hostAuthority {
		hostStart = d.hostStart(pos, end)
	}
	i := pos
	for i < end && !d.authorityEnds(pos, i, kind) {
		inHost := kind == opaqueBody || i >= hostStart
		switch c := s[i]; {
		case c == '@' || (c == '.' && inHost):
			writeBracketed(&d.b, s[i:i+1], ".@")
			i++
			continue
		case kind == hostAuthority && inHost && isEncodedDot(s, i, end):
			// The percent-encoded dot in a host is decoded and bracketed,
			// as the draft requires: the dot is unreserved, so "%2e" and
			// "." are the same (RFC 3986 Section 2.3). Everywhere else, and
			// for the reserved "%40" and "%3a" everywhere, the encoding is
			// kept, because decoding would change the URI.
			d.b.WriteString("[.]")
			i += 3
			continue
		}
		if next, ok := d.authorityPart(i, end, kind); ok {
			i = next
			continue
		}
		d.b.WriteByte(s[i])
		i++
	}
	return i
}

// hostStart returns where the host of the authority that starts at pos
// begins: after its last "@" or "[@]", or at pos. Like a browser, it reads
// "\" as the end of the authority, so in "https://evil.example\@good.example"
// the host is "evil.example".
func (d *safeWriter) hostStart(pos, end int) int {
	s := d.s
	start := pos
	for i := pos; i < end; i++ {
		switch {
		case hasTokenAt(s, i):
			if s[i+1] == '@' {
				start = i + 3
			}
			i += 2
		case s[i] == '@':
			start = i + 1
		case s[i] == '/' || s[i] == '\\' || s[i] == '?' || s[i] == '#':
			return start
		}
	}
	return start
}

// isEncodedDot reports whether a percent-encoded dot, "%2e" or "%2E",
// starts at i and ends before end.
func isEncodedDot(s string, i, end int) bool {
	return i+3 <= end && s[i] == '%' && s[i+1] == '2' && (s[i+2]|0x20) == 'e'
}

// authorityEnds reports whether the authority of the given kind that
// starts at pos ends at i.
func (d *safeWriter) authorityEnds(pos, i int, kind authorityKind) bool {
	switch c := d.s[i]; {
	case c == '?' || c == '#':
		return true
	case kind == opaqueBody:
		return false
	case c == '/':
		return true
	case i > pos && isAlpha(c) && atBoundary(d.s, i):
		_, sepLen, ok := matchScheme(d.s, i)
		return ok && sepLen == 3
	}
	return false
}

// authorityPart obfuscates the part of an authority that starts at i, if it
// is more than one character: a token, a bracketed part, or in an opaque
// body a nested indicator. It returns the position after it.
func (d *safeWriter) authorityPart(i, end int, kind authorityKind) (int, bool) {
	s := d.s
	switch {
	case hasTokenAt(s, i) && i+3 <= end:
		d.b.WriteString(s[i : i+3])
		return i + 3, true
	case s[i] == '[':
		return d.bracket(i, end)
	case kind == opaqueBody && atBoundary(s, i):
		return d.nestedURIOrAddress(i, end)
	}
	return 0, false
}

// bracket obfuscates what starts with the "[" at pos in an authority: an
// already wrapped scheme, an IPv6 literal, or other bracketed host text.
// It returns the position after it.
func (d *safeWriter) bracket(pos, end int) (int, bool) {
	s := d.s
	if _, sepEnd, ok := matchBracketedScheme(s, pos); ok && sepEnd <= end {
		return d.wrapped(pos, sepEnd, end), true
	}
	closing := d.sc.closingBracket(pos)
	if closing < 0 || closing >= end {
		return 0, false
	}
	inner := s[pos+1 : closing]
	switch {
	case containsTokens(inner):
		d.b.WriteString(s[pos : closing+1]) // already obfuscated
	case strings.IndexByte(inner, '[') >= 0:
		d.b.WriteByte('[') // nested brackets are obfuscated one at a time
		return pos + 1, true
	case strings.IndexByte(inner, ':') >= 0:
		// An IPv6 literal, valid or not: the outer brackets are part of
		// the URI syntax and kept, every ":" and "." inside is bracketed.
		d.b.WriteByte('[')
		writeBracketed(&d.b, inner, ".:")
		d.b.WriteByte(']')
	default:
		d.b.WriteByte('[')
		writeBracketed(&d.b, inner, ".@")
		d.b.WriteByte(']')
	}
	return closing + 1, true
}

// tail applies Step 4 to s[pos:end]: nested indicators are obfuscated and
// every other character is kept.
func (d *safeWriter) tail(pos, end int) {
	s := d.s
	for i := pos; i < end; {
		if hasTokenAt(s, i) {
			d.b.WriteString(s[i : i+3])
			i += 3
			continue
		}
		if _, sepEnd, ok := matchBracketedScheme(s, i); ok && sepEnd <= end {
			i = d.wrapped(i, sepEnd, end)
			continue
		}
		if atBoundary(s, i) {
			if next, ok := d.nested(i, end); ok {
				i = next
				continue
			}
		}
		d.b.WriteByte(s[i])
		i++
	}
}

// nested obfuscates the indicator at pos, if there is one, and returns the
// position after it: a URI with "scheme://", a "mailto:" URI, or a bare
// IP address or email address.
func (d *safeWriter) nested(pos, end int) (int, bool) {
	if next, ok := d.nestedURIOrAddress(pos, end); ok {
		return next, true
	}
	if m := d.sc.email(pos); m > 0 {
		writeEmail(&d.b, d.s[pos:pos+m])
		return pos + m, true
	}
	return 0, false
}

// nestedURIOrAddress is nested without email addresses, which an opaque
// body brackets as it reads them.
func (d *safeWriter) nestedURIOrAddress(pos, end int) (int, bool) {
	s := d.s
	if s[pos] == '[' {
		if _, sepEnd, ok := matchBracketedScheme(s, pos); ok && sepEnd <= end {
			return d.wrapped(pos, sepEnd, end), true
		}
		return 0, false
	}
	if sLen, sepLen, ok := matchScheme(s, pos); ok {
		sep := pos + sLen + sepLen
		if sepLen == 3 || (strings.EqualFold(s[pos:pos+sLen], "mailto") && d.sc.email(sep) > 0) {
			d.wrapScheme(pos, sLen, sep)
			return d.afterScheme(sep, end, sepLen == 3), true
		}
	}
	if pos == 0 || s[pos-1] != '%' { // not the hex digits of "%3A"
		if m := matchIPv6(s, pos); m > 0 {
			writeBracketed(&d.b, s[pos:pos+m], ".:")
			return pos + m, true
		}
	}
	if m := matchIPv4(s, pos, false); m > 0 {
		writeBracketed(&d.b, s[pos:pos+m], ".")
		return pos + m, true
	}
	return 0, false
}

// wrapScheme writes the scheme s[pos:pos+schemeLen] in brackets, followed
// by its separator, which ends at sep.
func (d *safeWriter) wrapScheme(pos, schemeLen, sep int) {
	d.b.WriteByte('[')
	d.b.WriteString(d.s[pos : pos+schemeLen])
	d.b.WriteByte(']')
	d.b.WriteString(d.s[pos+schemeLen : sep])
}

// wrapped copies the already obfuscated "[scheme]:" at pos, whose separator
// ends at sepEnd, and obfuscates the authority or body after it.
func (d *safeWriter) wrapped(pos, sepEnd, end int) int {
	d.b.WriteString(d.s[pos:sepEnd])
	if !strings.HasPrefix(d.s[sepEnd:end], "//") {
		return d.afterScheme(sepEnd, end, false)
	}
	d.b.WriteString("//")
	return d.afterScheme(sepEnd+2, end, true)
}

// writeEmail writes the email address s to b with its "@" and the dots of
// its domain bracketed. The local part is kept: it is no host.
func writeEmail(b *strings.Builder, s string) {
	at := strings.LastIndexByte(s, '@')
	b.WriteString(s[:at])
	b.WriteString("[@]")
	writeBracketed(b, s[at+1:], ".")
}

// writeBracketed writes s to b with every byte that is in chars bracketed.
func writeBracketed(b *strings.Builder, s, chars string) {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(chars, s[i]) >= 0 {
			b.WriteByte('[')
			b.WriteByte(s[i])
			b.WriteByte(']')
		} else {
			b.WriteByte(s[i])
		}
	}
}
