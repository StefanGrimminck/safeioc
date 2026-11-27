package safeioc

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// This file implements a UTS #58 style link and email detector and uses it
// as an additional oracle: a conformant linkifier must detect no link in any
// obfuscated output.

var (
	schemeAuthorityRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+\-.]*://[^\s<>"']+`)
	mailtoRe          = regexp.MustCompile(`(?i)\bmailto:[^\s<>"']*@[^\s<>"']+`)
	bareEmailRe       = regexp.MustCompile(
		`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\b`,
	)
	bareIPv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	// RE2 has no lookaround, so IPv6 detection uses two expressions.
	bareIPv6ShorthandRe = regexp.MustCompile(`(?:[0-9A-Fa-f]{1,4})?(?::(?:[0-9A-Fa-f]{1,4})?){2,}`)
	bareIPv6FullRe      = regexp.MustCompile(`(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}`)

	bracketLiteralRe = regexp.MustCompile(`\[[^\[\]]*\]`)

	bareDomainRe = regexp.MustCompile(
		`\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)+\b`,
	)

	knownTLDs = map[string]bool{
		"com": true, "org": true, "net": true, "edu": true, "gov": true,
		"mil": true, "io": true, "co": true, "uk": true, "de": true,
		"jp": true, "int": true, "arpa": true,
		"example": true, "invalid": true, "test": true, "localhost": true,
	}
)

// A linkDetector finds one kind of link in a text and returns the text
// it would turn into a link, or "".
type linkDetector struct {
	kind string
	find func(s string) string
}

// linkDetectors are tried in order, as a linkifier would.
var linkDetectors = []linkDetector{
	{"scheme-URL", schemeAuthorityRe.FindString},
	{"mailto", mailtoRe.FindString},
	{"bare-email", bareEmailRe.FindString},
	{"bare-IPv4", findBareIPv4},
	{"bare-IPv6", findBareIPv6},
	{"bracket-IP-literal", findBracketLiteral},
	{"bare-domain", findBareDomain},
}

// linkifierDetects returns the kind and text of the first link a
// linkifier would find in s, or "", "".
func linkifierDetects(s string) (kind, span string) {
	for _, d := range linkDetectors {
		if m := d.find(s); m != "" {
			return d.kind, m
		}
	}
	return "", ""
}

func findBareIPv4(s string) string {
	m := bareIPv4Re.FindString(s)
	if ip := net.ParseIP(m); ip == nil || ip.To4() == nil {
		return ""
	}
	return m
}

func findBareIPv6(s string) string {
	for _, re := range []*regexp.Regexp{bareIPv6FullRe, bareIPv6ShorthandRe} {
		loc := re.FindStringIndex(s)
		if loc == nil || colonHexExtends(s, loc) || !ipv6CandidateBounded(s, loc) {
			continue
		}
		if m := s[loc[0]:loc[1]]; strings.Count(m, ":") >= 2 && net.ParseIP(m) != nil {
			return m
		}
	}
	return ""
}

func findBracketLiteral(s string) string {
	for _, loc := range bracketLiteralRe.FindAllStringIndex(s, -1) {
		if looksLikeIPv6Inner(s[loc[0]+1 : loc[1]-1]) {
			return s[loc[0]:loc[1]]
		}
	}
	return ""
}

func findBareDomain(s string) string {
	for _, loc := range bareDomainRe.FindAllStringIndex(s, -1) {
		if loc[0] > 0 && s[loc[0]-1] == '%' {
			continue // the hex digits of a percent-encoding
		}
		if m := s[loc[0]:loc[1]]; knownTLDs[strings.ToLower(lastLabel(m))] {
			return m
		}
	}
	return ""
}

// colonHexExtends reports whether the match at loc is part of a longer
// colon-separated run.
func colonHexExtends(s string, loc []int) bool {
	if loc[1] < len(s) && s[loc[1]] == ':' {
		return true
	}
	if loc[0] > 0 && s[loc[0]-1] == ':' {
		return true
	}
	return false
}

// ipv6CandidateBounded reports whether the match at loc is not part of a
// longer run of IPv6 address characters.
func ipv6CandidateBounded(s string, loc []int) bool {
	if loc[0] > 0 && isIPv6RunChar(s[loc[0]-1]) {
		return false
	}
	if loc[1] < len(s) && isIPv6RunChar(s[loc[1]]) {
		return false
	}
	return true
}

// isIPv6RunChar reports whether c can be part of an IPv6 address with a
// zone.
func isIPv6RunChar(c byte) bool {
	if c == ':' || c == '.' || c == '%' {
		return true
	}
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}

// looksLikeIPv6Inner reports whether s, the inside of "[...]", is an IPv6
// address, with or without a zone.
func looksLikeIPv6Inner(s string) bool {
	if s == "" || !strings.Contains(s, ":") {
		return false
	}
	if strings.ContainsAny(s, "[]@") {
		return false
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	if idx := strings.Index(s, "%"); idx != -1 {
		if ip := net.ParseIP(s[:idx]); ip != nil {
			return true
		}
	}
	return false
}

// lastLabel returns the part of s after its last dot.
func lastLabel(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

// isRelevantIOC reports whether s looks like an indicator an analyst would
// share, as opposed to an input that only exercises URL parser edge cases.
func isRelevantIOC(s string) bool {
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		return err == nil && u.Host != "" && !strings.ContainsAny(s, "\t\r\n")
	}
	return looksLikeBareIOC(s)
}

// looksLikeBareIOC reports whether s, which has no "scheme://", looks like a
// host, an address or an opaque URI. Tabs and newlines inside an input,
// path-only references, relative paths, fragment or query scraps, input
// with nothing to defang, and a scheme-like prefix followed by "::" (the
// WPT inputs "http::@c:29" and "sc::a@example.net") are parser tests.
func looksLikeBareIOC(s string) bool {
	if s == "" || strings.ContainsAny(s, "\t\r\n") || strings.IndexByte("/.#?", s[0]) >= 0 {
		return false
	}
	if strings.HasPrefix(s, ":") && !strings.HasPrefix(s, "::") {
		return false
	}
	if !containsAlphaNum(s) || !strings.ContainsAny(s, ".@:") {
		return false
	}
	idx := strings.Index(s, "::")
	return idx <= 0 || idx >= 10 || strings.ContainsAny(s[:idx], ":/[")
}

// containsAlphaNum reports whether s contains an ASCII letter or digit.
func containsAlphaNum(s string) bool {
	for i := 0; i < len(s); i++ {
		if isAlphaNum(s[i]) {
			return true
		}
	}
	return false
}

// TestLinkifierBaseline checks that the detector finds links in most raw
// corpus inputs, so that finding none after defanging means something.
func TestLinkifierBaseline(t *testing.T) {
	entries := loadCorpus(t)
	detected := 0
	for _, e := range entries {
		if what, _ := linkifierDetects(e.text); what != "" {
			detected++
		}
	}
	if detected < len(entries)/2 {
		t.Fatalf("detector too weak: it finds a link in only %d of %d raw inputs", detected, len(entries))
	}
}

// TestLinkifierSelfCheck checks that the detector finds most raw unit
// vectors.
func TestLinkifierSelfCheck(t *testing.T) {
	missed := 0
	for _, v := range obfuscationVectors {
		if what, _ := linkifierDetects(v.in); what == "" {
			missed++
		}
	}
	if missed > len(obfuscationVectors)/3 {
		t.Errorf("detector missed %d of %d raw unit vectors", missed, len(obfuscationVectors))
	}
}

// TestCorpusDefeatsLinkifier checks that the detector finds no link in the
// defanged form of any IOC-shaped corpus input it found a link in before.
//
// A bare domain name in a path, query or fragment is not a failure: Step 4
// of the draft does not defang bare domains there, because they cannot be
// told apart from file names. The parser oracle in TestCorpusNeutralizes
// has no such exception.
func TestCorpusDefeatsLinkifier(t *testing.T) {
	tested, bareDomain := 0, 0
	for _, e := range loadCorpus(t) {
		if !isRelevantIOC(e.text) {
			continue
		}
		if what, _ := linkifierDetects(e.text); what == "" {
			continue
		}
		tested++
		obf := Obfuscate(e.text)
		switch what, span := linkifierDetects(obf); what {
		case "":
		case "bare-domain":
			bareDomain++
		default:
			t.Errorf("%v: detector finds %s %q after Obfuscate\n in  %q\n out %q", e, what, span, e.text, obf)
		}
	}
	t.Logf("%d IOC-shaped inputs tested, %d with a bare domain left in the path", tested, bareDomain)
}

// TestLinkifierOnVectors checks the unit vectors, alone and in text.
func TestLinkifierOnVectors(t *testing.T) {
	for _, v := range obfuscationVectors {
		if what, span := linkifierDetects(v.out); what != "" {
			t.Errorf("%s: detector finds %s %q in %q", v.name, what, span, v.out)
		}
	}
	for _, v := range textVectors {
		if v.in == v.out {
			continue // text with no indicator
		}
		if what, span := linkifierDetects(ObfuscateText(v.in)); what != "" && what != "bare-domain" {
			t.Errorf("%s: detector finds %s %q in ObfuscateText(%q)", v.name, what, span, v.in)
		}
	}
}

// TestTextDefeatsLinkifier places every IOC-shaped corpus input in a
// sentence and checks that ObfuscateText leaves nothing for the detector
// to find, other than the Step 4 bare-domain case.
func TestTextDefeatsLinkifier(t *testing.T) {
	for _, e := range loadCorpus(t) {
		if !isRelevantIOC(e.text) {
			continue
		}
		text := "Seen " + e.text + " today."
		if what, _ := linkifierDetects(text); what == "" || what == "bare-domain" {
			continue
		}
		obf := ObfuscateText(text)
		if what, span := linkifierDetects(obf); what != "" && what != "bare-domain" {
			t.Errorf("%v: detector finds %s %q after ObfuscateText\n in  %q\n out %q", e, what, span, text, obf)
		}
	}
}
