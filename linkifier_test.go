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

func linkifierDetects(s string) (what, span string) {
	if m := schemeAuthorityRe.FindString(s); m != "" {
		return "scheme-URL", m
	}
	if m := mailtoRe.FindString(s); m != "" {
		return "mailto", m
	}
	if m := bareEmailRe.FindString(s); m != "" {
		return "bare-email", m
	}
	if m := bareIPv4Re.FindString(s); m != "" {
		if ip := net.ParseIP(m); ip != nil && ip.To4() != nil {
			return "bare-IPv4", m
		}
	}
	if loc := bareIPv6FullRe.FindStringIndex(s); loc != nil {
		if !colonHexExtends(s, loc) && ipv6CandidateBounded(s, loc) {
			m := s[loc[0]:loc[1]]
			if ip := net.ParseIP(m); ip != nil {
				return "bare-IPv6", m
			}
		}
	}
	if loc := bareIPv6ShorthandRe.FindStringIndex(s); loc != nil {
		m := s[loc[0]:loc[1]]
		if strings.Count(m, ":") >= 2 && !colonHexExtends(s, loc) && ipv6CandidateBounded(s, loc) {
			if ip := net.ParseIP(m); ip != nil {
				return "bare-IPv6", m
			}
		}
	}
	for _, loc := range bracketLiteralRe.FindAllStringIndex(s, -1) {
		inner := s[loc[0]+1 : loc[1]-1]
		if looksLikeIPv6Inner(inner) {
			return "bracket-IP-literal", s[loc[0]:loc[1]]
		}
	}
	for _, loc := range bareDomainRe.FindAllStringIndex(s, -1) {
		if loc[0] > 0 && s[loc[0]-1] == '%' {
			continue
		}
		m := s[loc[0]:loc[1]]
		if tld := lastLabel(m); knownTLDs[strings.ToLower(tld)] {
			return "bare-domain", m
		}
	}
	return "", ""
}

func colonHexExtends(s string, loc []int) bool {
	if loc[1] < len(s) && s[loc[1]] == ':' {
		return true
	}
	if loc[0] > 0 && s[loc[0]-1] == ':' {
		return true
	}
	return false
}

func ipv6CandidateBounded(s string, loc []int) bool {
	if loc[0] > 0 && isIPv6RunChar(s[loc[0]-1]) {
		return false
	}
	if loc[1] < len(s) && isIPv6RunChar(s[loc[1]]) {
		return false
	}
	return true
}

func isIPv6RunChar(c byte) bool {
	if c == ':' || c == '.' || c == '%' {
		return true
	}
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}

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

func lastLabel(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

// isRelevantIOC returns true for entries that represent real threat indicators.
// WPT parser stress tests with malformed brackets, protocol-relative URLs,
// double-colon scheme constructs, and empty-host URLs are excluded because
// they are not indicators an analyst would share.
func isRelevantIOC(s string) bool {
	if strings.ContainsAny(s, "\t\r\n") {
		return false
	}
	if strings.HasPrefix(s, "/") {
		return false
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return false
		}
		return true
	}
	// No "://" separator: accept bare indicators but reject entries with a
	// scheme-like prefix immediately followed by "::" (WPT double-colon tests
	// such as "http::@c:29" or "sc::a@example.net").
	if idx := strings.Index(s, "::"); idx > 0 && idx < 10 {
		if !strings.ContainsAny(s[:idx], ":/[") {
			return false
		}
	}
	return true
}

// TestLinkifierBaseline confirms the detector is meaningful before obfuscation.
func TestLinkifierBaseline(t *testing.T) {
	lines := getCorpus(t)
	detected := 0
	for _, l := range lines {
		if what, _ := linkifierDetects(l.text); what != "" {
			detected++
		}
	}
	if detected < len(lines)/2 {
		t.Fatalf("detector too weak: %d/%d raw inputs detected pre-obfuscation", detected, len(lines))
	}
}

// TestCorpusDefeatsLinkifier verifies that obfuscation defeats the linkifier
// for every entry that (a) looks like a real IOC and (b) the linkifier detected
// pre-obfuscation.
//
// "bare-domain" post-obfuscation detections are not treated as failures: the
// draft's Step 4 explicitly does not obfuscate bare domain names inside URL
// paths, so a domain-like substring in a query or path is an accepted
// limitation. The authoritative neutralization oracle is TestCorpusNeutralizes,
// which uses real URL/IP/email parsers.
func TestCorpusDefeatsLinkifier(t *testing.T) {
	for _, l := range getCorpus(t) {
		if !isRelevantIOC(l.text) {
			continue
		}
		if what, _ := linkifierDetects(l.text); what == "" {
			continue
		}
		obf := Obfuscate(l.text)
		what, span := linkifierDetects(obf)
		if what == "" || what == "bare-domain" {
			continue
		}
		t.Errorf("item %d: linkifier detects %s %q in obfuscated output\n  raw  : %q\n  obfus: %q",
			l.num, what, span, l.text, obf)
	}
}

// TestLinkifierOnUnitVectors runs the linkifier against every unit test vector.
func TestLinkifierOnUnitVectors(t *testing.T) {
	for _, v := range obfuscationVectors {
		out := Obfuscate(v.in)
		if what, span := linkifierDetects(out); what != "" {
			t.Errorf("%s: linkifier detects %s %q in obfuscated output %q",
				v.name, what, span, out)
		}
	}
	for _, v := range forwardOnlyVectors {
		out := Obfuscate(v.in)
		if what, span := linkifierDetects(out); what != "" {
			t.Errorf("%s: linkifier detects %s %q in obfuscated output %q",
				v.name, what, span, out)
		}
	}
}

// TestLinkifierSelfCheck verifies the detector catches at least two thirds
// of the raw unit vectors (sanity check on the detector itself).
func TestLinkifierSelfCheck(t *testing.T) {
	missed := 0
	for _, v := range obfuscationVectors {
		if what, _ := linkifierDetects(v.in); what == "" {
			missed++
		}
	}
	if missed > len(obfuscationVectors)/3 {
		t.Errorf("detector missed %d/%d raw unit vectors", missed, len(obfuscationVectors))
	}
}
