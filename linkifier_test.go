package safeioc

import (
	"net"
	"net/url"
	"regexp"
	"sort"
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

// isRelevantIOCReason returns the empty string if s looks like a real
// threat indicator an analyst would share, or a short reason explaining
// why it was rejected as a parser-stress / non-IOC input.
func isRelevantIOCReason(s string) string {
	if strings.ContainsAny(s, "\t\r\n") {
		return "contains control whitespace (\\t/\\r/\\n)"
	}
	if strings.HasPrefix(s, "/") {
		return "starts with '/' (path-only or protocol-relative URL)"
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "url.Parse: " + classifyParseErr(err.Error())
		}
		if u.Host == "" {
			return "url.Parse returned empty host"
		}
		return ""
	}
	// No "://" separator: accept bare indicators but reject entries with a
	// scheme-like prefix immediately followed by "::" (WPT double-colon
	// stress tests such as "http::@c:29" or "sc::a@example.net").
	if idx := strings.Index(s, "::"); idx > 0 && idx < 10 {
		if !strings.ContainsAny(s[:idx], ":/[") {
			return "double-colon parser stress (e.g., 'http::@c:29')"
		}
	}
	return ""
}

func isRelevantIOC(s string) bool { return isRelevantIOCReason(s) == "" }

// classifyParseErr collapses a url.Parse error message into a reusable
// category so that per-item URL substrings do not fragment the reason
// breakdown into one bucket per input.
func classifyParseErr(msg string) string {
	switch {
	case strings.Contains(msg, "invalid port"):
		return "invalid port"
	case strings.Contains(msg, "invalid host"):
		return "invalid host (ParseAddr)"
	case strings.Contains(msg, "invalid character") && strings.Contains(msg, "host name"):
		return "invalid character in host"
	case strings.Contains(msg, "invalid userinfo"):
		return "invalid userinfo"
	case strings.Contains(msg, "invalid URL escape"):
		return "invalid percent-encoding"
	case strings.Contains(msg, "invalid control character"):
		return "invalid control character"
	case strings.Contains(msg, "missing ']'"):
		return "unmatched '[' in host"
	default:
		return "other"
	}
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
	lines := getCorpus(t)
	notIOCByReason := map[string]int{}
	notDetected, tested, tolerated, failures := 0, 0, 0, 0
	for _, l := range lines {
		if reason := isRelevantIOCReason(l.text); reason != "" {
			notIOCByReason[reason]++
			t.Logf("defeats-linkifier item %d: SKIP not-IOC [%s]\n  raw   : %q",
				l.num, reason, maskBreak(l.text))
			continue
		}
		preWhat, _ := linkifierDetects(l.text)
		if preWhat == "" {
			notDetected++
			t.Logf("defeats-linkifier item %d: SKIP linkifier-no-match-pre-obfuscation [IOC-shaped but no linkifier pattern matched]\n  raw   : %q",
				l.num, maskBreak(l.text))
			continue
		}
		obf := Obfuscate(l.text)
		postWhat, span := linkifierDetects(obf)
		switch {
		case postWhat == "":
			tested++
			t.Logf("defeats-linkifier item %d: PASS (pre=%s, post=none)\n  raw   : %q\n  obfus : %q",
				l.num, preWhat, maskBreak(l.text), maskBreak(obf))
		case postWhat == "bare-domain":
			tolerated++
			t.Logf("defeats-linkifier item %d: PASS-bare-domain (Step 4 limitation, pre=%s, post=bare-domain %q)\n  raw   : %q\n  obfus : %q",
				l.num, preWhat, span, maskBreak(l.text), maskBreak(obf))
		default:
			failures++
			t.Errorf("item %d: linkifier detects %s %q in obfuscated output\n  raw  : %q\n  obfus: %q",
				l.num, postWhat, span, l.text, obf)
		}
	}
	notIOCTotal := 0
	for _, c := range notIOCByReason {
		notIOCTotal += c
	}
	reasons := make([]string, 0, len(notIOCByReason))
	for r := range notIOCByReason {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	t.Logf("defeats-linkifier: %d total, %d skipped-not-IOC, %d skipped-linkifier-no-match, %d tested, %d tolerated (bare-domain), %d failures",
		len(lines), notIOCTotal, notDetected, tested, tolerated, failures)
	for _, r := range reasons {
		t.Logf("  not-IOC reason breakdown: %4d  %s", notIOCByReason[r], r)
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
