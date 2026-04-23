package safeioc

import (
	"strings"
	"testing"
)

type vector struct {
	name, in, out string
}

var obfuscationVectors = []vector{
	{"Standard URL", "https://bad.example", "[https]://bad[.]example"},
	{"URL with path", "https://evil.example/path", "[https]://evil[.]example/path"},
	{"Deep-link URL", "https://bad.example/path/to/page?q=1#frag", "[https]://bad[.]example/path/to/page?q=1#frag"},
	{"HTTP URL", "http://attacker.example", "[http]://attacker[.]example"},
	{"FTP URL", "ftp://files.example/", "[ftp]://files[.]example/"},
	{"Mailto", "mailto:user@example.com", "[mailto]:user[@]example[.]com"},
	{"IPv4 address", "198.51.100.1", "198[.]51[.]100[.]1"},
	{"IPv4 in URL", "http://192.0.2.1", "[http]://192[.]0[.]2[.]1"},
	{"IPv4 with port", "http://192.0.2.2:80", "[http]://192[.]0[.]2[.]2:80"},
	{"IPv6 in URL", "http://[2001:db8::1]:8080", "[http]://[2001[:]db8[:][:]1]:8080"},
	{"IPv6 no port", "http://[2001:db8::1]/", "[http]://[2001[:]db8[:][:]1]/"},
	{"IPv6 full form", "http://[2001:db8:0:0:0:0:0:1]/", "[http]://[2001[:]db8[:]0[:]0[:]0[:]0[:]0[:]1]/"},
	{"IPv4-mapped IPv6", "http://[::ffff:192.0.2.1]", "[http]://[[:][:]ffff[:]192[.]0[.]2[.]1]"},
	{"IPv6 with zone", "http://[2001:db8::1%25eth0]/", "[http]://[2001[:]db8[:][:]1%25eth0]/"},
	{"Bare IPv6", "2001:db8::1", "2001[:]db8[:][:]1"},
	{"Bare IPv6 loopback", "::1", "[:][:]1"},
	{"Bare IPv6 full form", "2001:db8:0:0:0:0:0:1", "2001[:]db8[:]0[:]0[:]0[:]0[:]0[:]1"},
	{"Bare IPv6 zone", "2001:db8::1%eth0", "2001[:]db8[:][:]1%eth0"},
	{"Bare bracketed IPv6", "[2001:db8::1]", "[2001[:]db8[:][:]1]"},
	{"Bare bracketed IPv6 port", "[2001:db8::1]:80", "[2001[:]db8[:][:]1]:80"},
	{"Email address", "phish@target.example", "phish[@]target[.]example"},
	{"Punycode domain", "xn--n3h.example", "xn--n3h[.]example"},
	{"URL with userinfo", "http://user:pass@attacker.example", "[http]://user:pass[@]attacker[.]example"},
	{"Bare domain with port", "evil.example:443", "evil[.]example:443"},
	{"URL with dotted path", "https://evil.example/payload.exe", "[https]://evil[.]example/payload.exe"},
	{"URL with dotted query", "https://bad.example/search?q=a.b.c", "[https]://bad[.]example/search?q=a.b.c"},
	{"URL with dotted fragment", "https://bad.example/x#a.b", "[https]://bad[.]example/x#a.b"},
	{"URL with dotted path and port", "http://192.0.2.1:8080/file.txt", "[http]://192[.]0[.]2[.]1:8080/file.txt"},
	{"URL with nested URL in query", "http://example.com/r?url=http://evil.example", "[http]://example[.]com/r?url=[http]://evil[.]example"},
	{"URL with nested URL in fragment", "http://example.com/#redir=http://evil.example", "[http]://example[.]com/#redir=[http]://evil[.]example"},
	{"URL with bare email in query", "http://example.com/?contact=abuse@evil.example", "[http]://example[.]com/?contact=abuse[@]evil[.]example"},
	{"URL with bare IPv4 in query", "http://example.com/?nbns=192.0.2.21", "[http]://example[.]com/?nbns=192[.]0[.]2[.]21"},
	{"Mailto with hfields", "mailto:user@example.com?subject=Nested", "[mailto]:user[@]example[.]com?subject=Nested"},
	{"Bare IPv6 link-local", "fe80::1%eth0", "fe80[:][:]1%eth0"},
	{"Bare IPv6 multicast", "ff02::1", "ff02[:][:]1"},
	{"Bare IPv6 alpha-leading", "abcd::1", "abcd[:][:]1"},
	{"IPv6 with embedded IPv4 non-mapped", "http://[2001:db8::192.0.2.1]/", "[http]://[2001[:]db8[:][:]192[.]0[.]2[.]1]/"},
	{"URL with bare IPv6 in query (Step 4)", "http://example.com/?ip=2001:db8::1", "[http]://example[.]com/?ip=2001[:]db8[:][:]1"},
	{"URL with bare IPv6 in fragment (Step 4)", "http://example.com/#ip=2001:db8::1", "[http]://example[.]com/#ip=2001[:]db8[:][:]1"},
}

// forwardOnlyVectors exercise transformations where Deobfuscate is not
// expected to reproduce the exact input byte-for-byte (e.g., scheme
// case-normalization, a draft SHOULD).
var forwardOnlyVectors = []vector{
	{"Mixed-case scheme lowercased", "HTTP://Example.COM/", "[http]://Example[.]COM/"},
	{"Upper-case HTTPS scheme", "HTTPS://bad.example", "[https]://bad[.]example"},
}

var idempotencyVectors = []vector{
	{"Already obfuscated URL", "[https]://bad[.]example", "[https]://bad[.]example"},
	{"Already obfuscated IPv6 URL", "[http]://[2001[:]db8[:][:]1]:8080", "[http]://[2001[:]db8[:][:]1]:8080"},
	{"Already obfuscated bare IPv6", "2001[:]db8[:][:]1", "2001[:]db8[:][:]1"},
	{"Already obfuscated mapped IPv6", "[http]://[[:][:]ffff[:]192[.]0[.]2[.]1]", "[http]://[[:][:]ffff[:]192[.]0[.]2[.]1]"},
}

var legacyDeobfuscationVectors = []vector{
	{"Legacy hxxps", "hxxps://bad[.]example", "https://bad.example"},
	{"Legacy hxxp", "hxxp://attacker[.]example", "http://attacker.example"},
}

func TestObfuscate(t *testing.T) {
	for _, v := range obfuscationVectors {
		got := Obfuscate(v.in)
		if got != v.out {
			t.Errorf("%s: Obfuscate(%q) = %q, want %q", v.name, v.in, got, v.out)
		}
	}
	for _, v := range forwardOnlyVectors {
		got := Obfuscate(v.in)
		if got != v.out {
			t.Errorf("%s: Obfuscate(%q) = %q, want %q", v.name, v.in, got, v.out)
		}
	}
}

// TestRoundtrip verifies that Deobfuscate(Obfuscate(x)) == x byte for byte
// for every obfuscation vector.
func TestRoundtrip(t *testing.T) {
	for _, v := range obfuscationVectors {
		got := Deobfuscate(v.out)
		if got != v.in {
			t.Errorf("%s: roundtrip mismatch\n  want: %q\n  got:  %q", v.name, v.in, got)
		}
	}
}

func TestIdempotency(t *testing.T) {
	for _, v := range idempotencyVectors {
		got := Obfuscate(v.in)
		if got != v.out {
			t.Errorf("%s: Obfuscate(%q) = %q, want %q (already-obfuscated input)", v.name, v.in, got, v.out)
		}
	}
	for _, v := range obfuscationVectors {
		once := Obfuscate(v.in)
		twice := Obfuscate(once)
		if twice != once {
			t.Errorf("%s: re-applying Obfuscate changed output: %q -> %q", v.name, once, twice)
		}
	}
	for _, v := range forwardOnlyVectors {
		once := Obfuscate(v.in)
		twice := Obfuscate(once)
		if twice != once {
			t.Errorf("%s: re-applying Obfuscate changed output: %q -> %q", v.name, once, twice)
		}
	}
}

func TestLegacyDeobfuscation(t *testing.T) {
	for _, v := range legacyDeobfuscationVectors {
		got := Deobfuscate(v.in)
		if got != v.out {
			t.Errorf("%s: Deobfuscate(%q) = %q, want %q", v.name, v.in, got, v.out)
		}
	}
}

func TestIPv6PortColonPreserved(t *testing.T) {
	got := Obfuscate("http://[2001:db8::1]:443")
	want := "[http]://[2001[:]db8[:][:]1]:443"
	if got != want {
		t.Errorf("Obfuscate(...) = %q, want %q", got, want)
	}
	if !strings.HasSuffix(got, "]:443") {
		t.Errorf("port not preserved verbatim: %q", got)
	}
}

func TestSchemeNotObfuscatedTwice(t *testing.T) {
	// A [scheme] at start must not be re-wrapped to [[scheme]].
	got := Obfuscate("[http]://example.com")
	if strings.HasPrefix(got, "[[") {
		t.Errorf("scheme was double-wrapped: %q", got)
	}
}

func TestBareDomainWithPortIsNotScheme(t *testing.T) {
	// "evil.example:443" must not be treated as a URI scheme.
	got := Obfuscate("evil.example:443")
	if strings.HasPrefix(got, "[evil.example]") {
		t.Errorf("domain:port treated as scheme: %q", got)
	}
}

// TestStep4NoPathProcessing verifies that Path, Query, and Fragment are
// preserved verbatim (draft Step 4). The assertion is that any "[.]"
// token in the output falls within the authority region, never after
// the first authority terminator ("/", "?", or "#").
func TestStep4NoPathProcessing(t *testing.T) {
	cases := []string{
		"https://example.com/file.txt",
		"https://example.com/a/b/c.d.e",
		"https://example.com/x?q=a.b.c",
		"https://example.com/x#frag.tag",
		"http://192.0.2.1:8080/file.txt",
		"http://[2001:db8::1]/x.y",
		"mailto:user@example.com?subject=a.b",
	}
	for _, in := range cases {
		out := Obfuscate(in)
		authEnd := len(out)
		if idx := firstOf(out, "://"); idx >= 0 {
			if j := firstAnyAt(out, idx+3, "/?#"); j >= 0 {
				authEnd = j
			}
		} else if idx := strings.Index(out, ":"); idx >= 0 {
			if j := firstAnyAt(out, idx+1, "?#"); j >= 0 {
				authEnd = j
			}
		}
		if tail := out[authEnd:]; strings.Contains(tail, "[.]") || strings.Contains(tail, "[@]") {
			t.Errorf("Step 4 violation: %q -> %q (tail %q contains obfuscation tokens)", in, out, tail)
		}
	}
}

func firstOf(s, sub string) int { return strings.Index(s, sub) }
func firstAnyAt(s string, start int, chars string) int {
	for i := start; i < len(s); i++ {
		if strings.IndexByte(chars, s[i]) >= 0 {
			return i
		}
	}
	return -1
}

// TestBareIPv6NotScheme verifies bare IPv6 literals starting with alpha
// hex characters (fe80::, ff02::, abcd::) are not misread as "scheme:".
func TestBareIPv6NotScheme(t *testing.T) {
	cases := map[string]string{
		"fe80::1%eth0": "fe80[:][:]1%eth0",
		"ff02::1":      "ff02[:][:]1",
		"abcd::1":      "abcd[:][:]1",
	}
	for in, want := range cases {
		got := Obfuscate(in)
		if got != want {
			t.Errorf("Obfuscate(%q) = %q, want %q", in, got, want)
		}
		if strings.HasPrefix(got, "[") {
			t.Errorf("bare IPv6 %q was wrapped as a scheme: %q", in, got)
		}
	}
}
