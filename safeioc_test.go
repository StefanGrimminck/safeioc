package safeioc

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type vector struct {
	name, in, out string
}

// obfuscationVectors hold indicators and their defanged form. Each one must
// also round-trip: Deobfuscate(out) == in.
var obfuscationVectors = []vector{
	// Step 1: scheme.
	{"https URL", "https://bad.example", "[https]://bad[.]example"},
	{"http URL", "http://attacker.example", "[http]://attacker[.]example"},
	{"ftp URL", "ftp://files.example/", "[ftp]://files[.]example/"},
	{"smb URL", "smb://fileserver.example/share", "[smb]://fileserver[.]example/share"},
	{"scheme with plus", "coap+tcp://device.example/r", "[coap+tcp]://device[.]example/r"},
	{"scheme with plus and path", "git+ssh://host.example/repo.git", "[git+ssh]://host[.]example/repo.git"},
	{"scheme case kept", "HTTPS://bad.example", "[HTTPS]://bad[.]example"},
	{"mixed case kept", "HTTP://Example.COM/", "[HTTP]://Example[.]COM/"},
	{"mailto", "mailto:user@example.com", "[mailto]:user[@]example[.]com"},
	{"mailto with hfields", "mailto:user@example.com?subject=a.b", "[mailto]:user[@]example[.]com?subject=a.b"},
	{"opaque scheme", "tel:+1-201-555-0123", "[tel]:+1-201-555-0123"},
	{"urn", "urn:example:a.b", "[urn]:example:a[.]b"},
	{"scheme without slashes", "http:evil.example", "[http]:evil[.]example"},
	{"view-source wraps both schemes", "view-source:https://bad.example", "[view-source]:[https]://bad[.]example"},
	{"legacy scheme is wrapped, not rewritten", "hxxp://evil.example", "[hxxp]://evil[.]example"},

	// Steps 2 and 3: userinfo and host.
	{"userinfo", "http://user:pass@attacker.example", "[http]://user:pass[@]attacker[.]example"},
	{"port", "https://evil.example:8443/", "[https]://evil[.]example:8443/"},
	{"email", "phish@target.example", "phish[@]target[.]example"},
	{"internationalized email", "σωκράτης@example.test", "σωκράτης[@]example[.]test"},
	{"email local part is no host", "first.last@target.example", "first.last[@]target[.]example"},
	{"userinfo is no host", "http://user.name@evil.example/", "[http]://user.name[@]evil[.]example/"},
	{"mailto body brackets every dot", "mailto:first.last@target.example", "[mailto]:first[.]last[@]target[.]example"},
	{"encoded dot in userinfo kept", "http://us%2eer@evil.example/", "[http]://us%2eer[@]evil[.]example/"},
	{"encoded dot in local part kept", "a%2eb@evil.example", "a%2eb[@]evil[.]example"},
	{"encoded dot in mailto body kept", "mailto:a%2eb@evil.example", "[mailto]:a%2eb[@]evil[.]example"},
	{"leading no-break space", "\u00a02001:db8::1", "\u00a02001[:]db8[:][:]1"},
	{"leading byte order mark", "\ufeffhttps://evil.example", "\ufeff[https]://evil[.]example"},
	{"IPv4 in query before CJK", "http://example.com/?ip=192.0.2.1\u7684", "[http]://example[.]com/?ip=192[.]0[.]2[.]1\u7684"},
	{"bare domain", "evil.example", "evil[.]example"},
	{"bare domain with port", "evil.example:443", "evil[.]example:443"},
	{"bare domain with path", "evil.example/path?x=1", "evil[.]example/path?x=1"},
	{"trailing root dot", "evil.example.", "evil[.]example[.]"},
	{"punycode", "xn--n3h.example", "xn--n3h[.]example"},
	{"U-label", "bücher.example", "bücher[.]example"},
	{"U-label in URL", "https://bücher.example/", "[https]://bücher[.]example/"},
	{"underscore label", "evil_host.example", "evil_host[.]example"},
	{"percent-encoded non-delimiter kept", "http://%65vil.example", "[http]://%65vil[.]example"},
	{"percent-encoded at kept", "http://user%40host.example", "[http]://user%40host[.]example"},
	{"percent-encoded colon kept", "http://evil%3a80.example", "[http]://evil%3a80[.]example"},
	{"backslash before at", `https://evil.example\@good.example`, `[https]://evil[.]example\[@]good[.]example`},

	// IPv4.
	{"IPv4", "198.51.100.1", "198[.]51[.]100[.]1"},
	{"IPv4 in URL", "http://192.0.2.1", "[http]://192[.]0[.]2[.]1"},
	{"IPv4 with port", "192.0.2.1:8080", "192[.]0[.]2[.]1:8080"},
	{"IPv4 CIDR", "192.0.2.0/24", "192[.]0[.]2[.]0/24"},
	{"IPv4 URL with dotted path", "http://192.0.2.1:8080/file.txt", "[http]://192[.]0[.]2[.]1:8080/file.txt"},

	// IPv6.
	{"IPv6 in URL", "http://[2001:db8::1]:8080", "[http]://[2001[:]db8[:][:]1]:8080"},
	{"IPv6 full form in URL", "http://[2001:db8:0:0:0:0:0:1]/", "[http]://[2001[:]db8[:]0[:]0[:]0[:]0[:]0[:]1]/"},
	{"IPv4-mapped IPv6", "http://[::ffff:192.0.2.1]", "[http]://[[:][:]ffff[:]192[.]0[.]2[.]1]"},
	{"IPv4-embedded IPv6", "http://[2001:db8::192.0.2.1]/", "[http]://[2001[:]db8[:][:]192[.]0[.]2[.]1]/"},
	{"well-known prefix", "64:ff9b::198.51.100.1", "64[:]ff9b[:][:]198[.]51[.]100[.]1"},
	{"IPv6 zone in URL", "http://[2001:db8::1%25eth0]/", "[http]://[2001[:]db8[:][:]1%25eth0]/"},
	{"bare IPv6", "2001:db8::1", "2001[:]db8[:][:]1"},
	{"bare IPv6 loopback", "::1", "[:][:]1"},
	{"bare IPv6 full form", "2001:db8:0:0:0:0:0:1", "2001[:]db8[:]0[:]0[:]0[:]0[:]0[:]1"},
	{"bare IPv6 zone", "fe80::1%eth0", "fe80[:][:]1%eth0"},
	{"bare IPv6 starting with letters", "abcd::1", "abcd[:][:]1"},
	{"bare IPv6 CIDR", "2001:db8::/32", "2001[:]db8[:][:]/32"},
	{"bracketed bare IPv6", "[2001:db8::1]", "[2001[:]db8[:][:]1]"},
	{"bracketed bare IPv6 with port", "[2001:db8::1]:80", "[2001[:]db8[:][:]1]:80"},
	{"malformed IPv6 literal", "http://[::1.2.3.4x]", "[http]://[[:][:]1[.]2[.]3[.]4x]"},
	{"nested brackets", "http://[[::]]", "[http]://[[[:][:]]]"},
	{"IPv6 then full stop", "2001:db8::1.", "2001[:]db8[:][:]1[.]"},
	{"quoted URL is read as text", `"https://evil.example"`, `"[https]://evil[.]example"`},
	{"URL in parentheses is read as text", "(https://evil.example)", "([https]://evil[.]example)"},
	{"network-path reference", "//evil.example/path", "//evil[.]example/path"},
	{"second URL after a comma", "https://a.example,https://b.example/", "[https]://a[.]example,[https]://b[.]example/"},
	{"domain in brackets", "http://[evil.example]/", "[http]://[evil[.]example]/"},
	{"single colon is a scheme, not IPv6", "evil:80", "[evil]:80"},

	// Step 4: the path, query and fragment are kept, nested indicators are defanged.
	{"dotted path kept", "https://evil.example/payload.exe", "[https]://evil[.]example/payload.exe"},
	{"dotted query kept", "https://bad.example/search?q=a.b.c", "[https]://bad[.]example/search?q=a.b.c"},
	{"dotted fragment kept", "https://bad.example/x#a.b", "[https]://bad[.]example/x#a.b"},
	{"nested URL in query", "http://example.com/r?url=http://evil.example", "[http]://example[.]com/r?url=[http]://evil[.]example"},
	{"nested URL in fragment", "http://example.com/#redir=http://evil.example", "[http]://example[.]com/#redir=[http]://evil[.]example"},
	{"chained redirect", "http://a.test/?u=http://b.test/?u=http://c.test", "[http]://a[.]test/?u=[http]://b[.]test/?u=[http]://c[.]test"},
	{"nested email in query", "http://example.com/?contact=abuse@evil.example", "[http]://example[.]com/?contact=abuse[@]evil[.]example"},
	{"nested mailto in query", "http://example.com/?r=mailto:abuse@evil.example", "[http]://example[.]com/?r=[mailto]:abuse[@]evil[.]example"},
	{"nested IPv4 in query", "http://example.com/?nbns=192.0.2.21", "[http]://example[.]com/?nbns=192[.]0[.]2[.]21"},
	{"nested IPv6 in query", "http://example.com/?ip=2001:db8::1", "[http]://example[.]com/?ip=2001[:]db8[:][:]1"},
	{"nested URL after port", "https://evil.example:8443/a@b.example", "[https]://evil[.]example:8443/a[@]b[.]example"},
	{"nested URL in data URL", "data:text/html,<a href=https://evil.example>", "[data]:text/html,<a href=[https]://evil[.]example>"},

	// Surrounding whitespace is kept and does not hide the indicator.
	{"leading space", " https://evil.example/x", " [https]://evil[.]example/x"},
	{"leading tab, trailing newline", "\thttps://evil.example\n", "\t[https]://evil[.]example\n"},
	{"trailing CRLF", "198.51.100.1\r\n", "198[.]51[.]100[.]1\r\n"},
	{"only whitespace", " \t ", " \t "},

	// Inputs that are short or have nothing to defang.
	{"empty", "", ""},
	{"one letter", "a", "a"},
	{"two labels", "a.b", "a[.]b"},
	{"lone at", "@", "[@]"},
	{"lone dot", ".", "[.]"},
	{"lone colon", ":", ":"},
	{"unspecified address", "::", "[:][:]"},
}

// idempotencyVectors are inputs that are already (partly) defanged.
var idempotencyVectors = []vector{
	{"defanged URL", "[https]://bad[.]example", "[https]://bad[.]example"},
	{"defanged IPv6 URL", "[http]://[2001[:]db8[:][:]1]:8080", "[http]://[2001[:]db8[:][:]1]:8080"},
	{"defanged bare IPv6", "2001[:]db8[:][:]1", "2001[:]db8[:][:]1"},
	{"defanged mapped IPv6", "[http]://[[:][:]ffff[:]192[.]0[.]2[.]1]", "[http]://[[:][:]ffff[:]192[.]0[.]2[.]1]"},
	{"scheme defanged, host live", "[https]://evil.example", "[https]://evil[.]example"},
	{"host defanged, scheme live", "https://evil[.]example", "[https]://evil[.]example"},
}

func TestObfuscate(t *testing.T) {
	for _, v := range obfuscationVectors {
		t.Run(v.name, func(t *testing.T) {
			if got := Obfuscate(v.in); got != v.out {
				t.Errorf("Obfuscate(%q)\n got  %q\n want %q", v.in, got, v.out)
			}
		})
	}
}

func TestObfuscateIsIdempotent(t *testing.T) {
	for _, v := range idempotencyVectors {
		t.Run(v.name, func(t *testing.T) {
			if got := Obfuscate(v.in); got != v.out {
				t.Errorf("Obfuscate(%q)\n got  %q\n want %q", v.in, got, v.out)
			}
		})
	}
	for _, v := range obfuscationVectors {
		if twice := Obfuscate(v.out); twice != v.out {
			t.Errorf("%s: Obfuscate(%q) = %q, want it unchanged", v.name, v.out, twice)
		}
	}
}

func TestRoundtrip(t *testing.T) {
	for _, v := range obfuscationVectors {
		if got := Deobfuscate(v.out); got != v.in {
			t.Errorf("%s: Deobfuscate(%q)\n got  %q\n want %q", v.name, v.out, got, v.in)
		}
	}
}

func TestDeobfuscate(t *testing.T) {
	tests := []vector{
		{"canonical", "[https]://bad[.]example", "https://bad.example"},
		{"case kept", "[HTTPS]://bad[.]example", "HTTPS://bad.example"},
		{"IPv6", "[http]://[2001[:]db8[:][:]1]:8080", "http://[2001:db8::1]:8080"},
		{"mailto", "[mailto]:user[@]example[.]com", "mailto:user@example.com"},
		{"legacy hxxps", "hxxps://bad[.]example", "https://bad.example"},
		{"legacy hxxp", "hxxp://attacker[.]example", "http://attacker.example"},
		{"legacy with live host", "hxxps://bad.example", "https://bad.example"},
		{"legacy with defanged colon", "hxxp[:]//evil[.]example", "http://evil.example"},
		{"legacy nested in query", "[http]://a[.]example/?u=hxxp://evil[.]example", "http://a.example/?u=http://evil.example"},
		{"legacy name in a path is not a scheme", "[https]://example[.]com/hxxp-guide", "https://example.com/hxxp-guide"},
		{"legacy name in a query value is not a scheme", "[https]://example[.]com/?q=hxxps", "https://example.com/?q=hxxps"},
		{"legacy name inside a word is not a scheme", "xhxxp://a", "xhxxp://a"},
		{"wrapped legacy name is restored as written", "[hxxp]://evil[.]example", "hxxp://evil.example"},
		{"legacy name in any case", "hXXps://evil[.]example", "hTTps://evil.example"},
		{"nothing to do", "plain text", "plain text"},
		{"unknown bracket kept", "[x]", "[x]"},
	}
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			if got := Deobfuscate(v.in); got != v.out {
				t.Errorf("Deobfuscate(%q)\n got  %q\n want %q", v.in, got, v.out)
			}
		})
	}
}

func TestIsObfuscated(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"[https]://evil[.]example", true},
		{"[https]://evil.example", true},
		{"evil[.]example", true},
		{"phish[@]target.example", true},
		{"2001[:]db8[:][:]1", true},
		{"hxxps://evil.example", true},
		{"hxxp[:]//evil.example", true},
		{"https://evil.example", false},
		{"https://example.com/hxxp-guide", false},
		{"[x]", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsObfuscated(tt.in); got != tt.want {
			t.Errorf("IsObfuscated(%q) = %v, want %v", tt.in, got, tt.want)
		}
		if want := Deobfuscate(tt.in) != tt.in; tt.want != want {
			t.Errorf("IsObfuscated(%q) = %v, but Deobfuscate changes it: %v", tt.in, tt.want, want)
		}
	}
}

// TestDraftVectors runs the test vectors of Section 10 of the draft,
// copied unchanged into testdata.
func TestDraftVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/draft-grimminck-safe-ioc-sharing-14-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Label, Operation, Input, Expected string
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vectors {
		t.Run(v.Label, func(t *testing.T) {
			var got string
			switch v.Operation {
			case "obfuscate":
				got = Obfuscate(v.Input)
			case "deobfuscate":
				got = Deobfuscate(v.Input)
			default:
				t.Fatalf("unknown operation %q", v.Operation)
			}
			if got != v.Expected {
				t.Errorf("%s(%q)\n got  %q\n want %q", v.Operation, v.Input, got, v.Expected)
			}
		})
	}
}

// TestPathIsNotDefanged checks the Step 4 rule that the path, query and
// fragment keep their dots and at-signs unless they belong to a nested
// indicator.
func TestPathIsNotDefanged(t *testing.T) {
	for in, tail := range map[string]string{
		"https://example.com/file.txt":         "/file.txt",
		"https://example.com/a/b/c.d.e":        "/a/b/c.d.e",
		"https://example.com/x?q=a.b.c":        "/x?q=a.b.c",
		"https://example.com/x#frag.tag":       "/x#frag.tag",
		"http://192.0.2.1:8080/file.txt":       "/file.txt",
		"http://[2001:db8::1]/x.y":             "/x.y",
		"mailto:user@example.com?subject=a.b":  "?subject=a.b",
		"https://example.com/x?to=a@b&v=1.2.3": "/x?to=a@b&v=1.2.3",
	} {
		out := Obfuscate(in)
		if !strings.HasSuffix(out, tail) {
			t.Errorf("Obfuscate(%q) = %q, want it to end in %q", in, out, tail)
		}
	}
}

func TestPercentEncodedDotInHostIsDecoded(t *testing.T) {
	for in, want := range map[string]string{
		"http://a%2eb.example": "[http]://a[.]b[.]example",
		"http://a%2Eb.example": "[http]://a[.]b[.]example",
		"a%2eb.example":        "a[.]b[.]example",
	} {
		got := Obfuscate(in)
		if got != want {
			t.Errorf("Obfuscate(%q) = %q, want %q", in, got, want)
		}
		if strings.Contains(got, "%2") {
			t.Errorf("Obfuscate(%q) = %q still holds an encoded dot", in, got)
		}
	}
}
