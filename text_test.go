package safeioc

import (
	"strings"
	"testing"
)

// textVectors hold free text and its obfuscated form. Each one must also
// round-trip through DeobfuscateText.
var textVectors = []vector{
	{"URL in a sentence", "see https://evil.example now", "see [https]://evil[.]example now"},
	{"full stop after URL", "Payload at https://evil.example/x.bin.", "Payload at [https]://evil[.]example/x.bin."},
	{"comma after URL", "https://a.example, https://b.example", "[https]://a[.]example, [https]://b[.]example"},
	{"URL in parentheses", "(https://evil.example)", "([https]://evil[.]example)"},
	{"parentheses inside URL kept", "https://evil.example/wiki/A_(b)", "[https]://evil[.]example/wiki/A_(b)"},
	{"URL in angle brackets", "<https://evil.example/>", "<[https]://evil[.]example/>"},
	{"URL in quotes", `href="https://evil.example/"`, `href="[https]://evil[.]example/"`},
	{"URL in single quotes", "'https://evil.example'", "'[https]://evil[.]example'"},
	{"URL as log value", "url=https://evil.example/a status=200", "url=[https]://evil[.]example/a status=200"},
	{"URL in Markdown link", "[click](https://evil.example/x)", "[click]([https]://evil[.]example/x)"},
	{"nested redirect", "go to http://a.example/?u=http://evil.example ok", "go to [http]://a[.]example/?u=[http]://evil[.]example ok"},
	{"mailto", "write mailto:abuse@evil.example today", "write [mailto]:abuse[@]evil[.]example today"},
	{"email", "From: phish@target.example", "From: phish[@]target[.]example"},
	{"mailto with only header fields", "mailto:?to=admin@example.test&subject=Hi", "[mailto]:?to=admin[@]example[.]test&subject=Hi"},
	{"internationalized email", "from 用户@example.invalid", "from 用户[@]example[.]invalid"},
	{"IPv4 between CJK characters", "IP\u5730\u5740198.51.100.7\u7684", "IP\u5730\u5740198[.]51[.]100[.]7\u7684"},
	{"IPv4 before Japanese", "198.51.100.7\u3067\u3059", "198[.]51[.]100[.]7\u3067\u3059"},
	{"email at end of sentence", "Mail phish@target.example.", "Mail phish[@]target[.]example."},
	{"IPv4", "C2 is 198.51.100.7.", "C2 is 198[.]51[.]100[.]7."},
	{"IPv4 with port", "beacon to 198.51.100.7:4444", "beacon to 198[.]51[.]100[.]7:4444"},
	{"IPv4 CIDR", "block 192.0.2.0/24", "block 192[.]0[.]2[.]0/24"},
	{"IPv6", "resolves to 2001:db8::1", "resolves to 2001[:]db8[:][:]1"},
	{"bracketed IPv6 with port", "listening on [2001:db8::1]:443", "listening on [2001[:]db8[:][:]1]:443"},
	{"domain", "the domain evil.example is new", "the domain evil[.]example is new"},
	{"domain at end of sentence", "Blocked evil.example.", "Blocked evil[.]example."},
	{"domain with path", "fetches evil.example/stage2.ps1", "fetches evil[.]example/stage2.ps1"},
	{"www domain", "www.evil.example", "www[.]evil[.]example"},
	{"upper-case domain", "EVIL.COM", "EVIL[.]COM"},
	{"several on lines", "evil.example\n198.51.100.7\nphish@target.example\n", "evil[.]example\n198[.]51[.]100[.]7\nphish[@]target[.]example\n"},
	{"tab separated", "ip\t192.0.2.1\tdomain\tevil.test", "ip\t192[.]0[.]2[.]1\tdomain\tevil[.]test"},
	{"JSON", `{"ioc":"https://evil.example/"}`, `{"ioc":"[https]://evil[.]example/"}`},

	{"two URLs joined by a comma", "https://evil.example,https://bad.example", "[https]://evil[.]example,[https]://bad[.]example"},
	{"Markdown link to itself", "[https://evil.example](https://evil.example)", "[[https]://evil[.]example]([https]://evil[.]example)"},
	{"curly quotes", "\u201cevil.example\u201d", "\u201cevil[.]example\u201d"},
	{"possessive apostrophe", "evil.example\u2019s infra", "evil[.]example\u2019s infra"},
	{"ellipsis", "evil.example\u2026", "evil[.]example\u2026"},
	{"no-break space", "evil.example\u00a0and", "evil[.]example\u00a0and"},
	{"ideographic full stop", "\u8bbf\u95ee www.evil.example\u3002", "\u8bbf\u95ee www[.]evil[.]example\u3002"},
	{"fullwidth parentheses", "\uff08198.51.100.7\uff09", "\uff08198[.]51[.]100[.]7\uff09"},
	{"IPv6 at end of sentence", "C2 is 2001:db8::1.", "C2 is 2001[:]db8[:][:]1."},
	{"mapped IPv6 at end of sentence", "::ffff:198.51.100.7.", "[:][:]ffff[:]198[.]51[.]100[.]7."},
	{"CIDR list", "192.0.2.0/24,evil.example;2001:db8::/32", "192[.]0[.]2[.]0/24,evil[.]example;2001[:]db8[:][:]/32"},
	{"Markdown emphasis", "_evil.example_ and __198.51.100.7__", "_evil[.]example_ and __198[.]51[.]100[.]7__"},
	{"underscore before scheme", "url_https://evil.example", "url_[https]://evil[.]example"},
	{"Cyrillic TLD", "\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444", "\u043f\u0440\u0438\u043c\u0435\u0440[.]\u0440\u0444"},
	{"Chinese TLD", "evil.\u4e2d\u56fd", "evil[.]\u4e2d\u56fd"},

	// Text that holds no indicator is left alone.
	{"abbreviations", "e.g. this, i.e. that, etc.", "e.g. this, i.e. that, etc."},
	{"file names with unknown TLD", "open notes.txt and report.pdf", "open notes.txt and report.pdf"},
	{"version numbers", "version 1.2.3 and v2.0", "version 1.2.3 and v2.0"},
	{"time of day", "at 10:30:00 UTC", "at 10:30:00 UTC"},
	{"MAC address", "00:11:22:33:44:55", "00:11:22:33:44:55"},
	{"scope operator", "Foo :: Bar and std::vector", "Foo :: Bar and std::vector"},
	{"colon after word", "Note: nothing here", "Note: nothing here"},
	{"empty", "", ""},
}

func TestObfuscateText(t *testing.T) {
	for _, v := range textVectors {
		t.Run(v.name, func(t *testing.T) {
			if got := ObfuscateText(v.in); got != v.out {
				t.Errorf("ObfuscateText(%q)\n got  %q\n want %q", v.in, got, v.out)
			}
		})
	}
}

func TestObfuscateTextIsIdempotent(t *testing.T) {
	for _, v := range textVectors {
		if twice := ObfuscateText(v.out); twice != v.out {
			t.Errorf("%s: ObfuscateText(%q) = %q, want it unchanged", v.name, v.out, twice)
		}
	}
}

// textCompletionVectors hold text that is already partly obfuscated.
// ObfuscateText completes it; it does not round-trip, because its input
// already holds Safe-IOC tokens.
var textCompletionVectors = []vector{
	{"legacy scheme is wrapped", "hxxp://evil.example", "[hxxp]://evil[.]example"},
	{"live host after an obfuscated scheme", "see [https]://evil.example", "see [https]://evil[.]example"},
}

func TestObfuscateTextCompletes(t *testing.T) {
	for _, v := range textCompletionVectors {
		if got := ObfuscateText(v.in); got != v.out {
			t.Errorf("%s: ObfuscateText(%q)\n got  %q\n want %q", v.name, v.in, got, v.out)
		}
	}
}

func TestTextRoundtrip(t *testing.T) {
	for _, v := range textVectors {
		if got := DeobfuscateText(v.out); got != v.in {
			t.Errorf("%s: DeobfuscateText(%q)\n got  %q\n want %q", v.name, v.out, got, v.in)
		}
	}
}

// Every indicator vector, placed in a sentence, comes out of
// ObfuscateText the way Obfuscate obfuscates it on its own.
func TestObfuscateTextAgreesWithObfuscate(t *testing.T) {
	// Free text is only searched for "scheme://" and "mailto:" URLs, emails,
	// IP addresses and domains with a known TLD. Obfuscate also accepts
	// these, which text recognition deliberately does not look for.
	notInText := map[string]bool{
		"opaque scheme": true, "urn": true, "scheme without slashes": true,
		"view-source wraps both schemes": true, "nested URL in data URL": true,
		"single colon is a scheme, not IPv6": true, "trailing root dot": true,
		"underscore label": true, "two labels": true, "lone at": true,
		"lone dot": true, "unspecified address": true, "IPv6 then full stop": true,
	}
	for _, v := range obfuscationVectors {
		if notInText[v.name] || strings.ContainsAny(v.in, " \t\r\n") || v.in == v.out {
			continue
		}
		in := "Indicator " + v.in + " seen."
		want := "Indicator " + v.out + " seen."
		if got := ObfuscateText(in); got != want {
			t.Errorf("%s: ObfuscateText(%q)\n got  %q\n want %q", v.name, in, got, want)
		}
	}
}

func TestDeobfuscateText(t *testing.T) {
	tests := []vector{
		{"regular expression kept", `match [0-9]+[.][0-9]+ here`, `match [0-9]+[.][0-9]+ here`},
		{"character class kept", `use [@] or [:] in a class`, `use [@] or [:] in a class`},
		{"Markdown reference kept", "[docs]: see below", "[docs]: see below"},
		{"obfuscated URL restored", "see [https]://evil[.]example now", "see https://evil.example now"},
		{"legacy restored", "see hxxps://evil[.]example now", "see https://evil.example now"},
		{"legacy with obfuscated colon", "hxxp[:]//evil[.]example", "http://evil.example"},
		{"obfuscated domain restored", "domain evil[.]example.", "domain evil.example."},
		{"obfuscated email restored", "from first[.]last[@]evil[.]example", "from first.last@evil.example"},
		{"obfuscated IPv4 restored", "C2 198[.]51[.]100[.]7:4444", "C2 198.51.100.7:4444"},
		{"obfuscated IPv6 restored", "addr 2001[:]db8[:][:]1%eth0 up", "addr 2001:db8::1%eth0 up"},
		{"obfuscated IPv6 literal restored", "at [[:][:]1]:80", "at [::1]:80"},
		{"legacy name in prose kept", "the hxxp convention", "the hxxp convention"},
		{"log level kept", "[INFO]:started worker", "[INFO]:started worker"},
		{"word class regex kept", `\w+[.]example`, `\w+[.]example`},
		{"file name with unknown TLD kept", "log[.]txt and 1[.]2", "log[.]txt and 1[.]2"},
		{"obfuscated opaque URI with a token restored", "[urn]:example:a[.]b", "urn:example:a.b"},
		{"upper-case legacy restored", "HXXPS://evil[.]example", "HTTPS://evil.example"},
		{"Unicode TLD restored", "phish[@]evil[.]\u4e2d\u56fd", "phish@evil.\u4e2d\u56fd"},
		{"mixed with regex", "evil[.]example matches [a-z]+[.]example", "evil.example matches [a-z]+[.]example"},
	}
	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			if got := DeobfuscateText(v.in); got != v.out {
				t.Errorf("DeobfuscateText(%q)\n got  %q\n want %q", v.in, got, v.out)
			}
		})
	}
}
