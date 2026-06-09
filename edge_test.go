package safeioc

import (
	"strings"
	"testing"
)

func TestObfuscateEmpty(t *testing.T) {
	if got := Obfuscate(""); got != "" {
		t.Errorf("Obfuscate(\"\") = %q, want empty string", got)
	}
	if got := Deobfuscate(""); got != "" {
		t.Errorf("Deobfuscate(\"\") = %q, want empty string", got)
	}
}

func TestObfuscateShortInputs(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a", "a"},
		{"ab", "ab"},
		{"a.b", "a[.]b"},
		{"a@b", "a[@]b"},
		{":", ":"},
		{"::", "[:][:]"},
		{".", "[.]"},
		{"@", "[@]"},
	}
	for _, c := range cases {
		if got := Obfuscate(c.in); got != c.want {
			t.Errorf("Obfuscate(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPercentEncodedDotDecoded(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://a%2eb.example", "[http]://a[.]b[.]example"},
		{"http://a%2Eb.example", "[http]://a[.]b[.]example"},
		{"a%2eb.example", "a[.]b[.]example"},
		{"http://%65vil.example", "[http]://%65vil[.]example"},
	}
	for _, c := range cases {
		got := Obfuscate(c.in)
		if got != c.want {
			t.Errorf("Obfuscate(%q) = %q, want %q", c.in, got, c.want)
		}
		if strings.Contains(got, "[%") {
			t.Errorf("Obfuscate(%q) emitted bracketed percent-encoding: %q", c.in, got)
		}
	}
}

// Reserved delimiters (%40, %3a/%3A) are not equivalent to their decoded
// forms (RFC 3986 Section 2.2) and pass through verbatim.
func TestPercentEncodedReservedPreserved(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://user%40host.example", "[http]://user%40host[.]example"},
		{"http://evil%3a80.example", "[http]://evil%3a80[.]example"},
		{"http://user%3Apass@evil.example", "[http]://user%3Apass[@]evil[.]example"},
	}
	for _, c := range cases {
		got := Obfuscate(c.in)
		if got != c.want {
			t.Errorf("Obfuscate(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLongerSchemeNames(t *testing.T) {
	cases := []struct{ in, want string }{
		{"coap+tcp://device.example/r", "[coap+tcp]://device[.]example/r"},
		{"git+ssh://host.example/repo.git", "[git+ssh]://host[.]example/repo.git"},
		{"view-source:https://bad.example", "[view-source]:[https]://bad[.]example"},
	}
	for _, c := range cases {
		if got := Obfuscate(c.in); got != c.want {
			t.Errorf("Obfuscate(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
