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

func TestPercentEncodedDelimitersNotBracketed(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://a%2eb.example", "[http]://a%2eb[.]example"},
		{"http://user%40host.example", "[http]://user%40host[.]example"},
		{"a%2eb.example", "a%2eb[.]example"},
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
