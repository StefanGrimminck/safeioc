package safeioc

import "testing"

// FuzzIndicator checks the guarantees for single indicators on well-formed
// indicators built by the generator: Obfuscate is idempotent, Deobfuscate
// restores the input byte for byte, and no URL, IP or email parser and no
// linkifier finds a live indicator in the result.
func FuzzIndicator(f *testing.F) {
	for _, seed := range []string{"", "\x00", "\x05\x01\x02", "\x09\x03\x01\x02\x03", "\x06\x02\x01\x01\x00\x02\x03"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		g := generator{data: data}
		in := g.indicator()
		out := Obfuscate(in)
		if again := Obfuscate(out); again != out {
			t.Fatalf("Obfuscate is not idempotent\n in    %q\n once  %q\n twice %q", in, out, again)
		}
		if back := Deobfuscate(out); back != in {
			t.Fatalf("round trip changed the indicator\n in   %q\n out  %q\n back %q", in, out, back)
		}
		if why := stillLive(out); why != "" {
			t.Fatalf("still live (%s)\n in  %q\n out %q", why, in, out)
		}
		if what, span := linkifierDetects(out); what != "" && what != "bare-domain" {
			t.Fatalf("linkifier finds %s %q\n in  %q\n out %q", what, span, in, out)
		}
	})
}

// FuzzText checks the guarantees for free text on text built by the
// generator from indicators, wrappers, separators and ordinary words:
// ObfuscateText obfuscates exactly the indicators, as Obfuscate does each on
// its own, is idempotent, and DeobfuscateText restores the text.
func FuzzText(f *testing.F) {
	for _, seed := range []string{"", "\x01\x02\x03", "\x03\x00\x07\x01\x04\x02\x05", "\x02\x09\x05\x03\x06\x01\x01"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		g := generator{data: data}
		text, want := g.text()
		got := ObfuscateText(text)
		if got != want {
			t.Fatalf("ObfuscateText differs from Obfuscate on each indicator\n text %q\n got  %q\n want %q", text, got, want)
		}
		if again := ObfuscateText(got); again != got {
			t.Fatalf("ObfuscateText is not idempotent\n text  %q\n once  %q\n twice %q", text, got, again)
		}
		if back := DeobfuscateText(got); back != text {
			t.Fatalf("round trip changed the input\n text %q\n out  %q\n back %q", text, got, back)
		}
	})
}

// FuzzSafety checks what holds for every input, well-formed or not: no
// function panics, the output grows at most threefold, and IsObfuscated
// agrees with Deobfuscate.
func FuzzSafety(f *testing.F) {
	for _, v := range obfuscationVectors {
		f.Add(v.in)
		f.Add(v.out)
	}
	for _, v := range textVectors {
		f.Add(v.in)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for name, fn := range map[string]func(string) string{"Obfuscate": Obfuscate, "ObfuscateText": ObfuscateText} {
			if out := fn(s); len(out) > 3*len(s) {
				t.Fatalf("%s grew %d bytes to %d: %q", name, len(s), len(out), s)
			}
		}
		if d := Deobfuscate(s); IsObfuscated(s) != (d != s) {
			t.Fatalf("IsObfuscated(%q) = %v, but Deobfuscate returns %q", s, IsObfuscated(s), d)
		}
		if d := DeobfuscateText(s); len(d) > len(s) {
			t.Fatalf("DeobfuscateText grew %q to %q", s, d)
		}
	})
}
