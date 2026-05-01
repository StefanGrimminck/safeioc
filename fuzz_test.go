package safeioc

import (
	"strings"
	"testing"
)

func seedFuzz(f *testing.F) {
	f.Helper()
	for _, v := range obfuscationVectors {
		f.Add(v.in)
	}
	for _, v := range idempotencyVectors {
		f.Add(v.in)
	}
	f.Add("")
	f.Add(":")
	f.Add("::")
	f.Add("[")
	f.Add("]")
	f.Add("[]")
	f.Add("[:][.][@]")
	f.Add("a.b.c.d.e.f.g.h")
	f.Add("http://[[[")
}

func FuzzObfuscateNoPanic(f *testing.F) {
	seedFuzz(f)
	f.Fuzz(func(t *testing.T, s string) {
		_ = Obfuscate(s)
		_ = Deobfuscate(s)
	})
}

func FuzzObfuscateIdempotent(f *testing.F) {
	seedFuzz(f)
	f.Fuzz(func(t *testing.T, s string) {
		once := Obfuscate(s)
		twice := Obfuscate(once)
		if once != twice {
			t.Fatalf("not idempotent\n  input: %q\n  once : %q\n  twice: %q", s, once, twice)
		}
	})
}

func FuzzRoundtrip(f *testing.F) {
	seedFuzz(f)
	f.Fuzz(func(t *testing.T, s string) {
		if containsObfuscationTokens(s) || strings.Contains(s, "hxxp") {
			t.Skip("input already contains obfuscation or legacy tokens")
		}
		if hasBracketedScheme(s) {
			t.Skip("input contains a bracketed scheme token")
		}
		obf := Obfuscate(s)
		got := Deobfuscate(obf)
		if got != s {
			t.Fatalf("roundtrip mismatch\n  input: %q\n  obfus: %q\n  back : %q", s, obf, got)
		}
	})
}

func hasBracketedScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '[' {
			continue
		}
		if _, _, ok := matchBracketedScheme(s, i); ok {
			return true
		}
	}
	return false
}
