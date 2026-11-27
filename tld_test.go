package safeioc

import "testing"

func TestPunycode(t *testing.T) {
	for in, want := range map[string]string{
		"bücher":  "bcher-kva",
		"рф":      "p1ai",
		"中国":      "fiqs8s",
		"ελ":      "qxam",
		"münchen": "mnchen-3ya",
		"ドメイン名例":  "eckwd4c7cu47r2wf",
	} {
		if got, ok := punycode(in); !ok || got != want {
			t.Errorf("punycode(%q) = %q, %v, want %q", in, got, ok, want)
		}
	}
}

func TestIsTLD(t *testing.T) {
	for label, want := range map[string]bool{
		"com": true, "COM": true, "example": true, "test": true, "onion": true,
		"рф": true, "中国": true, "xn--p1ai": true,
		"txt": false, "pdf": false, "": false, "c": false, "local-domain": false,
	} {
		if got := isTLD(label); got != want {
			t.Errorf("isTLD(%q) = %v, want %v", label, got, want)
		}
	}
}
