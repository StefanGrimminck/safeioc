package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/StefanGrimminck/safeioc"
)

func TestStreamLinesObfuscate(t *testing.T) {
	in := strings.NewReader("https://bad.example\nphish@target.example\n")
	var out bytes.Buffer
	if err := streamLines(in, &out, safeioc.Obfuscate); err != nil {
		t.Fatalf("streamLines: %v", err)
	}
	want := "[https]://bad[.]example\nphish[@]target[.]example\n"
	if got := out.String(); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestStreamLinesDeobfuscate(t *testing.T) {
	in := strings.NewReader("[https]://bad[.]example\nhxxps://attacker[.]example\n")
	var out bytes.Buffer
	if err := streamLines(in, &out, safeioc.Deobfuscate); err != nil {
		t.Fatalf("streamLines: %v", err)
	}
	want := "https://bad.example\nhttps://attacker.example\n"
	if got := out.String(); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestStreamLinesEmptyInput(t *testing.T) {
	in := strings.NewReader("")
	var out bytes.Buffer
	if err := streamLines(in, &out, safeioc.Obfuscate); err != nil {
		t.Fatalf("streamLines: %v", err)
	}
	if got := out.String(); got != "" {
		t.Errorf("output = %q, want empty", got)
	}
}

func TestStreamLinesCRLF(t *testing.T) {
	in := strings.NewReader("https://bad.example\r\nhttps://evil.example\r\n")
	var out bytes.Buffer
	if err := streamLines(in, &out, safeioc.Obfuscate); err != nil {
		t.Fatalf("streamLines: %v", err)
	}
	want := "[https]://bad[.]example\n[https]://evil[.]example\n"
	if got := out.String(); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}
