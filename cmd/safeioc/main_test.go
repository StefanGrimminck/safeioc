package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		stdin string
		want  string
		code  int
	}{
		{"argument", []string{"https://bad.example"}, "", "[https]://bad[.]example\n", 0},
		{"several arguments", []string{"phish@target.example", "198.51.100.1"}, "", "phish[@]target[.]example\n198[.]51[.]100[.]1\n", 0},
		{"refang argument", []string{"-d", "[https]://bad[.]example"}, "", "https://bad.example\n", 0},
		{"lines", nil, "https://bad.example\nphish@target.example\n", "[https]://bad[.]example\nphish[@]target[.]example\n", 0},
		{"CRLF lines keep their endings", nil, "https://bad.example\r\nhttps://evil.example\r\n", "[https]://bad[.]example\r\n[https]://evil[.]example\r\n", 0},
		{"last line without newline", nil, "evil.example", "evil[.]example\n", 0},
		{"empty input", nil, "", "", 0},
		{"refang lines", []string{"-d"}, "[https]://bad[.]example\nhxxps://attacker[.]example\n", "https://bad.example\nhttps://attacker.example\n", 0},
		{"text", []string{"-t"}, "C2 at https://evil.example, see 198.51.100.7.\n", "C2 at [https]://evil[.]example, see 198[.]51[.]100[.]7.\n", 0},
		{"refang text", []string{"-d", "-t"}, "C2 at [https]://evil[.]example, regex [0-9][.]x\n", "C2 at https://evil.example, regex [0-9][.]x\n", 0},
		{"long line", nil, "https://evil.example/" + strings.Repeat("a", 2<<20) + "\n", "[https]://evil[.]example/" + strings.Repeat("a", 2<<20) + "\n", 0},
		{"unknown flag", []string{"-x"}, "", "", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, strings.NewReader(tt.stdin), &stdout, &stderr)
			if code != tt.code {
				t.Fatalf("exit code %d, want %d (stderr %q)", code, tt.code, stderr.String())
			}
			if got := stdout.String(); got != tt.want {
				t.Errorf("stdout = %q, want %q", shorten(got), shorten(tt.want))
			}
		})
	}
}

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if got := stdout.String(); !strings.HasPrefix(got, "safeioc ") {
		t.Errorf("stdout = %q, want it to start with %q", got, "safeioc ")
	}
}

// shorten cuts s to 200 bytes so that a failure on a long line stays
// readable.
func shorten(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
