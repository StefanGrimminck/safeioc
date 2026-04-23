package safeioc

import "testing"

var benchInputs = []string{
	"https://malicious.example/path?q=1",
	"http://[2001:db8::1]:8080/api/v1",
	"phish@target.example",
	"mailto:abuse@example.com",
	"198.51.100.1",
	"http://example.com/r?url=http://evil.example&u=nested@evil.example",
}

func BenchmarkObfuscate(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, s := range benchInputs {
			_ = Obfuscate(s)
		}
	}
}

func BenchmarkDeobfuscate(b *testing.B) {
	obf := make([]string, len(benchInputs))
	for i, s := range benchInputs {
		obf[i] = Obfuscate(s)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, s := range obf {
			_ = Deobfuscate(s)
		}
	}
}
