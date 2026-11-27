package safeioc

import (
	"strings"
	"testing"
)

var benchIndicators = []string{
	"https://malicious.example/path?q=1",
	"http://[2001:db8::1]:8080/api/v1",
	"phish@target.example",
	"mailto:abuse@example.com",
	"198.51.100.1",
	"http://example.com/r?url=http://evil.example&u=nested@evil.example",
}

var benchText = strings.Repeat(`The loader fetched https://evil.example/stage2.ps1 and beaconed to
198.51.100.7:4444 every 60 seconds. Replies went to billing@target.example;
see section 4.2 of the report and notes.txt for the timeline.
`, 20)

func BenchmarkObfuscate(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, s := range benchIndicators {
			_ = Obfuscate(s)
		}
	}
}

func BenchmarkDeobfuscate(b *testing.B) {
	obf := make([]string, len(benchIndicators))
	for i, s := range benchIndicators {
		obf[i] = Obfuscate(s)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, s := range obf {
			_ = Deobfuscate(s)
		}
	}
}

func BenchmarkObfuscateText(b *testing.B) {
	b.SetBytes(int64(len(benchText)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ObfuscateText(benchText)
	}
}

func BenchmarkDeobfuscateText(b *testing.B) {
	obf := ObfuscateText(benchText)
	b.SetBytes(int64(len(obf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DeobfuscateText(obf)
	}
}
