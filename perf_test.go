package safeioc

import (
	"strings"
	"testing"
	"time"
)

// hostilePatterns repeat into inputs that would make a recognizer that
// rescans the rest of its input from every position take quadratic time.
var hostilePatterns = []string{
	"[", "]", "(", ")", ".", ":", "@", "%2e", "a-", "a.", "1:", "1.",
	"[a]:", "[.]", "a[.]", "[:]", "x@", "a.b@", "0.0.0.0.", "::%0",
	"http://", "hxxp:", "mailto:", "https://a.example,", "[[::]]", "_a.example_",
	"[a.b", "a+[.]", "evil.example/", "2001:db8::1 ", "a_", "a_a[.]", "a[.]",
	"a[@]", "1[.]", "[:]1", "a%", "x.y-", "\u4e2d.", "[[", "]]",
}

// TestLinearTime checks that every function takes time linear in the
// length of each hostile input: four times the input may take at most ten
// times as long (linear time takes four, quadratic sixteen). Comparing two
// sizes on the same machine keeps the test independent of how fast the
// machine is and of the race detector.
func TestLinearTime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large inputs in short mode")
	}
	funcs := map[string]func(string) string{
		"Obfuscate":       Obfuscate,
		"ObfuscateText":   ObfuscateText,
		"Deobfuscate":     Deobfuscate,
		"DeobfuscateText": DeobfuscateText,
	}
	for _, p := range hostilePatterns {
		for name, fn := range funcs {
			small, large := fastest(fn, hostileInput(p, 64<<10)), fastest(fn, hostileInput(p, 256<<10))
			if large > 10*small+20*time.Millisecond {
				t.Errorf("%s on %q: 64 KiB took %v, 256 KiB took %v", name, p, small, large)
			}
		}
	}
}

// hostileInput repeats pattern to about size bytes. The suffix keeps the
// functions off their fast paths for input with nothing to restore.
func hostileInput(pattern string, size int) string {
	return strings.Repeat(pattern, size/len(pattern)) + " [.]x hxxp://"
}

// fastest returns the shortest of three runs of fn on s.
func fastest(fn func(string) string, s string) time.Duration {
	best := time.Duration(1<<63 - 1)
	for i := 0; i < 3; i++ {
		start := time.Now()
		fn(s)
		if d := time.Since(start); d < best {
			best = d
		}
	}
	return best
}
