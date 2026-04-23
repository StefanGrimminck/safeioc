package safeioc

import (
	"encoding/json"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// wptCorpusURL is the canonical source for the URL test corpus.
// The WPT test data covers real-world URL shapes that browser URL-parser
// implementers test against, making neutralization claims stronger than
// a bespoke list would.
const wptCorpusURL = "https://raw.githubusercontent.com/web-platform-tests/wpt/master/url/resources/urltestdata.json"

type corpusLine struct {
	num  int
	text string
}

var (
	corpusOnce  sync.Once
	corpusCache []corpusLine
	corpusErr   error
)

// getCorpus downloads the WPT URL test data and returns all URL inputs.
// The download happens at most once per test binary run.
// Pass -short to skip all corpus tests.
func getCorpus(t *testing.T) []corpusLine {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping WPT corpus fetch in short mode")
	}

	corpusOnce.Do(func() {
		resp, err := http.Get(wptCorpusURL)
		if err != nil {
			corpusErr = err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			corpusErr = &httpError{resp.StatusCode}
			return
		}

		var raw []json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
			corpusErr = err
			return
		}

		for i, item := range raw {
			if len(item) == 0 || item[0] == '"' {
				continue
			}
			var entry struct {
				Input string `json:"input"`
			}
			if json.Unmarshal(item, &entry) == nil && entry.Input != "" {
				corpusCache = append(corpusCache, corpusLine{num: i + 1, text: entry.Input})
			}
		}
	})

	if corpusErr != nil {
		t.Fatalf("fetch corpus: %v", corpusErr)
	}
	if len(corpusCache) == 0 {
		t.Fatal("corpus is empty")
	}
	t.Logf("corpus: %d inputs from WPT URL test data", len(corpusCache))
	return corpusCache
}

type httpError struct{ code int }

func (e *httpError) Error() string {
	return "HTTP " + http.StatusText(e.code)
}

// parsesAsIndicator reports whether s is still recognizable as a live indicator
// by any parser relevant to IOC activation.
func parsesAsIndicator(s string) (reason string, live bool) {
	if u, err := url.Parse(s); err == nil && u.Scheme != "" {
		if u.Host != "" || u.Opaque != "" || u.Path != "" {
			return "url.Parse accepted scheme=" + u.Scheme, true
		}
	}
	if ip := net.ParseIP(s); ip != nil {
		return "net.ParseIP accepted", true
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.IndexByte(s, ']'); end > 0 {
			if ip := net.ParseIP(s[1:end]); ip != nil {
				return "bracketed IPv6 literal accepted", true
			}
		}
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		if net.ParseIP(host) != nil {
			return "net.SplitHostPort yielded IP host", true
		}
	}
	if _, err := mail.ParseAddress(s); err == nil {
		return "mail.ParseAddress accepted", true
	}
	if !strings.ContainsAny(s, " \t\r\n") && looksLikeBareDomain(s) {
		return "bare domain-like string", true
	}
	return "", false
}

func looksLikeBareDomain(s string) bool {
	if strings.ContainsAny(s, "[]@:/?#") {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// TestCorpusNeutralizes verifies that every WPT URL input, once obfuscated,
// is rejected by URL/IP/email parsers.
func TestCorpusNeutralizes(t *testing.T) {
	for _, l := range getCorpus(t) {
		obf := Obfuscate(l.text)
		if reason, live := parsesAsIndicator(obf); live {
			t.Errorf("item %d: still live after obfuscation\n  input: %q\n  obfus: %q\n  why:   %s",
				l.num, l.text, obf, reason)
		}
	}
}

// TestCorpusRoundtrip verifies that Deobfuscate(Obfuscate(x)) is identical
// to x byte for byte.
//
// Entries whose raw text already contains Safe-IOC bracket tokens (e.g.
// "http://[:]") are skipped: those are malformed WPT parser stress tests,
// not real IOCs, and the token ambiguity is a known, accepted limitation.
func TestCorpusRoundtrip(t *testing.T) {
	for _, l := range getCorpus(t) {
		if containsObfuscationTokens(l.text) {
			continue
		}
		obf := Obfuscate(l.text)
		got := Deobfuscate(obf)
		if got != l.text {
			t.Errorf("item %d: roundtrip mismatch\n  input : %q\n  obfus : %q\n  deobf : %q",
				l.num, l.text, obf, got)
		}
	}
}

// TestCorpusIdempotent verifies that Obfuscate(Obfuscate(x)) == Obfuscate(x).
func TestCorpusIdempotent(t *testing.T) {
	for _, l := range getCorpus(t) {
		once := Obfuscate(l.text)
		twice := Obfuscate(once)
		if twice != once {
			t.Errorf("item %d: not idempotent\n  input : %q\n  once  : %q\n  twice : %q",
				l.num, l.text, once, twice)
		}
	}
}
