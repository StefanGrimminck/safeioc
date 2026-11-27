package safeioc

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
)

// The corpus tests run two sets of inputs through the package:
//
//   - testdata/indicators.txt: about 1,200 indicators in the shapes analysts
//     share (URLs with every common scheme, userinfo, ports, IPv4 and IPv6
//     forms, emails, nested redirects, traversal and encoding tricks), all
//     on reserved documentation names and addresses;
//   - testdata/wpt/urltestdata.json: the inputs of the web-platform-tests
//     URL test data, the edge cases browsers' URL parsers are tested
//     against.
//
// Every input must come out of Obfuscate unparseable as a URL, IP address
// or email address; the indicators among them must also round-trip
// exactly.
//
// The WPT copy is pinned to the commit named in testdata/wpt/README.md, so
// the tests are reproducible and need no network. Set SAFEIOC_WPT=latest
// to test against the current upstream file instead; CI does this once a
// week.
const wptLatestURL = "https://raw.githubusercontent.com/web-platform-tests/wpt/master/url/resources/urltestdata.json"

type corpusEntry struct {
	src  string // file the entry comes from
	num  int    // line number or JSON array index in that file
	text string
}

func (e corpusEntry) String() string { return fmt.Sprintf("%s:%d", e.src, e.num) }

var (
	corpusOnce sync.Once
	corpus     []corpusEntry
	corpusErr  error
)

func loadCorpus(t *testing.T) []corpusEntry {
	t.Helper()
	corpusOnce.Do(func() {
		corpus, corpusErr = readIndicators()
		if corpusErr == nil {
			var wpt []corpusEntry
			wpt, corpusErr = readWPT()
			corpus = append(corpus, wpt...)
		}
	})
	if corpusErr != nil {
		t.Fatalf("loading the corpora: %v", corpusErr)
	}
	return corpus
}

func readIndicators() ([]corpusEntry, error) {
	data, err := os.ReadFile("testdata/indicators.txt")
	if err != nil {
		return nil, err
	}
	var out []corpusEntry
	for i, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimRight(line, "\r"); line != "" {
			out = append(out, corpusEntry{src: "indicators.txt", num: i + 1, text: line})
		}
	}
	if len(out) < 1000 {
		return nil, fmt.Errorf("indicators.txt has only %d lines", len(out))
	}
	return out, nil
}

func readWPT() ([]corpusEntry, error) {
	var data []byte
	var err error
	if os.Getenv("SAFEIOC_WPT") == "latest" {
		data, err = fetch(wptLatestURL)
	} else {
		data, err = os.ReadFile("testdata/wpt/urltestdata.json")
	}
	if err != nil {
		return nil, err
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	var out []corpusEntry
	for i, item := range raw {
		if len(item) == 0 || item[0] != '{' {
			continue // section comments are plain strings
		}
		var e struct {
			Input string `json:"input"`
		}
		if json.Unmarshal(item, &e) == nil && e.Input != "" {
			out = append(out, corpusEntry{src: "urltestdata.json", num: i, text: e.Input})
		}
	}
	if len(out) < 500 {
		return nil, fmt.Errorf("only %d inputs, expected several hundred", len(out))
	}
	return out, nil
}

func fetch(u string) ([]byte, error) {
	resp, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// stillLive reports why s would still be taken as a URL, IP address or
// email address by Go's standard parsers, or "" if none accepts it.
func stillLive(s string) string {
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && (u.Host != "" || u.Opaque != "" || u.Path != "") {
		return "url.Parse accepts scheme " + u.Scheme
	}
	if net.ParseIP(s) != nil {
		return "net.ParseIP accepts it"
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.IndexByte(s, ']'); end > 0 && net.ParseIP(s[1:end]) != nil {
			return "bracketed IP literal"
		}
	}
	if host, _, err := net.SplitHostPort(s); err == nil && net.ParseIP(host) != nil {
		return "net.SplitHostPort yields an IP"
	}
	if _, err := mail.ParseAddress(s); err == nil {
		return "mail.ParseAddress accepts it"
	}
	if looksLikeBareDomain(s) {
		return "bare domain name"
	}
	return ""
}

func looksLikeBareDomain(s string) bool {
	if !strings.Contains(s, ".") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlphaNum(c) && c != '.' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// TestCorpusNeutralizes checks that no obfuscated corpus input is accepted
// by the URL, IP or email parsers of the standard library.
func TestCorpusNeutralizes(t *testing.T) {
	for _, e := range loadCorpus(t) {
		obf := Obfuscate(e.text)
		if why := stillLive(obf); why != "" {
			t.Errorf("%v: still live after Obfuscate (%s)\n in  %q\n out %q", e, why, e.text, obf)
		}
	}
}

// exactCovered reports whether the guarantees of exactness apply to the
// corpus entry e: it is an indicator, not a URL parser edge case, and it
// holds no Safe-IOC or legacy token and no percent-encoded dot, which is
// decoded in a host as the draft requires.
func exactCovered(e corpusEntry) bool {
	if e.src != "indicators.txt" && !isRelevantIOC(e.text) {
		return false
	}
	return !IsObfuscated(e.text) && !strings.Contains(strings.ToLower(e.text), "%2e")
}

// TestCorpusExact checks, for every indicator in the corpora, that
// Obfuscate is idempotent and that Deobfuscate restores the indicator byte
// for byte.
func TestCorpusExact(t *testing.T) {
	tested := 0
	for _, e := range loadCorpus(t) {
		if !exactCovered(e) {
			continue
		}
		tested++
		once := Obfuscate(e.text)
		if twice := Obfuscate(once); twice != once {
			t.Errorf("%v: Obfuscate is not idempotent\n in    %q\n once  %q\n twice %q", e, e.text, once, twice)
		}
		if back := Deobfuscate(once); back != e.text {
			t.Errorf("%v: round trip changed the input\n in   %q\n obf  %q\n back %q", e, e.text, once, back)
		}
	}
	if tested < 1500 {
		t.Errorf("only %d indicators were tested", tested)
	}
}

// TestCorpusInText places every indicator of the corpora in a sentence and
// checks that ObfuscateText is idempotent and that DeobfuscateText
// restores the sentence.
func TestCorpusInText(t *testing.T) {
	for _, e := range loadCorpus(t) {
		if !exactCovered(e) {
			continue
		}
		text := "Seen " + e.text + " today."
		once := ObfuscateText(text)
		if twice := ObfuscateText(once); twice != once {
			t.Errorf("%v: ObfuscateText is not idempotent\n in    %q\n once  %q\n twice %q", e, text, once, twice)
		}
		if back := DeobfuscateText(once); back != text {
			t.Errorf("%v: text round trip changed the input\n in   %q\n obf  %q\n back %q", e, text, once, back)
		}
	}
}
