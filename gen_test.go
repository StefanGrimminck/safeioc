package safeioc

import (
	"strconv"
	"strings"
)

// A generator builds realistic indicators and text from fuzz input: every
// choice it makes is read from data, so the fuzzer explores the space of
// well-formed indicators instead of random bytes. Once data runs out,
// every choice is the first option.
type generator struct {
	data []byte
}

// intn returns a choice in [0, n).
func (g *generator) intn(n int) int {
	if len(g.data) == 0 {
		return 0
	}
	c := int(g.data[0])
	g.data = g.data[1:]
	return c % n
}

func (g *generator) pick(options ...string) string { return options[g.intn(len(options))] }

// Pools of parts. Domain names use reserved TLDs (RFC 2606) and TLDs from
// the IANA root zone, IP addresses use documentation ranges where it
// matters to a reader, and nothing here is a real indicator.
var (
	genSchemes = []string{"http", "https", "HTTPS", "ftp", "smb", "ssh", "coap+tcp", "git+ssh"}
	genLabels  = []string{"evil", "a-b", "cdn", "www", "mail", "0day", "xn--n3h", "bücher", "пример", "sub1"}
	genTLDs    = []string{"example", "test", "invalid", "com", "org", "net", "io", "рф", "中国", "xn--p1ai"}
	genLocals  = []string{"a", "info", "first.last", "x_y", "a+tag", "abuse", "用户", "σωκράτης"}
	genPaths   = []string{"a", "x.php", "a.b.c", "~u", "wp-admin", "index.html", "%20x", "file.tar.gz", "v1"}
	genValues  = []string{"1", "a.b", "x", "%2F", "true"}
	genZones   = []string{"eth0", "en0", "eth0.100"}
	genWords   = []string{"see", "C2", "e.g.", "notes.txt", "v1.2", "10:30", "std::vector", "the", "and"}
	genSeps    = []string{" ", ", ", "; ", "\n", " and ", ". ", "\t"}
	genWraps   = [][2]string{{"", ""}, {"(", ")"}, {"<", ">"}, {`"`, `"`}, {"'", "'"}, {"_", "_"}, {"“", "”"}, {"[", "]"}}
)

func (g *generator) domain() string {
	labels := make([]string, 1+g.intn(3))
	for i := range labels {
		labels[i] = g.pick(genLabels...)
	}
	return strings.Join(labels, ".") + "." + g.pick(genTLDs...)
}

func (g *generator) ipv4() string {
	return strconv.Itoa(g.intn(256)) + "." + strconv.Itoa(g.intn(256)) + "." +
		strconv.Itoa(g.intn(256)) + "." + strconv.Itoa(g.intn(256))
}

func (g *generator) ipv6() string {
	hex := strconv.FormatInt(int64(g.intn(0x10000)), 16)
	switch g.intn(7) {
	case 0:
		return "2001:db8::" + hex
	case 1:
		return "2001:db8:0:0:0:0:0:" + hex
	case 2:
		return "::ffff:" + g.ipv4()
	case 3:
		return "64:ff9b::" + g.ipv4()
	case 4:
		return "::1"
	case 5:
		return "fe80::" + hex + "%" + g.pick(genZones...)
	default:
		return "2001:db8:" + hex + "::"
	}
}

func (g *generator) email() string {
	return g.pick(genLocals...) + "@" + g.domain()
}

// host returns a URL host: a domain name, an IPv4 address or an IPv6
// literal.
func (g *generator) host() string {
	switch g.intn(4) {
	case 0:
		return g.ipv4()
	case 1:
		ip := g.ipv6()
		return "[" + strings.Replace(ip, "%", "%25", 1) + "]"
	default:
		return g.domain()
	}
}

func (g *generator) url(depth int) string {
	var b strings.Builder
	b.WriteString(g.pick(genSchemes...) + "://")
	b.WriteString(g.pick("", "", "user@", "user:pass@"))
	b.WriteString(g.host())
	b.WriteString(g.pick("", "", ":8080", ":443"))
	for i := g.intn(4); i > 0; i-- {
		b.WriteString("/" + g.pick(genPaths...))
	}
	switch g.intn(4) {
	case 1:
		b.WriteString("?q=" + g.pick(genValues...))
	case 2:
		if depth > 0 {
			b.WriteString("?u=" + g.nested(depth-1))
		}
	case 3:
		b.WriteString("?a=" + g.pick(genValues...) + "&b=" + g.pick(genValues...))
	}
	if g.intn(4) == 0 {
		b.WriteString("#" + g.pick("top", "a.b", "x"))
	}
	return b.String()
}

// nested returns an indicator that Step 4 defangs inside a URL.
func (g *generator) nested(depth int) string {
	switch g.intn(5) {
	case 0:
		return g.email()
	case 1:
		return g.ipv4()
	case 2:
		return g.ipv6()
	case 3:
		return "mailto:" + g.email()
	default:
		return g.url(depth)
	}
}

// indicator returns one well-formed indicator.
func (g *generator) indicator() string {
	switch g.intn(10) {
	case 0:
		return g.email()
	case 1:
		return "mailto:" + g.email() + g.pick("", "?subject=Hi")
	case 2:
		return g.domain()
	case 3:
		return g.domain() + ":" + strconv.Itoa(1+g.intn(65535))
	case 4:
		return g.ipv4() + g.pick("", ":4444", "/24", "/32")
	case 5:
		return g.ipv6() + g.pick("", "", "/64")
	default:
		return g.url(1)
	}
}

// text returns free text made of indicators, wrappers, separators and
// ordinary words, together with the same text in which every indicator is
// replaced by Obfuscate's result.
func (g *generator) text() (text, defanged string) {
	var t, d strings.Builder
	for i := 1 + g.intn(4); i > 0; i-- {
		if g.intn(3) == 0 {
			w := g.pick(genWords...) + " "
			t.WriteString(w)
			d.WriteString(w)
		}
		ind := g.indicator()
		wrap := genWraps[g.intn(len(genWraps))]
		t.WriteString(wrap[0] + ind + wrap[1])
		d.WriteString(wrap[0] + Obfuscate(ind) + wrap[1])
		if i > 1 {
			sep := g.pick(genSeps...)
			t.WriteString(sep)
			d.WriteString(sep)
		}
	}
	if end := g.pick("", ".", "!", "\n"); end != "" {
		t.WriteString(end)
		d.WriteString(end)
	}
	return t.String(), d.String()
}
