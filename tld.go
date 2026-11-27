package safeioc

import (
	"sort"
	"strings"
	"unicode/utf8"
)

//go:generate go run ./internal/gentlds -o tlds.go

// isTLD reports whether label is a top-level domain in the IANA root zone
// or a reserved name such as "example", in any case. A Unicode label is
// looked up by its A-label ("рф" as "xn--p1ai").
func isTLD(label string) bool {
	if len(label) < 2 || len(label) > 4*63 {
		return false
	}
	name := strings.ToLower(label)
	for i := 0; i < len(name); i++ {
		if name[i] >= utf8.RuneSelf {
			encoded, ok := punycode(name)
			if !ok {
				return false
			}
			name = "xn--" + encoded
			break
		}
	}
	k := sort.SearchStrings(tlds[:], name)
	return k < len(tlds) && tlds[k] == name
}

// Parameters of Punycode, RFC 3492 Section 5.
const (
	punyBase        = 36
	punyTMin        = 1
	punyTMax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 0x80
)

// punycode encodes label as in RFC 3492 Section 6.3. It applies no IDNA
// mapping, which is enough to look up a TLD written in lower case.
func punycode(label string) (string, bool) {
	runes := []rune(label)
	if len(runes) > 63 {
		return "", false
	}
	out := make([]byte, 0, 2*len(label))
	for _, r := range runes {
		if r < punyInitialN {
			out = append(out, byte(r))
		}
	}
	basic := len(out)
	if basic > 0 {
		out = append(out, '-')
	}
	n, delta, bias := rune(punyInitialN), 0, punyInitialBias
	for h := basic; h < len(runes); {
		m := rune(utf8.MaxRune + 1)
		for _, r := range runes {
			if r >= n && r < m {
				m = r
			}
		}
		delta += int(m-n) * (h + 1)
		n = m
		for _, r := range runes {
			if r < n {
				delta++
			}
			if r == n {
				out = appendPunyDelta(out, delta, bias)
				bias = punyAdapt(delta, h+1, h == basic)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return string(out), true
}

// appendPunyDelta appends delta as a generalized variable-length integer
// (RFC 3492 Section 3.3).
func appendPunyDelta(out []byte, delta, bias int) []byte {
	q := delta
	for k := punyBase; ; k += punyBase {
		t := k - bias
		if t < punyTMin {
			t = punyTMin
		} else if t > punyTMax {
			t = punyTMax
		}
		if q < t {
			return append(out, punyDigit(q))
		}
		out = append(out, punyDigit(t+(q-t)%(punyBase-t)))
		q = (q - t) / (punyBase - t)
	}
}

// punyAdapt is the bias adaptation function of RFC 3492 Section 6.1.
func punyAdapt(delta, points int, first bool) int {
	if first {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / points
	k := 0
	for delta > (punyBase-punyTMin)*punyTMax/2 {
		delta /= punyBase - punyTMin
		k += punyBase
	}
	return k + (punyBase-punyTMin+1)*delta/(delta+punySkew)
}

// punyDigit returns the basic code point of the digit d (RFC 3492 Section 5).
func punyDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}
