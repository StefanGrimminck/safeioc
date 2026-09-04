package safeioc

import "testing"

// TestDraftVectors runs the Figure 2 golden vectors from draft-grimminck-safe-ioc-sharing,
// keyed by the exact labels defined in the specification.
func TestDraftVectors(t *testing.T) {
	vectors := []struct {
		label     string
		operation string
		input     string
		expected  string
	}{
		{"standard-url", "obfuscate", "https://bad.example", "[https]://bad[.]example"},
		{"url-with-path", "obfuscate", "https://evil.example/path", "[https]://evil[.]example/path"},
		{"deep-link-url", "obfuscate", "https://bad.example/path/to/page?q=1#frag", "[https]://bad[.]example/path/to/page?q=1#frag"},
		{"http-url", "obfuscate", "http://attacker.example", "[http]://attacker[.]example"},
		{"ftp-url", "obfuscate", "ftp://files.example/", "[ftp]://files[.]example/"},
		{"mailto", "obfuscate", "mailto:user@example.com", "[mailto]:user[@]example[.]com"},
		{"ipv4-address", "obfuscate", "198.51.100.1", "198[.]51[.]100[.]1"},
		{"ipv4-in-url", "obfuscate", "http://192.0.2.1", "[http]://192[.]0[.]2[.]1"},
		{"ipv6-in-url", "obfuscate", "http://[2001:db8::1]:8080", "[http]://[2001[:]db8[:][:]1]:8080"},
		{"ipv6-full-form", "obfuscate", "http://[2001:db8:0:0:0:0:0:1]/", "[http]://[2001[:]db8[:]0[:]0[:]0[:]0[:]0[:]1]/"},
		{"ipv4-mapped-ipv6", "obfuscate", "http://[::ffff:192.0.2.1]", "[http]://[[:][:]ffff[:]192[.]0[.]2[.]1]"},
		{"ipv4-embedded-ipv6-wkp", "obfuscate", "http://[64:ff9b::198.51.100.1]/", "[http]://[64[:]ff9b[:][:]198[.]51[.]100[.]1]/"},
		{"ipv4-embedded-ipv6-nsp", "obfuscate", "2001:db8:122:344::198.51.100.1", "2001[:]db8[:]122[:]344[:][:]198[.]51[.]100[.]1"},
		{"ipv6-with-zone-id", "obfuscate", "http://[2001:db8::1%25eth0]/", "[http]://[2001[:]db8[:][:]1%25eth0]/"},
		{"bare-ipv6", "obfuscate", "2001:db8::1", "2001[:]db8[:][:]1"},
		{"bracketed-bare-ipv6", "obfuscate", "[2001:db8::1]", "[2001[:]db8[:][:]1]"},
		{"bare-ipv6-with-zone", "obfuscate", "2001:db8::1%eth0", "2001[:]db8[:][:]1%eth0"},
		{"email-address", "obfuscate", "phish@target.example", "phish[@]target[.]example"},
		{"punycode-domain", "obfuscate", "xn--n3h.example", "xn--n3h[.]example"},
		{"url-with-userinfo", "obfuscate", "http://user:pass@attacker.example", "[http]://user:pass[@]attacker[.]example"},
		{"bare-domain-with-port", "obfuscate", "evil.example:443", "evil[.]example:443"},
		{"scheme-case-preserved", "obfuscate", "HTTPS://bad.example", "[HTTPS]://bad[.]example"},
		{"percent-encoded-dot-in-host", "obfuscate", "http://evil%2eexample", "[http]://evil[.]example"},
		{"percent-encoded-dot-upper", "obfuscate", "http://evil%2Eexample", "[http]://evil[.]example"},
		{"percent-encoded-at-preserved", "obfuscate", "http://user%40attacker.example", "[http]://user%40attacker[.]example"},
		{"percent-encoded-colon", "obfuscate", "http://evil%3a80.example", "[http]://evil%3a80[.]example"},
		{"percent-encoded-non-delim", "obfuscate", "http://%65vil.example", "[http]://%65vil[.]example"},
		{"ipv4-cidr", "obfuscate", "192.0.2.0/24", "192[.]0[.]2[.]0/24"},
		{"ipv6-cidr", "obfuscate", "2001:db8::/32", "2001[:]db8[:][:]/32"},
		{"nested-url-in-query", "obfuscate", "http://example.com/r?url=http://evil.example", "[http]://example[.]com/r?url=[http]://evil[.]example"},
		{"nested-email-in-query", "obfuscate", "http://example.com/?contact=abuse@evil.example", "[http]://example[.]com/?contact=abuse[@]evil[.]example"},
		{"chained-redirect", "obfuscate", "http://a.test/?u=http://b.test/?u=http://c.test", "[http]://a[.]test/?u=[http]://b[.]test/?u=[http]://c[.]test"},
		{"idempotency-check", "obfuscate", "[https]://bad[.]example", "[https]://bad[.]example"},
		{"ipv6-idempotency", "obfuscate", "[http]://[2001[:]db8[:][:]1]:8080", "[http]://[2001[:]db8[:][:]1]:8080"},
		{"legacy-deobfuscation", "deobfuscate", "hxxps://bad[.]example", "https://bad.example"},
		{"legacy-deobfuscation-bare", "deobfuscate", "hxxps://bad.example", "https://bad.example"},
		{"case-preserved-roundtrip", "deobfuscate", "[HTTPS]://bad[.]example", "HTTPS://bad.example"},
		{"ipv6-uri-deobfuscation", "deobfuscate", "[http]://[2001[:]db8[:][:]1]:8080", "http://[2001:db8::1]:8080"},
		{"mailto-deobfuscation", "deobfuscate", "[mailto]:user[@]example[.]com", "mailto:user@example.com"},
	}

	for _, v := range vectors {
		t.Run(v.label, func(t *testing.T) {
			var got string
			switch v.operation {
			case "obfuscate":
				got = Obfuscate(v.input)
			case "deobfuscate":
				got = Deobfuscate(v.input)
			default:
				t.Fatalf("unknown operation %q", v.operation)
			}
			if got != v.expected {
				t.Errorf("\n  input:    %q\n  got:      %q\n  expected: %q", v.input, got, v.expected)
			}
		})
	}
}
