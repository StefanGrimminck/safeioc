// Package safeioc defangs and refangs indicators of compromise (IOCs):
// URLs, domain names, IP addresses and email addresses that analysts need
// to share without anyone, or any program, opening them by accident.
//
// It implements the Safe-IOC format of draft-grimminck-safe-ioc-sharing
// (https://datatracker.ietf.org/doc/draft-grimminck-safe-ioc-sharing/):
// the scheme is wrapped in brackets, and the dots, at-signs and IPv6
// colons that make a string an address are replaced by bracketed tokens.
//
//	https://evil.example/login     [https]://evil[.]example/login
//	phish@target.example           phish[@]target[.]example
//	198.51.100.7                   198[.]51[.]100[.]7
//	http://[2001:db8::1]:8080/     [http]://[2001[:]db8[:][:]1]:8080/
//
// The result is still readable, no longer parses as a URI, IP address or
// email address, and is not turned into a link by mail clients, chat
// tools or ticket systems. It converts back without loss.
//
// # One indicator or a whole text
//
// [Obfuscate] and [Deobfuscate] take a single indicator, such as a value
// from a feed, a database column or one line of an indicator list. They
// apply the canonical transformation of the draft and are the functions
// to use when the input is known to be an indicator.
//
// [ObfuscateText] and [DeobfuscateText] take free text, such as a report,
// a ticket, an email body or a log line. They find the indicators in the
// text, transform only those, and leave the words around them as they
// are. [Obfuscate] does not search text: given "see 2001:db8::1", it
// does not find the address after the space. Input that cannot start an
// indicator, such as "(https://evil.example)" or "//evil.example/x", is an
// exception: Obfuscate passes it to ObfuscateText rather than return it
// live.
//
// # Guarantees
//
// An indicator here is what the draft defines: a URI, a domain name, an
// IPv4 or IPv6 address with an optional port or prefix length, or an email
// address. For every indicator s, and for every text made of indicators
// and ordinary words:
//
//   - Obfuscate(s) is the canonical form of the draft, and the test
//     vectors of its Section 10 pass.
//   - Obfuscate(Obfuscate(s)) == Obfuscate(s): defanged input is never
//     bracketed twice. The same holds for ObfuscateText.
//   - Deobfuscate(Obfuscate(s)) == s, byte for byte, unless s already
//     contains a Safe-IOC token ("[.]", "[@]", "[:]", "[scheme]:") or a
//     legacy "hxxp:" scheme, or a percent-encoded dot ("%2e") in a host:
//     that dot is decoded before it is bracketed, as the draft requires,
//     and comes back as ".". The same holds for ObfuscateText and
//     DeobfuscateText.
//
// For every input at all, including input that is no indicator:
//
//   - the functions never panic, keep no state, and are safe for
//     concurrent use;
//   - they run in time linear in the length of the input, and the output
//     is at most three times as long;
//   - IsObfuscated(s) is true exactly when Deobfuscate(s) != s.
//
// What Obfuscate makes of a string that is no indicator, such as
// "::%0::x", is not specified beyond that.
//
// # Bare domain names
//
// Recognition is purely syntactic. Inside the path, query or fragment of
// a URL, nested URLs, email addresses and IP addresses are defanged, but
// bare domain names are not, because "report.pdf" and "evil.example"
// cannot be told apart there. In free text, a bare domain name is
// recognized when its last label is a top-level domain in the IANA root
// zone (in ASCII or Unicode form) or a reserved name such as "example" or
// "test"; "readme.md" is therefore defanged (".md" is a country code) and
// "notes.txt" is not. DeobfuscateText applies the same rule, so it restores
// "evil[.]example" but leaves "log[.]txt" alone.
//
// Deobfuscate turns a defanged indicator back into a live one. Write its
// result only to places that will not render or follow it, as Section 6.1
// of the draft requires.
//
// Legacy "hxxp" and "hxxps" schemes, in any case, are restored by
// Deobfuscate and DeobfuscateText but never produced:
// Obfuscate("hxxp://evil.example") keeps the legacy name and returns
// "[hxxp]://evil[.]example".
//
// This version implements draft-grimminck-safe-ioc-sharing-14 and passes
// all of its test vectors.
package safeioc
