# safeioc

[![Go Reference](https://pkg.go.dev/badge/github.com/StefanGrimminck/safeioc.svg)](https://pkg.go.dev/github.com/StefanGrimminck/safeioc)
[![Test](https://github.com/StefanGrimminck/safeioc/actions/workflows/test.yml/badge.svg)](https://github.com/StefanGrimminck/safeioc/actions/workflows/test.yml)

Obfuscate and de-obfuscate indicators of compromise (IOCs) in Go: URLs,
domain names, IP addresses and email addresses that analysts share in
tickets, chat, mail and reports. safeioc implements the Safe-IOC format of
[draft-grimminck-safe-ioc-sharing](https://datatracker.ietf.org/doc/draft-grimminck-safe-ioc-sharing/).

```
https://evil.example/login     ->  [https]://evil[.]example/login
phish@target.example           ->  phish[@]target[.]example
198.51.100.7:4444              ->  198[.]51[.]100[.]7:4444
http://[2001:db8::1]:8080/     ->  [http]://[2001[:]db8[:][:]1]:8080/
```

An obfuscated indicator stays readable, does not parse as a URI, IP address or
email address, and is not turned into a link by mail clients, chat tools or
ticket systems. De-obfuscating restores the original byte for byte.

## The format

Clicking a malicious link by accident can reveal an analyst's address,
deliver malware, or tell an attacker their infrastructure is being looked
at. Mail and chat systems that fetch link previews do the same without a
click. Teams have altered indicators for years, a practice known as
"defanging", with `hxxp`, `[.]`, `(.)`, `[dot]` and other spellings that
each tool parses differently. Safe-IOC replaces those conventions with one
canonical form: brackets around the scheme and around each
`.`, `@` and IPv6 `:` that makes the string an address, applied in a fixed
order so that every implementation produces the same output.

## Install

```
go get github.com/StefanGrimminck/safeioc
```

The package has no dependencies outside the standard library and needs
Go 1.18 or later. The command-line tool:

```
go install github.com/StefanGrimminck/safeioc/cmd/safeioc@latest
```

## Use

One indicator, such as a value from a feed or a database column:

```go
import "github.com/StefanGrimminck/safeioc"

safeioc.Obfuscate("https://evil.example/a?u=http://198.51.100.7/")
// [https]://evil[.]example/a?u=[http]://198[.]51[.]100[.]7/

safeioc.Deobfuscate("[https]://evil[.]example/a")
// https://evil.example/a

safeioc.Deobfuscate("hxxps://evil[.]example") // legacy form, any case
// https://evil.example
```

Free text, such as a report, a ticket or a log line. Only the indicators
are changed:

```go
safeioc.ObfuscateText("Dropper (https://evil.example/s.ps1) beacons to 198.51.100.7.")
// Dropper ([https]://evil[.]example/s.ps1) beacons to 198[.]51[.]100[.]7.

safeioc.DeobfuscateText("C2 at evil[.]example, matched by [a-z]+[.]example")
// C2 at evil.example, matched by [a-z]+[.]example
```

`IsObfuscated(s)` reports whether `s` contains Safe-IOC tokens. To check
that an indicator is completely obfuscated, compare it with
`Obfuscate(s)`: `[https]://evil.example` is obfuscated but its host is
still live.

A de-obfuscated indicator is live again: write it only where it will not be
rendered as a link or fetched (Section 6.1 of the draft).

## Guarantees

For every indicator, and for every text made of indicators and words:
the output is the draft's canonical form, obfuscating twice changes nothing,
and de-obfuscating restores the input byte for byte. Two kinds of input are
exceptions. Input that already holds Safe-IOC tokens or a legacy `hxxp:`
scheme cannot round-trip, because de-obfuscating restores those too. And a
percent-encoded dot in a host (`evil%2eexample`) is decoded before it is
bracketed, as the draft requires, and comes back as `evil.example`.

For every input at all, indicator or not: no function panics, keeps
state or needs locking, and each runs in time linear in its input. What
the functions make of a string that is no indicator is not specified
beyond that.

## Command line

```
safeioc https://evil.example        # obfuscate arguments, one per line
safeioc -d '[https]://evil[.]example'
safeioc < iocs.txt                  # one indicator per line
safeioc -t < report.txt             # free text
safeioc -d -t < report-safe.txt
```

## Supported indicators

- URIs with any scheme, current or future (`http`, `https`, `ftp`, `smb`,
  `ssh`, `mailto`, `coap+tcp`, ...), with userinfo and ports. Scheme case is
  kept.
- Domain names, including punycode and Unicode labels.
- IPv4 addresses, with ports and CIDR prefixes.
- IPv6 addresses in every form: `::` shorthand, full form, IPv4-mapped and
  IPv4-embedded, zone identifiers, inside URLs and bare, with CIDR prefixes.
- Email addresses, including UTF-8 addresses. As the draft says, dots are
  bracketed in the host only: `first.last@evil.example` becomes
  `first.last[@]evil[.]example`, and the userinfo of a URL is kept the
  same way.
- URLs, emails and IP addresses nested in a path, query or fragment, such
  as open-redirect targets, to any depth.
- Input that is already obfuscated, completely or in part.

Recognition is syntactic. Inside a URL's path, query or fragment, bare
domain names are left as they are, because `report.pdf` and `evil.example`
look the same there; the draft makes the same choice. In free text, a bare
domain is recognized when its last label is a top-level domain in the IANA
root zone (ASCII or Unicode, such as `.рф`) or a reserved name such as
`.example` or `.test`, so `readme.md` is obfuscated (`.md` is Moldova) and
`notes.txt` is not. `DeobfuscateText` uses the same rule: it restores
`evil[.]example` and leaves `log[.]txt` alone.

The full contract is in the
[package documentation](https://pkg.go.dev/github.com/StefanGrimminck/safeioc).

## Tests

```
go test ./...                 # unit tests, draft vectors, corpora, fuzz seeds
go test -race ./...
go test -bench . -benchmem
go test -run '^$' -fuzz FuzzText -fuzztime 1m
```

The tests check four properties on two corpora and on indicators and
text generated by the fuzzer:

1. Neutralization: Go's `net/url`, `net`, `net/mail` parsers and a
   linkifier modelled on Unicode UTS #58 find no live indicator in the
   output.
2. Exact round trip: `Deobfuscate(Obfuscate(x)) == x`, and the same for
   the text functions.
3. Idempotency: `Obfuscate(Obfuscate(x)) == Obfuscate(x)`.
4. Conformance: every test vector in Section 10 of the draft passes.

Random-byte fuzzing and a test on 256 KiB of hostile input check the
guarantees that hold for every input. The corpora are about 1,200
IOC-shaped indicators
(`testdata/indicators.txt`) and the ~900 inputs of the
[web-platform-tests URL test data](https://github.com/web-platform-tests/wpt/tree/master/url),
the edge cases browser URL parsers are tested against. The WPT copy is
pinned (see `testdata/wpt/README.md`); `SAFEIOC_WPT=latest go test ./...`
runs against upstream, and CI does that weekly together with a 5-minute
fuzz run per target and a check of the TLD list.

## Versioning

The module follows semantic versioning, and when a new revision of the draft
changes the canonical output for some input, the change is released as a
minor version and described in [CHANGELOG.md](CHANGELOG.md). The package
documentation names the draft revision it implements.

## Contributing

Issues and pull requests are welcome. A change in behaviour needs a test
vector in `safeioc_test.go` or `text_test.go`, and `gofmt`,
`golangci-lint run` (configured in `.golangci.yml`) and
`go test -race ./...` must pass. Report anything that leaves an indicator
live privately, as described in [SECURITY.md](SECURITY.md).

## License

The code is under the BSD 3-Clause license in [LICENSE](LICENSE). The WPT
test data in `testdata/wpt` is under its own BSD 3-Clause license.
