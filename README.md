# safeioc

Go implementation of the Safe-IOC obfuscation format defined in
[draft-grimminck-safe-ioc-sharing](https://datatracker.ietf.org/doc/draft-grimminck-safe-ioc-sharing/).

## Why it exists

Security analysts share malicious URLs, IP addresses, and email addresses in
email threads, tickets, chat channels, and reports. Many of those channels
automatically detect and activate raw URLs: an analyst clicking a link by
accident can reveal their IP address, trigger malware delivery, or alert the
threat actor that their infrastructure is under investigation. Some mail and
web infrastructure pre-fetches links for preview purposes, producing the same
exposure without any deliberate user action.

Safe-IOC breaks the syntactic validity of an indicator while keeping it
human-readable and fully reversible:

```
https://malicious.example/path    ->  [https]://malicious[.]example/path
http://[2001:db8::1]:8080         ->  [http]://[2001[:]db8[:][:]1]:8080
phish@target.example              ->  phish[@]target[.]example
```

The result cannot be parsed as a valid URI by compliant parsers, cannot be
auto-linked, and cannot be accidentally clicked, while remaining immediately
recognizable to a human reader.

## Install

```
go get github.com/StefanGrimminck/safeioc
```

CLI tool:

```
go install github.com/StefanGrimminck/safeioc/cmd/safeioc@latest
```

## Library

```go
import "github.com/StefanGrimminck/safeioc"

// Obfuscate a raw indicator.
out := safeioc.Obfuscate("https://malicious.example/path")
// [https]://malicious[.]example/path

// Restore the original byte for byte.
orig := safeioc.Deobfuscate(out)
// https://malicious.example/path

// Legacy hxxp/hxxps tokens are accepted during de-obfuscation.
safeioc.Deobfuscate("hxxps://bad[.]example")
// https://bad.example
```

Obfuscate is idempotent: applying it twice produces the same output as
applying it once.

## CLI

```
safeioc URL...             # obfuscate one or more indicators
safeioc -d URL...          # de-obfuscate

cat iocs.txt | safeioc     # stream-obfuscate
cat iocs.txt | safeioc -d  # stream-de-obfuscate
```

## How it works

The algorithm follows the four steps in the specification:

1. **Scheme** - wrap the URI scheme in square brackets: `https` -> `[https]`.
   The case of the scheme name is preserved verbatim so the transformation
   is reversible byte for byte. Any current or future scheme is handled
   without a lookup table.
2. **Userinfo** - replace `@` in the userinfo subcomponent with `[@]`.
3. **Host** - replace `.` in the host with `[.]`. Inside an IPv6 literal,
   replace `:` with `[:]` and any embedded IPv4 dots with `[.]`. Bare IPv6
   addresses (with `::` or the full eight-group form) receive the same
   colon-bracketing.
4. **Nested indicators** - obfuscate recognizable nested URIs (with a scheme,
   including `mailto:`), bare email addresses, and bare IPv4/IPv6 literals
   that appear in the Path, Query, or Fragment, by recursively applying
   Steps 1-3 to the matched span. Dots, `@`, and `:` characters outside a
   recognized indicator are preserved verbatim (file extensions, query
   values, and fragment labels are never touched).

Already-obfuscated tokens (`[.]`, `[:]`, `[@]`, `[scheme]`) are treated as
opaque, so the transformation is idempotent.

## What it handles

- URIs with any scheme (`http`, `https`, `ftp`, `ssh`, `smb`, `mailto`, ...).
- IPv4 addresses, bare or inside URIs.
- IPv6 literals: `::` shorthand, full eight-group form, IPv4-mapped addresses,
  and zone identifiers per RFC 9844.
- Bare email addresses.
- Nested indicators in Path, Query, or Fragment (open-redirect targets, email
  parameters, bare IP literals).
- Already-obfuscated input (no double-bracketing).

## Testing

```
go test ./...              # run all tests (fetches WPT URL corpus)
go test -short ./...       # skip network corpus fetch
go test -bench=. -benchmem ./...
```

The test suite runs four independent oracles against every unit vector and
against every URL input in the
[WPT URL test data](https://github.com/web-platform-tests/wpt/blob/master/url/resources/urltestdata.json)
(fetched at test time, not bundled):

1. **Neutralization** - `net/url`, `net.ParseIP`, `net.SplitHostPort`, and
   `net/mail` all reject the obfuscated form.
2. **Exact round-trip** - `Deobfuscate(Obfuscate(x)) == x` byte for byte.
3. **Idempotency** - `Obfuscate(Obfuscate(x)) == Obfuscate(x)`.
4. **Defeats a linkifier** - a regex-based URL/email/IP detector modelled on
   UTS #58 finds no link in any obfuscated output. Bare domain names inside
   paths, queries, or fragments are an accepted limitation of purely
   syntactic recognition and are recorded as a separate PASS category
   rather than a failure.

Every corpus item is logged per-line in the CI output (PASS / SKIP /
tolerated), so the Actions run can be cited as a per-entry audit trail.
Credential-shaped URL substrings in log output have a U+200B inserted so
GitHub Actions log masking does not redact them; test assertions always
use the unmodified strings.

## Reference

- Specification: `draft-grimminck-safe-ioc-sharing` (latest).
- Package docs: `go doc github.com/StefanGrimminck/safeioc`.
