# Changelog

All notable changes to this module are listed here. Versions follow
[Semantic Versioning](https://semver.org/); see "Versioning" in the README
for how changes to the draft are released.

## v1.2.0 (2026-11-27)

Implements draft-grimminck-safe-ioc-sharing-14.

### Added

- `ObfuscateText` and `DeobfuscateText` defang and restore the indicators
  inside free text (reports, tickets, mail, logs) and leave the words around
  them unchanged. Bare domain names are recognized by their top-level
  domain, from the IANA root zone list (`go generate` refreshes it).
- `IsObfuscated` reports whether a string contains Safe-IOC tokens
  (Section 5 of the draft).
- The `safeioc` command has `-t` for free text and `-version`, and reads
  lines of any length.
- A BSD 3-Clause license.

### Changed

- `Obfuscate` keeps leading and trailing whitespace and defangs the
  indicator between it. Before, `" https://evil.example"` came back
  unchanged and live.
- `Obfuscate` decodes a percent-encoded dot (`%2e`, `%2E`) in the host
  before bracketing it, as drafts -12 and later require. `%40` and `%3a`
  are kept as they are.
- `Deobfuscate` restores `hxxp` and `hxxps` only in scheme position
  (Section 11.3 of the draft). Before, `/hxxp-guide` in a path
  became `/http-guide`. `Deobfuscate` now
  also recognizes `hxxp[:]//`.
- `Deobfuscate` restores a wrapped legacy name as written:
  `[hxxp]://evil[.]example` becomes `hxxp://evil.example`, so it
  round-trips with `Obfuscate`.
- Email addresses with UTF-8 local parts or domains (RFC 6531) are
  recognized as nested indicators.
- Brackets in a host that do not hold a valid IPv6 address are defanged
  too: `http://[evil.example]/` becomes `[http]://[evil[.]example]/` and
  `http://[::1.2.3.4x]` becomes `[http]://[[:][:]1[.]2[.]3[.]4x]`. Before,
  their contents were copied unchanged.
- `Obfuscate` defangs input that starts with a character no indicator
  starts with (a quote, a parenthesis, `<`, `/`) as free text. Before,
  `(https://evil.example)` and `//evil.example/x` came back live.
- Dots are bracketed in the host only, as Section 4.3 of the draft says:
  the local part of an email address and the userinfo of a URL are kept
  (`first.last[@]evil[.]example`). The body of an opaque URI such as
  `mailto:` still has every dot bracketed.
- A percent-encoded dot is decoded only in a host. Elsewhere it is kept,
  as the draft requires for all other percent-encoded content.
- Input that starts with a no-break space, a byte order mark or other
  non-letter character is read as text, so an indicator after it is
  defanged.
- An IPv4 address directly followed by Chinese or Japanese text is
  recognized.
- A URL joined to another without a path (`https://a.example,https://b.example`,
  `[x](https://b.example)`) ends at the second scheme, so both are defanged.
  Before, the second one stayed live.
- An IPv6 address followed by a full stop (`2001:db8::1.`) is recognized.
- Legacy schemes are recognized in any case (`HXXPS://`, `hXXp://`), as
  the ABNF of the draft allows; their case is kept (`HTTPS://`).

### Fixed

- Every function runs in time linear in its input. Before, long runs of
  dots, brackets or address characters took time quadratic in their
  length.

### Retracted

- v1.0.0 and v1.1.0: an indicator with leading whitespace came back live,
  and `Deobfuscate` rewrote `hxxp` anywhere in a string.

### Tests

- The WPT URL test data is pinned in `testdata/wpt` instead of being
  downloaded on every run, so `go test ./...` works offline and is
  reproducible. `SAFEIOC_WPT=latest` tests against upstream; CI does so
  weekly.
- A second corpus of about 1,200 IOC-shaped indicators.
- The draft's test vectors are read from a copy of its JSON.
- Fuzz targets that build well-formed indicators and text, for the exact
  guarantees, and one that feeds arbitrary bytes, for the guarantees that
  hold for every input. Every `go test` runs their seeds and saved
  failures; CI fuzzes each target for 5 minutes once a week.
- A test that every function stays fast on 256 KiB of hostile input.
- CI tests Go 1.18 and the current release, and runs golangci-lint.

## v1.1.0 (2026-05-01)

- Documentation update.

## v1.0.0 (2026-04-23)

- First release: `Obfuscate` and `Deobfuscate`, the `safeioc` command.
