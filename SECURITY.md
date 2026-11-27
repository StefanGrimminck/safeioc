# Security policy

The purpose of this package is to make indicators safe to share, so a
string that is still live after `Obfuscate` or `ObfuscateText` is a
security bug: for example a URL a mail client still links, or an address a
parser still accepts. So is a panic or a run time that grows faster than
the input.

Report such a problem privately through GitHub's
[private vulnerability reporting](https://github.com/StefanGrimminck/safeioc/security/advisories/new)
rather than in a public issue. Include the input, the output you got, and
where the output is still live. Expect a first reply within a week.

Fixes are released as a new patch or minor version and listed in
`CHANGELOG.md`. Only the latest release is supported.

Bare domain names inside a URL's path, query or fragment are not obfuscated
(see "Bare domain names" in the package documentation). That is a
documented limit, not a vulnerability.
