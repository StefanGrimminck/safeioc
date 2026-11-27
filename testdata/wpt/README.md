# WPT URL test data

`urltestdata.json` is a copy of
[`url/resources/urltestdata.json`](https://github.com/web-platform-tests/wpt/blob/d29e99bec8fbf722fda01122834433e967427c6d/url/resources/urltestdata.json)
from the web-platform-tests project at commit
`d29e99bec8fbf722fda01122834433e967427c6d`, the last commit to change the
file as of 2026-11-27. It is distributed under the 3-Clause BSD License in
`LICENSE.md`.

The corpus tests read this copy so that they are reproducible and run
offline. To test against the current upstream file instead:

    SAFEIOC_WPT=latest go test -run Corpus ./...

To update the copy, replace the file with the upstream version, update the
commit above, and run the tests.
