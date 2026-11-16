# ICCP Test Captures

These deterministic packet captures are committed fixtures for the default
`btest` suite. The scripts in `testing/scripts` copy the requested scenario
into each test's temporary directory. The default test suite requires no
packet-capture generation tools.

The `synthetic` directory contains valid and intentionally incomplete traffic.
The `malformed` directory contains captures designed to exercise parser error
handling. These files are test inputs and must not be treated as representative
production traffic.
