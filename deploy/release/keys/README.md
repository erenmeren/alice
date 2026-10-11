# Release public keys

This directory holds the **public** halves of the vendor's release signing keys, one file per key, named after its
key ID: `rk-YYYY-NN.pem` (a line `key-id: rk-YYYY-NN` and a PKIX `PUBLIC KEY` PEM block, as
`licensectl release-keygen` writes it). `make release` copies them into the package as `release-keys/`, and the
installer and the updater verify `SHA256SUMS.sig` with them (C5, SEC-107).

- Never put a private key here. `licensectl release-keygen` and `tools/releasesign` refuse to write into this
  directory.
- Never put a test key (`rk-test-NN`) here: a customer package (`make release`) refuses one, and only
  `make release-test` packages a test key, generated at test time in `bin/release-test-key/`.
- The release keys and the license keys (`internal/license/keys/production.json`) are separate keys:
  `make release-keycheck` fails when a key is in both, and fails while this directory has no `rk-*.pem`.

How the key is made, stored, used and rotated: `docs/vendor/licensing-vendor.md`, section "Release key".
