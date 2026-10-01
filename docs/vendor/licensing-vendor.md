# Licensing: vendor guide

This guide is for the Alice vendor (the person who signs licenses). Customers never see it and
never get `licensectl`. Spec references: §16.7, §19.2, R8. Task 22 of Phase 2 completes this guide;
this version holds the rules that must be followed from the first key on.

## Rules that never change

- The production license signing key is created and used **only on an offline machine** (a freshly
  installed machine or live USB with no network). It is never on a laptop connected to the
  internet, in CI, in cloud storage, in a password manager sync, or in this repository.
- No script, test, agent or CI job ever creates, stores or prints the production key or its
  passphrase. Tests use throw-away keys in temporary directories.
- Only the **public** key goes into Alice builds, through `internal/license/keys/production.json`.

## 1. Create the signing key (once per key)

On the offline machine:

```
make licensectl                       # or: go build -trimpath -o bin/licensectl ./cmd/licensectl
bin/licensectl keygen --out ~/alice-vendor --key-id vk-2026-01
```

- Choose a passphrase of **at least 6 random Diceware words** (licensectl refuses fewer than 6 words
  or 24 characters). It is read from the terminal without echo, asked twice, and never printed.
- The private key file `alice-license-private.pem` is encrypted with Argon2id (256 MiB, 4 passes)
  and AES-256-GCM, written with mode 0600. `keygen` never overwrites an existing key.
- Write down the printed **fingerprint** (`SHA256:…`). The release process compares the embedded
  key with this recorded fingerprint.

### Backups (R8)

1. Copy `alice-license-private.pem` to **two hardware-encrypted USB drives**. Keep one in a
   fireproof safe on the vendor premises and the other in a second place (bank safe deposit box or
   notary).
2. Make a **paper backup**: print the (encrypted) private key file and keep it in a safe.
3. Write the **passphrase on paper** and store it **separately** from the drives and the printout.
4. Check that each drive's copy opens: run `licensectl issue --key <copy> …` up to the summary
   and answer `no` (nothing is signed and nothing is written).

If the key is lost, no new licenses can be issued for shipped binaries. If it leaks, anyone can
forge licenses: follow "Key compromise" below at once.

## 2. Put the public key into Alice

```
bin/licensectl keyset --pub ~/alice-vendor/alice-license-public.pem
```

Copy the printed `{"keys": [...]}` entry into `internal/license/keys/production.json`, compare the
fingerprint with the recorded one, commit, and run `make release-keycheck` (it fails while the file
lists no key, and it refuses test keys such as `vk-test-01`).

## 3. Issue, inspect and verify licenses

```
bin/licensectl issue --key ~/alice-vendor/alice-license-private.pem \
    --installation ALICE-7F3K-92QD-M4XT-A81P --customer "Example Bank A.S." --targets 100 \
    --out alice-license-examplebank-20261001.alicelic
bin/licensectl inspect alice-license-examplebank-20261001.alicelic
bin/licensectl verify --pub ~/alice-vendor/alice-license-public.pem alice-license-examplebank-20261001.alicelic
```

- A mistyped Installation ID is refused (it ends with a check character) before the key is opened.
- `issue` asks for the passphrase, shows a summary and signs only after you type `yes`.
- Customer names are normalized to Unicode NFC before signing.
- Every license is appended to the ledger `issued.csv` next to the key. Each row is chained to the
  previous one and signed with the license key, so an edited, removed or reordered row is detected.
  `issue` refuses to sign while the ledger does not verify; check it any time with
  `licensectl ledger-verify --pub ~/alice-vendor/alice-license-public.pem`. Back the ledger up with
  the key.

### Correction licenses (R7)

Use `--replaces <license_id>` (and `--from` for an earlier start, for example after a customer clock
jump). The replaced license must be in the ledger. A correction that ends **earlier** than the license
it replaces is refused unless you add `--shorten`; replacing licenses in a cycle is always refused,
and a license ID is never issued twice.

## Key compromise

If the private key or its passphrase may have leaked:

1. Create a new key with the next key ID (`vk-YYYY-NN`) as in step 1.
2. In the next release, mark the leaked key `"status": "revoked"` in
   `internal/license/keys/production.json` **with no `revoked_from` cutoff**. `issued_at` is chosen
   by whoever signs, so an attacker holding the key can backdate a license before any cutoff; only a
   revocation without a cutoff rejects every license signed with that key.
3. Reissue every customer's license under the new key, free of charge, and send them with the
   release that revokes the old key.

`revoked_from` (a cutoff) is only for retiring a key that was **not** compromised.
