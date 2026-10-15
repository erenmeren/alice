# Vendor console (Phase 1)

The vendor console keeps the vendor's customers, license requests and issued licenses in a
PostgreSQL database and issues licenses from requests. It is for the vendor only and is never
part of a customer build. Design: `docs/superpowers/specs/2026-10-15-vendor-console-design.md`.

## Set up the database

1. Create the database (for example on Neon, EU region) and a migration login that may create
   roles. Set `VENDOR_DATABASE_URL` to its connection string. Never put the string in a file in
   this repository.
2. `vendor-console migrate`.
3. Create one login per person and add it to one group role:
   `CREATE ROLE "<login>" LOGIN PASSWORD '<password>' IN ROLE vendor_sales;` (sales people),
   `vendor_signer` (the people who sign) or `vendor_owner` (the owner).

## Daily use

    vendor-console customer add --name "Acme Ltd"
    vendor-console request add --customer 1 --installation ALICE-... --targets 5
    vendor-console request show 1          # note the hash on the last line
    vendor-console issue --request 1 --hash <hash> --key alice-license-private.pem --out acme.json
    vendor-console audit-verify

`issue` refuses when the request changed after you looked at it (the hash no longer matches),
when the request is no longer open, and when a correction would end earlier than the license it
replaces. The key passphrase is asked on the terminal. An existing output file is never
overwritten.

## What the audit check proves

`audit-verify` proves that no audit row was edited or removed from the middle of the log. It does
not prove that the newest rows were not removed. A signed checkpoint that closes this gap is
planned for Phase 5.

## Not yet there

YubiKey signing (Phase 2), the sales web page (Phase 3), e-mail and reminders (Phase 4).
