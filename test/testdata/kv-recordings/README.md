# Key Vault and Entra ID reference answers

These files are the **reference shapes** the in-repo fake Azure service (`internal/testutil/fakekv`)
is compared with (`shapes_test.go`: `TestAnswersMatchTheReferenceShapes`). A test compares the key
structure of each fake answer (object keys recursively, array elements by their first item, JSON
types) with the file: the fake may add nothing and omit nothing the file shows, except the keys the
test lists as optional (`nextLink` on a last page, `crv` of an RSA key, `sans`).

## Rules

- **Placeholders only, never real values.** Every key, thumbprint, DER, GUID, token, secret value
  and host name is a placeholder string (`"<cer>"`, `"<value>"`, `"<x5t>"`, `"<n>"`, `"<guid>"`,
  `<vault>`). Timestamps stay numbers (Unix seconds). A test (`TestReferenceFilesHoldPlaceholders`)
  fails on a long string, a GUID or a base64-looking value.
- The files carry no secret and nothing a secret scanner matches; if one does, change the file.
- The fake's api-version is `2025-07-01` (the only one it serves).

## Source of each file

| File | Source (Microsoft Learn) |
|---|---|
| `list_certificates.json` | REST "Get Certificates", api-version 2025-07-01: https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificates/get-certificates?view=rest-keyvault-certificates-2025-07-01 |
| `list_certificate_versions.json` | "Get Certificate Versions" (same item model): https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificate-versions/get-certificate-versions?view=rest-keyvault-certificates-2025-07-01 |
| `get_certificate.json` | "Get Certificate": https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificate/get-certificate?view=rest-keyvault-certificates-2025-07-01 |
| `import_certificate.json` | "Import Certificate": https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/import-certificate/import-certificate?view=rest-keyvault-certificates-2025-07-01 |
| `get_secret_pkcs12.json`, `get_secret_pem.json` | "Get Secret" (SecretBundle): https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret?view=rest-keyvault-secrets-2025-07-01 (`kid` and `managed` for a certificate's backing secret are in the SecretBundle model) |
| `list_secrets.json` | "Get Secrets" (SecretItem) |
| `list_keys.json` | "Get Keys": https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys?view=rest-keyvault-keys-2025-07-01 |
| `get_key_rsa.json`, `get_key_ec.json` | "Get Key" (KeyBundle, public JWK): https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key/get-key?view=rest-keyvault-keys-2025-07-01 |
| `error_*.json` | `KeyVaultError` model of every operation page; the error codes: https://learn.microsoft.com/en-us/azure/key-vault/general/rest-error-codes ; the inner codes (`ForbiddenByRbac`, `ForbiddenByPolicy`, `ForbiddenByFirewall`) and the 429 code are NOT in the documentation: **GUESS** |
| `token_*.json`, `openid_configuration.json`, `imds_token.json`, `challenge.txt` | Microsoft identity platform token endpoint, OpenID discovery, managed-identity (IMDS) and the Key Vault challenge; see the notes in each file's test and `docs`/report |

The examples of the REST reference sometimes omit fields the service sends (for instance `tags`,
`managed`, `recoveryLevel`); the files here show the fields the fake sends. Where the reference is
silent the file says what the fake does and is a guess (see the fake's package comment).

## Recording against real Azure

`make record-azure` runs `TestRecordShapes` (`internal/providers/azurekv/record_test.go`, build tag `azure`)
with `ALICE_AZURE_RECORD=1`. It needs the variables of the real-Azure suite (`ALICE_AZURE_TEST_VAULT_URL`,
`ALICE_AZURE_TEST_TENANT_ID`, `ALICE_AZURE_TEST_CLIENT_ID`, `ALICE_AZURE_TEST_CLIENT_SECRET`,
`ALICE_AZURE_TEST_CERT_NAME`, ...) and is never part of `make test`, `make coverage` or `make ci`. Through
the provider's own guarded vault transport it reads one vault and rewrites these files, each from one
request: `list_certificates.json`, `list_certificate_versions.json`, `get_certificate.json`,
`get_secret_pkcs12.json`, `list_keys.json` and `list_secrets.json`. Only the shape is written: every value
is replaced with the placeholders above (ids keep their form with `<vault>`, `<name>`, `<version>`; key
material becomes `<cer>`, `<x5t>`, `<value>`, `<n>`; tags are emptied; free text becomes `"<string>"`;
numbers and booleans stay). The other files (errors, tokens, IMDS, the challenge, PEM secrets, single keys,
imports) are still maintained by hand from the pages above.

**Review the diff before committing it**: run `make test` (the shape and placeholder tests above) and check
that no real value, host name or tenant detail reached a file.
