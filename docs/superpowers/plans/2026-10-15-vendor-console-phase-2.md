# Vendor Console Phase 2 (YubiKey Signing) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `vendor-console issue` can sign a license with an Ed25519 key that lives on a YubiKey (OpenPGP applet), after showing the signer exactly what will be signed and asking for the PIN and a touch.

**Architecture:** A pure-Go OpenPGP card client (APDU level) behind a small `Card` interface, a `Signer` built on it, and a PC/SC transport in a separate package compiled only with the build tag `yubikey` (it needs cgo on Linux and macOS). Everything above the transport is tested against a software OpenPGP card simulator. The hardware itself cannot be tested in this environment: the code is verified against the card specification and the simulator, and a hardware smoke-test checklist is written for the owner (owner-pending).

**Tech Stack:** Go 1.27, `github.com/ebfe/scard` (PC/SC; cgo on Linux and macOS, system `winscard` on Windows; only in the tagged transport package), standard library `crypto/ed25519`.

**Spec:** `docs/superpowers/specs/2026-10-15-vendor-console-design.md` (sections 4.1 to 4.4, 9, 10 phase 2, 11 O1 and O3)

## Global Constraints

- Branch `vendor-console-yubikey`, cut from `master`. Merged into `master` locally (fast-forward) at the end; never pushed.
- `alice` and every product binary are built with `CGO_ENABLED=0` and must never link `ebfe/scard` or any package under `internal/vconsole/...`: extend `TestReleaseBinaryLinksNoTestOrVendorCode` for the new packages and the new module.
- The default `vendor-console` build (no tag) stays `CGO_ENABLED=0` and has no PC/SC code. The YubiKey build is `go build -tags yubikey ./cmd/vendor-console` on each target OS (Linux needs `libpcsclite-dev` and `pcscd`; macOS and Windows use the system PC/SC).
- The license key signs nothing but licenses. The one exception is the smoke test (Task 4), which signs the fixed text `alice-vendor-console smoke test: not a license` (a message that can never parse as a license, so the product verifier refuses it); it is documented as such.
- The PIN is read with no echo, never put in an argument, an environment variable, a log, an error or the audit; it is zeroed after use. A wrong PIN is never retried automatically. If the card reports one try left, signing is refused unless the operator passes `--last-pin-try`.
- Time and context: `Issue` honours `ctx` (cancel closes the card connection); the whole signing step has a 2 minute limit.
- No new dependency outside the tagged transport package.
- Go style: errors lower-case and wrapped with `%w`, no `panic` in library code, comments say why.
- Commits end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; commit with `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit ...`.

## Rulings (open items O1, O3 and the spec's "1 or 2")

1. **OpenPGP only, no PIV.** The firmware of the owner's three keys is not known (O1). OpenPGP Ed25519 works from firmware 5.2.3, PIV Ed25519 only from 5.7. One implementation therefore covers every key that PIV would cover and more, and a second implementation (with its own untestable hardware paths) is not built. PIV stays out of scope; the spec is updated.
2. **Library (O3):** `ebfe/scard` for PC/SC, used only for transport. The OpenPGP card protocol is implemented here on top of it (about 400 lines), because no maintained Go library offers Ed25519 signing on the OpenPGP applet across Linux, macOS and Windows. `piv-go` was examined and rejected (PIV only, firmware 5.7 and later).
3. **No local browser UI.** The spec's "signing app serving a local browser UI" is replaced by the command line: the console prints every field of the license and the SHA-256 of the exact bytes to be signed, then asks for the PIN. A local web server would add attack surface and no information.
4. **Key creation is outside the program** (key ceremony, documented with `gpg --card-edit` or `ykman`): the program only reads the public key, checks it against the key set, and signs.
5. **Touch policy** is checked and reported (`signer info`), and signing is refused when a touch is not required for signatures unless `--allow-no-touch` is given (spec 4.4 requires touch).

## Review Focus

- A wrong PIN must not be retried; one try left must refuse; a blocked PIN must give a clear message; the retry counter is read before VERIFY. Pinned in Task 1.
- The public key on the card must equal the key-set key for the `--key-id`; a card with the wrong key, no signature key, or an algorithm other than Ed25519 is refused before any PIN prompt. Pinned in Task 2.
- The signature is verified (`ed25519.Verify` and the product's `license.Check`) before the file is returned; a card that returns garbage must not produce a recorded license. Pinned in Task 2.
- Cancelling while the card waits for a touch must return promptly and leave no hung connection. Pinned in Task 3 (interface level) and the owner checklist.
- The display shown before the PIN must contain every field that ends up in the signed payload, and the SHA-256 must be of the bytes the card receives. Pinned in Task 4.
- A build without the `yubikey` tag must refuse `--signer openpgp` with a clear message; the tagged and untagged builds both compile; the product binary links neither. Pinned in Task 3 and Task 5.

---

## File Structure

| Path | Responsibility |
|---|---|
| `internal/vconsole/sign/openpgp/card.go` | `Card` interface, APDU helpers, status words, GET RESPONSE and command chaining |
| `internal/vconsole/sign/openpgp/openpgp.go` | select, application data, PW status, public key, UIF, VERIFY, PSO:COMPUTE DIGITAL SIGNATURE |
| `internal/vconsole/sign/openpgp/openpgptest/sim.go` | software OpenPGP card (importable, tests only) |
| `internal/vconsole/sign/openpgp.go` | `OpenPGPSigner` implementing `sign.Signer` |
| `internal/vconsole/sign/pcsc/pcsc_yubikey.go` (tag `yubikey`), `pcsc_stub.go` (tag `!yubikey`) | PC/SC transport |
| `internal/vconsole/issue/issue.go` | `Params.Confirm` hook |
| `cmd/vendor-console/signer.go` | `--signer`, `signer info`, `signer test`, confirmation display |
| `Makefile` | `vendor-console-yubikey` target |
| `docs/vendor-console-operations.md`, spec | ceremony, smoke test, build notes |

---

### Task 1: OpenPGP card protocol over a `Card` interface, with a simulator

**Files:**
- Create: `internal/vconsole/sign/openpgp/card.go`, `openpgp.go`, `openpgptest/sim.go`
- Test: `internal/vconsole/sign/openpgp/openpgp_test.go`

**Interfaces:**
- Produces:

```go
// Card is one connected card. Transmit sends one command APDU and returns the full response
// including the two status bytes.
type Card interface {
	Transmit(ctx context.Context, apdu []byte) ([]byte, error)
	Close() error
}

type Applet struct { /* wraps a Card */ }
func Open(ctx context.Context, c Card) (*Applet, error) // SELECT AID D2760001240103 (prefix D27600012401 plus the version bytes not fixed: select with the 6-byte prefix then GET DATA 004F)

type Info struct {
	AID        []byte // full AID from DO 004F
	Serial     string // 8 hex digits from the AID bytes 10..13
	SigAlg     string // "ed25519", "other:<hex>" or "none"
	PW1Retries int    // from DO 00C4 byte 4 (PW1 tries left)
	PW1Blocked bool
	SigUIF     string // "off", "on", "fixed", "cached", "cached-fixed", "unsupported"
	SigCount   int    // from DO 0093 (signature counter)
}
func (a *Applet) Info(ctx context.Context) (Info, error)
func (a *Applet) PublicKey(ctx context.Context) (ed25519.PublicKey, error) // GENERATE ASYMMETRIC KEY PAIR with P1=0x81 and CRT B6 00 (read existing key), parse 7F49/86 or 7F49/86 with 32 bytes; ErrNoKey when the slot is empty
func (a *Applet) VerifyPIN(ctx context.Context, pin []byte) error      // VERIFY P2=0x81 (PW1 for signing); maps 63Cx, 6983, 6982
func (a *Applet) Sign(ctx context.Context, message []byte) ([]byte, error) // PSO:COMPUTE DIGITAL SIGNATURE 002A9E9A with command chaining for > 255 bytes; returns the 64-byte signature

var (
	ErrNoKey       = errors.New("openpgp: the card has no signature key")
	ErrWrongPIN    = errors.New("openpgp: wrong PIN") // wraps a typed error with TriesLeft
	ErrPINBlocked  = errors.New("openpgp: the PIN is blocked")
	ErrTouchNeeded = errors.New("openpgp: the card wants a touch that did not happen") // 6982 after a PSO with UIF on and no touch within the card's time
	ErrNotEd25519  = errors.New("openpgp: the signature key is not Ed25519")
)
type PINError struct{ TriesLeft int }
```

  Protocol facts to implement (OpenPGP card specification 3.4; the implementer must follow the spec, not guess): SELECT `00 A4 04 00 06 D2 76 00 01 24 01`; GET DATA `00 CA <tag high> <tag low> 00`; DO 006E application related data (contains 004F AID, 0073 discretionary DOs: 00C1 algorithm attributes of the signature key (first byte 0x16 = EdDSA, followed by the curve OID 2B 06 01 04 01 DA 47 0F 01 for Ed25519), 00C4 PW status bytes (byte 1 PW1 valid for several signatures, bytes 5..7 retry counters PW1, RC, PW3)), 0093 signature counter (3 bytes), and the YubiKey UIF object `00 D6` (2 bytes: first byte 00 off, 01 on, 02 fixed, 03 cached, 04 cached-fixed; a status word 6A88 means unsupported); public key: `00 47 81 00 00` with data field `B6 00`, response `7F49 ... 86 20 <32 bytes>` for EdDSA; VERIFY `00 20 00 81 <len> <PIN bytes>`, response 63Cx = x tries left, 6983 blocked, 6982 security status; PSO: `00 2A 9E 9A <Lc> <message> 00`; messages longer than 255 bytes use command chaining (`10 2A 9E 9A FF <255 bytes>` ... last `00 2A 9E 9A <rest> 00`), responses `61xx` are completed with `00 C0 00 00 xx`; `6C xx` retries with the correct Le. The simulator implements exactly this subset with a software Ed25519 key, PIN state (retry counter decrement, block at 0), UIF on/off with a hook that decides whether the "touch" happens, SELECT of the wrong applet, status words for malformed commands, and chaining/GET RESPONSE behavior with configurable response chunking (to test `61xx` handling).
- [ ] **Step 1: Write the failing tests** (`openpgp_test.go`, driving the simulator): `TestInfoReadsSerialAlgorithmRetriesAndUIF`; `TestPublicKeyIsTheSimulatorKey`; `TestEmptySlotGivesErrNoKey`; `TestNonEd25519SlotGivesErrNotEd25519` (simulator configured with an RSA attribute); `TestVerifyPINRightAndWrong` (wrong gives `*PINError` with TriesLeft 2, then 1, then blocked on the third, and a blocked PIN gives `ErrPINBlocked` without sending VERIFY again — the applet reads the counter first: assert the simulator saw no VERIFY when blocked); `TestVerifyPINDoesNotRetryAutomatically` (simulator counts VERIFY commands: exactly one per call); `TestSignProducesAValidSignature` (ed25519.Verify with the public key over the message); `TestSignLongMessageUsesChaining` (message of 700 bytes, the simulator records `10` class bytes on the first APDUs and the right total, signature valid); `TestSignWithResponseChunking` (simulator returns 61xx and the applet issues GET RESPONSE); `TestSignRefusedBeforeVerify` (6982 maps to a clear error and not ErrTouchNeeded when UIF is off); `TestTouchNotGivenGivesErrTouchNeeded` (UIF on, hook says no touch); `TestContextCancelStopsBeforeTransmit` (cancelled ctx returns ctx error and sends nothing); `TestPINIsZeroedAfterVerify` (the applet clears the slice it was given; assert the caller's buffer is zero) and `TestErrorsNeverContainThePIN` (distinctive PIN across all failure paths); `TestMalformedResponsesAreRejected` (short responses, missing status bytes, truncated TLV, oversize length fields, a 7F49 with a wrong inner length) — none may panic.
- [ ] **Step 2: Run to verify failure:** `go test ./internal/vconsole/sign/openpgp/...` → FAIL (does not build).
- [ ] **Step 3: Implement** `card.go`, `openpgp.go`, `openpgptest/sim.go`. TLV parsing is bounds-checked everywhere.
- [ ] **Step 4: Run to verify it passes:** `go test ./internal/vconsole/sign/openpgp/... -race -count=1`; `golangci-lint run ./internal/vconsole/sign/...`.
- [ ] **Step 5: Commit** (`feat(vconsole): OpenPGP card protocol for Ed25519 signing with a software card simulator`).

---

### Task 2: `OpenPGPSigner`

**Files:**
- Create: `internal/vconsole/sign/openpgp.go`
- Test: `internal/vconsole/sign/openpgp_test.go`

**Interfaces:**
- Consumes: Task 1 `openpgp.Applet`, `openpgptest` simulator; `issuer` (how a signed file is built: read `internal/license/issuer` to reuse `license.SignedBytes` and `license.EncodeFile` exactly as `SigningKey.Issue` does).
- Produces:

```go
type OpenPGPOptions struct {
	KeyID        string            // key ID written into licenses; must exist in Expected
	Expected     ed25519.PublicKey // public key from the key set for KeyID
	AskPIN       func(ctx context.Context, tries int) ([]byte, error)
	NotifyTouch  func()            // called right before the signature command when the card requires a touch
	LastPINTry   bool              // allow VERIFY when one try is left
	AllowNoTouch bool              // allow signing when touch is not required
}
func NewOpenPGPSigner(ctx context.Context, card openpgp.Card, o OpenPGPOptions) (*OpenPGPSigner, error)
// NewOpenPGPSigner opens the applet and checks, BEFORE any PIN prompt: Ed25519 signature key present, card public key == Expected (constant-time compare is not needed; use bytes.Equal), PW1 not blocked, retries > 1 (or LastPINTry), touch required (SigUIF on/fixed/cached/cached-fixed) unless AllowNoTouch.
func (s *OpenPGPSigner) KeyID() string
func (s *OpenPGPSigner) Public() ed25519.PublicKey
func (s *OpenPGPSigner) Issue(ctx context.Context, p license.Payload) ([]byte, error)
func (s *OpenPGPSigner) Close() error
// SignedBytes helper for the confirmation display:
func PayloadDigest(p license.Payload) (signed []byte, sha256hex string, err error)
```

  `Issue`: build the signed bytes with the product's function, ask the PIN (retries shown), VerifyPIN (a `PINError` is returned as is so the CLI can show tries left; the PIN is zeroed), call `NotifyTouch`, `Sign`, `ed25519.Verify` against `Expected`, build the file with the product's encoder, then check it with `sign.Verify(raw, s)`; any failure returns no file. A 2 minute limit is applied with `context.WithTimeout`; on cancel the card is closed to abort a pending touch wait.
- [ ] **Step 1: Write the failing tests** (simulator): `TestIssueProducesAFileTheProductAccepts` (run `license.Check` with a key set built from `Expected`); `TestWrongKeyOnCardIsRefusedBeforeThePINPrompt` (AskPIN must not be called); `TestNoSignatureKeyIsRefused`; `TestNonEd25519KeyIsRefused`; `TestBlockedPINIsRefusedBeforeThePINPrompt`; `TestOneTryLeftIsRefusedUnlessLastPINTry`; `TestNoTouchPolicyIsRefusedUnlessAllowed`; `TestWrongPINReturnsPINErrorWithTriesLeftAndGivesNoFile`; `TestNotifyTouchIsCalledOnceBeforeSigning` (order: AskPIN, VerifyPIN, NotifyTouch, Sign); `TestGarbageSignatureFromTheCardGivesNoFile` (simulator returns 64 random bytes: `ed25519.Verify` fails → error, no file); `TestSignatureFromAnotherKeyGivesNoFile`; `TestCancelDuringTouchWaitReturnsPromptly` (simulator blocks inside the PSO until the card is closed; cancel ctx; Issue returns within 1 s; the simulator saw Close); `TestTwoMinuteLimit` (injectable timeout, unexported field); `TestPayloadDigestMatchesTheBytesSentToTheCard` (the simulator records the message it signed; sha256 equals `PayloadDigest`).
- [ ] **Steps 2-5:** fail → implement → pass (`go test ./internal/vconsole/sign/... -race -count=1`; lint) → commit (`feat(vconsole): OpenPGP card signer with pre-flight key checks and verified output`).

---

### Task 3: PC/SC transport (build tag `yubikey`), build wiring, architecture rules

**Files:**
- Create: `internal/vconsole/sign/pcsc/pcsc_yubikey.go` (`//go:build yubikey`), `pcsc_stub.go` (`//go:build !yubikey`), `pcsc_test.go`
- Modify: `go.mod`/`go.sum` (add `github.com/ebfe/scard`), `Makefile`, `internal/archtest/arch_test.go`, `cmd/alice/license_release_test.go`

**Interfaces:**
- Produces (both build variants):

```go
var ErrNoPCSC = errors.New("pcsc: this build has no YubiKey support (build with -tags yubikey)")
// Readers lists the names of the connected PC/SC readers.
func Readers() ([]string, error)
// Connect opens the reader named exactly, or when name is "" the only reader whose name contains
// "yubi" (case-insensitive); more than one candidate is an error that lists the names.
func Connect(name string) (openpgp.Card, error)
```

  Tagged implementation with `scard`: `EstablishContext(scard.ScopeSystem)`, `Connect(reader, ShareExclusive? ShareShared, ProtocolAny)` — use `ShareShared` so gpg-agent/scdaemon is not locked out permanently but warn in the docs that scdaemon may hold the card (the runbook has `gpgconf --kill scdaemon`); `Transmit` implements `openpgp.Card.Transmit`: cancel through `ctx` calls `scard.Context.Cancel()` and closes the connection (the transmit runs in a goroutine; the function returns when either finishes; no goroutine leak after Close); errors map PC/SC codes to readable messages (no card, reader unavailable, sharing violation) without leaking anything sensitive. The stub returns `ErrNoPCSC` from `Readers` and `Connect`.
- Makefile: target `vendor-console-yubikey` runs `CGO_ENABLED=1 go build -trimpath -tags yubikey -o bin/vendor-console-yubikey ./cmd/vendor-console` (native; note in a comment that it must run on each OS) and the existing vendor-console target stays `CGO_ENABLED=0` without the tag.
- Architecture: `sign/pcsc` may import only `sign/openpgp` and the platform (and the third-party scard); `sign/openpgp` imports nothing from vconsole except none; `sign` may import `sign/openpgp`; `web`, `notify`, `mail`, `store`, `webuser` -> `sign/...` stay denied (web already denies sign; add `sign/pcsc` and `sign/openpgp` to its denied list); `cmd/alice` release test forbids `github.com/ebfe/scard` and the new packages; a test runs `go list -deps -tags yubikey ./cmd/alice` and asserts neither `ebfe/scard` nor `internal/vconsole` appears.
- [ ] **Step 1: Write the failing tests:** untagged `pcsc_test.go` (build tag `!yubikey`): `Connect("")` and `Readers()` return `ErrNoPCSC`; tagged test file (`//go:build yubikey`): `TestReadersWithoutPCSCDaemonGivesAReadableError` (when no daemon is running the call returns an error, not a panic; skip if a daemon is present and say so), `TestSelectionRules` through an unexported `pick(names []string, want string) (string, error)` function shared by both variants (so it is testable without hardware): exact name wins, "" with one yubikey reader wins, "" with two yubikey readers is an error listing both, "" with none is an error, matching is case-insensitive; arch test rows (allowed and denied) written first; the `go list -deps` release test.
- [ ] **Step 2: Run to verify failure:** `go test ./internal/vconsole/sign/pcsc/ ./internal/archtest/ ./cmd/alice/`; `go test -tags yubikey ./internal/vconsole/sign/pcsc/` (needs libpcsclite; installed here).
- [ ] **Step 3: Implement**; `go build -tags yubikey ./... && go build ./...` both pass; the tagged build links scard; `go vet -tags yubikey ./internal/vconsole/...`; lint with `--build-tags yubikey` too.
- [ ] **Step 4: Run to verify it passes** (the commands above) and `CGO_ENABLED=0 go build ./cmd/vendor-console` still works without the tag.
- [ ] **Step 5: Commit** (`feat(vconsole): PC/SC transport behind the yubikey build tag and architecture rules`).

---

### Task 4: Command line: `--signer openpgp`, confirmation display, `signer info`, `signer test`

**Files:**
- Create: `cmd/vendor-console/signer.go`
- Modify: `cmd/vendor-console/run.go` (usage, `issue` flags), `internal/vconsole/issue/issue.go` (add `Params.Confirm`)
- Test: `cmd/vendor-console/signer_test.go`, `cmd/vendor-console/signer_integration_test.go`, `internal/vconsole/issue/issue_integration_test.go` (append)

**Interfaces:**
- `issue.Params.Confirm func(p license.Payload, signedSHA256 string) error` — called inside `Issue` after the payload is built and the correction rules passed, BEFORE `s.Issue` (so before any PIN prompt); a non-nil error aborts the issue with that error wrapped (`ErrNotConfirmed` sentinel when the operator answers no). nil Confirm = old behavior.
- `vendor-console issue --signer file|openpgp` (default `file`, existing flags unchanged; `--key FILE` required only for `file`); for `openpgp`: `--key-id ID` (required), `--pub FILE` (the public key file for that key ID, same format `licensectl keyset --pub` reads; or `--keyset FILE` plus the key ID), `--reader NAME`, `--last-pin-try`, `--allow-no-touch`, `--yes` (skips the question, still prints the display). Without the `yubikey` tag `--signer openpgp` exits 2 with `ErrNoPCSC`'s text before connecting to the database.
- Display (stderr, before the PIN): customer, installation ID (the full ID: the signer must check it against what the customer sent; this is the only place besides `request show`), targets, valid from, valid until, months, features, replaces, license ID, key ID and the card serial, then `SHA-256 of the signed bytes: <hex>` and the question `Sign this license? [y/N]` (reads one line; anything but `y`/`yes` aborts; `--yes` skips). Then the PIN prompt with `tries left`, then `Touch the YubiKey now...` right before the card signs.
- `vendor-console signer info [--reader NAME] [--pub FILE --key-id ID]`: prints reader, card serial, signature algorithm, PIN tries left, touch policy, signature counter, the public key as base64, its SHA-256 fingerprint (same fingerprint form `licensectl keyset` prints: reuse the product function) and, when `--pub`/`--key-id` are given, `matches key set: yes|NO`. No PIN is needed.
- `vendor-console signer test --pub FILE --key-id ID [--reader NAME]`: asks the PIN and a touch, signs the fixed text `alice-vendor-console smoke test: not a license`, verifies with ed25519, prints `smoke test OK`. The text is shown first with the warning that the key signs nothing but licenses and this text is not a license.
- [ ] **Step 1: Write the failing tests:** issue package: `TestConfirmIsCalledBeforeSigningAndCanAbort` (the signer must not be called when Confirm returns an error; the request stays open), `TestConfirmSeesTheExactSignedBytesDigest`; cmd unit tests with the simulator injected through an unexported package variable `openCard func(reader string) (openpgp.Card, error)` set by tests (default: the pcsc package): `TestIssueOpenPGPShowsEveryFieldBeforeThePINPrompt` (capture stderr in order: display, question, PIN prompt, touch notice — order asserted), `TestAnswerNoAbortsWithoutPINPrompt`, `TestYesFlagSkipsTheQuestionButStillPrints`, `TestWrongPINShowsTriesLeftAndExits1`, `TestWrongKeyOnCardExitsBeforeThePINPrompt`, `TestPINNeverAppearsInOutput`, `TestOpenPGPNeedsKeyIDAndPub` (exit 2), `TestNoYubikeyTagGivesTheBuildMessage` (build-tag-free: uses the stub's behavior through a variable, or a `//go:build !yubikey` test), `TestSignerInfoPrintsFingerprintAndMatch`, `TestSignerTestSignsOnlyTheFixedText` (the simulator records the message; equals the constant; the text could never parse as a license: assert `license.ParseFile` fails on it); integration (tag `integration`, simulator + real database): `TestIssueWithTheSimulatedCardRecordsALicenseThatVerifiesAgainstTheKeySet` and the same through `license export` then `verify-licenses --pub`.
- [ ] **Steps 2-5:** fail → implement → pass (`go test ./cmd/vendor-console/ ./internal/vconsole/issue/ && go test -tags integration ./cmd/vendor-console/ ./internal/vconsole/issue/ -race -count=1 && go test -tags yubikey ./cmd/vendor-console/`) → commit (`feat(vconsole): issue with an OpenPGP card, confirmation display, signer info and smoke test`).

---

### Task 5: Documents, owner checklist, spec, final checks

**Files:**
- Modify: `docs/vendor-console-operations.md`, `docs/vendor-console.md`, `docs/vendor/licensing-vendor.md` (one note), design spec, `internal/archtest/arch_test.go` (only if a rule is missing)

- [ ] **Step 1: Documents.**
  - Runbook section 2 (key ceremony) is rewritten for OpenPGP: prerequisites (`ykman info`: firmware 5.2.3 or later and OpenPGP enabled), steps with commands marked **not run by the author, check against your installed versions on first use**: (1) `ykman info`, `ykman openpgp info`; (2) change Admin PIN and PIN from the defaults (`ykman openpgp access change-pin`, `change-admin-pin`) and set the Reset Code decision; (3) set touch policy for signatures (`ykman openpgp keys set-touch sig on` or the `cached`/`fixed` choice, with the trade-off, and that `fixed` cannot be changed back); (4) generate the Ed25519 signing key ON the card (`gpg --card-edit`, `admin`, `key-attr` choose ECC with curve25519 for the signature key, `generate` and say no to the off-card backup), and the alternative `ykman openpgp keys` if the installed ykman supports generation; (5) record the public key (`vendor-console signer info`, then `licensectl keyset --pub` equivalent for the console: describe how to turn the public key into the key-set entry — check what `licensectl keyset` needs (a public key file) and explain exactly how to write the public key to that file format from `signer info --out FILE` if you add that flag: add `--out FILE` to `signer info` writing the public key in the format `licensectl keyset --pub` reads, with a test); (6) add it to `internal/license/keys/production.json` (owner key, IT manager key, spare), release, embed; (7) store spares apart; (8) smoke test (`signer test`). Add the `gpgconf --kill scdaemon` hint for "card busy" errors, the Linux `pcscd` requirement, and the statement that the two YubiKeys of the two signers each get their own key ID.
  - The signing section (option 1 offline `licensectl` versus option 2 file key on an online machine) gets a third option, **option 3: the YubiKey** (preferred, once the owner has run the smoke test on each platform), and the "owner picks and dates the decision" line is updated.
  - **Owner hardware checklist** (new section "Smoke test on real hardware", owner-pending): per OS (Linux, Windows, macOS): build or obtain the binary (`make vendor-console-yubikey` natively on that OS; Linux needs `libpcsclite-dev` and `pcscd` running; macOS needs nothing; Windows needs the Smart Card service), run `vendor-console signer info`, then `signer test`, then one real `issue` against a throwaway database and `verify-licenses`; expected output of each step; what each error means (no reader, card busy, wrong PIN with tries left, touch timeout, wrong key); what to do if a step fails and how to report it (the `signer info` output without any PIN); record the firmware, OS and result in a table.
  - `docs/vendor-console.md`: the `issue` section gets `--signer openpgp` and its flags, the build tag, the new commands.
  - `docs/vendor/licensing-vendor.md`: one note pointing at the runbook for the YubiKey.
  - Spec: Phase 2 marked built in code with hardware verification pending (owner checklist), O1/O3 resolved by rulings 1 and 2, section 4.1 (OpenPGP only, PIV not built), "local browser UI" replaced by the command line display (ruling 3), section 4.4 matches the runbook, phase table updated (all five phases built, hardware smoke test owner-pending).
- [ ] **Step 2: Architecture/build checks:** `go build ./... && go build -tags yubikey ./...`; `CGO_ENABLED=0 go build ./cmd/alice ./cmd/vendor-console ./cmd/vendor-web`; `go list -deps -tags yubikey ./cmd/alice | grep -E 'ebfe/scard|vconsole'` prints nothing.
- [ ] **Step 3: Final verification:** `gofmt -l cmd internal` (empty); `go vet ./... && go vet -tags yubikey ./cmd/vendor-console/ ./internal/vconsole/...`; `golangci-lint run ./cmd/... ./internal/vconsole/... ./internal/archtest/...` and again with `--build-tags yubikey` (0 issues); `go test ./... -count=1`; `go test -tags yubikey ./cmd/vendor-console/ ./internal/vconsole/sign/...`; `go test -tags integration ./internal/vconsole/... ./cmd/vendor-console/... -count=1`.
- [ ] **Step 4: Commit** (`docs(vconsole): YubiKey ceremony, hardware smoke-test checklist and spec update`), then the final whole-branch review and fast-forward `master`.

---

## Self-Review

- **Spec coverage:** signer implementation (Tasks 1-2), PIN and touch flow (Tasks 2 and 4), what-you-see-is-what-you-sign display and hash (Task 4), cross-platform build and smoke test (Task 3 build wiring, Task 5 checklist; hardware run is owner-pending), key setup checklist (Task 5, spec 4.4), O1 and O3 closed by rulings.
- **Placeholders:** none. Where hardware is needed the work is explicitly marked owner-pending, not stubbed.
- **Types:** `openpgp.Card`, `Applet`, `Info`, `PINError`, `OpenPGPSigner`, `OpenPGPOptions`, `PayloadDigest`, `pcsc.Connect/Readers/pick`, `issue.Params.Confirm`, `ErrNotConfirmed` are defined before use.
- **Review Focus** lines each map to a named test.
