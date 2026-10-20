# Rulings: vendor emergency extension

Owner decision 2026-10-20: when a customer's license lapses, the vendor issues a short, offline-signed
license for the same installation, valid from now for a short period (default 14 days, at most 30),
carrying over customer, installation_id, max_targets and features from the installation's latest
license. Operator text: `docs/vendor-console.md`, "Emergency extensions".

## Rulings

1. **No change to the signed payload or to Alice.** The extension is an ordinary license
   (`license.FormatVersion`, no new field, no `replaces`). `internal/license/file.go` rejects unknown
   fields and deployed Alices must accept it, and nothing in Alice needs to tell it apart:
   `Evaluate` already puts the newest started license in force. The label lives on the vendor
   side only. Pinned by `internal/license/emergency_test.go` (pure `Evaluate`) and
   `emergency_integration_test.go` (upload path: locked → extension → active → grace → lock from
   the extension's end → renewal signed before the extension still accepted).
2. **A request kind, not a hand-filled request.** Migration `00005_emergency.sql` adds
   `license_requests.kind` (`license` | `emergency`), `days` (1–30), `reason` (required, ≤ 200,
   one line) and `extends` (the carried-over license). An emergency row has `months` NULL, no
   `valid_from`, no `replaces`; a table CHECK holds the shape for every client. Normal rows are
   unchanged (kind `license`, `months` NOT NULL by the same CHECK).
3. **Carried over by the server, never by the browser.** `store.AddEmergencyRequest` takes only a
   license ID, days and reason; it resolves the installation and reads its latest non-revoked
   license (latest `valid_until`, then `issued_at`) and that license's request for targets and
   features. Opening the form from an older license of the installation carries over the latest
   one; a revoked or unknown ID is 404.
4. **Term: from 00:00 UTC of the signing day for `days` days** (`issuer.Request.Days`, exclusive
   with Months/From/Replaces). Start of day rather than the signing second: a customer clock a few
   minutes behind would otherwise see the extension as pending while locked; it is also how every
   other license of the console starts. The cost: an extension signed late in the day gives up to
   one day less than its number; the term never exceeds 30 days. The start is fixed at signing,
   not at request time, so a request signed a day later still starts "now".
5. **Signing path unchanged.** The request is signed by `vendor-console issue` (file key or
   YubiKey, PIN, touch, confirmation, request hash) like any other. The request hash covers kind,
   days, reason and extended license for an extension; a normal request hashes exactly as before
   (pinned by `TestRequestHashCoversTheEmergencyFields`). The YubiKey confirmation says "this
   EMERGENCY EXTENSION" and shows `days` instead of `months`; `request show`/`list` label it.
6. **Who may ask.** Anyone who may make a request (sales, signer, owner; web or CLI database
   login). No new role and no second approval: the signer's review is the approval, as for every
   license.
7. **Refused when it would not help.** At request time and again at signing time: refused if a
   non-revoked license of the installation that is valid on the start day ends on or after the
   extension's end (`store.ErrExtensionNotNeeded`): the extension adds nothing and, as the later
   start, would hide that license in Alice. At signing time also refused if the carried-over
   license was revoked meanwhile (`issue.ErrExtendedRevoked`). An extension issued shortly before
   the lapse is allowed (it ends later than the running license). Extensions may be chained; each
   one is a separate, audited request with a reason.
8. **Audit and history.** `request.add` of an extension carries `kind: "emergency"`, `days`,
   `reason` (cleaned to one line) and `extends`; `license.issue` carries `kind` and `days`. The
   action names are unchanged so existing filters (`--action request.add`, `license.`) and the
   weekly summary's "licenses without issue audit" check keep working. The owner's notification
   reads "Emergency extension issued: <customer> (<id>)" with term and reason. The license list,
   the request page and the open requests on the home page show an "Emergency extension" badge.
9. **The real renewal afterwards.** Alice picks, among started licenses that are still valid, the
   latest `valid_from`. Therefore:
   - Renew from the extension's row (the default Renew prefill): starts where the extension ends;
     pending until then, then in force with no gap and no grace.
   - Starting on the day it is signed (or any day from the extension's start on): in force at once
     (later start; same start → later upload).
   - Backdated to the original lapse: must name the extension in Replaces; it then supersedes the
     extension at once. Without that, Alice would keep the extension in force (with its targets and
     "ends in N days" warnings) until it ends, then switch silently. The console refuses that shape
     at request and signing time (`store.ErrStartsBeforeExtension`, message says what to do).
   - A renewal signed before the extension and uploaded after it is accepted by Alice's
     older-license rule because it ends later.
10. **Reminders.** The extension is a later license for the installation, so the lapsed license's
    reminders stop; the extension gets its own 30-day reminder at once, whose Renew path is the
    recommended renewal.
11. **Languages.** vendor-web is English-only today (`lang="en"`, no translation layer, every
    template in English). The new texts are English to match; adding a Turkish layer for one page
    would make the UI inconsistent. When vendor-web gets i18n, these are the Turkish texts:

    | English | Turkish |
    | --- | --- |
    | Emergency extension | Acil uzatma |
    | A short license so a lapsed installation keeps working until its renewal arrives. A signer issues it like any request. | Süresi dolan bir kurulumun yenileme gelene kadar çalışmaya devam etmesi için kısa süreli lisans. İmzacı bunu her talep gibi düzenler. |
    | Term and reason | Süre ve gerekçe |
    | Days (1 to 30) | Gün (1–30) |
    | 14 unless there is a reason for more. | Daha uzun süre için bir gerekçe yoksa 14. |
    | Reason | Gerekçe |
    | Recorded in the audit log and shown to the signer and the owner. | Denetim kaydına yazılır; imzacıya ve sahibe gösterilir. |
    | Carried over from | Aktarıldığı lisans |
    | Request the extension | Uzatmayı talep et |
    | The extension is valid from the start of the day it is signed (00:00 UTC) for the days below, at most 30. … cannot be changed here. For anything else, make a normal request. | Uzatma, imzalandığı günün başından (00:00 UTC) itibaren aşağıdaki gün sayısı kadar, en fazla 30 gün geçerlidir. … burada değiştirilemez. Başka bir şey için normal bir talep oluşturun. |
    | Emergency extension issued | Acil uzatma düzenlendi |

## Open (owner)

- Chaining is unlimited (ruling 7). If the owner wants a cap (e.g. one extension per lapse, or a
  total of 30 days per installation), it is one query in `AddEmergencyRequest` and `checkExtension`.
- The vendor-console CLI has no `request emergency` command; extensions are asked for on the web
  (or by SQL as a database login). Add one if signers want to ask for and sign one alone.
