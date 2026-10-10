# First Run: the Setup Wizard

This guide walks you through the Alice setup wizard. Allow 10 minutes.

## Before you begin

- A phone with an authenticator app (Microsoft Authenticator, Google Authenticator or any app that supports
  "time-based codes").
- A place to store 10 recovery codes (a password manager or a printed sheet in a safe).
- A recovery passphrase of at least 16 characters, written on paper and stored somewhere safe. It protects your
  backups. If you lose it, nobody (including the vendor) can open your backups.
- The one-time setup code. On a development installation, run `make setup-token`. On a server installation,
  run `sudo docker compose exec alice /usr/local/bin/alice setup-token --reset` in the Alice directory. The code
  looks like `K7QX2M-9TPD4R-WB5H8N-3VZC6A` and stops working as soon as the administrator exists. Creating a new
  code makes the previous one invalid.
- Optional: a license file from your vendor. Without one, start the 30-day evaluation and add the license later on
  the **License** page ([licensing.md](licensing.md)).

## Steps

1. Open `https://<server-address>` in your browser. Accept the temporary certificate warning. Alice shows
   **Set up Alice**.
   Expected: **Enter the setup code**, with a **Setup code** field.
2. Type the setup code and choose **Continue**. After five wrong codes from one computer, the wizard waits
   15 minutes before it accepts new attempts.
   Expected: **Choose your language**.
3. Choose English or Türkçe and choose **Continue**. This is the default language for everyone; each person can
   change it later.
   Expected: **Create the administrator account**.
4. Enter a username, your full name, an optional email address and a password of at least 12 characters (twice).
   Alice refuses common passwords from a list of 100,000 leaked passwords and tells you why. Choose **Continue**.
   Expected: **Set up your authenticator app** with a QR code.
5. Scan the QR code with your authenticator app (or type the key shown below it), then type the
   **6-digit code** from the app and choose **Verify**.
   Expected: **Save your recovery codes**.
6. Save the 10 recovery codes (**Copy codes** or **Download codes**). Each code signs you in once if you lose your
   phone. Tick **I saved these codes in a safe place** and choose **Continue**. You are now signed in as the
   administrator, and the setup code no longer works.
   Expected: **Choose a recovery passphrase**.
7. Type the recovery passphrase twice, tick **I stored the passphrase safely** and choose **Save passphrase**.
   If more than five minutes passed since you last typed a code, Alice first asks for a new 6-digit code
   (**Confirm it's you**).
   Expected: **Add a license**, with your Installation ID.
8. Either upload the license file from your vendor (**Check the file**, then **Install license**), or choose
   **Start 30-day evaluation (up to 5 targets)**. The evaluation has been running since Alice was installed.
   Expected: **Connect your servers**.
9. **Connect your servers** shows Alice's public key and the commands that prepare a server
   ([nginx-host-preparation.md](nginx-host-preparation.md)). Choose **Add a server now** to add one at once, or
   **Continue** to do it later on the **Servers** page.
   Expected: **Alice is ready**.
10. Choose **Go to the dashboard**. Here too, Alice may ask for a new 6-digit code if more than five minutes
    passed.
    Expected: the **Dashboard**, headed **Welcome, <your name>**, with a blue evaluation banner if you started the
    evaluation.

If you close the browser after step 6, sign in normally (password, then the code from your app). Alice shows a
red banner **Finish setting up: choose a recovery passphrase.** until you complete step 7,
**Finish setting up: add a license or start the evaluation.** until you complete step 8, and
**Finish setting up: open the setup wizard to confirm the last step.** until you complete step 10. The banner
links back to the wizard.

## After the wizard

The wizard does not set up e-mail or single sign-on: both are in **Settings** (administrators only), see
[admin-guide.md](admin-guide.md).

- **Settings → Email**: the mail server, then **Send test e-mail**. Without it Alice sends no e-mail at all (expiry
  alerts, license warnings, sign-in blocks, deployment and rotation e-mails), and scheduled SSH key rotations never
  start.
- **Settings → Recipients** and **Settings → Alerts**: who gets the e-mails (by default every administrator with an
  e-mail address) and how many days before an expiry.
- **Settings → General**: **Alice's address** (the `https://` address people open), needed for single sign-on and for
  the link in e-mails.
- **Settings → Single sign-on**: identity providers and group mappings. Keep the administrator you just created: it
  is the break-glass account that signs in with password and authenticator code when the identity provider is down.

An installation upgraded from a version that read the mail settings from `ALICE_SMTP_*` takes them over once at its
first start ([operator-guide.md](operator-guide.md#email)).

## If something goes wrong

Every error message shows a code such as `ALC-SET-0001`. Look it up in [troubleshooting.md](troubleshooting.md).
