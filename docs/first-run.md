# First Run: the Setup Wizard

This guide walks you through the Alice setup wizard. Allow 15 minutes.

## Before you begin

Have these ready:

- [ ] **A phone with an authenticator app** (Microsoft Authenticator, Google Authenticator or any app that supports
      "time-based codes").
- [ ] **A place to store 10 recovery codes** (a password manager or a printed sheet in a safe).
- [ ] **A recovery passphrase** of at least 16 characters that the strength meter rates **Good** or **Strong**
      (several unrelated words work well), written on paper and stored somewhere safe, away from the server. It
      protects your backups: if you lose it, nobody (including the vendor) can open them, and it cannot be changed
      later in this version ([backup-restore.md](backup-restore.md#the-recovery-passphrase)).
- [ ] **Your HTTPS certificate** for Alice's DNS name, with its private key: a certificate file (PEM, followed by the
      intermediate certificates) and an unencrypted key file (PEM), or one PFX file with its password. Without it you
      can keep Alice's temporary certificate for now; browsers then warn until you upload yours.
- [ ] **Your mail server details** (optional): server name and port, encryption (STARTTLS or TLS), the sender
      address, and a user name and password if the server needs them. Without them Alice sends no e-mail; you can add
      them later.
- [ ] **A license** (optional): send the Installation ID, which the wizard shows on its license step, to your vendor
      to get a license file; or start the 30-day evaluation and add the license later on the **License** page
      ([licensing.md](licensing.md)).
- [ ] **The one-time setup code.** The installer printed it. To make a new one, run
      `sudo /opt/alice/alicectl setup-token --reset` on the server (development: `make setup-token`). The code looks
      like `K7QX2M-9TPD4R-WB5H8N-3VZC6A`, stops working as soon as the administrator exists, and creating a new code
      makes the previous one invalid.

## Steps

1. Open `https://<server-address>/setup` in your browser. Accept the temporary certificate warning. Alice shows
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
7. Type the recovery passphrase twice. The meter shows **Too short**, **Fair**, **Good** or **Strong**; Alice accepts
   only **Good** or **Strong** (a **Fair** one shows "This passphrase is too easy to guess. …" and is refused with
   `ALC-SET-0010`). Tick **I stored the passphrase safely** and choose **Save passphrase**.
   If more than five minutes passed since you last typed a code, Alice first asks for a new 6-digit code
   (**Confirm it's you**).
   Expected: **HTTPS certificate**.
8. Install your certificate: under **Upload certificate** choose the **File format** (**PEM: a certificate file and a
   key file** or **PFX (PKCS#12): one file with a password**), choose the files (and the PFX password), then
   **Upload certificate**. Expected: **The new certificate is in use.**, possibly with points to check (for example
   that the names do not match this server's address); see [admin-guide.md](admin-guide.md#https-certificate). Or
   choose **Keep the temporary certificate** to do it later in **Settings → HTTPS certificate**. Then choose
   **Continue**.
   Expected: **Mail server (optional)**.
9. Enter the mail server details and choose **Save mail settings**, then **Send test e-mail** to check them
   ([admin-guide.md](admin-guide.md#mail-server)), and choose **Continue**. Or choose **Skip** to set up the mail
   server later in **Settings → Email**. **Continue** with unsaved details says "Save the mail settings first, or
   choose Skip."
   Expected: **Add a license**, with your Installation ID.
10. Either upload the license file from your vendor (**Check the file**, then **Install license**), or choose
    **Start 30-day evaluation (up to 5 targets)**. The evaluation has been running since Alice was installed.
    Expected: **Connect your servers**.
11. **Connect your servers** shows Alice's public key and the commands that prepare a server
    ([nginx-host-preparation.md](nginx-host-preparation.md)). Choose **Add a server now** to add one at once, or
    **Continue** to do it later on the **Servers** page.
    Expected: **Alice is ready**.
12. Choose **Go to the dashboard**. Here too, Alice may ask for a new 6-digit code if more than five minutes
    passed.
    Expected: the **Dashboard**, headed **Welcome, <your name>**, with a blue evaluation banner if you started the
    evaluation, and **Finish setting up** listing what you skipped.

**Back** is on every step from **HTTPS certificate** on. It shows the step before as it is now (for example the
certificate in use, or **You chose to keep the temporary certificate. …**), where you can still change it. The
recovery passphrase cannot be changed: going back to it only shows **The recovery passphrase is set. It cannot be
changed here.**

If you close the browser after step 6, sign in normally (password, then the code from your app). The wizard resumes
at the first step that is not finished. Until then Alice shows a red banner **Finish setting up: choose a recovery
passphrase.** until you complete step 7, **Finish setting up: add a license or start the evaluation.** until you
complete step 10, and **Finish setting up: open the setup wizard to confirm the last step.** until you complete step
12. The banner links back to the wizard.

## After the wizard

The **Dashboard** lists what is still open under **Finish setting up** (the recovery passphrase and your HTTPS
certificate are marked **Required**). Everything else is in **Settings** (administrators only), see
[admin-guide.md](admin-guide.md).

- **Settings → Email**, if you skipped the mail step: the mail server, then **Send test e-mail**. Without it Alice
  sends no e-mail at all (expiry alerts, failed backups, license warnings, sign-in blocks, deployment and rotation
  e-mails), and scheduled SSH key rotations never start.
- **Settings → HTTPS certificate**, if you kept the temporary certificate.
- **Settings → Backups**: the first daily backup runs at 02:30 (server time zone); choose **Back up now** for a first
  backup at once, and set up a copy to another machine ([backup-restore.md](backup-restore.md#copy-backups-off-the-server)).
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
