# Azure Key Vault setup

This guide is for the Azure administrator who gives Alice access to a Key Vault. It covers the identity Alice
signs in with, the roles it needs for each feature, the network path, and adding the vault in Alice. How to use the
vault in Alice afterwards is in [operator-guide.md](operator-guide.md#key-vaults); the error codes are in
[troubleshooting.md](troubleshooting.md#key-vault).

**What has been checked.** The `az` and `openssl` commands below follow the Azure CLI and OpenSSL documentation.
Alice's own behaviour was tested against a fake Key Vault service built into its test suite, not against a real
Azure subscription. Where a statement depends on what real Azure does, this guide says so. The project's list of
unconfirmed Azure behaviour is "Not verified against Azure" in
[security/reviews/phase-5.md](security/reviews/phase-5.md).

## What Alice does with the vault

- **Monitor** (every vault): Alice lists the vault's certificates, keys and secrets and reads each certificate's
  details (expiry, versions, thumbprints, whether its private key is exportable). It never reads the value of a
  secret that is not a certificate's.
- **Deploy to Nginx** (optional): to put a vault certificate on a website, Alice reads that certificate's secret
  (the certificate with its private key) of one exact version, right before it changes the server, and keeps it in
  memory only.
- **Import** (optional): an administrator can copy a certificate that Alice holds with its key into the vault.

Alice never changes roles, policies, networking or certificates in Azure, except the import an administrator asks
for.

## 1. The identity Alice signs in with

Alice signs in in one of three ways. Choose one per vault.

| Sign-in method in Alice | What you create in Azure | What Alice stores |
|---|---|---|
| **Certificate (recommended)** | An app registration with a certificate | The certificate and its private key, encrypted |
| **Client secret** | An app registration with a client secret | The secret, encrypted, and its expiry date as you type it |
| **Managed identity** | Nothing extra: the identity of the Azure virtual machine Alice runs on | Nothing secret |

Alice signs in only to the public Azure cloud (`login.microsoftonline.com`). Sovereign clouds (Azure Government,
Azure China) and Managed HSM are not supported in this release.

### Create the app registration

Run these with the Azure CLI, signed in to the tenant of the vault (`az login`):

```
az ad app create --display-name alice-keyvault --query appId --output tsv
az ad sp create --id <client-id>
az account show --query tenantId --output tsv
```

The first command prints the **application (client) ID** (`<client-id>` below); the last one prints the
**directory (tenant) ID**. Alice needs both. In the Azure portal they are on the app registration's **Overview**
page. Alice accepts them only as GUIDs (a tenant domain name such as `contoso.onmicrosoft.com` is refused).

### Option A: a certificate (recommended)

A certificate's private key never leaves the Alice server when it signs in; a client secret is sent to Azure at
every sign-in. Create a key pair and a self-signed certificate on a trusted machine, and upload only the public
part to Azure:

```
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes -subj "/CN=alice-keyvault" -keyout alice-keyvault.key -out alice-keyvault.crt
az ad app credential reset --id <client-id> --cert @alice-keyvault.crt --append
```

The key must be RSA with at least 2048 bits (`ALC-AKV-0027` otherwise). In Alice choose **Certificate
(recommended)** and give either **PEM text** (the content of `alice-keyvault.crt` as **Certificate (PEM)** and of
`alice-keyvault.key` as **Private key (PEM)**) or a **PFX file** with its password. Delete the key file from the
machine where you created it once Alice has it. The vault page shows the certificate's thumbprint and expiry date.

### Option B: a client secret

```
az ad app credential reset --id <client-id> --append --display-name alice --years 1 --query password --output tsv
```

The command prints the secret's **value** once (in the portal: **Certificates & secrets**, **New client secret**,
then copy the **Value**, not the **Secret ID**). In Alice choose **Client secret**, paste the value into **Secret
value** and type the secret's end date into **The secret expires on**: Alice cannot read that date from Azure, and
it is the date the vault page warns about.

### Replacing the certificate or secret before it expires

From 30 days before the date, the vault's page says "The sign-in credentials expire within 30 days." Create a new
certificate or secret in Azure (with `--append`, so the old one keeps working meanwhile), then choose **Replace
credentials** on the vault's page in Alice. Alice checks the new credentials as when the vault was added and keeps
the old ones if the check fails. Remove the old certificate or secret in Azure afterwards. This release sends no
email before the date; when a secret has expired the vault shows **Credentials expired** (`ALC-AKV-0002`).

### Option C: managed identity (Azure virtual machines only)

Alice can use the managed identity of the **Azure virtual machine** it runs on. It asks for a token only at the
machine's own instance metadata address (`http://169.254.169.254`, port 80, from the Alice container). App Service,
Container Apps, Azure Arc and other hosts that provide an identity through another endpoint are not supported: the
vault then shows `ALC-AKV-0010`.

- **System-assigned identity:**

  ```
  az vm identity assign --resource-group <resource-group> --name <vm-name>
  ```

  It prints the identity's principal (object) ID. Assign the roles below with that ID in place of `<client-id>`
  (`--assignee` accepts either). In Alice choose **Managed identity** and leave **Application (client) ID
  (optional)** empty.
- **User-assigned identity:** create it (`az identity create --resource-group <resource-group> --name
  alice-keyvault`), attach it to the virtual machine (`az vm identity assign --resource-group <resource-group>
  --name <vm-name> --identities <identity resource ID>`), assign the roles with its client ID, and enter that
  client ID in Alice.

A managed-identity vault takes no tenant ID in Alice.

## 2. Roles

Each feature needs the roles of its row and of the rows above it. Assign them on the vault (or, for **Key Vault
Secrets User**, preferably on each certificate's secret, which has the certificate's name). Alice shows the same
table, with the commands filled in, under **Roles Alice needs** when you add a vault and on the vault's page.

| Feature | Role | Notes |
|---|---|---|
| Monitor certificates, keys and secrets | `Key Vault Reader` | Expected to be enough; not yet confirmed on a real vault. |
| Deploy certificates to Nginx | + `Key Vault Secrets User` | Lets Alice read a certificate's private key. Scope it to the secrets of the certificates you deploy. |
| Import certificates into the vault | + `Key Vault Certificates Officer` | Only needed if administrators import certificates from Alice. |

The commands, exactly as Alice shows them (`<client-id>` is the application's client ID, or the managed identity's
ID; `<vault-name>` is the vault's name; `<certificate-name>` is the name of the certificate in the vault):

Monitor:

```
az role assignment create --role "Key Vault Reader" --assignee <client-id> --scope "$(az keyvault show --name <vault-name> --query id --output tsv)"
```

Deploy to Nginx, for one certificate (run it once per certificate):

```
az role assignment create --role "Key Vault Secrets User" --assignee <client-id> --scope "$(az keyvault show --name <vault-name> --query id --output tsv)/secrets/<certificate-name>"
```

Import:

```
az role assignment create --role "Key Vault Certificates Officer" --assignee <client-id> --scope "$(az keyvault show --name <vault-name> --query id --output tsv)"
```

Role assignments can take a few minutes to apply. Then choose **Check again** under **Access check** on the vault's
page in Alice.

**Why "expected".** Whether `Key Vault Reader` alone may list certificates, keys and secrets and read a
certificate's details on every vault (and read a key's public part) has not been confirmed on a real vault by the
project yet. If the access check shows **Not allowed** for monitoring with only this role, the vault needs a
broader read role; the access check tells.

### Vaults that use access policies

A vault whose **Permission model** is **Vault access policy** ignores the roles above. Check the model with
`az keyvault show --name <vault-name> --query properties.enableRbacAuthorization` (`true`: Azure roles; `false`:
access policies) and run instead the command of the feature you need (each includes the permissions of the one
before):

Monitor:

```
az keyvault set-policy --name <vault-name> --spn <client-id> --certificate-permissions get list --key-permissions list --secret-permissions list
```

Deploy to Nginx (access policies cannot be limited to one secret):

```
az keyvault set-policy --name <vault-name> --spn <client-id> --certificate-permissions get list --key-permissions list --secret-permissions get list
```

Import:

```
az keyvault set-policy --name <vault-name> --spn <client-id> --certificate-permissions get list import --key-permissions list --secret-permissions get list
```

For a managed identity use `--object-id <principal ID>` in place of `--spn <client-id>`.

### Certificates Alice can deploy

- The certificate's private key must be **exportable** (in its issuance policy). Alice marks a certificate whose key
  is not exportable **Monitor only** and never deploys it. After you turn **Exportable private key** on, create a new
  version of the certificate.
- The certificate's content type may be PFX or PEM.
- Alice deploys only RSA and ECDSA certificates, to websites whose key type matches.
- The secret should hold the intermediate certificates. A version whose chain Alice finds incomplete is never
  deployed automatically, and an Alice administrator has to confirm the chain for each manual deployment.

## 3. Network

Alice connects only to these, directly (outbound TCP 443, TLS):

- `login.microsoftonline.com` (sign-in; not needed for a managed identity, which uses
  `169.254.169.254` port 80 instead);
- `<vault-name>.vault.azure.net`.

It follows no redirect and no link to any other host. Allow both in your outbound firewall.

- **No HTTP proxy.** This release connects to Azure without a proxy: the proxy variables of the environment
  (`HTTPS_PROXY` and similar) are ignored, and Alice trusts only the operating system's public certificate
  authorities. A proxy that inspects TLS makes the vault show `ALC-AKV-0012`. Proxy settings arrive in a later
  release.
- **Vault firewall.** If the vault allows only selected networks, add the public address Alice connects from:

  ```
  az keyvault network-rule add --name <vault-name> --ip-address <alice-public-address>/32
  ```

  When the firewall refuses Alice, the vault shows "Vault firewall blocks Alice" (`ALC-AKV-0004`) and, when Azure
  names it, the address the vault saw under **Alice's address as the vault saw it**. (The form of Azure's firewall
  answer is not yet confirmed on a real vault; if it differs, the refusal may read as a missing permission.)
- **Private endpoint.** Alice also works with a private endpoint: the vault's name must resolve on the Alice host to
  the endpoint's private address, usually through a private DNS zone `privatelink.vaultcore.azure.net` linked to the
  network Alice's DNS uses. Alice keeps connecting to `<vault-name>.vault.azure.net` and checks the vault's own TLS
  certificate.
- **Environment variables.** Do not set `AZURE_REGIONAL_AUTHORITY_NAME`, `MSAL_FORCE_REGION` or
  `AZURE_SDK_GO_LOGGING` for the Alice container: with any of them set, Alice refuses to sign in to Azure
  (`ALC-AKV-0011`) until it is restarted without them.
- **Clock.** The Alice host's clock must be correct (NTP); Azure refuses sign-ins from a clock that is too far off
  (`ALC-AKV-0009`).

## 4. Adding the vault in Alice

An Alice administrator (with a fresh authenticator code) does this:

1. Open **Key Vaults** and choose **Add Key Vault**.
2. **Name**: a label in Alice. **Vault address**: the vault's name (`contoso-prod`), `contoso-prod.vault.azure.net`
   or `https://contoso-prod.vault.azure.net`. Anything else (another port, a path, another cloud's suffix) is
   refused before Alice sends anything.
3. **Sign-in method** and its fields, as in section 1.
4. Choose **Add Key Vault**. Alice signs in and reads the first page of the vault's certificate list before it stores
   anything (up to 45 seconds).

What happens next:

- **"Key Vault added."** The vault is added, with its **Access check**: one row each for monitoring, deploying and
  importing, with **Allowed**, **Not allowed: needs** a role, **Not checked**, **Checked when you import** or
  **Check failed**. Deployment access is checked only when you ask (**Also test deployment access**, which reads
  one exportable certificate's secret once and discards it; the read is in the audit log). Import access is never
  checked in advance.
- **Added, but not everything works.** A missing role or the vault firewall still adds the vault, as **Partly
  working**, so that you can fix it afterwards; the access check and the vault page say what is missing.
- **Refused, nothing stored.** A wrong vault name, a refused sign-in, an expired secret, an unreachable vault, an
  untrusted certificate, a wrong clock or an unavailable managed identity add nothing and use no license slot. The
  message names the cause.

The vault's page also shows **Alice signs in to Azure as** the object ID Azure gave Alice's identity: the ID to look
for in the vault's **Access control (IAM)**.

Alice checks the vault every 15 minutes by default (5 to 1440 minutes, on the vault's page; administrators).
**Check now** runs a check at once. Each vault counts as one target of the license
([licensing.md](licensing.md)).

## 5. Common errors

| Code | Message | Usual fix |
|---|---|---|
| [`ALC-AKV-0001`](troubleshooting.md#alc-akv-0001-azure-sign-in-refused) | Azure sign-in refused | Check the tenant ID, client ID and the secret's **value** or the certificate registered on the app registration; then **Replace credentials**. |
| [`ALC-AKV-0002`](troubleshooting.md#alc-akv-0002-azure-sign-in-secret-expired) | Azure sign-in secret expired | Create a new secret or certificate, then **Replace credentials**. |
| [`ALC-AKV-0003`](troubleshooting.md#alc-akv-0003-missing-permission-in-the-vault) | Missing permission in the vault | Assign the role the message names (section 2), wait a few minutes, **Check again**. |
| [`ALC-AKV-0004`](troubleshooting.md#alc-akv-0004-vault-firewall-blocks-alice) | Vault firewall blocks Alice | Add Alice's address to the vault firewall, or use a private endpoint (section 3). |
| [`ALC-AKV-0005`](troubleshooting.md#alc-akv-0005-vault-not-found) | Vault not found | Check the vault's name; with a private endpoint, check that the name resolves on the Alice host. |
| [`ALC-AKV-0006`](troubleshooting.md#alc-akv-0006-cannot-reach-azure) | Cannot reach Azure | Allow outbound TCP 443 to both hosts of section 3 and check DNS. |
| [`ALC-AKV-0010`](troubleshooting.md#alc-akv-0010-managed-identity-not-available) | Managed identity not available | Run Alice on an Azure virtual machine with a managed identity, or use a certificate or a client secret. |

Every other code is in [troubleshooting.md](troubleshooting.md).

## Removing Alice's access

Remove the vault in Alice (**Remove Key Vault** on its page), then delete the role assignments or access policies,
and the app registration (`az ad app delete --id <client-id>`) or the managed identity's role assignments. Removing
the vault in Alice changes nothing in Azure and nothing on the websites Alice deployed to.
