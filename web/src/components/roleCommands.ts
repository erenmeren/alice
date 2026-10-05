// The `az` commands of the access checklist, as literal text with their placeholders (D41: the guide
// docs/azure-setup.md repeats these lines verbatim and a Go test compares them). RoleGuide replaces
// <client-id>, <vault-name> and <certificate-name>; nothing else is changed. One command per line.

export const ROLE_READER = 'Key Vault Reader';
export const ROLE_SECRETS_USER = 'Key Vault Secrets User';
export const ROLE_CERTIFICATES_OFFICER = 'Key Vault Certificates Officer';

export const CMD_READER =
  'az role assignment create --role "Key Vault Reader" --assignee <client-id> --scope "$(az keyvault show --name <vault-name> --query id --output tsv)"';
export const CMD_SECRETS_USER =
  'az role assignment create --role "Key Vault Secrets User" --assignee <client-id> --scope "$(az keyvault show --name <vault-name> --query id --output tsv)/secrets/<certificate-name>"';
export const CMD_CERTIFICATES_OFFICER =
  'az role assignment create --role "Key Vault Certificates Officer" --assignee <client-id> --scope "$(az keyvault show --name <vault-name> --query id --output tsv)"';
export const CMD_POLICY_READER =
  'az keyvault set-policy --name <vault-name> --spn <client-id> --certificate-permissions get list --key-permissions list --secret-permissions list';
export const CMD_POLICY_SECRETS =
  'az keyvault set-policy --name <vault-name> --spn <client-id> --certificate-permissions get list --key-permissions list --secret-permissions get list';
export const CMD_POLICY_OFFICER =
  'az keyvault set-policy --name <vault-name> --spn <client-id> --certificate-permissions get list import --key-permissions list --secret-permissions get list';

export interface CommandValues {
  clientId?: string;
  vaultName?: string;
  certificateName?: string;
}

// fillCommand replaces the placeholders that have a value and leaves the others as they are. The
// values come from fields the person typed or from the vault; a value with characters a shell would
// treat specially (anything outside letters, digits, dot, hyphen, underscore) is not substituted.
export function fillCommand(cmd: string, v: CommandValues): string {
  const safe = (s: string | undefined): s is string => s !== undefined && /^[A-Za-z0-9._-]+$/.test(s);
  let out = cmd;
  if (safe(v.clientId)) out = out.split('<client-id>').join(v.clientId);
  if (safe(v.vaultName)) out = out.split('<vault-name>').join(v.vaultName);
  if (safe(v.certificateName)) out = out.split('<certificate-name>').join(v.certificateName);
  return out;
}
