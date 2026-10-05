import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { I18nextProvider } from 'react-i18next';
import { MantineProvider } from '@mantine/core';
import { createI18n } from '../i18n';
import { expectNoRawKeys } from '../test/i18nAssert';
import { RoleGuide } from './RoleGuide';
import { CMD_CERTIFICATES_OFFICER, CMD_POLICY_OFFICER, CMD_POLICY_READER, CMD_POLICY_SECRETS, CMD_READER, CMD_SECRETS_USER, fillCommand } from './roleCommands';

async function show(props: Parameters<typeof RoleGuide>[0], lang = 'en-US') {
  const i18n = await createI18n([lang]);
  return render(
    <I18nextProvider i18n={i18n}>
      <MantineProvider>
        <RoleGuide {...props} />
      </MantineProvider>
    </I18nextProvider>,
  );
}

describe('RoleGuide', () => {
  it('lists the three roles with the role names in <code> and the Reader note', async () => {
    await show({});
    const monitor = document.querySelector('[data-role-row="monitor"]') as HTMLElement;
    const deploy = document.querySelector('[data-role-row="deploy"]') as HTMLElement;
    const imp = document.querySelector('[data-role-row="import"]') as HTMLElement;
    expect(within(monitor).getByText('Key Vault Reader').tagName).toBe('CODE');
    expect(within(deploy).getByText('Key Vault Secrets User').tagName).toBe('CODE');
    expect(deploy).toHaveTextContent('+ Key Vault Secrets User');
    expect(within(imp).getByText('Key Vault Certificates Officer').tagName).toBe('CODE');
    expect(imp).toHaveTextContent('+ Key Vault Certificates Officer');
    expect(within(monitor).getByText('Expected to be enough; not yet confirmed on a real vault.')).toBeInTheDocument();
    expect(within(monitor).getByText('Monitor certificates, keys and secrets')).toBeInTheDocument();
    expect(within(deploy).getByText('Deploy certificates to Nginx')).toBeInTheDocument();
    expect(within(imp).getByText('Import certificates into the vault')).toBeInTheDocument();
  });

  it('shows the az commands with the placeholders when nothing is known', async () => {
    await show({});
    const text = document.body.textContent ?? '';
    for (const c of [CMD_READER, CMD_SECRETS_USER, CMD_CERTIFICATES_OFFICER, CMD_POLICY_READER, CMD_POLICY_SECRETS, CMD_POLICY_OFFICER]) expect(text).toContain(c);
    expect(CMD_SECRETS_USER).toBe(
      'az role assignment create --role "Key Vault Secrets User" --assignee <client-id> --scope "$(az keyvault show --name <vault-name> --query id --output tsv)/secrets/<certificate-name>"',
    );
  });

  it('fills in the typed client ID, the vault name and the certificate name', async () => {
    await show({ clientId: '0f1e2d3c-4b5a-4968-8776-655443322110', vaultName: 'contoso-prod', certificateName: 'web-cert' });
    const deploy = document.querySelector('[data-role-row="deploy"]') as HTMLElement;
    expect(deploy).toHaveTextContent(
      'az role assignment create --role "Key Vault Secrets User" --assignee 0f1e2d3c-4b5a-4968-8776-655443322110 --scope "$(az keyvault show --name contoso-prod --query id --output tsv)/secrets/web-cert"',
    );
    expect(deploy.textContent).not.toContain('<certificate-name>');
    const reader = document.querySelector('[data-role-row="monitor"]') as HTMLElement;
    expect(reader.textContent).toContain('--assignee 0f1e2d3c-4b5a-4968-8776-655443322110');
    expect(reader.textContent).not.toContain('<vault-name>');
  });

  it('never puts a value with shell characters into a command', () => {
    expect(fillCommand(CMD_READER, { clientId: 'x; rm -rf /', vaultName: '$(evil)' })).toBe(CMD_READER);
    expect(fillCommand(CMD_READER, { vaultName: 'contoso-prod' })).toContain('--name contoso-prod');
  });

  it('copies a command as text and has a collapsible access-policy section with its commands', async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    await show({ vaultName: 'contoso-prod' });
    const buttons = screen.getAllByRole('button', { name: /^Copy command: Deploy certificates to Nginx$/ });
    expect(buttons).toHaveLength(1);
    await user.click(buttons[0]);
    expect(writeText).toHaveBeenCalledWith(fillCommand(CMD_SECRETS_USER, { vaultName: 'contoso-prod' }));
    const summary = screen.getByText('Vault uses access policies');
    const details = summary.closest('details') as HTMLDetailsElement;
    expect(details.open).toBe(false);
    expect(details.textContent).toContain('az keyvault set-policy --name contoso-prod --spn <client-id> --certificate-permissions get list import');
    expect(screen.getByRole('button', { name: 'Copy command: Import certificates into the vault (access policy)' })).toBeInTheDocument();
  });

  it('opens the access-policy section when asked to', async () => {
    await show({ openPolicies: true });
    expect((screen.getByText('Vault uses access policies').closest('details') as HTMLDetailsElement).open).toBe(true);
  });

  it('speaks Turkish and keeps the role names and commands untranslated', async () => {
    await show({}, 'tr-TR');
    expect(screen.getAllByText("Alice'in ihtiyaç duyduğu roller").length).toBeGreaterThan(0);
    expect(screen.getByText('Kasa erişim ilkeleri kullanıyor')).toBeInTheDocument();
    expect(screen.getByText('Key Vault Reader')).toBeInTheDocument();
    expect(document.body.textContent).toContain(CMD_READER);
    expectNoRawKeys();
  });
});
