import { Group, Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { SOURCE_CAPABILITIES, type Certificate } from '../../api/types';
import { Icon } from '../../design/Icon';
import { Notice, Panel } from '../ui';

// CapabilitiesPanel says what Alice can do with this certificate (the API's per-source capability list): each capability
// with a mark and its words, and for a certificate Alice did not order over ACME that only its issuing authority can
// revoke it. The buttons of the page follow the same list.
export function CapabilitiesPanel({ certificate }: { certificate: Pick<Certificate, 'source' | 'capabilities' | 'revoked_at' | 'compromised_at'> }) {
  const { t } = useTranslation();
  const has = new Set(certificate.capabilities);
  const blocked = certificate.revoked_at !== null || certificate.compromised_at !== null;
  // Why a capability is missing: the source's matrix, or this certificate's revocation or compromise.
  const why = (c: (typeof SOURCE_CAPABILITIES)[number]) => {
    if (c === 'revoke' && certificate.revoked_at !== null) return 'certificates.capabilities.revokedAlready';
    if ((c === 'deploy' || c === 'verify') && blocked) return 'certificates.capabilities.deployBlocked';
    return `certificates.capabilities.no.${c}`;
  };
  return (
    <Panel title={t('certificates.capabilities.title')} description={t('certificates.capabilities.description')} testId="capabilities-panel">
      <Stack gap={6}>
        <ul aria-label={t('certificates.capabilities.title')} style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {SOURCE_CAPABILITIES.map((c) => (
            <li key={c} data-capability={c} data-enabled={has.has(c) ? 'true' : 'false'}>
              <Group gap={8} wrap="nowrap" align="flex-start">
                <Icon name={has.has(c) ? 'CircleCheck' : 'CircleOff'} size={16} />
                <Text size="sm">
                  <strong>{t(`certificates.capabilities.names.${c}`)}</strong>
                  {' — '}
                  {t(has.has(c) ? `certificates.capabilities.yes.${c}` : why(c))}
                </Text>
              </Group>
            </li>
          ))}
        </ul>
        {certificate.source !== 'acme' && (
          <Notice tone="neutral" title={t('certificates.capabilities.noRevokeTitle')} testId="no-revoke">
            {t('certificates.capabilities.noRevokeText')}
          </Notice>
        )}
      </Stack>
    </Panel>
  );
}
