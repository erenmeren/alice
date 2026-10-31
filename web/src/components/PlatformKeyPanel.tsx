import { Button, Code, CopyButton, NativeSelect, Stack, Text } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { WEB_SERVER_TYPES, type WebServerType } from '../api/webServer';
import { softwareName } from './software';
import { getPlatformKey } from '../api/endpoints';
import { PLATFORM_KEY_KEY } from '../api/queryKeys';
import { Icon } from '../design/Icon';
import { ErrorAlert } from './ErrorAlert';
import { Panel } from './ui';
import { WRAP } from './wrap';

type Profile = 'linux' | WebServerType | 'windows';

// PlatformKeyPanel shows Alice's public key and the commands that prepare a server (spec §12.2,
// §18.5 step 7). The public key is not secret; the private key never leaves the secret store.
// The design has no such panel: it is the design's Panel with labelled code blocks (gap row, Phase 9 Task 7).
export function PlatformKeyPanel({ titleOrder = 2 }: { titleOrder?: 2 | 3 }) {
  const { t } = useTranslation();
  const key = useQuery({ queryKey: PLATFORM_KEY_KEY, queryFn: () => getPlatformKey() });
  const [profile, setProfile] = useState<Profile>('linux');
  const script = key.data?.profiles[profile]?.script ?? '';
  return (
    <Panel title={t('targets.prepare.title')} description={t('targets.prepare.help')} headingOrder={titleOrder}>
      <Stack gap="xs">
        <ErrorAlert error={key.error} />
        {key.data && (
          <>
            <Text size="sm" fw={600}>
              {t('targets.prepare.publicKey')}
            </Text>
            <Code block data-testid="platform-public-key" style={WRAP} translate="no">
              {key.data.public_key}
            </Code>
            <Text size="sm" fw={600}>
              {t('targets.prepare.fingerprint')}
            </Text>
            <Code data-testid="platform-fingerprint" style={WRAP} translate="no">
              {key.data.fingerprint}
            </Code>
            <NativeSelect
              label={t('targets.prepare.profile')}
              value={profile}
              onChange={(e) => setProfile(e.currentTarget.value as Profile)}
              data={[
                { value: 'linux', label: t('targets.prepare.profileLinux') },
                ...WEB_SERVER_TYPES.map((type) => ({ value: type, label: t('targets.prepare.profileWebServer', { software: softwareName(t, type) }) })),
                { value: 'windows', label: t('targets.prepare.profileWindows') },
              ]}
              maw={320}
            />
            <Text size="sm" fw={600}>
              {t(profile === 'windows' ? 'targets.prepare.scriptWindows' : 'targets.prepare.script')}
            </Text>
            <Code block data-testid="setup-script" style={WRAP} translate="no">
              {script}
            </Code>
            <CopyButton value={script}>
              {({ copied, copy }) => (
                <Button size="xs" variant="light" onClick={copy} w="fit-content" leftSection={<Icon name={copied ? 'Check' : 'Copy'} size={14} />}>
                  {copied ? t('targets.prepare.copied') : t('targets.prepare.copy')}
                </Button>
              )}
            </CopyButton>
          </>
        )}
      </Stack>
    </Panel>
  );
}
