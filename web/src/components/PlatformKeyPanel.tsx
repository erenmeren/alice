import { Button, Card, Code, CopyButton, NativeSelect, Stack, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getPlatformKey } from '../api/endpoints';
import { PLATFORM_KEY_KEY } from '../api/queryKeys';
import { ErrorAlert } from './ErrorAlert';
import { WRAP } from './wrap';

type Profile = 'linux' | 'nginx';

// PlatformKeyPanel shows Alice's public key and the commands that prepare a server (spec §12.2,
// §18.5 step 7). The public key is not secret; the private key never leaves the secret store.
export function PlatformKeyPanel({ titleOrder = 2 }: { titleOrder?: 2 | 3 }) {
  const { t } = useTranslation();
  const key = useQuery({ queryKey: PLATFORM_KEY_KEY, queryFn: getPlatformKey });
  const [profile, setProfile] = useState<Profile>('linux');
  const script = key.data?.profiles[profile].script ?? '';
  return (
    <Card withBorder padding="md">
      <Stack gap="xs">
        <Title order={titleOrder} size="h3">
          {t('targets.prepare.title')}
        </Title>
        <Text size="sm">{t('targets.prepare.help')}</Text>
        <ErrorAlert error={key.error} />
        {key.data && (
          <>
            <Text size="sm" fw={600}>
              {t('targets.prepare.publicKey')}
            </Text>
            <Code block data-testid="platform-public-key" style={WRAP}>
              {key.data.public_key}
            </Code>
            <Text size="sm" fw={600}>
              {t('targets.prepare.fingerprint')}
            </Text>
            <Code data-testid="platform-fingerprint" style={WRAP}>
              {key.data.fingerprint}
            </Code>
            <NativeSelect
              label={t('targets.prepare.profile')}
              value={profile}
              onChange={(e) => setProfile(e.currentTarget.value as Profile)}
              data={[
                { value: 'linux', label: t('targets.prepare.profileLinux') },
                { value: 'nginx', label: t('targets.prepare.profileNginx') },
              ]}
              maw={320}
            />
            <Text size="sm" fw={600}>
              {t('targets.prepare.script')}
            </Text>
            <Code block data-testid="setup-script" style={WRAP}>
              {script}
            </Code>
            <CopyButton value={script}>
              {({ copied, copy }) => (
                <Button size="xs" variant="light" onClick={copy} w="fit-content">
                  {copied ? t('targets.prepare.copied') : t('targets.prepare.copy')}
                </Button>
              )}
            </CopyButton>
          </>
        )}
      </Stack>
    </Card>
  );
}
