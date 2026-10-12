import { Button, Checkbox, Group, Stack, Text, Title } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Icon } from '../design/Icon';
import auth from './auth/auth.module.css';

interface Props {
  codes: string[];
  onContinue: () => void;
}

// RecoveryCodes shows one-time recovery codes once and makes the user confirm they saved them.
export function RecoveryCodes({ codes, onContinue }: Props) {
  const { t } = useTranslation();
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(codes.join('\n'));
      setCopied(true);
    } catch {
      setCopied(false); // clipboard blocked: the codes stay on screen and can be downloaded
    }
  };

  const download = () => {
    const url = URL.createObjectURL(new Blob([`${codes.join('\n')}\n`], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'alice-recovery-codes.txt';
    a.click();
    // Some browsers read the blob only after click() returns, so release it on the next task.
    setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  return (
    <Stack>
      <Title order={2}>{t('ui.recoveryCodes.title')}</Title>
      <Text>{t('ui.recoveryCodes.help')}</Text>
      {/* role="list": WebKit drops the list role of a list without bullets. */}
      <ul data-testid="recovery-codes" className={auth.codes} role="list">
        {codes.map((c) => (
          <li key={c}>
            <code className={auth.code} translate="no">
              {c}
            </code>
          </li>
        ))}
      </ul>
      <Group>
        <Button variant="default" leftSection={<Icon name="Copy" size={15} />} onClick={() => void copy()}>
          {t('ui.recoveryCodes.copy')}
        </Button>
        <Button variant="default" leftSection={<Icon name="Download" size={15} />} onClick={download}>
          {t('ui.recoveryCodes.download')}
        </Button>
        {copied && (
          <Text size="sm" role="status">
            {t('ui.recoveryCodes.copied')}
          </Text>
        )}
      </Group>
      <Checkbox
        label={t('ui.recoveryCodes.saved')}
        checked={saved}
        onChange={(e) => setSaved(e.currentTarget.checked)}
      />
      <Button onClick={onContinue} disabled={!saved}>
        {t('ui.continue')}
      </Button>
    </Stack>
  );
}
