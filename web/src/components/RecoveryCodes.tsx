import { Button, Checkbox, Code, Group, List, Stack, Text, Title } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

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
    URL.revokeObjectURL(url);
  };

  return (
    <Stack>
      <Title order={2}>{t('ui.recoveryCodes.title')}</Title>
      <Text>{t('ui.recoveryCodes.help')}</Text>
      <List data-testid="recovery-codes" listStyleType="none" spacing={4}>
        {codes.map((c) => (
          <List.Item key={c}>
            <Code>{c}</Code>
          </List.Item>
        ))}
      </List>
      <Group>
        <Button variant="default" onClick={() => void copy()}>
          {t('ui.recoveryCodes.copy')}
        </Button>
        <Button variant="default" onClick={download}>
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
