import { Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { capabilityText } from '../api/capabilities';
import type { Target } from '../api/types';
import { locationWarningKey } from '../api/warnings';
import { LabelledCode } from './LabelledCode';

// LocationWarning words one warning of a website. The site name of san_mismatch is data and is shown
// in <Code> after the sentence; the key mode of key_mode_open is text from the server's own fixed set. With the
// target, a server that cannot deploy shows the read-only wording (capabilityText).
export function LocationWarning({ code, site, mode, size = 'xs', target }: { code: string; site: string; mode: string; size?: 'xs' | 'sm'; target?: Pick<Target, 'capabilities'> }) {
  const { t } = useTranslation();
  const key = target ? capabilityText(target, locationWarningKey(code)) : locationWarningKey(code);
  if (code === 'san_mismatch') return <LabelledCode size={size} text={t(key, { site: '' })} value={site} />;
  return <Text size={size}>{t(key, { mode })}</Text>;
}
