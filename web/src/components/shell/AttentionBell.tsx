import { ActionIcon, Anchor, Code, Popover } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { getAlerts } from '../../api/phase7';
import { ALERTS_KEY } from '../../api/queryKeys';
import { Icon } from '../../design/Icon';
import { useConditionItems } from '../dashboard/conditions';
import { ErrorAlert } from '../ErrorAlert';
import { LoadingIndicator } from '../LoadingIndicator';
import { AttentionItem } from '../ui';
import ui from '../ui/ui.module.css';
import classes from './shell.module.css';

const SHOWN = 6;

// BellContent is mounted only while the popover is open, so /alerts is read then and never polled by the shell (R8).
function BellContent({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const alerts = useQuery({ queryKey: ALERTS_KEY, queryFn: getAlerts });
  const items = useConditionItems(alerts.data?.items ?? []);
  let body;
  if (alerts.isPending) body = <LoadingIndicator />;
  else if (alerts.isError) body = <ErrorAlert error={alerts.error} />;
  else if (items.length === 0) body = <p className={classes.bellState}>{t('dashboard.noAttention')}</p>;
  else
    body = (
      // Any click on a row leaves for its page: the popover closes.
      <ul role="list" className={ui.attentionList} onClick={onDone}>
        {items.slice(0, SHOWN).map((i) => (
          <li key={i.key}>
            <AttentionItem
              tone={i.tone}
              icon={i.icon}
              title={i.title}
              detail={i.name ? <Code translate="no">{i.name}</Code> : undefined}
              meta={i.since}
              to={i.to ?? undefined}
            />
          </li>
        ))}
      </ul>
    );
  return (
    <>
      <p className={classes.bellTitle}>{t('dashboard.needsAttention')}</p>
      {body}
      <Anchor component={Link} to="/" className={classes.bellFoot} onClick={onDone}>
        {t('shell.attention.overview')}
      </Anchor>
    </>
  );
}

// AttentionBell is the top bar's bell: a popover with the conditions that need someone (the dashboard's mapping, C6).
// There is no unread state server-side, so the bell carries no dot.
export function AttentionBell() {
  const { t } = useTranslation();
  const [opened, setOpened] = useState(false);
  return (
    // The bell sits in the fixed top bar and never scrolls away, so the dropdown need not hide with a detached target.
    <Popover opened={opened} onChange={setOpened} position="bottom-end" width={340} trapFocus shadow="md" hideDetached={false}>
      <Popover.Target>
        <ActionIcon variant="subtle" color="gray" size="lg" aria-label={t('shell.attention.open')} title={t('shell.attention.open')} aria-expanded={opened} onClick={() => setOpened((o) => !o)}>
          <Icon name="Bell" />
        </ActionIcon>
      </Popover.Target>
      <Popover.Dropdown>{opened && <BellContent onDone={() => setOpened(false)} />}</Popover.Dropdown>
    </Popover>
  );
}
