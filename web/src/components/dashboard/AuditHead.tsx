import { Anchor, Code } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { DashboardSummary } from '../../api/phase7';
import { formatDateTime } from '../../datetime';
import { FactList, Notice, StatusBadge, type Fact } from '../ui';
import { WRAP } from '../wrap';
import classes from './dashboard.module.css';
import { Widget } from './Widget';

// AuditHead is the design's "Audit integrity", shown to Administrators and Auditors (audit is null for Operators and for
// an empty log: then hidden). It states what the latest chain check found and what that does not prove: hash-chain
// continuity is no independent proof against a compromised host (IMPLEMENTATION §3); no score is derived from it.
// head_seq is the sequence number of the last verification checkpoint, not the log's current head (which keeps growing
// after the check), so the caption says the entries were checked through it. Forwarding is shown to Administrators as
// the way to set it up, without a state: the summary has none, and reading the setting needs a fresh verification.
export function AuditHead({ audit, admin = false }: { audit: NonNullable<DashboardSummary['audit']>; admin?: boolean }) {
  const { t, i18n } = useTranslation();
  const facts: Fact[] = [
    { key: 'checked', label: t('dashboard.assurance.lastChecked'), value: audit.checked_at ? formatDateTime(audit.checked_at, i18n.language) : t('dashboard.assurance.notChecked') },
    {
      key: 'hash',
      label: t('dashboard.assurance.headHash'),
      value: (
        <Code translate="no" style={WRAP}>
          {audit.head_hash}
        </Code>
      ),
    },
  ];
  if (admin) {
    facts.push({
      key: 'forwarding',
      label: t('dashboard.assurance.forwarding'),
      value: (
        <Anchor component={Link} to="/settings?tab=forwarding" size="sm">
          {t('dashboard.assurance.forwardingSettings')}
        </Anchor>
      ),
    });
  }
  return (
    <Widget
      title={t('dashboard.assurance.audit')}
      description={t('dashboard.assurance.auditSub')}
      testId="audit-head"
      action={
        audit.intact ? (
          <StatusBadge tone="success" icon="ShieldCheck">
            {t('dashboard.assurance.intact')}
          </StatusBadge>
        ) : (
          <StatusBadge tone="danger" icon="ShieldAlert">
            {t('dashboard.assurance.broken')}
          </StatusBadge>
        )
      }
      footer={
        <Anchor component={Link} to="/audit" size="xs">
          {t('dashboard.assurance.inspect')}
        </Anchor>
      }
    >
      {!audit.intact && (
        <Notice tone="danger" role="alert" title={t('dashboard.auditBroken')} />
      )}
      <div className={audit.intact ? undefined : classes.section}>
        <span className={classes.largeValue}>{audit.head_seq}</span>
        <p className={classes.caption}>{t('dashboard.assurance.seqCaption', { seq: audit.head_seq })}</p>
      </div>
      <div className={classes.section}>
        <FactList facts={facts} />
      </div>
      <p className={classes.note}>{t('dashboard.auditHeadHelp')}</p>
      <p className={classes.note}>{t('dashboard.assurance.scope')}</p>
    </Widget>
  );
}
