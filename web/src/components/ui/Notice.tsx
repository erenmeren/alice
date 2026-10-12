import { Alert } from '@mantine/core';
import type { ReactNode } from 'react';
import { Icon, type IconName } from '../../design/Icon';
import { TONE_COLOR, type Tone } from '../../theme';
import classes from './ui.module.css';

export interface NoticeProps {
  tone: Tone;
  title: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
  role?: 'alert' | 'status' | 'note';
  testId?: string;
}

const ICON: Record<Tone, IconName> = { brand: 'ShieldCheck', success: 'ShieldCheck', info: 'CircleDot', neutral: 'CircleDot', warning: 'CircleAlert', danger: 'ShieldAlert' };

// Notice is the design's status line for page-level information. A static notice is a "note"; pass role="alert" only
// for something that just went wrong and role="status" for a result the person is waiting for.
export function Notice({ tone, title, children, action, role = 'note', testId }: NoticeProps) {
  return (
    <Alert color={TONE_COLOR[tone]} title={title} role={role} data-testid={testId} icon={<Icon name={ICON[tone]} size={17} />}>
      {children}
      {action && <div className={classes.noticeAction}>{action}</div>}
    </Alert>
  );
}
