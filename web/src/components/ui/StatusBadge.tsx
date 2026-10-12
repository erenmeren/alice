import { Badge } from '@mantine/core';
import type { HTMLAttributes, ReactNode } from 'react';
import { Icon, type IconName } from '../../design/Icon';
import { TONE_COLOR, type Tone } from '../../theme';
import classes from './ui.module.css';

export type { Tone };

export interface StatusBadgeProps extends Omit<HTMLAttributes<HTMLDivElement>, 'color' | 'children'> {
  tone: Tone;
  icon?: IconName;
  children: ReactNode;
  testId?: string;
  size?: 'sm' | 'md' | 'lg';
}

// StatusBadge is the design's status pill: text plus an icon (or a dot) plus color, never color alone. It stays a Mantine
// Badge, so existing selectors (.mantine-Badge-root) and data attributes keep working.
export function StatusBadge({ tone, icon, children, testId, size = 'md', ...rest }: StatusBadgeProps) {
  return (
    <Badge
      color={TONE_COLOR[tone]}
      variant="light"
      size={size}
      data-tone={tone}
      data-testid={testId}
      leftSection={icon ? <Icon name={icon} size={13} /> : <span className={classes.dot} aria-hidden="true" />}
      {...rest}
    >
      {children}
    </Badge>
  );
}
