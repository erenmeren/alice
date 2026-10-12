import type { ReactNode } from 'react';
import { Icon, type IconName } from '../../design/Icon';
import classes from './ui.module.css';

export interface EmptyStateProps {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  icon?: IconName;
  testId?: string;
}

// EmptyState distinguishes "nothing here yet" (with the way to add it) from "no match" (with Clear filters): the
// caller chooses the copy; the design's guide requires both.
export function EmptyState({ title, description, action, icon = 'Search', testId }: EmptyStateProps) {
  return (
    <div className={classes.empty} data-testid={testId}>
      <Icon name={icon} size={32} className={classes.emptyIcon} />
      <p className={classes.emptyTitle}>{title}</p>
      {description && <p className={classes.emptyText}>{description}</p>}
      {action}
    </div>
  );
}
