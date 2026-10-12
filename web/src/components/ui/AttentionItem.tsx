import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { Icon, type IconName } from '../../design/Icon';
import classes from './ui.module.css';

export interface AttentionItemProps {
  tone: 'warning' | 'danger' | 'info';
  icon: IconName;
  title: ReactNode;
  detail?: ReactNode;
  meta?: ReactNode;
  to?: string;
  onClick?: () => void;
  testId?: string;
}

// AttentionItem is one row of "Needs attention": a tinted status box, what happened, which resource, and where to act.
export function AttentionItem({ tone, icon, title, detail, meta, to, onClick, testId }: AttentionItemProps) {
  const body = (
    <>
      <span className={classes.statusBox} data-tone={tone} aria-hidden="true">
        <Icon name={icon} size={15} />
      </span>
      <span className={classes.attentionText}>
        <span className={classes.attentionTitle}>{title}</span>
        {detail && <span className={classes.attentionDetail}>{detail}</span>}
        {meta && <span className={classes.attentionMeta}>{meta}</span>}
      </span>
      {(to || onClick) && <Icon name="ChevronRight" size={14} className={classes.chevron} />}
    </>
  );
  if (to)
    return (
      <Link to={to} className={classes.attentionRow} data-testid={testId}>
        {body}
      </Link>
    );
  if (onClick)
    return (
      <button type="button" className={classes.attentionRow} onClick={onClick} data-testid={testId}>
        {body}
      </button>
    );
  return (
    <div className={classes.attentionRow} data-testid={testId}>
      {body}
    </div>
  );
}
