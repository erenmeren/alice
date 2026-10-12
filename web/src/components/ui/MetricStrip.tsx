import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { Icon, type IconName } from '../../design/Icon';
import classes from './ui.module.css';

export interface Metric {
  label: ReactNode;
  value: ReactNode;
  foot?: ReactNode;
  icon: IconName;
  to?: string;
  tone?: 'warning' | 'danger';
  testId?: string;
}

export interface MetricStripProps {
  items: Metric[];
  label: string;
}

// MetricStrip is the design's four-number band. A metric with "to" is a link to exactly the rows it counts.
export function MetricStrip({ items, label }: MetricStripProps) {
  return (
    <div className={classes.metricStrip} role="group" aria-label={label}>
      {items.map((m, i) => {
        const body = (
          <>
            <span className={classes.metricLabel}>
              {m.label}
              <Icon name={m.icon} size={16} />
            </span>
            <span className={classes.metricValue}>{m.value}</span>
            {m.foot && (
              <span className={classes.metricFoot} data-tone={m.tone}>
                {m.foot}
              </span>
            )}
          </>
        );
        return m.to ? (
          <Link key={i} to={m.to} className={classes.metric} data-testid={m.testId}>
            {body}
          </Link>
        ) : (
          <div key={i} className={classes.metric} data-testid={m.testId}>
            {body}
          </div>
        );
      })}
    </div>
  );
}
