import type { ReactNode } from 'react';
import classes from './ui.module.css';

export interface Fact {
  label: ReactNode;
  value: ReactNode;
  testId?: string;
  key?: string;
}

export interface FactListProps {
  facts: Fact[];
  label?: string;
}

// FactList is the design's label/value list as a description list; values wrap anywhere (fingerprints, paths, URLs).
export function FactList({ facts, label }: FactListProps) {
  return (
    <dl className={classes.facts} aria-label={label}>
      {facts.map((f, i) => (
        <div className={classes.fact} key={f.key ?? i}>
          <dt className={classes.factLabel}>{f.label}</dt>
          <dd className={classes.factValue} data-testid={f.testId}>
            {f.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
