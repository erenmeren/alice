import { Text, Title } from '@mantine/core';
import type { ReactNode } from 'react';
import { cx } from './cx';
import classes from './ui.module.css';

export interface PanelProps {
  title?: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
  padded?: boolean;
  headingOrder?: 2 | 3;
  testId?: string;
  className?: string;
  'aria-label'?: string;
}

// Panel is the design's bordered surface with a heading, an optional subtitle, a corner action and a footer bar.
// Unnamed it is no landmark; give it aria-label only where a region is wanted.
export function Panel({ title, description, action, footer, children, padded = true, headingOrder = 2, testId, className, 'aria-label': label }: PanelProps) {
  return (
    <section className={cx(classes.panel, className)} data-testid={testId} aria-label={label}>
      {(title || action) && (
        <header className={classes.panelHead}>
          <div>
            {title && (
              <Title order={headingOrder} className={classes.panelTitle}>
                {title}
              </Title>
            )}
            {description && <Text className={classes.panelDescription}>{description}</Text>}
          </div>
          {action}
        </header>
      )}
      <div className={padded ? classes.panelBody : classes.panelFlush}>{children}</div>
      {footer && <footer className={classes.panelFoot}>{footer}</footer>}
    </section>
  );
}
