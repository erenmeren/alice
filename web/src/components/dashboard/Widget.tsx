import type { ReactNode } from 'react';
import { Panel } from '../ui';

export interface WidgetProps {
  title: string;
  testId: string;
  children: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  footer?: ReactNode;
  padded?: boolean;
  className?: string;
}

// Widget is the frame of a dashboard part: the design's Panel, named by its title (a region the tests and a screen
// reader can find), with the design's subtitle, corner action and footer. Colour is never the only signal in its
// content (badges carry text).
export function Widget({ title, testId, children, description, action, footer, padded, className }: WidgetProps) {
  return (
    <Panel title={title} description={description} action={action} footer={footer} padded={padded} testId={testId} aria-label={title} className={className}>
      {children}
    </Panel>
  );
}
