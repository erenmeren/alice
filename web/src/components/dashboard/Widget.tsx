import { Paper, Title } from '@mantine/core';
import type { ReactNode } from 'react';

// Widget is the frame of a dashboard part: a bordered panel with a level-2 heading. Colour is never the only signal in
// its content (badges carry text).
export function Widget({ title, testId, children }: { title: string; testId: string; children: ReactNode }) {
  return (
    <Paper withBorder p="md" data-testid={testId} component="section" aria-label={title}>
      <Title order={2} size="h4" mb="sm">
        {title}
      </Title>
      {children}
    </Paper>
  );
}
