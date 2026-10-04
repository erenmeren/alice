import { Anchor, type AnchorProps } from '@mantine/core';
import type { ReactNode } from 'react';
import { Link, useInRouterContext } from 'react-router';

// InternalLink links inside the app: a router link where there is a router, a plain anchor where a
// component is shown on its own (a dialog under test).
export function InternalLink({ to, children, ...rest }: { to: string; children: ReactNode; translate?: 'yes' | 'no' } & AnchorProps) {
  const inRouter = useInRouterContext();
  return inRouter ? (
    <Anchor component={Link} to={to} {...rest}>
      {children}
    </Anchor>
  ) : (
    <Anchor href={to} {...rest}>
      {children}
    </Anchor>
  );
}
