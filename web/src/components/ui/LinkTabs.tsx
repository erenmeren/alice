import type { ReactNode } from 'react';
import { Link, useLocation } from 'react-router';
import classes from './ui.module.css';

export interface LinkTab {
  to: string;
  label: ReactNode;
  match?: string[];
}

export interface LinkTabsProps {
  items: LinkTab[];
  label: string;
}

// LinkTabs are the design's page tabs when each tab is its own address (SSH keys | Key rotations). They are links in
// a named group — not a tablist and not a navigation landmark (the shell's nav must stay the only one).
export function LinkTabs({ items, label }: LinkTabsProps) {
  const { pathname } = useLocation();
  return (
    <div className={classes.linkTabs} role="group" aria-label={label}>
      {items.map((it) => {
        const active = pathname === it.to || pathname.startsWith(`${it.to}/`) || (it.match ?? []).some((m) => pathname.startsWith(m));
        return (
          <Link key={it.to} to={it.to} className={classes.linkTab} aria-current={active ? 'page' : undefined} data-active={active || undefined}>
            {it.label}
          </Link>
        );
      })}
    </div>
  );
}
