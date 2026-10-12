import type { ReactNode } from 'react';
import classes from './ui.module.css';

export interface DialogActionsProps {
  children: ReactNode;
  note?: ReactNode;
}

// DialogActions is the design's dialog footer bar (subtle background, a note on the left, buttons on the right).
export function DialogActions({ children, note }: DialogActionsProps) {
  return (
    <div className={classes.dialogActions}>
      {note && <span className={classes.dialogNote}>{note}</span>}
      {children}
    </div>
  );
}
