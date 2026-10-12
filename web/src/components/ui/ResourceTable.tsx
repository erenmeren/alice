import { Table } from '@mantine/core';
import type { ReactNode } from 'react';
import classes from './ui.module.css';

export interface ResourceTableProps {
  label: string;
  minWidth?: number;
  toolbar?: ReactNode;
  footer?: ReactNode;
  testId?: string;
  striped?: boolean;
  children: ReactNode;
}

// ResourceTable is the design's inventory table: a toolbar (search, native selects, saved views, export), the table in
// the theme's focusable scroll region, and a footer for "N shown" and the cursor's Load more (R13). The caller writes
// Table.Thead and Table.Tbody, so rows keep their test ids and cells.
export function ResourceTable({ label, minWidth = 640, toolbar, footer, testId, striped = false, children }: ResourceTableProps) {
  return (
    <div className={classes.tablePanel}>
      {toolbar && <div className={classes.toolbar}>{toolbar}</div>}
      <Table.ScrollContainer minWidth={minWidth}>
        <Table aria-label={label} data-testid={testId} striped={striped} highlightOnHover>
          {children}
        </Table>
      </Table.ScrollContainer>
      {footer && <div className={classes.tableBottom}>{footer}</div>}
    </div>
  );
}
