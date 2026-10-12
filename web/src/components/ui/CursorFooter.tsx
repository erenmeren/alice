import { Button, Loader } from '@mantine/core';
import { useLayoutEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import classes from './ui.module.css';

export interface CursorFooterProps {
  shown: number;
  hasMore: boolean;
  loading: boolean;
  onMore: () => void;
  moreLabel: string;
}

// CursorFooter is a ResourceTable footer for cursor-paged lists: how many rows are on screen and Load more. It never
// states a total (the API has none) and never numbers pages.
// Keyboard focus never falls to the page: while loading the button stays focusable (aria-disabled, not disabled), and
// when the last page removes it, focus moves to the table's scroll region (or, outside a table, to the count).
export function CursorFooter({ shown, hasMore, loading, onMore, moreLabel }: CursorFooterProps) {
  const { t } = useTranslation();
  const countRef = useRef<HTMLSpanElement>(null);
  const buttonFocused = useRef(false);
  useLayoutEffect(() => {
    if (hasMore || !buttonFocused.current) return;
    buttonFocused.current = false;
    const count = countRef.current;
    const region = count?.closest(`.${classes.tablePanel}`)?.querySelector<HTMLElement>('[role="group"][tabindex="0"]');
    (region ?? count)?.focus();
  }, [hasMore]);
  return (
    <>
      <span ref={countRef} tabIndex={-1} aria-live="polite">
        {t('ui.table.shown', { count: shown })}
      </span>
      {hasMore && (
        <Button
          variant="default"
          size="xs"
          aria-disabled={loading || undefined}
          leftSection={loading ? <Loader size={12} /> : undefined}
          onClick={loading ? undefined : onMore}
          onFocus={() => (buttonFocused.current = true)}
          onBlur={() => (buttonFocused.current = false)}
        >
          {moreLabel}
        </Button>
      )}
    </>
  );
}
