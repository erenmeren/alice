import { Button } from '@mantine/core';
import { useTranslation } from 'react-i18next';

export interface CursorFooterProps {
  shown: number;
  hasMore: boolean;
  loading: boolean;
  onMore: () => void;
  moreLabel: string;
}

// CursorFooter is a ResourceTable footer for cursor-paged lists: how many rows are on screen and Load more. It never
// states a total (the API has none) and never numbers pages.
export function CursorFooter({ shown, hasMore, loading, onMore, moreLabel }: CursorFooterProps) {
  const { t } = useTranslation();
  return (
    <>
      <span>{t('ui.table.shown', { count: shown })}</span>
      {hasMore && (
        <Button variant="default" size="xs" onClick={onMore} loading={loading}>
          {moreLabel}
        </Button>
      )}
    </>
  );
}
