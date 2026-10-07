import { Button, Group, Menu, Stack, TextInput } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Fragment, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { createView, deleteView, listViews, type SavedView, type ViewPage } from '../api/phase7';
import { viewsKey } from '../api/queryKeys';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';

const MAX_NAME_RUNES = 60;

interface Props {
  page: ViewPage;
  // keys are every filter key of the page; values are the filters now in the address (from useUrlFilters).
  keys: readonly string[];
  values: Record<string, string>;
  set: (next: Record<string, string>) => void;
}

// SavedViews lists the signed-in user's saved filter sets of a list page and saves the current ones. Applying a view
// writes exactly the view's query to the address: every other filter key is cleared. Each view is two menu items (apply,
// delete): no control is nested inside another.
export function SavedViews({ page, keys, values, set }: Props) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const [saving, setSaving] = useState(false);
  const [name, setName] = useState('');
  const views = useQuery({ queryKey: viewsKey(page), queryFn: () => listViews(page) });

  const refresh = () => client.invalidateQueries({ queryKey: viewsKey(page) });
  const create = useMutation({
    mutationFn: (viewName: string) => {
      const query: Record<string, string> = {};
      for (const k of keys) if (values[k]) query[k] = values[k];
      return createView({ page, name: viewName, query });
    },
    onSuccess: () => {
      setSaving(false);
      setName('');
      void refresh();
    },
  });
  const remove = useMutation({ mutationFn: (id: string) => deleteView(id), onSuccess: () => void refresh() });

  const apply = (v: SavedView) => {
    const next: Record<string, string> = {};
    for (const k of keys) next[k] = v.query[k] ?? '';
    set(next);
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const trimmed = name.trim();
    if (trimmed && !tooLong) create.mutate(trimmed);
  };
  const items = views.data?.items ?? [];
  // The rule is 1 to 60 characters (runes): maxLength would count UTF-16 units and refuse an emoji name too early.
  const tooLong = [...name.trim()].length > MAX_NAME_RUNES;

  return (
    <Stack gap="xs">
      <Group gap="xs">
        {/* No focus placeholder: a role="menu" may hold menu items only (axe aria-required-children). */}
        <Menu shadow="md" width={280} withinPortal withInitialFocusPlaceholder={false}>
          <Menu.Target>
            <Button variant="default">{t('filters.views')}</Button>
          </Menu.Target>
          <Menu.Dropdown>
            {items.length === 0 && <Menu.Label>{t('filters.noViews')}</Menu.Label>}
            {items.map((v) => (
              <Fragment key={v.id}>
                <Menu.Item onClick={() => apply(v)}>{v.name}</Menu.Item>
                <Menu.Item c="red.9" onClick={() => remove.mutate(v.id)}>
                  {t('filters.deleteView', { name: v.name })}
                </Menu.Item>
              </Fragment>
            ))}
          </Menu.Dropdown>
        </Menu>
        <Button
          variant="default"
          onClick={() => {
            create.reset();
            setSaving(true);
          }}
        >
          {t('filters.saveView')}
        </Button>
      </Group>
      <ErrorAlert error={views.error} />
      <ErrorAlert error={remove.error} />
      <AppModal opened={saving} onClose={() => setSaving(false)} title={t('filters.saveView')}>
        <form onSubmit={submit}>
          <Stack gap="sm">
            <TextInput label={t('filters.viewName')} value={name} onChange={(e) => setName(e.currentTarget.value)} error={tooLong ? t('filters.viewNameTooLong') : undefined} data-autofocus />
            <ErrorAlert error={create.error} />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setSaving(false)}>
                {t('ui.cancel')}
              </Button>
              <Button type="submit" loading={create.isPending} disabled={!name.trim() || tooLong}>
                {t('filters.saveView')}
              </Button>
            </Group>
          </Stack>
        </form>
      </AppModal>
    </Stack>
  );
}
