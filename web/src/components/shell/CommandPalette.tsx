import { Box, Button, TextInput } from '@mantine/core';
import { useHotkeys } from '@mantine/hooks';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { Icon, type IconName } from '../../design/Icon';
import { AppModal } from '../AppModal';
import classes from './shell.module.css';

export interface PaletteItem {
  to: string;
  labelKey: string;
  icon: IconName;
}

const isMac = () => typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);

// CommandPalette is the top bar's "go to a page" dialog (Ctrl+K / ⌘K). It searches only the destinations it is given —
// the shell passes the ones the signed-in role may open — and never queries resources: there is no search endpoint
// (plan R7; resource search is a recorded gap).
export function CommandPalette({ items }: { items: PaletteItem[] }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [opened, setOpened] = useState(false);
  const [query, setQuery] = useState('');
  useHotkeys([['mod+K', () => setOpened(true)]]);
  const close = () => {
    setOpened(false);
    setQuery('');
  };
  const needle = query.trim().toLocaleLowerCase(i18n.language);
  const found = items.filter((i) => t(i.labelKey).toLocaleLowerCase(i18n.language).includes(needle));
  const openFirst = () => {
    const first = found[0];
    if (!first) return;
    close();
    void navigate(first.to);
  };
  return (
    <>
      <Button variant="subtle" color="gray" size="xs" className={classes.trigger} aria-label={t('shell.search.open')} leftSection={<Icon name="Search" size={15} />} onClick={() => setOpened(true)}>
        <Box component="span" visibleFrom="sm">
          {t('shell.search.open')}
        </Box>
        <Box component="kbd" visibleFrom="sm" aria-hidden="true" className={classes.kbd} ml={8}>
          {isMac() ? '⌘K' : 'Ctrl K'}
        </Box>
      </Button>
      <AppModal opened={opened} onClose={close} title={t('shell.search.title')} size="lg">
        <TextInput
          aria-label={t('shell.search.placeholder')}
          placeholder={t('shell.search.placeholder')}
          leftSection={<Icon name="Search" size={16} />}
          value={query}
          onChange={(e) => setQuery(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              openFirst();
            }
          }}
          autoComplete="off"
          data-autofocus
        />
        {found.length === 0 ? (
          <p className={classes.empty}>{t('shell.search.empty')}</p>
        ) : (
          <ul className={classes.results} role="list">
            {found.map((i, n) => (
              <li key={i.to}>
                <Link to={i.to} className={classes.item} data-first={n === 0 && needle !== '' ? '' : undefined} onClick={close}>
                  <Icon name={i.icon} size={16} />
                  <span>{t(i.labelKey)}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
        <p className={classes.hint}>{t('shell.search.hint')}</p>
      </AppModal>
    </>
  );
}
