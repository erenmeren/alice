import { Button, CloseButton, Stack, Text, TextInput } from '@mantine/core';
import { useId, type KeyboardEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { suffixProblem } from '../../api/acme';
import { Notice } from '../ui';
import classes from './acme.module.css';

export interface SuffixInputProps {
  value: string[];
  onChange: (value: string[]) => void;
  // draft is the entry being typed; the form adds it on save when it is valid (takeDraft).
  draft: string;
  onDraftChange: (draft: string) => void;
  // problem is the draft's own problem, shown under the field (set by Add or by the form's save).
  problem: string;
  onProblem: (problem: string) => void;
  // serverError is the field error of the last save (allowed_suffixes).
  serverError?: string;
  disabled?: boolean;
}

// takeDraft adds a typed entry the person did not add with the button: the list to save, or the problem's label key.
export function takeDraft(list: string[], draft: string): { list: string[]; problem: string } {
  if (draft.trim() === '') return { list, problem: '' };
  const problem = suffixProblem(draft, list);
  return problem ? { list, problem } : { list: [...list, draft.trim()], problem: '' };
}

// SuffixInput edits an allow-list of domain endings (A9): each entry is a chip with its own remove button, a new one
// is typed and added with Enter or the Add button, and the rules (two labels at least, letters, digits and hyphens) are
// told before the save. An empty list allows no name at all, which the warning below says.
export function SuffixInput({ value, onChange, draft, onDraftChange, problem, onProblem, serverError, disabled }: SuffixInputProps) {
  const { t } = useTranslation();
  const listId = useId();
  const add = () => {
    const r = takeDraft(value, draft);
    onProblem(r.problem);
    if (!r.problem && r.list !== value) {
      onChange(r.list);
      onDraftChange('');
    }
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== 'Enter') return;
    e.preventDefault(); // Enter adds the entry; it does not send the form
    add();
  };
  return (
    <Stack gap={6}>
      <div className={classes.addRow}>
        <TextInput
          label={t('acme.suffix.label')}
          description={t('acme.suffix.help')}
          value={draft}
          onChange={(e) => {
            onDraftChange(e.currentTarget.value);
            if (problem) onProblem('');
          }}
          onKeyDown={onKey}
          error={problem ? t(problem) : serverError}
          autoComplete="off"
          spellCheck={false}
          disabled={disabled}
          aria-describedby={value.length > 0 ? listId : undefined}
        />
        <Button variant="default" onClick={add} disabled={disabled || draft.trim() === ''}>
          {t('acme.suffix.add')}
        </Button>
      </div>
      {value.length > 0 ? (
        <ul className={classes.chips} id={listId} aria-label={t('acme.suffix.listLabel')}>
          {value.map((s) => (
            <li key={s} className={classes.chip}>
              <span className={classes.chipText} translate="no">
                {s}
              </span>
              <CloseButton size="sm" aria-label={t('acme.suffix.remove', { name: s })} disabled={disabled} onClick={() => onChange(value.filter((x) => x !== s))} />
            </li>
          ))}
        </ul>
      ) : (
        <Notice tone="warning" title={t('acme.suffix.emptyTitle')}>
          <Text size="sm">{t('acme.suffix.emptyText')}</Text>
        </Notice>
      )}
    </Stack>
  );
}
