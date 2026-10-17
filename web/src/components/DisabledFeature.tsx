import { Tooltip, VisuallyHidden } from '@mantine/core';
import type { TFunction } from 'i18next';
import { cloneElement, useId } from 'react';
import type { MouseEvent, ReactElement } from 'react';
import { useTranslation } from 'react-i18next';
import { can } from '../api/capabilities';
import type { Capability } from '../api/capabilities';
import type { Target } from '../api/types';
import { softwareName } from './software';

// unavailableNote says a server's software does not have a feature yet.
export function unavailableNote(t: TFunction, target: Pick<Target, 'type'>): string {
  return t('webServer.notAvailable', { software: softwareName(t, target.type) });
}

// DisabledFeature shows a control the server's provider does not support yet aria-disabled, not hidden, with the note as
// its tooltip (on hover, touch and keyboard focus) and as its accessible description. The control is not `disabled`:
// it stays a tab stop so the note is reachable by keyboard; its click is swallowed.
export function DisabledFeature({
  target,
  capability,
  children,
}: {
  target: Pick<Target, 'type' | 'capabilities'>;
  capability: Capability;
  children: ReactElement<{ onClick?: (e: MouseEvent<HTMLElement>) => void; 'aria-describedby'?: string; 'aria-disabled'?: boolean; 'data-disabled'?: boolean }>;
}): ReactElement {
  const { t } = useTranslation();
  const id = useId();
  if (can(target, capability)) return children;
  const note = unavailableNote(t, target);
  return (
    <>
      <Tooltip label={note} events={{ hover: true, focus: true, touch: true }}>
        <span data-testid="disabled-feature" style={{ display: 'inline-block' }}>
          {cloneElement(children, {
            'aria-disabled': true,
            'data-disabled': true,
            'aria-describedby': id,
            onClick: (e: MouseEvent<HTMLElement>) => e.preventDefault(),
          })}
        </span>
      </Tooltip>
      <VisuallyHidden id={id}>{note}</VisuallyHidden>
    </>
  );
}
