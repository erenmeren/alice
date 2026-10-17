import { Tooltip, VisuallyHidden } from '@mantine/core';
import type { TFunction } from 'i18next';
import { cloneElement, useId } from 'react';
import type { ReactElement } from 'react';
import { useTranslation } from 'react-i18next';
import { can } from '../api/capabilities';
import type { Capability } from '../api/capabilities';
import type { Target } from '../api/types';
import { softwareName } from './software';

// unavailableNote says a server's software does not have a feature yet.
export function unavailableNote(t: TFunction, target: Pick<Target, 'type'>): string {
  return t('webServer.notAvailable', { software: softwareName(t, target.type) });
}

// DisabledFeature shows a control the server's provider does not support yet disabled, not hidden, with the note as its
// tooltip (on a wrapper: a disabled button gets no pointer events) and as its accessible description.
export function DisabledFeature({
  target,
  capability,
  children,
}: {
  target: Pick<Target, 'type' | 'capabilities'>;
  capability: Capability;
  children: ReactElement<{ disabled?: boolean; 'aria-describedby'?: string }>;
}): ReactElement {
  const { t } = useTranslation();
  const id = useId();
  if (can(target, capability)) return children;
  const note = unavailableNote(t, target);
  return (
    <>
      <Tooltip label={note}>
        <span data-testid="disabled-feature" style={{ display: 'inline-block' }}>
          {cloneElement(children, { disabled: true, 'aria-describedby': id })}
        </span>
      </Tooltip>
      <VisuallyHidden id={id}>{note}</VisuallyHidden>
    </>
  );
}
