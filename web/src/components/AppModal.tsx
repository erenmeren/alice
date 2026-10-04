import { Modal, type ModalProps } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

// AppModal is Mantine's Modal with a translated name on its icon-only close button
// (axe "button-name": a button without an accessible name is a critical violation).
//
// It also returns keyboard focus to the control that opened it when the modal was MOUNTED already
// open (`{x && <Dialog opened … />}`, the pattern of most dialogs here): Mantine remembers the
// focused element only when `opened` changes after mounting, so such a dialog used to leave focus on
// the page body when it closed or unmounted. The element focused when the modal mounts is
// remembered and focused again when the modal closes or unmounts while open (if it is still on the
// page). A modal mounted closed and opened later is left to Mantine.
export function AppModal({ closeButtonProps, opened, ...props }: ModalProps) {
  const { t } = useTranslation();
  // Read once, while the first render runs and before the modal takes focus.
  const [opener] = useState<HTMLElement | null>(() => (opened && document.activeElement instanceof HTMLElement ? document.activeElement : null));
  const pending = useRef(opener !== null);
  const openRef = useRef(opened);

  const giveBack = () => {
    if (!pending.current) return;
    pending.current = false;
    if (opener && opener.isConnected && opener !== document.body) opener.focus({ preventScroll: true });
  };

  useEffect(() => {
    openRef.current = opened;
    if (!opened) giveBack();
    // giveBack reads refs only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opened]);

  // On unmount: given back after the commit, and only if the modal really went away (React's
  // development double mount runs this cleanup and mounts again at once).
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (!openRef.current) return;
      window.setTimeout(() => {
        if (!mounted.current) giveBack();
      }, 0);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return <Modal opened={opened} closeButtonProps={{ 'aria-label': t('ui.close'), ...closeButtonProps }} {...props} />;
}
