import { Alert, Button, Checkbox, Stack, Text, TextInput } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../api/client';
import { updateLocation } from '../api/endpoints';
import { locationsKey } from '../api/queryKeys';
import type { CertificateLocation, LocationPatch } from '../api/types';
import { parsePort, validateSNI } from '../api/validation';
import { Icon } from '../design/Icon';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { SiteName } from './SiteName';
import { DialogActions } from './ui';

interface Props {
  // location is the latest copy of the website (the list refreshes it after a save or a 412).
  location: CertificateLocation;
  // canEdit: only an Administrator changes verification settings; others see them read-only.
  canEdit: boolean;
  onClose: () => void;
}

// LocationSettingsDialog shows a website's verification settings (port, name, skip) and, for an
// Administrator, saves them with If-Match set to the website's version. Only changed fields are
// sent; an empty port or name clears it. A form that fails stays as typed, except after a 412
// (someone changed the website meanwhile): then the current values are loaded and the person is
// told that their change was not saved.
export function LocationSettingsDialog({ location, canEdit, onClose }: Props) {
  const { t } = useTranslation();
  return (
    <AppModal opened onClose={onClose} title={t('locations.verify.title')} size="lg">
      <SettingsForm location={location} canEdit={canEdit} onClose={onClose} />
    </AppModal>
  );
}

const portText = (l: CertificateLocation) => (l.verify_port === null ? '' : String(l.verify_port));

function SettingsForm({ location, canEdit, onClose }: Props) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const [port, setPort] = useState(portText(location));
  const [sni, setSni] = useState(location.verify_sni);
  const [skip, setSkip] = useState(location.skip_verify);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);
  const [notSaved, setNotSaved] = useState(false);
  const [touched, setTouched] = useState(false);
  const reloadFrom = useRef<number | null>(null);

  // After a 412 the list gives a newer copy: the form takes its values.
  const version = location.version;
  useEffect(() => {
    // Only when the list really moved on from the version that was refused, and only if the person
    // has not typed since: a later change must never be overwritten.
    if (reloadFrom.current === null || version === reloadFrom.current) return;
    reloadFrom.current = null;
    setPort(portText(location));
    setSni(location.verify_sni);
    setSkip(location.skip_verify);
  }, [version, location]);

  const portValue = parsePort(port);
  const sniProblem = validateSNI(sni);
  const patch: LocationPatch = {};
  if (portValue !== null && portValue !== (location.verify_port ?? 0)) patch.verify_port = portValue;
  // The server folds the name to lower case, so "WWW.Example.test" equals what it stored.
  if (sni.trim().localeCompare(location.verify_sni, 'en', { sensitivity: 'accent' }) !== 0) patch.verify_sni = sni.trim();
  if (skip !== location.skip_verify) patch.skip_verify = skip;
  const changed = Object.keys(patch).length > 0;
  const valid = portValue !== null && sniProblem === null;
  const portError = touched && portValue === null ? t('locations.verify.portInvalid') : undefined;
  const sniError =
    touched && sniProblem
      ? t(sniProblem === 'ip' ? 'locations.verify.sniIp' : sniProblem === 'wildcard' ? 'locations.verify.sniWildcard' : 'locations.verify.sniInvalid')
      : undefined;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!canEdit || !valid || !changed) return;
    setBusy(true);
    setError(null);
    setSaved(false);
    setNotSaved(false);
    try {
      await updateLocation(location.id, location.version, patch);
      setSaved(true);
      setTouched(false);
    } catch (err) {
      setError(err);
      if (isApiError(err) && err.status === 412) {
        reloadFrom.current = location.version;
        setNotSaved(true);
      }
    }
    void client.invalidateQueries({ queryKey: locationsKey(location.target_id) });
    setBusy(false);
  };

  return (
    <form onSubmit={(e) => void submit(e)} noValidate>
      <Stack gap="sm">
        <Text size="sm" fw={600}>
          <SiteName loc={location} />
        </Text>
        <Text size="sm">{t('locations.verify.help')}</Text>
        {!canEdit && (
          <Alert color="gray" role="note" icon={<Icon name="Eye" size={17} />}>
            {t('locations.verify.readOnly')}
          </Alert>
        )}
        <TextInput
          label={t('locations.verify.port')}
          value={port}
          onChange={(e) => {
            reloadFrom.current = null;
            setPort(e.currentTarget.value);
          }}
          inputMode="numeric"
          disabled={!canEdit}
          error={portError}
          autoComplete="off"
          data-autofocus
        />
        <TextInput
          label={t('locations.verify.sni')}
          value={sni}
          onChange={(e) => {
            reloadFrom.current = null;
            setSni(e.currentTarget.value);
          }}
          disabled={!canEdit}
          error={sniError}
          maxLength={253}
          autoComplete="off"
          spellCheck={false}
        />
        <Checkbox
          label={t('locations.verify.skip')}
          description={t('locations.verify.skipHelp')}
          checked={skip}
          onChange={(e) => {
            reloadFrom.current = null;
            setSkip(e.currentTarget.checked);
          }}
          disabled={!canEdit}
        />
        {touched && canEdit && valid && !changed && <Text size="sm">{t('locations.verify.nothingChanged')}</Text>}
        {saved && (
          <Alert color="green" role="status">
            {t('locations.verify.saved')}
          </Alert>
        )}
        <ErrorAlert error={error} />
        {notSaved && (
          <Alert color="yellow" role="status">
            {t('locations.verify.notSaved')}
          </Alert>
        )}
      </Stack>
      <DialogActions>
        <Button variant="default" onClick={onClose}>
          {canEdit ? t('locations.verify.cancel') : t('locations.verify.close')}
        </Button>
        {canEdit && (
          <Button type="submit" loading={busy}>
            {t('locations.verify.save')}
          </Button>
        )}
      </DialogActions>
    </form>
  );
}
