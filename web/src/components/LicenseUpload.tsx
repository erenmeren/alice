import { Alert, Button, Group, Input, Stack, Text } from "@mantine/core";
import { useQueryClient } from "@tanstack/react-query";
import { useId, useState, type ChangeEvent } from "react";
import { useTranslation } from "react-i18next";
import { installLicense, previewLicense } from "../api/endpoints";
import type { LicenseUploadResult } from "../api/types";
import { formatDateTime } from "../datetime";
import { AppModal } from "./AppModal";
import { ErrorAlert } from "./ErrorAlert";
import { useStepUp } from "./StepUpProvider";

const MAX_LICENSE_BYTES = 64 * 1024;

// LicenseUpload reads a license file, lets the server check it (preview) and installs it
// after the administrator confirms what it says (spec §19.1).
export function LicenseUpload({
  onInstalled,
}: {
  onInstalled: (r: LicenseUploadResult) => void;
}) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const inputId = useId();
  const [text, setText] = useState<string | null>(null);
  const [preview, setPreview] = useState<LicenseUploadResult | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [tooLarge, setTooLarge] = useState(false);
  const fmt = (iso: string) => formatDateTime(iso, i18n.language);

  const choose = async (ev: ChangeEvent<HTMLInputElement>) => {
    setError(null);
    setPreview(null);
    setText(null);
    const file = ev.currentTarget.files?.[0];
    if (!file) return;
    // Check the size before reading: the server accepts at most 64 KiB (spec §16.3).
    if (file.size > MAX_LICENSE_BYTES) {
      setTooLarge(true);
      return;
    }
    setTooLarge(false);
    try {
      setText(await file.text());
    } catch (e) {
      setError(e);
    }
  };

  const check = async () => {
    if (text === null) return;
    setBusy(true);
    setError(null);
    try {
      setPreview(await run(() => previewLicense(text)));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    if (text === null) return;
    setBusy(true);
    setError(null);
    try {
      const res = await run(() => installLicense(text));
      setPreview(null);
      await client.invalidateQueries({ queryKey: ["license"] });
      onInstalled(res);
    } catch (e) {
      setPreview(null);
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const p = preview?.license;
  return (
    <Stack gap="sm">
      <ErrorAlert error={error} />
      {tooLarge && (
        <Alert color="red" role="alert">
          {t("license.upload.tooLarge")}
        </Alert>
      )}
      <Input.Wrapper
        id={inputId}
        label={t("license.upload.label")}
        description={t("license.upload.help")}
      >
        <input
          id={inputId}
          type="file"
          accept=".alicelic,.json,application/json"
          aria-describedby={`${inputId}-description`}
          onChange={(e) => void choose(e)}
        />
      </Input.Wrapper>
      <Group>
        <Button
          onClick={() => void check()}
          disabled={text === null}
          loading={busy && preview === null}
        >
          {t("license.upload.check")}
        </Button>
      </Group>
      <AppModal
        opened={preview !== null}
        onClose={() => setPreview(null)}
        title={t("license.upload.previewTitle")}
        centered
      >
        {preview && p && (
          <Stack>
            <Text>
              {t("license.upload.previewSummary", {
                customer: p.customer,
                max: p.max_targets,
                from: fmt(p.valid_from),
                until: fmt(p.valid_until),
              })}
            </Text>
            {preview.correction && (
              <Text size="sm">
                {t("license.upload.correction", { replaces: p.replaces })}
              </Text>
            )}
            {preview.already_expired && (
              <Alert color="yellow">{t("license.upload.alreadyExpired")}</Alert>
            )}
            {preview.pending && (
              <Alert color="blue">
                {t("license.upload.pending", { from: fmt(p.valid_from) })}
              </Alert>
            )}
            {preview.duplicate && (
              <Alert color="blue">{t("license.upload.duplicate")}</Alert>
            )}
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setPreview(null)}>
                {t("license.upload.cancel")}
              </Button>
              {!preview.duplicate && (
                <Button onClick={() => void confirm()} loading={busy}>
                  {t("license.upload.confirm")}
                </Button>
              )}
            </Group>
          </Stack>
        )}
      </AppModal>
    </Stack>
  );
}
