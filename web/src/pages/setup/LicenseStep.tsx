import { Button, Divider, Group, Stack, Text, Title } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { chooseEvaluation, getLicense } from "../../api/endpoints";
import { useAuth } from "../../auth/AuthProvider";
import { ErrorAlert } from "../../components/ErrorAlert";
import { LicenseUpload } from "../../components/LicenseUpload";
import { useStepUp } from "../../components/StepUpProvider";
import { InstallationID } from "../LicensePage";
import { isGone } from "./gone";

// LicenseStep is wizard step 6 (spec §18.5): upload the vendor's license, or start with the
// 30-day evaluation. The evaluation has run since Alice was first started (R27).
export function LicenseStep({
  onDone,
  onGone,
  done = false,
}: {
  onDone: () => void;
  onGone: () => void;
  // done: a license is already chosen (the step was reached with Back); Continue goes on without a new choice.
  done?: boolean;
}) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const { refreshSetupStatus } = useAuth();
  const detail = useQuery({
    queryKey: ["license", "detail"],
    queryFn: getLicense,
  });
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const finish = async () => {
    await refreshSetupStatus();
    onDone();
  };

  const evaluate = async () => {
    setBusy(true);
    setError(null);
    try {
      await run(chooseEvaluation); // settings.manage: a fresh code if the step-up expired
      await finish();
    } catch (e) {
      if (isGone(e)) return onGone();
      setError(e);
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Title order={2}>{t("setup.license.title")}</Title>
      {done && (
        <Group>
          <Text>{t("setup.license.doneState")}</Text>
          <Button onClick={onDone}>{t("ui.continue")}</Button>
        </Group>
      )}
      <Text>{t("setup.license.help")}</Text>
      <ErrorAlert error={detail.error} />
      {detail.data && <InstallationID id={detail.data.installation_id} />}
      <Title order={3} size="h4">
        {t("setup.license.uploadTitle")}
      </Title>
      <LicenseUpload onInstalled={() => void finish()} />
      <Divider
        label={
          <Text span size="sm" c="gray.8">
            {t("setup.license.or")}
          </Text>
        }
        labelPosition="center"
      />
      <ErrorAlert error={error} />
      <Button variant="default" onClick={() => void evaluate()} loading={busy}>
        {t("setup.license.evaluate")}
      </Button>
      <Text size="sm" c="gray.7">
        {t("setup.license.evaluateHelp")}
      </Text>
    </Stack>
  );
}
