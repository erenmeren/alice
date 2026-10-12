import { Button, Divider, Stack, Text, Title } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { chooseEvaluation, getLicense } from "../../api/endpoints";
import { useAuth } from "../../auth/AuthProvider";
import { ErrorAlert } from "../../components/ErrorAlert";
import { LicenseUpload } from "../../components/LicenseUpload";
import { useStepUp } from "../../components/StepUpProvider";
import { InstallationID } from "../LicensePage";
import { Icon } from "../../design/Icon";
import { isGone } from "./gone";
import { StepActions, StepHeading } from "./SetupShell";
import classes from "./setup.module.css";

// LicenseStep is wizard step 6 (spec §18.5): upload the vendor's license, or start with the
// 30-day evaluation. The evaluation has run since Alice was first started (R27).
export function LicenseStep({
  onDone,
  onGone,
  done = false,
  back,
}: {
  onDone: () => void;
  onGone: () => void;
  // done: a license is already chosen (the step was reached with Back); Continue goes on without a new choice.
  done?: boolean;
  back?: ReactNode;
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
      <StepHeading title={t("setup.license.title")} intro={t("setup.license.help")} />
      {done && <Text>{t("setup.license.doneState")}</Text>}
      <ErrorAlert error={detail.error} />
      {detail.data && <InstallationID id={detail.data.installation_id} />}
      <div className={classes.choice}>
        <Title order={3} className={classes.choiceTitle}>
          {t("setup.license.uploadTitle")}
        </Title>
        <LicenseUpload onInstalled={() => void finish()} />
      </div>
      <Divider
        label={
          <Text span size="sm" c="dimmed">
            {t("setup.license.or")}
          </Text>
        }
        labelPosition="center"
      />
      <div className={classes.choice}>
        <ErrorAlert error={error} />
        <div>
          <Button variant="default" className={classes.wrapButton} onClick={() => void evaluate()} loading={busy}>
            {t("setup.license.evaluate")}
          </Button>
        </div>
        <p className={classes.hint}>{t("setup.license.evaluateHelp")}</p>
      </div>
      <StepActions back={back}>
        {done && (
          <Button onClick={onDone} rightSection={<Icon name="ArrowRight" size={15} />}>
            {t("ui.continue")}
          </Button>
        )}
      </StepActions>
    </Stack>
  );
}
