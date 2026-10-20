import { Alert, Button, Code, CopyButton, Group, Progress, Stack, Table, Title } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { getLicense } from "../api/endpoints";
import type { LicenseFileEntry, LicensePhase, LicenseUploadResult } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { PageLoader } from "../auth/guards";
import { ErrorAlert } from "../components/ErrorAlert";
import { LicenseUpload } from "../components/LicenseUpload";
import { FactList, Notice, PageHeader, Panel, StatusBadge, type Tone } from "../components/ui";
import { formatDateTime } from "../datetime";
import { Icon } from "../design/Icon";
import classes from "./LicensePage.module.css";

const PHASE_TONE: Record<LicensePhase, Tone> = {
  evaluation: "info",
  evaluation_expired: "danger",
  active: "success",
  // Grace is danger like the server's grace banner (internal/license/banners.go) and docs/licensing.md.
  grace: "danger",
  locked: "danger",
};
const FILE_TONE: Record<LicenseFileEntry["status"], Tone> = {
  current: "success",
  pending: "info",
  superseded: "neutral",
  invalid: "danger",
};
const RULES = [1, 2, 3] as const;

// InstallationID shows the ID with a Copy button (spec §19.1 step 1).
export function InstallationID({ id }: { id: string }) {
  const { t } = useTranslation();
  return (
    <Group gap="xs">
      <Code data-testid="installation-id" fz="md">
        {id}
      </Code>
      <CopyButton value={id}>
        {({ copied, copy }) => (
          <Button size="xs" variant="default" onClick={copy}>
            {copied
              ? t("license.installation.copied")
              : t("license.installation.copy")}
          </Button>
        )}
      </CopyButton>
    </Group>
  );
}

export function LicensePage() {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const admin = session?.user.role === "admin";
  const detail = useQuery({
    queryKey: ["license", "detail"],
    queryFn: getLicense,
  });
  const [installed, setInstalled] = useState<LicenseUploadResult | null>(null);
  const uploadRef = useRef<HTMLDivElement>(null);
  const fmt = (iso: string) => formatDateTime(iso, i18n.language);
  const phase = (p: string) =>
    i18n.exists(`license.phase.${p}`) ? t(`license.phase.${p}`) : p;
  // The history names the evaluation "evaluation" in place of a license ID.
  const licenseName = (id: string) =>
    id === "evaluation" ? t("license.history.evaluation") : id;
  // noticeText names a one-time notice from its stored key ("expiry:30", "grace:2",
  // "clock_behind:2026-10-20", "tampered:<file id>", …); an unknown key is shown as stored.
  const noticeText = (notice: string) => {
    const sep = notice.indexOf(":");
    const kind = sep < 0 ? notice : notice.slice(0, sep);
    const arg = sep < 0 ? "" : notice.slice(sep + 1);
    const key = `license.notice.${kind}`;
    if (!i18n.exists(key) && !i18n.exists(`${key}_other`)) return notice;
    const n = Number(arg);
    return t(key, { count: Number.isInteger(n) ? n : 0, day: arg, date: arg });
  };
  // The header's Upload takes an administrator to the upload section's file field.
  const focusUpload = () => uploadRef.current?.querySelector<HTMLInputElement>('input[type="file"]')?.focus();
  const d = detail.data;
  const evaluation = d?.phase === "evaluation" || d?.phase === "evaluation_expired";
  const usagePct = d && d.max_targets > 0 ? Math.min(100, Math.round((d.targets_used * 100) / d.max_targets)) : 0;

  let installedText = "";
  if (installed) {
    installedText = installed.already_expired
      ? t("license.upload.installedExpired")
      : installed.pending
        ? t("license.upload.installedPending", {
            from: fmt(installed.license.valid_from),
          })
        : t("license.upload.activated");
  }

  // phaseNotice says what the phase means for the installation: in lock (and after the evaluation)
  // external changes pause while inventory, exports, the audit trail and backups stay available.
  const phaseNotice = () => {
    if (!d) return null;
    switch (d.phase) {
      case "locked":
        // The continuity window (owner decision 2026-10-20): certificates already managed keep renewing and
        // deploying until continuity_ends_at; after it the notice says that this stopped too.
        if (d.continuity_ends_at && d.continuity_days_left > 0) {
          return (
            <Notice tone="danger" title={t("license.page.continuityTitle")} testId="license-continuity">
              {t("license.page.continuityText", { date: fmt(d.continuity_ends_at), count: d.continuity_days_left })}
            </Notice>
          );
        }
        return (
          <Notice tone="danger" title={t("license.page.lockedTitle")}>
            {t("license.page.lockedText")}
            {d.continuity_ends_at && <> {t("license.page.continuityEnded", { date: fmt(d.continuity_ends_at) })}</>}
          </Notice>
        );
      case "evaluation_expired":
        return (
          <Notice tone="danger" title={t("license.page.evaluationEndedTitle")}>
            {t("license.page.lockedText")}
          </Notice>
        );
      case "grace":
        return (
          <Notice tone="danger" title={t("license.page.graceTitle")}>
            {t("license.page.graceText", { date: fmt(d.locks_at) })}
          </Notice>
        );
      case "evaluation":
        return (
          <Notice tone="info" title={t("license.page.evaluationTitle")}>
            {t("license.page.evaluationText")}
          </Notice>
        );
      default:
        return null;
    }
  };

  return (
    <Stack gap="lg">
      <PageHeader
        title={t("license.title")}
        description={t("license.page.description")}
        actions={
          admin &&
          d && (
            <Button variant="filled" leftSection={<Icon name="Upload" size={15} />} onClick={focusUpload}>
              {t("license.page.upload")}
            </Button>
          )
        }
      />
      {installed && (
        <Alert
          color={installed.already_expired ? "yellow" : "green"}
          role="status"
          data-testid="license-installed"
        >
          {installedText}
        </Alert>
      )}
      {detail.isPending && <PageLoader />}
      {detail.isError && <ErrorAlert error={detail.error} />}
      {d && (
        <>
          {phaseNotice()}
          {d.tampered && (
            <Notice tone="danger" role="alert" title={t("license.notice.tampered")}>
              {t("license.current.tampered")}
            </Notice>
          )}

          <div className={classes.grid}>
            <section className={classes.licenseCard}>
              <div className={classes.cardHead}>
                <span className={classes.eyebrow}>{t("license.page.eyebrow")}</span>
                <StatusBadge tone={PHASE_TONE[d.phase] ?? "neutral"} testId="license-phase">
                  {phase(d.phase)}
                </StatusBadge>
              </div>
              <Title order={2} className={classes.customer}>
                {d.current ? d.current.customer : evaluation ? t("license.history.evaluation") : phase(d.phase)}
              </Title>
              {d.current && (
                <p className={classes.licenseNumber} translate="no">
                  {d.current.license_id}
                </p>
              )}
              {d.current ? (
                <p className={classes.summary} data-testid="license-summary">
                  {t("license.current.summary", {
                    date: fmt(d.current.valid_until),
                    count: d.current.max_targets,
                  })}
                </p>
              ) : (
                <p className={classes.summary} data-testid="license-summary">
                  {d.phase === "evaluation"
                    ? t("license.current.evaluation", {
                        count: d.days_left,
                        max: d.max_targets,
                      })
                    : phase(d.phase)}
                </p>
              )}
              <div className={classes.usage}>
                <div className={classes.usageHead}>
                  <Title order={3} className={classes.usageTitle}>
                    {t("license.page.usage")}
                  </Title>
                  <span className={classes.usageValue}>
                    {t("license.current.usage", {
                      used: d.targets_used,
                      max: d.max_targets,
                    })}
                  </span>
                </div>
                {d.max_targets > 0 && (
                  // A bar cannot draw more than 100 %: over the limit it turns the warning color and reads the
                  // real numbers ("12 of 10 targets used") instead of Mantine's "100%".
                  <Progress.Root className={classes.progress} size={5} radius={5}>
                    <Progress.Section
                      value={usagePct}
                      color={d.targets_used > d.max_targets ? "var(--alice-warning)" : undefined}
                      withAria={false}
                      role="progressbar"
                      aria-label={t("license.current.usageLabel")}
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-valuenow={usagePct}
                      aria-valuetext={t("license.current.usage", { used: d.targets_used, max: d.max_targets })}
                    />
                  </Progress.Root>
                )}
                <p className={classes.small}>{t("license.page.usageHelp")}</p>
              </div>
              {d.pending && (
                <p className={classes.small}>
                  {t("license.current.pending", {
                    id: d.pending.license_id,
                    date: fmt(d.pending.valid_from),
                  })}
                </p>
              )}
              <FactList
                facts={[
                  ...(d.ends_at ? [{ key: "ends", label: t("license.page.ends"), value: fmt(d.ends_at) }] : []),
                  {
                    key: "installation",
                    label: t("license.installation.title"),
                    value: (
                      <>
                        <InstallationID id={d.installation_id} />
                        <p className={classes.help}>{t("license.installation.help")}</p>
                      </>
                    ),
                  },
                ]}
              />
            </section>

            <div className={classes.stack}>
              <Panel title={t("license.page.renewal")}>
                <ol role="list" className={classes.ruleList}>
                  {RULES.map((n) => (
                    <li key={n} className={classes.ruleItem}>
                      <span className={classes.ruleNum} aria-hidden="true">
                        {`0${n}`}
                      </span>
                      <div>
                        <Title order={3} className={classes.ruleTitle}>
                          {t(`license.page.rule${n}Title`)}
                        </Title>
                        <p className={classes.ruleText}>{t(`license.page.rule${n}`)}</p>
                      </div>
                    </li>
                  ))}
                </ol>
              </Panel>

              {d.history.length > 0 && (
                <Panel title={t("license.history.title")} padded={false}>
                  <Table.ScrollContainer minWidth={520}>
                    <Table aria-label={t("license.history.title")}>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th>{t("license.history.columns.time")}</Table.Th>
                          <Table.Th>{t("license.history.columns.event")}</Table.Th>
                          <Table.Th>{t("license.history.columns.license")}</Table.Th>
                          <Table.Th>{t("license.history.columns.change")}</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {d.history.map((h, i) => (
                          <Table.Tr key={`${h.at}-${i}`}>
                            <Table.Td>{fmt(h.at)}</Table.Td>
                            <Table.Td>{t(`license.event.${h.event}`)}</Table.Td>
                            <Table.Td>{licenseName(h.license_id)}</Table.Td>
                            <Table.Td>
                              {h.from_state && h.to_state
                                ? t("license.change", {
                                    from: phase(h.from_state),
                                    to: phase(h.to_state),
                                  })
                                : h.notice
                                  ? noticeText(h.notice)
                                  : ""}
                            </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </Table.ScrollContainer>
                </Panel>
              )}
            </div>
          </div>

          {admin && (
            <div ref={uploadRef}>
              <Panel title={t("license.upload.title")}>
                <LicenseUpload onInstalled={setInstalled} />
              </Panel>
            </div>
          )}

          {d.files.length > 0 && (
            <Panel title={t("license.files.title")} padded={false}>
              <Table.ScrollContainer minWidth={560}>
                <Table aria-label={t("license.files.title")}>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>{t("license.files.columns.license")}</Table.Th>
                      <Table.Th>{t("license.files.columns.customer")}</Table.Th>
                      <Table.Th>{t("license.files.columns.validUntil")}</Table.Th>
                      <Table.Th>{t("license.files.columns.status")}</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {d.files.map((f) => (
                      <Table.Tr key={`${f.uploaded_at}-${f.license?.license_id ?? "invalid"}`}>
                        <Table.Td>
                          {f.license && <Code translate="no">{f.license.license_id}</Code>}
                        </Table.Td>
                        <Table.Td>{f.license?.customer ?? ""}</Table.Td>
                        <Table.Td>{f.license ? fmt(f.license.valid_until) : ""}</Table.Td>
                        <Table.Td>
                          <StatusBadge tone={FILE_TONE[f.status] ?? "neutral"} size="sm">
                            {t(`license.fileStatus.${f.status}`)}
                          </StatusBadge>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            </Panel>
          )}
        </>
      )}
    </Stack>
  );
}
