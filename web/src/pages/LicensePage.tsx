import {
  Alert,
  Button,
  Code,
  CopyButton,
  Group,
  Paper,
  Progress,
  Stack,
  Table,
  Text,
  Title,
} from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { getLicense } from "../api/endpoints";
import type { LicenseUploadResult } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { PageLoader } from "../auth/guards";
import { ErrorAlert } from "../components/ErrorAlert";
import { LicenseUpload } from "../components/LicenseUpload";
import { formatDateTime } from "../datetime";

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
  const detail = useQuery({
    queryKey: ["license", "detail"],
    queryFn: getLicense,
  });
  const [installed, setInstalled] = useState<LicenseUploadResult | null>(null);
  const fmt = (iso: string) => formatDateTime(iso, i18n.language);
  const phase = (p: string) =>
    i18n.exists(`license.phase.${p}`) ? t(`license.phase.${p}`) : p;
  const d = detail.data;

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

  return (
    <Stack gap="lg">
      <Title order={1}>{t("license.title")}</Title>
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
          <Paper withBorder p="md">
            <Stack gap="xs">
              <Title order={2} size="h3">
                {t("license.installation.title")}
              </Title>
              <Text size="sm">{t("license.installation.help")}</Text>
              <InstallationID id={d.installation_id} />
            </Stack>
          </Paper>

          <Paper withBorder p="md">
            <Stack gap="xs">
              <Title order={2} size="h3">
                {t("license.current.title")}
              </Title>
              <Text fw={700} data-testid="license-phase">
                {phase(d.phase)}
              </Text>
              {d.current ? (
                <>
                  <Text data-testid="license-summary">
                    {t("license.current.summary", {
                      date: fmt(d.current.valid_until),
                      count: d.current.max_targets,
                    })}
                  </Text>
                  <Text size="sm">
                    {t("license.current.customer", {
                      customer: d.current.customer,
                      id: d.current.license_id,
                    })}
                  </Text>
                </>
              ) : (
                <Text data-testid="license-summary">
                  {t("license.current.evaluation", {
                    count: d.days_left,
                    max: d.max_targets,
                  })}
                </Text>
              )}
              <Text size="sm">
                {t("license.current.usage", {
                  used: d.targets_used,
                  max: d.max_targets,
                })}
              </Text>
              <Progress
                value={
                  d.max_targets > 0
                    ? Math.min(100, (d.targets_used * 100) / d.max_targets)
                    : 0
                }
                aria-label={t("license.current.usageLabel")}
              />
              {d.pending && (
                <Text size="sm">
                  {t("license.current.pending", {
                    id: d.pending.license_id,
                    date: fmt(d.pending.valid_from),
                  })}
                </Text>
              )}
              {d.tampered && (
                <Alert color="red" role="alert">
                  {t("license.current.tampered")}
                </Alert>
              )}
            </Stack>
          </Paper>

          {session?.user.role === "admin" && (
            <Paper withBorder p="md">
              <Stack gap="xs">
                <Title order={2} size="h3">
                  {t("license.upload.title")}
                </Title>
                <LicenseUpload onInstalled={setInstalled} />
              </Stack>
            </Paper>
          )}

          {d.files.length > 0 && (
            <Table.ScrollContainer minWidth={560}>
              <Table striped aria-label={t("license.files.title")}>
                <Table.Caption>{t("license.files.title")}</Table.Caption>
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
                    <Table.Tr
                      key={`${f.uploaded_at}-${f.license?.license_id ?? "invalid"}`}
                    >
                      <Table.Td>{f.license?.license_id ?? ""}</Table.Td>
                      <Table.Td>{f.license?.customer ?? ""}</Table.Td>
                      <Table.Td>
                        {f.license ? fmt(f.license.valid_until) : ""}
                      </Table.Td>
                      <Table.Td>{t(`license.fileStatus.${f.status}`)}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}

          {d.history.length > 0 && (
            <Table.ScrollContainer minWidth={560}>
              <Table striped aria-label={t("license.history.title")}>
                <Table.Caption>{t("license.history.title")}</Table.Caption>
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
                      <Table.Td>{h.license_id}</Table.Td>
                      <Table.Td>
                        {h.from_state && h.to_state
                          ? t("license.change", {
                              from: phase(h.from_state),
                              to: phase(h.to_state),
                            })
                          : ""}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
        </>
      )}
    </Stack>
  );
}
