import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import type { LicenseUploadResult } from "../api/types";
import {
  errorResponse,
  licenseDetailFixture,
  licenseInfoFixture,
  sessionFor,
  sessionHandlers,
} from "../test/fixtures";
import { expectNoRawKeys } from "../test/i18nAssert";
import { renderRoute } from "../test/render";
import { server } from "../test/server";
import classes from "./LicensePage.module.css";

const fileText = '{\n  "format": 1,\n  "key_id": "vk-2026-01"\n}\n';
const result: LicenseUploadResult = {
  license: { ...licenseInfoFixture, customer: "Test Company", max_targets: 25 },
  pending: false,
  already_expired: false,
  correction: false,
  duplicate: false,
  phase: "active",
};

async function chooseFile() {
  const input = screen.getByLabelText("License file");
  await userEvent.upload(
    input,
    new File([fileText], "alice-license-test.alicelic", {
      type: "application/json",
    }),
  );
  await userEvent.click(screen.getByRole("button", { name: "Check the file" }));
}

describe("license page", () => {
  it("shows the installation ID, the license in force and the history", async () => {
    server.use(...sessionHandlers(sessionFor("admin")));
    await renderRoute("/license");
    expect(
      await screen.findByRole("heading", { name: "License", level: 1 }),
    ).toBeInTheDocument();
    expect(await screen.findByTestId("installation-id")).toHaveTextContent(
      "ALICE-7F3K-9Q2M-XD41-B8TC",
    );
    expect(screen.getByRole("button", { name: "Copy" })).toBeInTheDocument();
    expect(screen.getByTestId("license-phase")).toHaveTextContent("Active");
    expect(screen.getByTestId("license-summary")).toHaveTextContent(
      /^Valid until .*2027.*, 10 targets$/,
    );
    expect(
      screen.getByRole("heading", { level: 2, name: "Örnek Bankası A.Ş." }),
    ).toBeInTheDocument();
    expect(screen.getByText("LIC-2026-000123", { selector: "p" })).toBeInTheDocument();
    expect(screen.getByText("3 of 10 targets used")).toBeInTheDocument();
    const history = screen.getByRole("table", { name: "History" });
    expect(within(history).getByText("License installed")).toBeInTheDocument();
    expect(
      within(history).getByText("Evaluation → Active"),
    ).toBeInTheDocument();
  });

  it("has the design header, the license card with usage, the renewal rules and the history", async () => {
    server.use(...sessionHandlers(sessionFor("admin")));
    await renderRoute("/license");
    expect(
      await screen.findByRole("heading", { name: "License", level: 1 }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("A predictable annual license. Your data stays yours."),
    ).toBeInTheDocument();
    await screen.findByTestId("installation-id");
    // No phase notice for an active license.
    expect(screen.queryByRole("note")).not.toBeInTheDocument();

    // The license card: eyebrow, phase badge, customer, license number, usage and facts.
    const card = screen.getByTestId("license-phase").closest(`.${classes.licenseCard}`) as HTMLElement;
    expect(card).not.toBeNull();
    expect(within(card).getByText("Alice license")).toBeInTheDocument();
    expect(screen.getByTestId("license-phase")).toHaveAttribute("data-tone", "success");
    expect(screen.getByTestId("license-phase")).toHaveTextContent(/^Active$/);
    expect(within(card).getByRole("heading", { level: 2, name: "Örnek Bankası A.Ş." })).toBeInTheDocument();
    expect(within(card).getByTestId("license-summary")).toHaveTextContent(/^Valid until .*2027.*, 10 targets$/);
    expect(within(card).getByRole("heading", { level: 3, name: "Managed targets" })).toBeInTheDocument();
    expect(within(card).getByText("3 of 10 targets used")).toBeInTheDocument();
    expect(within(card).getByRole("progressbar", { name: "Targets used" })).toHaveAttribute("aria-valuenow", "30");
    expect(within(card).getByText("Certificates and keys are not counted.")).toBeInTheDocument();
    expect(within(card).getByText("License end")).toBeInTheDocument();
    expect(within(card).getByText("Installation ID")).toBeInTheDocument();
    expect(within(card).getByTestId("installation-id")).toBeInTheDocument();

    // The renewal rules: three numbered rules.
    const rules = screen.getByRole("heading", { level: 2, name: "What happens at renewal?" }).closest("section")!;
    // An ordered list (role=list keeps it a list for VoiceOver after list-style: none); the 01–03 tiles are hidden.
    const list = within(rules).getByRole("list");
    expect(list.tagName).toBe("OL");
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(3);
    expect(items.map((i) => within(i).getByRole("heading", { level: 3 }).textContent)).toEqual([
      "Upload the signed file",
      "Seven-day grace period",
      "Your inventory remains accessible",
    ]);
    expect(items.map((i) => i.querySelector(`.${classes.ruleNum}`)?.textContent)).toEqual(["01", "02", "03"]);

    // History and uploaded files as titled panels with their tables; file states as badges.
    expect(screen.getByRole("heading", { level: 2, name: "History" })).toBeInTheDocument();
    const files = screen.getByRole("table", { name: "Uploaded licenses" });
    expect(within(files).getByText("In use").closest(".mantine-Badge-root")).toHaveAttribute("data-tone", "success");

    // The upload section is a panel; the header action takes the administrator to its file field.
    expect(screen.getByRole("heading", { level: 2, name: "Upload a license" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Upload license" }));
    expect(screen.getByLabelText("License file")).toHaveFocus();
    expectNoRawKeys();
  });

  it("offers no upload to auditors", async () => {
    server.use(...sessionHandlers(sessionFor("auditor")));
    await renderRoute("/license");
    await screen.findByTestId("installation-id");
    expect(screen.queryByRole("button", { name: "Upload license" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Upload a license" })).not.toBeInTheDocument();
  });

  it("shows the lock as a danger notice: changes paused, inventory, exports, audit and backups available", async () => {
    server.use(
      ...sessionHandlers(sessionFor("auditor")),
      http.get("/api/v1/license", () =>
        HttpResponse.json({ ...licenseDetailFixture, phase: "locked", days_left: 0 }),
      ),
    );
    await renderRoute("/license");
    expect(await screen.findByTestId("license-phase")).toHaveTextContent(/^Expired, locked$/);
    expect(screen.getByTestId("license-phase")).toHaveAttribute("data-tone", "danger");
    const note = screen.getByRole("note");
    expect(note).toHaveTextContent("License expired · external changes paused");
    expect(note).toHaveTextContent("Inventory, exports, the audit trail and backups remain available. Renew the license to resume changes.");
    expect(note.getAttribute("style")).toContain("--alert-bg: var(--alice-danger-soft)");
  });

  it("shows usage over the limit honestly: a full bar in the warning tone that reads the real numbers", async () => {
    server.use(
      ...sessionHandlers(sessionFor("auditor")),
      http.get("/api/v1/license", () => HttpResponse.json({ ...licenseDetailFixture, targets_used: 12 })),
    );
    await renderRoute("/license");
    const bar = await screen.findByRole("progressbar", { name: "Targets used" });
    expect(screen.getByText("12 of 10 targets used")).toBeInTheDocument();
    // The bar cannot draw 120 %; it says the real usage to a screen reader and turns the warning color.
    expect(bar).toHaveAttribute("aria-valuetext", "12 of 10 targets used");
    expect(bar.getAttribute("style")).toContain("var(--alice-warning)");
  });

  it("explains the grace period, the evaluation and its end", async () => {
    const detail = (over: object) =>
      http.get("/api/v1/license", () => HttpResponse.json({ ...licenseDetailFixture, ...over }));
    server.use(...sessionHandlers(sessionFor("admin")), detail({ phase: "grace", grace_day: 2 }));
    const first = await renderRoute("/license");
    // Grace is danger, as the server's banner (internal/license/banners.go) and docs/licensing.md ("red banner") say.
    expect(await screen.findByTestId("license-phase")).toHaveAttribute("data-tone", "danger");
    let note = screen.getByRole("note");
    expect(note).toHaveTextContent("License expired · grace period");
    expect(note).toHaveTextContent(/^.*Full operation continues until .*2027.*\. Then external changes pause/);
    expect(note.getAttribute("style")).toContain("--alert-bg: var(--alice-danger-soft)");
    first.unmount();

    server.use(detail({ phase: "evaluation", current: null, max_targets: 5, days_left: 30, files: [], history: [] }));
    const second = await renderRoute("/license");
    expect(await screen.findByTestId("license-phase")).toHaveAttribute("data-tone", "info");
    note = screen.getByRole("note");
    expect(note).toHaveTextContent("Evaluation license");
    expect(note).toHaveTextContent("An evaluation has no grace period");
    expect(screen.getByRole("heading", { level: 2, name: "Evaluation" })).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    second.unmount();

    server.use(detail({ phase: "evaluation_expired", current: null, max_targets: 5, days_left: 0, files: [], history: [] }));
    await renderRoute("/license");
    expect(await screen.findByTestId("license-phase")).toHaveAttribute("data-tone", "danger");
    note = screen.getByRole("note");
    expect(note).toHaveTextContent("Evaluation ended · external changes paused");
    expect(note).toHaveTextContent("Inventory, exports, the audit trail and backups remain available.");
  });

  it("says when a license file was damaged and draws no usage bar without a target limit", async () => {
    server.use(
      ...sessionHandlers(sessionFor("admin")),
      http.get("/api/v1/license", () =>
        HttpResponse.json({
          ...licenseDetailFixture,
          tampered: true,
          max_targets: 0,
          files: [{ status: "invalid", uploaded_at: "2026-10-02T09:00:00Z", license: null }],
        }),
      ),
    );
    await renderRoute("/license");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Changed license file");
    expect(alert).toHaveTextContent("A stored license file was changed outside Alice and is ignored.");
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
    const files = screen.getByRole("table", { name: "Uploaded licenses" });
    expect(within(files).getByText("Damaged").closest(".mantine-Badge-root")).toHaveAttribute("data-tone", "danger");
  });

  it("shows a license that starts later, the file states and a phase this version does not know", async () => {
    const pending = { ...licenseInfoFixture, license_id: "LIC-2027-000200", valid_from: "2027-09-30T00:00:00Z" };
    server.use(
      ...sessionHandlers(sessionFor("auditor")),
      http.get("/api/v1/license", () =>
        HttpResponse.json({
          ...licenseDetailFixture,
          phase: "future_phase",
          pending,
          ends_at: "",
          files: [
            { status: "pending", uploaded_at: "2026-10-03T09:00:00Z", license: pending },
            { status: "superseded", uploaded_at: "2026-10-02T09:00:00Z", license: licenseInfoFixture },
            { status: "archived", uploaded_at: "2026-10-01T09:00:00Z", license: { ...licenseInfoFixture, license_id: "LIC-OLD" } },
          ],
          history: [{ at: "2026-10-01T09:00:00Z", event: "renewed", license_id: "LIC-2026-000123", from_state: "", to_state: "", notice: null }],
        }),
      ),
    );
    await renderRoute("/license");
    const badge = await screen.findByTestId("license-phase");
    expect(badge).toHaveTextContent(/^future_phase$/);
    expect(badge).toHaveAttribute("data-tone", "neutral");
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
    expect(screen.getByText(/^A new license \(LIC-2027-000200\) starts on .*2027/)).toBeInTheDocument();
    expect(screen.queryByText("License end")).not.toBeInTheDocument();
    const files = screen.getByRole("table", { name: "Uploaded licenses" });
    expect(within(files).getByText("Starts later").closest(".mantine-Badge-root")).toHaveAttribute("data-tone", "info");
    expect(within(files).getByText("Replaced").closest(".mantine-Badge-root")).toHaveAttribute("data-tone", "neutral");
    expect(within(files).getByText("LIC-OLD").closest("tr")!.querySelector(".mantine-Badge-root")).toHaveAttribute("data-tone", "neutral");
    expect(within(screen.getByRole("table", { name: "History" })).getByText("License renewed")).toBeInTheDocument();
  });

  it("previews and installs a license (§19.1)", async () => {
    const bodies: unknown[] = [];
    server.use(
      ...sessionHandlers(sessionFor("admin")),
      http.post("/api/v1/license/preview", async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json(result);
      }),
      http.post("/api/v1/license", async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json(result);
      }),
    );
    await renderRoute("/license");
    await screen.findByTestId("installation-id");
    await chooseFile();
    const dialog = await screen.findByRole("dialog", {
      name: "Confirm the license",
    });
    expect(dialog).toHaveTextContent(
      "Licensed to Test Company. Up to 25 managed targets. Valid from",
    );
    await userEvent.click(
      within(dialog).getByRole("button", { name: "Install license" }),
    );
    expect(await screen.findByTestId("license-installed")).toHaveTextContent(
      "License activated. All features are available again.",
    );
    expect(bodies).toEqual([{ license: fileText }, { license: fileText }]);
  });

  it("explains an edited file and a license for another installation", async () => {
    let call = 0;
    server.use(
      ...sessionHandlers(sessionFor("admin")),
      http.post("/api/v1/license/preview", () => {
        call += 1;
        return call === 1
          ? errorResponse(422, "ALC-LIC-0002", "license.invalid")
          : errorResponse(422, "ALC-LIC-0003", "license.wrong_installation", {
              params: { expected: "D41B8T", got: "Q2MXD4" },
            });
      }),
    );
    await renderRoute("/license");
    await screen.findByTestId("installation-id");
    await chooseFile();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "This file is not a valid Alice license.",
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Check the file" }),
    );
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        "This license file was made for a different installation (ending in Q2MXD4).",
      ),
    );
    expect(
      screen.queryByRole("dialog", { name: "Confirm the license" }),
    ).not.toBeInTheDocument();
  });

  it("asks to update Alice for a license in a newer format", async () => {
    server.use(
      ...sessionHandlers(sessionFor("admin")),
      http.post("/api/v1/license/preview", () => errorResponse(422, "ALC-LIC-0006", "license.unsupported_format")),
    );
    await renderRoute("/license");
    await screen.findByTestId("installation-id");
    await chooseFile();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("This license needs a newer version of Alice.");
    expect(alert).toHaveTextContent("Update Alice, then upload the file again. The current license stays in use meanwhile.");
  });

  it("says so when the installed license has already expired (L-32)", async () => {
    server.use(
      ...sessionHandlers(sessionFor("admin")),
      http.post("/api/v1/license/preview", () =>
        HttpResponse.json({ ...result, already_expired: true, phase: "grace" }),
      ),
      http.post("/api/v1/license", () =>
        HttpResponse.json({ ...result, already_expired: true, phase: "grace" }),
      ),
    );
    await renderRoute("/license");
    await screen.findByTestId("installation-id");
    await chooseFile();
    const dialog = await screen.findByRole("dialog", {
      name: "Confirm the license",
    });
    expect(dialog).toHaveTextContent("This license has already expired.");
    await userEvent.click(
      within(dialog).getByRole("button", { name: "Install license" }),
    );
    expect(await screen.findByTestId("license-installed")).toHaveTextContent(
      "This license has already expired.",
    );
  });

  it("asks for a fresh code before uploading", async () => {
    let attempts = 0;
    server.use(
      ...sessionHandlers(sessionFor("admin")),
      http.post("/api/v1/license/preview", () => {
        attempts += 1;
        return attempts === 1
          ? errorResponse(403, "ALC-AUTH-0003", "auth.stepup_required")
          : HttpResponse.json(result);
      }),
      http.post("/api/v1/auth/stepup", () =>
        HttpResponse.json(sessionFor("admin")),
      ),
    );
    await renderRoute("/license");
    await screen.findByTestId("installation-id");
    await chooseFile();
    const stepUp = await screen.findByRole("dialog", {
      name: "Confirm it's you",
    });
    await userEvent.type(
      within(stepUp).getByLabelText("6-digit code"),
      "123456",
    );
    await userEvent.click(
      within(stepUp).getByRole("button", { name: "Confirm" }),
    );
    expect(
      await screen.findByRole("dialog", { name: "Confirm the license" }),
    ).toBeInTheDocument();
  });

  it("refuses a file over 64 KiB without sending it", async () => {
    let calls = 0;
    server.use(
      ...sessionHandlers(sessionFor("admin")),
      http.post("/api/v1/license/preview", () => {
        calls += 1;
        return HttpResponse.json(result);
      }),
    );
    await renderRoute("/license");
    await screen.findByTestId("installation-id");
    await userEvent.upload(
      screen.getByLabelText("License file"),
      new File(["x".repeat(64 * 1024 + 1)], "big.alicelic"),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "This file is too large to be a license.",
    );
    expect(
      screen.getByRole("button", { name: "Check the file" }),
    ).toBeDisabled();
    expect(calls).toBe(0);
  });

  it("is read-only for auditors and hidden from operators", async () => {
    server.use(...sessionHandlers(sessionFor("auditor")));
    await renderRoute("/license");
    await screen.findByTestId("installation-id");
    expect(screen.queryByLabelText("License file")).not.toBeInTheDocument();

    server.use(...sessionHandlers(sessionFor("operator")));
    await renderRoute("/license");
    expect(
      await screen.findByText("You do not have access to this page."),
    ).toBeInTheDocument();
  });

  it("names the notices in the history and the ended evaluation (W4, W7)", async () => {
    const notice = (license_id: string, n: string) => ({
      at: "2026-10-31T09:00:00Z",
      event: "notice" as const,
      license_id,
      from_state: "",
      to_state: "",
      notice: n,
    });
    server.use(
      ...sessionHandlers(sessionFor("admin")),
      http.get("/api/v1/license", () =>
        HttpResponse.json({
          ...licenseDetailFixture,
          phase: "evaluation_expired",
          current: null,
          max_targets: 5,
          days_left: 0,
          files: [],
          history: [
            notice("evaluation", "evaluation_ended"),
            notice("evaluation", "evaluation:1"),
            notice("evaluation", "evaluation:7"),
            notice("LIC-1", "expiry:30"),
            notice("LIC-1", "grace:2"),
            notice("LIC-1", "locked"),
            notice("", "clock_behind:2026-10-20"),
            notice("", "tampered:0192a000-0000-7000-8000-0000000000f1"),
            notice("", "installation_tampered:ALICE-7F3K-9Q2M-XD41-B8TC:2"),
            notice("", "installation_restored:ALICE-7F3K-9Q2M-XD41-B8TC:1"),
            notice("", "something_new:1"),
          ],
        }),
      ),
    );
    await renderRoute("/license");
    const summary = await screen.findByTestId("license-summary");
    expect(summary).toHaveTextContent("Evaluation ended");
    expect(summary).not.toHaveTextContent("0 days");
    const history = screen.getByRole("table", { name: "History" });
    expect(within(history).getAllByText("Evaluation")).toHaveLength(3);
    expect(within(history).queryByText("evaluation")).not.toBeInTheDocument();
    for (const text of [
      "Evaluation ended",
      "Evaluation warning: 1 day left",
      "Evaluation warning: 7 days left",
      "Expiry warning: 30 days left",
      "Grace day 2 of 7",
      "License locked",
      "Server clock behind (2026-10-20)",
      "Changed license file",
      "Installation record changed",
      "Installation record restored",
      "something_new:1",
    ]) {
      expect(within(history).getByText(text)).toBeInTheDocument();
    }
    expectNoRawKeys();
  });

  it("shows the evaluation and is translated into Turkish", async () => {
    server.use(
      ...sessionHandlers(sessionFor("admin", "tr")),
      http.get("/api/v1/license", () =>
        HttpResponse.json({
          ...licenseDetailFixture,
          phase: "evaluation",
          current: null,
          max_targets: 5,
          days_left: 30,
          files: [],
          history: [],
        }),
      ),
    );
    await renderRoute("/license", { languages: ["tr-TR"] });
    expect(await screen.findByTestId("license-summary")).toHaveTextContent(
      "Deneme: 30 gün kaldı, en fazla 5 hedef.",
    );
    expect(screen.getByLabelText("Lisans dosyası")).toBeInTheDocument();
    expectNoRawKeys();
  });
});
