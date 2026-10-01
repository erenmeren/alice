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
      screen.getByText(
        "Licensed to Örnek Bankası A.Ş. (license LIC-2026-000123)",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("3 of 10 targets used")).toBeInTheDocument();
    const history = screen.getByRole("table", { name: "History" });
    expect(within(history).getByText("License installed")).toBeInTheDocument();
    expect(
      within(history).getByText("Evaluation → Active"),
    ).toBeInTheDocument();
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
            notice("", "installation_tampered:ALICE-7F3K-9Q2M-XD41-B8TC"),
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
