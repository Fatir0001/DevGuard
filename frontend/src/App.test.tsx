// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  render,
  screen,
  waitFor,
  fireEvent,
  cleanup,
} from "@testing-library/react";
import App from "./App";

function makeHistoryScan(id: string, projectName: string) {
  return {
    id,
    project_id: `project-${id}`,
    project_name: projectName,
    status: "completed",
    stage: "Complete",
    files_processed: 2,
    dependencies_analyzed: 0,
    findings_count: 1,
    reviewed_count: 0,
    awaiting_review_count: 1,
    severity_counts: { Critical: 0, High: 0, Medium: 1, Low: 0, Informational: 0 },
    started_at: "2026-01-01T00:00:00+00:00",
    finished_at: "2026-01-01T00:00:01+00:00",
    duration_seconds: 1,
  };
}

function installBinApi(activeInput: any[] = [], binInput: any[] = [], failTrash = false) {
  let active = [...activeInput];
  let bin = [...binInput];
  const response = (body: any, ok = true, status = 200) => ({
    ok,
    status,
    json: async () => body,
  });
  const fetchMock = vi.fn(async (input: any, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method || "GET";
    if (url.includes("/scans?limit=1000")) return response({ items: active });
    if (url.endsWith("/projects")) return response({ items: [] });
    if (url.endsWith("/health")) return response({ status: "ok", scanner_version: "1.1.0" });
    if (url.includes("/bin?limit=1000")) return response({ items: bin, total: bin.length });
    if (url.includes("/bin?limit=1")) return response({ items: bin.slice(0, 1), total: bin.length });
    if (method === "POST" && url.endsWith("/scans/trash")) {
      if (failTrash) return response({ detail: "Server refused trash request" }, false, 503);
      const ids = JSON.parse(String(init?.body)).scan_ids;
      const moving = active.filter((scan) => ids.includes(scan.id));
      active = active.filter((scan) => !ids.includes(scan.id));
      bin = [...bin, ...moving.map((scan) => ({ ...scan, deleted_at: "2026-01-02T00:00:00+00:00" }))];
      return response({ updated: moving.length });
    }
    if (method === "POST" && url.endsWith("/bin/restore")) {
      const ids = JSON.parse(String(init?.body)).scan_ids;
      const restoring = bin.filter((scan) => ids.includes(scan.id));
      bin = bin.filter((scan) => !ids.includes(scan.id));
      active = [...restoring.map(({ deleted_at, ...scan }) => scan), ...active];
      return response({ updated: restoring.length });
    }
    if (method === "DELETE" && url.endsWith("/bin")) {
      const deleted = bin.length;
      bin = [];
      return response({ deleted });
    }
    if (method === "DELETE" && url.includes("/bin/")) {
      const id = url.split("/bin/")[1];
      const previous = bin.length;
      bin = bin.filter((scan) => scan.id !== id);
      return response({ deleted: previous - bin.length });
    }
    return response({ items: [] });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("DevGuard workstation", () => {
  afterEach(() => {
    cleanup();
    window.history.replaceState({}, "", "/");
  });

  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("offline"))),
    );
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    );
  });
  it("shows a useful dashboard and truthful offline state", async () => {
    render(<App />);
    expect(screen.getByText(/Project security overview/)).toBeTruthy();
    expect(screen.getAllByText(/New scan/i).length).toBeGreaterThan(0);
    expect(await screen.findByText("API offline")).toBeTruthy();
    expect(screen.getByText(/Retry connection/)).toBeTruthy();
  });
  it("defers full Bin and project lists until their pages are opened", async () => {
    const fetchMock = installBinApi();
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Project security overview" })).toBeTruthy();
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes("/bin?limit=1000"))).toBe(false);
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith("/projects"))).toBe(false);
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes("/bin?limit=1"))).toBe(true);

    fireEvent.click(screen.getAllByRole("button", { name: "Bin" })[0]);
    expect(await screen.findByText(/The Bin is empty/)).toBeTruthy();
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([url]) => String(url).includes("/bin?limit=1000"))).toBe(true),
    );

    fireEvent.click(screen.getAllByRole("button", { name: "Projects" })[0]);
    expect(await screen.findByRole("heading", { name: "Projects" })).toBeTruthy();
    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith("/projects"))).toBe(true),
    );
  });
  it("restores client pages from their URL after a refresh", async () => {
    const scan = makeHistoryScan("scan-url-route", "url-demo");
    installBinApi([], [{ ...scan, deleted_at: "2026-01-02T00:00:00+00:00" }]);
    window.history.replaceState({}, "", "/bin");

    const firstLoad = render(<App />);
    expect(await screen.findByRole("heading", { name: "Bin" })).toBeTruthy();
    expect(window.location.pathname).toBe("/bin");
    firstLoad.unmount();

    render(<App />);
    expect(await screen.findByRole("heading", { name: "Bin" })).toBeTruthy();
    fireEvent.click(screen.getAllByRole("button", { name: "Scan History" })[0]);
    expect(window.location.pathname).toBe("/history");
    expect(await screen.findByRole("heading", { name: "Scan history" })).toBeTruthy();
  });
  it("loads each primary page directly from its URL", async () => {
    const routes = [
      ["/", "Project security overview"],
      ["/scan", "Start a new scan"],
      ["/projects", "Projects"],
      ["/findings", "Findings"],
      ["/history", "Scan history"],
      ["/bin", "Bin"],
      ["/reports", "Scan reports"],
      ["/settings", "Settings"],
    ];

    for (const [path, title] of routes) {
      window.history.replaceState({}, "", path);
      installBinApi();
      const page = render(<App />);
      expect(await screen.findByRole("heading", { name: title })).toBeTruthy();
      page.unmount();
    }
  });
  it("keeps a configured BYOK key only in App memory across page navigation and removes it", async () => {
    installBinApi();
    window.history.replaceState({}, "", "/settings");
    render(<App />);

    const key = "sk-synthetic-app-memory-key-001";
    const input = (await screen.findByLabelText("OpenAI API key")) as HTMLInputElement;
    fireEvent.change(input, { target: { value: key } });
    fireEvent.click(screen.getAllByRole("button", { name: "Dashboard" })[0]);
    fireEvent.click(screen.getAllByRole("button", { name: "Settings" })[0]);

    const returnedInput = (await screen.findByLabelText("OpenAI API key")) as HTMLInputElement;
    expect(returnedInput.value).toBe(key);
    fireEvent.click(screen.getByRole("button", { name: "Remove Key" }));
    fireEvent.click(screen.getAllByRole("button", { name: "Dashboard" })[0]);
    fireEvent.click(screen.getAllByRole("button", { name: "Settings" })[0]);
    expect((await screen.findByLabelText("OpenAI API key") as HTMLInputElement).value).toBe("");
  });
  it("loads scan progress and findings from the scan URL after a refresh", async () => {
    const scan = makeHistoryScan("scan-route-refresh", "route-demo");
    const finding = {
      id: "finding-route-refresh",
      scan_id: scan.id,
      project_id: scan.project_id,
      project_name: scan.project_name,
      title: "Retained route finding",
      description: "Evidence from the saved scan.",
      severity: "Medium",
      confidence: "High",
      category: "Test",
      rule_id: "DG-TEST-ROUTE",
      file_path: "app.py",
      line: 2,
      evidence: "safe test evidence",
      remediation: "Review the code.",
      reviewed: false,
    };
    const response = (body: any) => ({ ok: true, json: async () => body });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: any) => {
        const url = String(input);
        if (url.includes("/scans?limit=1000")) return response({ items: [scan] });
        if (url.endsWith("/projects")) return response({ items: [] });
        if (url.endsWith("/health"))
          return response({ status: "ok", scanner_version: "1.1.0" });
        if (url.includes("/bin?limit=1000")) return response({ items: [] });
        if (url.endsWith("/scans/" + scan.id + "/findings"))
          return response({ items: [finding] });
        if (url.endsWith("/scans/" + scan.id)) return response(scan);
        return response({ items: [] });
      }),
    );
    window.history.replaceState({}, "", "/scan-progress/" + scan.id);

    render(<App />);
    expect(await screen.findByRole("heading", { name: "route-demo" })).toBeTruthy();
    expect(await screen.findByText("Retained route finding")).toBeTruthy();
  });
  it("uses latest database-backed scan summaries without double-counting rescans", async () => {
    const scan = {
      id: "scan-latest",
      project_id: "project-1",
      project_name: "sample",
      status: "completed",
      stage: "Complete",
      files_processed: 4,
      dependencies_analyzed: 1,
      findings_count: 2,
      reviewed_count: 1,
      awaiting_review_count: 1,
      severity_counts: {
        Critical: 0,
        High: 1,
        Medium: 1,
        Low: 0,
        Informational: 0,
      },
      started_at: "2026-01-01T00:00:00+00:00",
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: any) => ({
        ok: true,
        json: async () =>
          String(input).includes("/projects")
            ? { items: [{ id: "project-1", name: "sample", scans_count: 2 }] }
            : {
                items: [
                  scan,
                  {
                    ...scan,
                    id: "old",
                    findings_count: 8,
                    started_at: "2025-01-01T00:00:00+00:00",
                  },
                ],
              },
      })),
    );
    const { container } = render(<App />);
    await waitFor(() =>
      expect(container.querySelectorAll(".stat strong")[1]?.textContent).toBe(
        "2",
      ),
    );
    expect(container.querySelectorAll(".stat strong")[0]?.textContent).toBe(
      "1",
    );
    expect(container.querySelectorAll(".stat strong")[2]?.textContent).toBe(
      "1",
    );
  });
  it("uploads a ZIP through the API and displays the returned finding", async () => {
    const scan = {
      id: "scan-upload",
      project_id: "project-upload",
      project_name: "portfolio-sample",
      status: "completed",
      stage: "Complete",
      files_processed: 1,
      dependencies_analyzed: 0,
      findings_count: 1,
      reviewed_count: 0,
      awaiting_review_count: 1,
      severity_counts: {
        Critical: 0,
        High: 0,
        Medium: 1,
        Low: 0,
        Informational: 0,
      },
      started_at: "2026-01-01T00:00:00+00:00",
    };
    const finding = {
      id: "finding-upload",
      scan_id: scan.id,
      project_id: scan.project_id,
      project_name: scan.project_name,
      title: "Synthetic SQL warning",
      description: "Potential query construction issue.",
      severity: "Medium",
      confidence: "Medium",
      category: "Static analysis",
      rule_id: "DG-PY-SQL-FSTRING",
      file_path: "app.py",
      line: 4,
      evidence: 'execute(f"...{value}...")',
      remediation: "Use query parameters.",
      reviewed: false,
    };
    const response = (body: any) => ({ ok: true, json: async () => body });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: any, init?: RequestInit) => {
        const url = String(input);
        if (init?.method === "POST" && url.endsWith("/scans"))
          return response({
            scan_id: scan.id,
            project_id: scan.project_id,
            status: "queued",
          });
        if (url.endsWith("/projects")) return response({ items: [] });
        if (url.endsWith("/health"))
          return response({ status: "ok", scanner_version: "1.1.0" });
        if (url.endsWith("/findings"))
          return response({ items: [finding], scan });
        if (url.endsWith("/scan-upload")) return response(scan);
        return response({ items: [] });
      }),
    );
    render(<App />);
    fireEvent.click(screen.getAllByRole("button", { name: "New Scan" })[0]);
    fireEvent.change(screen.getByLabelText("PROJECT NAME"), {
      target: { value: "portfolio-sample" },
    });
    const archive = new File(["synthetic zip placeholder"], "sample.zip", {
      type: "application/zip",
    });
    fireEvent.change(screen.getByLabelText("Choose project ZIP archive"), {
      target: { files: [archive] },
    });
    fireEvent.click(screen.getByRole("button", { name: /Start scan/i }));
    expect(await screen.findByText("Synthetic SQL warning")).toBeTruthy();
    expect(screen.getByText(/app.py:4/)).toBeTruthy();
  });

  it("displays all severity labels returned by the findings API unchanged", async () => {
    const severities = [
      "Critical",
      "High",
      "Medium",
      "Low",
      "Informational",
    ];
    const findings = severities.map((severity) => ({
      id: `finding-${severity}`,
      scan_id: "scan-severity",
      project_id: "project-severity",
      project_name: "severity-demo",
      title: `Synthetic ${severity} finding`,
      description: "Synthetic API fixture.",
      severity,
      confidence: "High",
      category: "Synthetic test",
      rule_id: `DG-${severity.toUpperCase()}`,
      file_path: "app.py",
      line: 1,
      evidence: "synthetic evidence",
      remediation: "Synthetic remediation.",
      reviewed: false,
    }));
    const scan = {
      id: "scan-severity",
      project_id: "project-severity",
      project_name: "severity-demo",
      status: "completed",
      stage: "Complete",
      files_processed: findings.length,
      dependencies_analyzed: 0,
      findings_count: findings.length,
      reviewed_count: 0,
      awaiting_review_count: findings.length,
      severity_counts: Object.fromEntries(severities.map((value) => [value, 1])),
      started_at: "2026-01-01T00:00:00+00:00",
    };
    const response = (body: any) => ({ ok: true, json: async () => body });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: any) => {
        const url = String(input);
        if (url.includes("/scans?limit=1000"))
          return response({ items: [scan] });
        if (url.endsWith("/projects"))
          return response({
            items: [
              { id: "project-severity", name: "severity-demo", scans_count: 1 },
            ],
          });
        if (url.endsWith("/health"))
          return response({ status: "ok", scanner_version: "1.1.0" });
        if (url.includes("/findings"))
          return response({ items: findings, limit: 1000, offset: 0, total: 5 });
        return response({ items: [] });
      }),
    );

    const { container } = render(<App />);
    fireEvent.click(screen.getAllByRole("button", { name: /Findings/ })[0]);
    expect(await screen.findByText("Synthetic Critical finding")).toBeTruthy();
    await waitFor(() =>
      expect(
        container.querySelectorAll(".table-wrap tbody .severity").length,
      ).toBe(5),
    );
    expect(
      Array.from(
        container.querySelectorAll(".table-wrap tbody .severity"),
      ).map((badge) => badge.textContent),
    ).toEqual(severities);
    expect(container.querySelector(".severity.critical")?.textContent).toBe(
      "Critical",
    );
    expect(container.querySelector(".severity.informational")?.textContent).toBe(
      "Informational",
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: "Open finding Synthetic Critical finding",
      }),
    );
    expect((await screen.findByRole("dialog")).textContent).toContain(
      "Critical",
    );
  }, 30000);

  it("moves a scan into the Bin and restores it through the API", async () => {
    const scan = makeHistoryScan("scan-history-1", "history-demo");
    const fetchMock = installBinApi([scan]);
    render(<App />);

    expect(await screen.findByText("API connected")).toBeTruthy();
    fireEvent.click(screen.getAllByRole("button", { name: "Scan History" })[0]);
    expect(await screen.findByText("history-demo")).toBeTruthy();
    fireEvent.click(screen.getByRole("checkbox", { name: "Select scan history-demo" }));
    fireEvent.click(screen.getByRole("button", { name: /Move selected to Bin/ }));
    expect(await screen.findByRole("alertdialog")).toBeTruthy();
    expect(screen.getByText(/findings and reports remain available in the Bin/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Move to Bin" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/scans/trash"),
      expect.objectContaining({ method: "POST" }),
    ));
    expect((await screen.findByRole("status")).textContent).toContain("Scan moved to Bin.");
    fireEvent.click(screen.getAllByRole("button", { name: /Bin/ })[0]);
    expect(await screen.findByText("history-demo")).toBeTruthy();
    expect(screen.getByRole("link", { name: /JSON/ }).getAttribute("href")).toContain("/scans/scan-history-1/report.json");
    fireEvent.click(screen.getByRole("button", { name: "Restore history-demo" }));
    expect(await screen.findByRole("alertdialog")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Restore" }));
    expect((await screen.findByRole("status")).textContent).toContain("Scan restored to Scan History.");
    fireEvent.click(screen.getAllByRole("button", { name: "Scan History" })[0]);
    expect(await screen.findByText("history-demo")).toBeTruthy();
  });

  it("requires a typed confirmation before emptying the Bin and confirms permanent deletion", async () => {
    const scan = { ...makeHistoryScan("scan-history-2", "bin-demo"), deleted_at: "2026-01-02T00:00:00+00:00" };
    const fetchMock = installBinApi([], [scan]);
    render(<App />);
    expect(await screen.findByText("API connected")).toBeTruthy();
    fireEvent.click(screen.getAllByRole("button", { name: /Bin/ })[0]);
    expect(await screen.findByText("bin-demo")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Empty Bin" }));
    const emptyDialog = await screen.findByRole("alertdialog");
    expect(emptyDialog.textContent).toContain("cannot be undone");
    const emptyButton = screen.getByRole("button", { name: "Empty Bin permanently" });
    expect((emptyButton as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByRole("textbox", { name: "Type EMPTY to confirm" }), { target: { value: "EMPTY" } });
    expect((emptyButton as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(emptyButton);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      expect.stringMatching(/\/api\/bin$/),
      expect.objectContaining({ method: "DELETE" }),
    ));
    expect(await screen.findByText(/The Bin is empty/)).toBeTruthy();
  });

  it("confirms individual permanent deletion separately from moving a scan to the Bin", async () => {
    const scan = { ...makeHistoryScan("scan-history-delete", "delete-demo"), deleted_at: "2026-01-02T00:00:00+00:00" };
    const fetchMock = installBinApi([], [scan]);
    render(<App />);
    expect(await screen.findByText("API connected")).toBeTruthy();
    fireEvent.click(screen.getAllByRole("button", { name: /Bin/ })[0]);
    expect(await screen.findByText("delete-demo")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Permanently delete delete-demo" }));
    expect((await screen.findByRole("alertdialog")).textContent).toContain("This action cannot be undone");
    fireEvent.click(screen.getByRole("button", { name: "Delete permanently" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/bin/scan-history-delete"),
      expect.objectContaining({ method: "DELETE" }),
    ));
    expect((await screen.findByRole("status")).textContent).toContain("Scan permanently deleted.");
  });

  it("keeps history visible and reports an API failure when trashing is rejected", async () => {
    const scan = makeHistoryScan("scan-history-error", "error-demo");
    installBinApi([scan], [], true);
    render(<App />);
    expect(await screen.findByText("API connected")).toBeTruthy();
    fireEvent.click(screen.getAllByRole("button", { name: "Scan History" })[0]);
    expect(await screen.findByText("error-demo")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Move error-demo to Bin" }));
    fireEvent.click(await screen.findByRole("button", { name: "Move to Bin" }));
    await waitFor(() =>
      expect(
        screen.getAllByRole("alert").some((notice) =>
          notice.textContent?.includes("Server refused trash request"),
        ),
      ).toBe(true),
    );
    expect(screen.getByText("error-demo")).toBeTruthy();
  });
});
