// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { AiFindingAssistant, AiProvider, AiSettingsPanel } from "./AiTools";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function SettingsHarness({ apiBase = "http://127.0.0.1:8000/api" }: { apiBase?: string }) {
  const [key, setKey] = useState("");
  const [provider, setProvider] = useState<AiProvider>("openai");
  const [model, setModel] = useState("gpt-6-luna");
  return (
    <AiSettingsPanel
      apiBase={apiBase}
      apiKey={key}
      provider={provider}
      model={model}
      onKeyChange={setKey}
      onProviderChange={setProvider}
      onModelChange={setModel}
    />
  );
}

const finding = {
  title: "Potential credential assignment",
  description: "A credential-like value was found in a source assignment.",
  severity: "High",
  category: "Secrets",
  rule_id: "DG-SECRET",
  remediation: "Rotate the credential and load it from a secret manager.",
  file_path: "private/config.py",
  line: 12,
  evidence: "API_TOKEN = 'do-not-send-source-or-secret'",
  project_name: "private-project",
  scan_id: "private-scan-id",
} as any;

function okTestResponse(provider = "OpenAI", model = "gpt-6-luna") {
  return { ok: true, status: 200, json: async () => ({ status: "ok", provider, model }) };
}

describe("optional BYOK AI tools", () => {
  it("masks the key, tests the selected model through DevGuard, then removes it from tab state", async () => {
    const secret = "sk-synthetic-test-ui-key-001";
    const fetchMock = vi.fn(async () => okTestResponse());
    vi.stubGlobal("fetch", fetchMock);

    const page = render(<SettingsHarness />);
    const input = screen.getByLabelText("OpenAI API key") as HTMLInputElement;
    expect(input.type).toBe("password");
    fireEvent.change(input, { target: { value: secret } });
    expect(input.value).toBe(secret);

    fireEvent.click(screen.getByRole("button", { name: "Test Connection" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://127.0.0.1:8000/api/ai/test");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>)).toMatchObject({
      Authorization: `Bearer ${secret}`,
      "X-DevGuard-Provider": "openai",
      "X-DevGuard-Model": "gpt-6-luna",
    });
    expect(init.body).toBeUndefined();
    expect(await screen.findByText(/accepted a minimal request/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Remove Key" }));
    expect(input.value).toBe("");
    expect(await screen.findByText(/key was removed from this tab/i)).toBeTruthy();
    page.unmount();
    render(<SettingsHarness />);
    expect((screen.getByLabelText("OpenAI API key") as HTMLInputElement).value).toBe("");
  });

  it("allows selecting a provider and editing the provider model ID", () => {
    render(<SettingsHarness />);
    fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "gemini" } });
    expect((screen.getByLabelText("Model ID") as HTMLInputElement).value).toBe("gemini-3.8-flash");
    expect(screen.getByLabelText("Google Gemini API key")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "openrouter" } });
    expect((screen.getByLabelText("Model ID") as HTMLInputElement).value).toBe("");
    fireEvent.change(screen.getByLabelText("Model ID"), { target: { value: "anthropic/claude-sonnet-5" } });
    expect((screen.getByLabelText("Model ID") as HTMLInputElement).value).toBe("anthropic/claude-sonnet-5");
    expect(screen.getByText(/does not fall back to another provider or model/i)).toBeTruthy();
  });

  it("maps provider rejection codes to useful errors without echoing keys", async () => {
    const secret = "sk-synthetic-unauthorized-key";
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: false,
      status: 402,
      json: async () => ({ detail: { code: "insufficient_quota", message: secret } }),
    })));
    render(
      <AiSettingsPanel
        apiBase="/api"
        apiKey={secret}
        provider="openai"
        model="gpt-6-luna"
        onKeyChange={() => {}}
        onProviderChange={() => {}}
        onModelChange={() => {}}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Test Connection" }));
    const error = await screen.findByText(/insufficient credits, billing, or account quota/i);
    expect(error.textContent).not.toContain(secret);
  });

  it("explains a missing backend AI route without exposing the API key", async () => {
    const secret = "sk-synthetic-missing-route-key";
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: false,
      status: 404,
      json: async () => ({ detail: secret }),
    })));
    render(
      <AiSettingsPanel
        apiBase="/api"
        apiKey={secret}
        provider="openai"
        model="gpt-6-luna"
        onKeyChange={() => {}}
        onProviderChange={() => {}}
        onModelChange={() => {}}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Test Connection" }));
    const error = await screen.findByText(/AI route not found \(404\).*API URL ends in \/api/i);
    expect(error.textContent).not.toContain(secret);
  });

  it("does not report success if the backend response names a different provider or model", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => okTestResponse("Anthropic Claude", "claude-sonnet-5")));
    render(
      <AiSettingsPanel
        apiBase="/api"
        apiKey="sk-synthetic-provider-mismatch-key"
        provider="openai"
        model="gpt-6-luna"
        onKeyChange={() => {}}
        onProviderChange={() => {}}
        onModelChange={() => {}}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Test Connection" }));
    expect(await screen.findByText(/did not match the selected provider and model/i)).toBeTruthy();
  });

  it("does not send a key over non-HTTPS to a non-local backend", async () => {
    const secret = "sk-synthetic-transport-key";
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<SettingsHarness apiBase="http://api.devguard.example/api" />);
    fireEvent.change(screen.getByLabelText("OpenAI API key"), { target: { value: secret } });
    fireEvent.click(screen.getByRole("button", { name: "Test Connection" }));
    expect(await screen.findByText(/key was not sent.*HTTPS/i)).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("requires explicit consent and sends only the approved finding summary to the chosen provider", async () => {
    const secret = "sk-synthetic-consent-key";
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ explanation: "Rotate it, then move the value into managed secret storage." }),
    }));
    vi.stubGlobal("fetch", fetchMock);
    render(
      <AiFindingAssistant
        apiBase="/api"
        apiKey={secret}
        provider="gemini"
        model="gemini-3.8-flash"
        finding={finding}
        onOpenSettings={() => {}}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Explain with Google Gemini" }));
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.getByText(/source code, evidence excerpts, file paths/i)).toBeTruthy();
    const cancelButton = screen.getByRole("button", { name: "Cancel" });
    const sendButton = screen.getByRole("button", { name: "Send summary to Google Gemini" });
    expect(document.activeElement).toBe(cancelButton);
    sendButton.focus();
    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement).toBe(cancelButton);
    cancelButton.focus();
    fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(sendButton);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Explain with Google Gemini" }));
    fireEvent.click(screen.getByRole("button", { name: "Send summary to Google Gemini" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/ai/explain");
    expect((init.headers as Record<string, string>)).toMatchObject({
      Authorization: `Bearer ${secret}`,
      "X-DevGuard-Provider": "gemini",
      "X-DevGuard-Model": "gemini-3.8-flash",
    });
    const sent = JSON.parse(String(init.body));
    expect(sent).toEqual({
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      category: finding.category,
      rule_id: finding.rule_id,
      remediation: finding.remediation,
    });
    expect(JSON.stringify(sent)).not.toContain("do-not-send-source-or-secret");
    expect(JSON.stringify(sent)).not.toContain("private/config.py");
    expect(JSON.stringify(sent)).not.toContain("private-scan-id");
    expect(await screen.findByText(/Rotate it, then move the value/i)).toBeTruthy();
  });

  it("shows backend error categories without exposing provider responses", async () => {
    const secret = "sk-synthetic-error-key";
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: false,
      status: 429,
      json: async () => ({ detail: { code: "rate_limited", message: secret } }),
    })));
    render(
      <AiFindingAssistant
        apiBase="/api"
        apiKey={secret}
        provider="anthropic"
        model="claude-sonnet-5"
        finding={finding}
        onOpenSettings={() => {}}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Explain with Anthropic Claude" }));
    fireEvent.click(screen.getByRole("button", { name: "Send summary to Anthropic Claude" }));
    expect(await screen.findByText(/provider rate-limited this request/i)).toBeTruthy();
    expect(screen.queryByText(secret)).toBeNull();
  });

  it("distinguishes a DevGuard internal error from a provider error", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 500, json: async () => ({}) })));
    render(
      <AiFindingAssistant
        apiBase="/api"
        apiKey="sk-synthetic-backend-error-key"
        provider="openai"
        model="gpt-6-luna"
        finding={finding}
        onOpenSettings={() => {}}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Explain with OpenAI" }));
    fireEvent.click(screen.getByRole("button", { name: "Send summary to OpenAI" }));
    expect(await screen.findByText(/DevGuard returned an internal error/i)).toBeTruthy();
  });
});
