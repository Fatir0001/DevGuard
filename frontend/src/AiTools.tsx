import { useEffect, useRef, useState } from "react";

export type AiProvider = "openai" | "gemini" | "anthropic" | "openrouter";
type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";

const PROVIDERS: Record<AiProvider, string> = {
  openai: "OpenAI",
  gemini: "Google Gemini",
  anthropic: "Anthropic Claude",
  openrouter: "OpenRouter",
};
const MODEL_SUGGESTIONS: Record<AiProvider, string> = {
  openai: "gpt-6-luna",
  gemini: "gemini-3.8-flash",
  anthropic: "claude-sonnet-5",
  openrouter: "",
};
const MODEL_PLACEHOLDERS: Record<AiProvider, string> = {
  openai: "gpt-6-luna",
  gemini: "gemini-3.8-flash",
  anthropic: "claude-sonnet-5",
  openrouter: "provider/model-id (for example, openai/gpt-5)",
};

export type AiFindingSummary = {
  title: string;
  description: string;
  severity: Severity;
  category: string;
  rule_id: string;
  remediation: string;
};

type AiSettingsProps = {
  apiBase: string;
  apiKey: string;
  provider: AiProvider;
  model: string;
  onKeyChange: (value: string) => void;
  onProviderChange: (value: AiProvider) => void;
  onModelChange: (value: string) => void;
};

type AiFindingProps = {
  apiBase: string;
  apiKey: string;
  provider: AiProvider;
  model: string;
  finding: Omit<AiFindingSummary, "severity"> & { severity: string };
  onOpenSettings: () => void;
};

const ERROR_MESSAGES: Record<string, string> = {
  invalid_credentials: "The selected provider rejected these credentials.",
  invalid_key_format: "The key format is not accepted. Check the key for this provider.",
  insufficient_quota: "The provider reports insufficient credits, billing, or account quota.",
  unsupported_model: "The selected model is not available for this provider or account.",
  model_required: "Enter a model ID for the selected provider.",
  invalid_model_id: "The model ID contains unsupported characters or is too long.",
  permission_denied: "The provider denied this request for the selected account or model.",
  rate_limited: "The provider rate-limited this request. Wait and try again.",
  network_timeout: "The request timed out while contacting the provider.",
  network_error: "The DevGuard backend could not reach the selected provider.",
  provider_error: "The provider could not complete the request. Check the selected model and provider status.",
  backend_error: "DevGuard returned an internal error while processing this request.",
};

function secureBackendTransport(apiBase: string): boolean {
  try {
    const destination = new URL(apiBase, window.location.href);
    const hostname = destination.hostname.toLowerCase();
    const localhost = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(hostname);
    return destination.protocol === "https:" || (destination.protocol === "http:" && localhost);
  } catch {
    return false;
  }
}

async function errorMessage(response: Response): Promise<string> {
  let code = "";
  try {
    const payload = await response.json();
    const detail = payload?.detail;
    code = typeof detail === "object" && detail ? detail.code : payload?.error_code;
  } catch {
    // Older API builds may return a text response; do not show provider bodies.
  }
  if (code && ERROR_MESSAGES[code]) return ERROR_MESSAGES[code];
  if (response.status === 401) return "The selected provider rejected these credentials.";
  if (response.status === 402) return "The provider reports insufficient credits or account quota.";
  if (response.status === 403) return "The provider denied this request for the selected account or model.";
  if (response.status === 429) return "The provider rate-limited this request. Wait and try again.";
  if (response.status === 504) return "The request timed out while contacting the provider.";
  if (response.status === 404) {
    return "DevGuard AI route not found (404). Check that the API URL ends in /api and the backend supports AI requests.";
  }
  if (response.status === 500 || response.status === 503) return ERROR_MESSAGES.backend_error;
  if (response.status >= 500) return "The provider could not complete the request. Check provider status and try again.";
  return "The DevGuard API could not complete this AI request.";
}

function validModel(model: string, provider: AiProvider) {
  const value = model.trim();
  return value.length <= 200 && (provider === "openrouter"
    ? /^[A-Za-z0-9._+-]+\/[A-Za-z0-9._:+-]+$/.test(value)
    : /^[A-Za-z0-9._+-]{1,200}$/.test(value));
}

function aiHeaders(provider: AiProvider, model: string, apiKey: string) {
  return {
    Authorization: `Bearer ${apiKey}`,
    "X-DevGuard-Provider": provider,
    "X-DevGuard-Model": model.trim(),
  };
}

export function AiSettingsPanel({
  apiBase,
  apiKey,
  provider,
  model,
  onKeyChange,
  onProviderChange,
  onModelChange,
}: AiSettingsProps) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [messageKind, setMessageKind] = useState<"success" | "error" | "info">("info");
  const providerName = PROVIDERS[provider];

  const testConnection = async () => {
    const key = apiKey.trim();
    if (key.length < 16 || key.length > 1024 || /\s/.test(key)) {
      setMessage("Enter a correctly formatted API key for the selected provider.");
      setMessageKind("error");
      return;
    }
    if (!validModel(model, provider)) {
      setMessage("Enter a valid model ID for the selected provider.");
      setMessageKind("error");
      return;
    }
    if (!secureBackendTransport(apiBase)) {
      setMessage("The API key was not sent: configure an HTTPS DevGuard API URL outside localhost.");
      setMessageKind("error");
      return;
    }
    setBusy(true);
    setMessage("");
    try {
      const response = await fetch(`${apiBase}/ai/test`, {
        method: "POST",
        headers: aiHeaders(provider, model, key),
      });
      if (!response.ok) {
        setMessage(await errorMessage(response));
        setMessageKind("error");
        return;
      }
      const result = await response.json();
      if (result?.provider !== providerName || result?.model !== model.trim()) {
        setMessage("The backend response did not match the selected provider and model.");
        setMessageKind("error");
        return;
      }
      setMessage(`${providerName} accepted a minimal request for ${model.trim()}. A small usage charge may apply.`);
      setMessageKind("success");
    } catch {
      setMessage("Could not reach the DevGuard API. Check its configured endpoint.");
      setMessageKind("error");
    } finally {
      setBusy(false);
    }
  };

  const removeKey = () => {
    onKeyChange("");
    setMessage("The key was removed from this tab's memory.");
    setMessageKind("success");
  };

  return (
    <section className="ai-settings" aria-labelledby="ai-settings-title">
      <div className="ai-section-heading">
        <div>
          <h3 id="ai-settings-title">Optional AI assistance</h3>
          <p>Use your own provider API key for on-demand finding explanations and remediation suggestions.</p>
        </div>
        <span className="ai-optional-badge">OPTIONAL</span>
      </div>
      <label className="ai-provider-value" htmlFor="ai-provider">
        <span>Provider</span>
        <select
          id="ai-provider"
          value={provider}
          disabled={busy}
          onChange={(event) => {
            const nextProvider = event.target.value as AiProvider;
            onProviderChange(nextProvider);
            onModelChange(MODEL_SUGGESTIONS[nextProvider]);
            setMessage("");
          }}
        >
          <option value="openai">OpenAI</option>
          <option value="gemini">Google Gemini</option>
          <option value="anthropic">Anthropic Claude</option>
          <option value="openrouter">OpenRouter</option>
        </select>
      </label>
      <label className="ai-key-label" htmlFor="ai-model">
        Model ID
        <input
          id="ai-model"
          name="ai-model"
          type="text"
          value={model}
          maxLength={200}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => {
            onModelChange(event.target.value);
            setMessage("");
          }}
          placeholder={MODEL_PLACEHOLDERS[provider]}
          aria-describedby="ai-provider-help"
        />
      </label>
      <p id="ai-provider-help" className="ai-privacy-copy">
        Use a model ID supported by your provider account. OpenRouter requires a catalog ID such as author/model. DevGuard uses the selected provider and model exactly; it does not fall back to another provider or model.
      </p>
      <label className="ai-key-label" htmlFor="ai-api-key">
        {providerName} API key
        <input
          id="ai-api-key"
          name="ai-api-key"
          type="password"
          value={apiKey}
          maxLength={1024}
          autoComplete="new-password"
          autoCorrect="off"
          spellCheck={false}
          onChange={(event) => {
            onKeyChange(event.target.value);
            setMessage("");
          }}
          placeholder="Paste your key; it stays in this tab's memory"
          aria-describedby="ai-key-privacy"
        />
      </label>
      <p id="ai-key-privacy" className="ai-privacy-copy">
        The key is held in browser memory and clears on refresh, closing the tab, or Remove Key. Each request sends it to this DevGuard backend over HTTPS outside localhost; the backend handles it transiently and forwards it to the selected provider over HTTPS. DevGuard application code does not persist or log it. The backend operator and hosting or proxy layers can handle the key while the request is processed; disable Authorization-header logging and use only a trusted backend. Provider retention and privacy terms apply to requests.
      </p>
      <p className="ai-privacy-copy">
        Test Connection sends a minimal generation request to the selected model and may incur a small charge. Custom endpoints are disabled because arbitrary destinations cannot be safely protected from server-side request forgery in this backend.
      </p>
      <div className="ai-settings-actions">
        <button className="primary" onClick={testConnection} disabled={busy || !apiKey.trim()}>
          {busy ? "Testing…" : "Test Connection"}
        </button>
        <button className="secondary" onClick={removeKey} disabled={busy || !apiKey}>
          Remove Key
        </button>
      </div>
      <p className="ai-status" role={messageKind === "error" ? "alert" : "status"} data-kind={messageKind} aria-live="polite">
        {message || (apiKey ? "Key is held in this tab's memory." : "No key configured.")}
      </p>
      <p className="ai-deployment-warning">
        This DevGuard backend has no user authentication or user-data isolation. Do not expose it publicly until authentication, authorization, rate limiting, and per-user data isolation are implemented; CORS is not authentication.
      </p>
    </section>
  );
}

export function AiFindingAssistant({ apiBase, apiKey, provider, model, finding, onOpenSettings }: AiFindingProps) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [explanation, setExplanation] = useState("");
  const consentDialogRef = useRef<HTMLElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const providerName = PROVIDERS[provider];

  useEffect(() => {
    if (!confirming) return;
    const dialog = consentDialogRef.current;
    const previousFocus = previousFocusRef.current;
    dialog?.querySelector<HTMLElement>("button:not([disabled])")?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setConfirming(false);
        return;
      }
      if (event.key !== "Tab" || !dialog) return;
      const focusable = dialog.querySelectorAll<HTMLElement>("button:not([disabled])");
      if (!focusable.length) {
        event.preventDefault();
        dialog.focus();
      } else if (event.shiftKey && document.activeElement === focusable[0]) {
        event.preventDefault();
        focusable[focusable.length - 1].focus();
      } else if (!event.shiftKey && document.activeElement === focusable[focusable.length - 1]) {
        event.preventDefault();
        focusable[0].focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      previousFocus?.focus?.();
    };
  }, [confirming]);

  const generate = async () => {
    const severities: Severity[] = ["Critical", "High", "Medium", "Low", "Informational"];
    if (!severities.includes(finding.severity as Severity)) {
      setError("This finding has an unsupported severity label and cannot be sent.");
      return;
    }
    if (!validModel(model, provider)) {
      setError("Enter a valid model ID for the selected provider in Settings.");
      return;
    }
    if (!secureBackendTransport(apiBase)) {
      setError("The API key was not sent: configure an HTTPS DevGuard API URL outside localhost.");
      return;
    }
    const summary: AiFindingSummary = {
      title: finding.title,
      description: finding.description,
      severity: finding.severity as Severity,
      category: finding.category,
      rule_id: finding.rule_id,
      remediation: finding.remediation,
    };
    setBusy(true);
    setError("");
    setExplanation("");
    try {
      const response = await fetch(`${apiBase}/ai/explain`, {
        method: "POST",
        headers: { ...aiHeaders(provider, model, apiKey), "Content-Type": "application/json" },
        body: JSON.stringify(summary),
      });
      if (!response.ok) {
        setError(await errorMessage(response));
        return;
      }
      const body = await response.json();
      if (typeof body?.explanation !== "string" || !body.explanation.trim()) {
        setError(`${providerName} returned no usable explanation. Review the finding manually.`);
        return;
      }
      setExplanation(body.explanation.slice(0, 12000).split(apiKey).join("[redacted key]"));
      setConfirming(false);
    } catch {
      setError("Could not reach the DevGuard API. Check its configured endpoint.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="ai-assist" aria-labelledby="ai-assist-title">
      <h3 id="ai-assist-title">AI explanation · optional</h3>
      <p>AI output is advisory. Review the scanner finding and verify remediation yourself.</p>
      {apiKey ? (
        <button
          className="secondary"
          disabled={busy}
          onClick={(event) => {
            previousFocusRef.current = event.currentTarget;
            setError("");
            setConfirming(true);
          }}
        >
          Explain with {providerName}
        </button>
      ) : (
        <button className="secondary" onClick={onOpenSettings}>Configure a key in Settings</button>
      )}
      {error && !confirming && <p className="ai-assist-error" role="alert">{error}</p>}
      {explanation && (
        <div className="ai-result" aria-live="polite">
          <strong>AI suggestion · verify before applying</strong>
          <pre>{explanation}</pre>
        </div>
      )}
      {confirming && (
        <div
          className="ai-consent-backdrop"
          onClick={(event) => {
            event.stopPropagation();
            setConfirming(false);
          }}
        >
          <section
            className="ai-consent-dialog"
            ref={consentDialogRef}
            tabIndex={-1}
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="ai-consent-title"
            aria-describedby="ai-consent-description"
            onClick={(event) => event.stopPropagation()}
          >
            <h3 id="ai-consent-title">Send this finding summary to {providerName}?</h3>
            <p id="ai-consent-description">
              After you confirm, DevGuard sends these fields to {providerName} through your configured backend:
            </p>
            <ul>
              <li>Finding title and scanner description</li>
              <li>Severity, category, and rule ID</li>
              <li>Current remediation recommendation</li>
            </ul>
            <p>
              Source code, evidence excerpts, file paths, line numbers, project names, scan IDs, and reports are excluded. The result is shown in this tab only and is not saved to scan history or reports.
            </p>
            <p>This request may incur API usage charges on the account associated with your key.</p>
            {error && <p className="ai-assist-error" role="alert">{error}</p>}
            <div className="ai-consent-actions">
              <button className="secondary" onClick={() => setConfirming(false)}>Cancel</button>
              <button className="primary" disabled={busy} onClick={() => void generate()}>
                {busy ? "Requesting…" : `Send summary to ${providerName}`}
              </button>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}
