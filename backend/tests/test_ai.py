import json

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.app import ai, main
from backend.app.main import Base, app


@pytest.fixture
def isolated_database(monkeypatch, tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.engine import URL
    from sqlalchemy.orm import sessionmaker

    path = tmp_path / "ai-feature.db"
    engine = create_engine(
        URL.create("sqlite", database=str(path)),
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    monkeypatch.setattr(main, "engine", engine)
    monkeypatch.setattr(main, "Session", sessionmaker(bind=engine))
    yield path
    engine.dispose()


class ProviderResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self.payload = payload or {}

    def json(self):
        return self.payload


def provider_payload(provider, text="OK"):
    if provider == "openai":
        return {"output": [{"content": [{"type": "output_text", "text": text}]}]}
    if provider == "gemini":
        return {"candidates": [{"content": {"parts": [{"text": text}]}}]}
    if provider == "anthropic":
        return {"content": [{"type": "text", "text": text}]}
    return {"choices": [{"message": {"content": text}}]}


@pytest.mark.parametrize(
    ("provider", "model", "url", "key_header"),
    [
        ("openai", "gpt-6-luna", ai.PROVIDER_URLS["openai"], "Authorization"),
        ("gemini", "gemini-3.8-flash", ai.PROVIDER_URLS["gemini"].format(model="gemini-3.8-flash"), "x-goog-api-key"),
        ("anthropic", "claude-sonnet-5", ai.PROVIDER_URLS["anthropic"], "x-api-key"),
        ("openrouter", "openai/gpt-6-luna", ai.PROVIDER_URLS["openrouter"], "Authorization"),
    ],
)
def test_connection_sends_minimal_request_to_exact_provider_and_model(
    provider, model, url, key_header, monkeypatch, isolated_database
):
    secret = f"synthetic-provider-key-{provider}-0001"
    calls = []

    def fake_post(actual_url, **kwargs):
        calls.append((actual_url, kwargs))
        return ProviderResponse(200, provider_payload(provider))

    monkeypatch.setattr(ai.httpx, "post", fake_post)
    with TestClient(app) as client:
        response = client.post(
            "/api/ai/test",
            headers={
                "Authorization": f"Bearer {secret}",
                "X-DevGuard-Provider": provider,
                "X-DevGuard-Model": model,
            },
        )

    assert response.status_code == 200, response.text
    assert response.json() == {"status": "ok", "provider": ai.PROVIDER_NAMES[provider], "model": model}
    assert len(calls) == 1
    actual_url, request = calls[0]
    assert actual_url == url
    assert request["follow_redirects"] is False
    assert request["timeout"] == ai.REQUEST_TIMEOUT
    assert request["headers"][key_header] == (f"Bearer {secret}" if key_header == "Authorization" else secret)
    assert request["json"] != {}
    assert request["json"].get("model", model) == model if provider != "gemini" else True
    if provider == "openai":
        assert request["json"] == {
            "model": model,
            "instructions": "Reply with OK.",
            "input": "Reply with OK.",
            "max_output_tokens": 64,
            "store": False,
        }
    elif provider == "gemini":
        assert request["json"]["contents"] == [{"role": "user", "parts": [{"text": "Reply with OK."}]}]
        assert request["json"]["generationConfig"] == {
            "maxOutputTokens": 64,
            "thinkingConfig": {"thinkingLevel": "low"},
        }
    elif provider == "anthropic":
        assert request["headers"]["anthropic-version"] == "2023-06-01"
        assert request["json"]["messages"] == [{"role": "user", "content": "Reply with OK."}]
        assert request["json"]["max_tokens"] == 32
    else:
        assert request["json"]["model"] == model
        assert request["json"]["messages"] == [
            {"role": "system", "content": "Reply with OK."},
            {"role": "user", "content": "Reply with OK."},
        ]
        assert request["json"]["max_tokens"] == 32
    stored = isolated_database.read_bytes()
    assert secret.encode() not in stored
    assert secret not in response.text


@pytest.mark.parametrize(
    "authorization",
    [None, "", "Basic sk-not-a-bearer-token", "Bearer short", "Bearer key with spaces"],
)
def test_invalid_or_missing_key_is_rejected_without_provider_request(authorization, monkeypatch):
    monkeypatch.setattr(ai.httpx, "post", lambda *args, **kwargs: pytest.fail("provider must not be called"))
    headers = {"Authorization": authorization} if authorization else {}
    with TestClient(app) as client:
        response = client.post("/api/ai/test", headers=headers)
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("status", "provider_error", "expected_status", "expected_code"),
    [
        (401, {"type": "authentication_error", "message": "no"}, 401, "invalid_credentials"),
        (403, {"type": "permission_error", "message": "denied"}, 403, "permission_denied"),
        (402, {"type": "payment_required", "message": "credit"}, 402, "insufficient_quota"),
        (429, {"code": "insufficient_quota", "message": "quota"}, 402, "insufficient_quota"),
        (429, {"type": "rate_limit_error", "message": "Quota exceeded for requests per minute"}, 429, "rate_limited"),
        (429, {"type": "rate_limit_error", "message": "Monthly spending limit reached"}, 402, "insufficient_quota"),
        (400, {"type": "invalid_request_error", "message": "Organization usage limit reached"}, 402, "insufficient_quota"),
        (400, {"status": "INVALID_ARGUMENT", "message": "models/gemini-unknown is not found for API version v1beta, or is not supported for generateContent."}, 422, "unsupported_model"),
        (429, {"type": "rate_limit_error", "message": "slow down"}, 429, "rate_limited"),
        (404, {"code": "model_not_found", "message": "missing"}, 422, "unsupported_model"),
        (500, {"message": "provider internal error"}, 502, "provider_error"),
    ],
)
def test_provider_errors_are_classified_and_sanitized(
    status, provider_error, expected_status, expected_code, monkeypatch, caplog
):
    secret = "synthetic-key-never-return-this-value"
    provider_error["message"] += f" {secret}"
    monkeypatch.setattr(
        ai.httpx,
        "post",
        lambda *args, **kwargs: ProviderResponse(status, {"error": provider_error}),
    )
    with TestClient(app) as client:
        response = client.post("/api/ai/test", headers={"Authorization": f"Bearer {secret}"})
    assert response.status_code == expected_status
    assert response.json()["detail"]["code"] == expected_code
    assert secret not in response.text
    assert secret not in caplog.text


@pytest.mark.parametrize("is_timeout", [True, False])
def test_network_failures_are_classified_without_echoing_exception(is_timeout, monkeypatch, caplog):
    secret = "synthetic-network-key-secret"

    def fail_post(url, **kwargs):
        request = httpx.Request("POST", url)
        if is_timeout:
            raise httpx.ReadTimeout(f"diagnostic {secret}", request=request)
        raise httpx.ConnectError(f"diagnostic {secret}", request=request)

    monkeypatch.setattr(ai.httpx, "post", fail_post)
    with TestClient(app) as client:
        response = client.post("/api/ai/test", headers={"Authorization": f"Bearer {secret}"})
    assert response.status_code == (504 if is_timeout else 502)
    assert response.json()["detail"]["code"] == ("network_timeout" if is_timeout else "network_error")
    assert secret not in response.text
    assert secret not in caplog.text


def test_connection_does_not_accept_empty_success_response(monkeypatch):
    monkeypatch.setattr(ai.httpx, "post", lambda *args, **kwargs: ProviderResponse(200, {}))
    with TestClient(app) as client:
        response = client.post(
            "/api/ai/test",
            headers={"Authorization": "Bearer sk-synthetic-empty-response-key"},
        )
    assert response.status_code == 502
    assert response.json()["detail"]["code"] == "provider_error"


@pytest.mark.parametrize(
    ("provider", "model"),
    [
        ("openai", "gpt-6-luna"),
        ("gemini", "gemini-3.8-flash"),
        ("anthropic", "claude-sonnet-5"),
        ("openrouter", "openai/gpt-6-luna"),
    ],
)
def test_explanation_uses_provider_format_and_only_consented_finding_fields(
    provider, model, monkeypatch
):
    secret = f"synthetic-explanation-secret-{provider}-key"
    forwarded = {}

    def fake_post(url, **kwargs):
        forwarded.update(url=url, **kwargs)
        return ProviderResponse(200, provider_payload(provider, f"Risk and safe remediation. {secret}"))

    monkeypatch.setattr(ai.httpx, "post", fake_post)
    finding = {
        "title": "Debug mode enabled",
        "description": "A production configuration enables debug mode.",
        "severity": "Medium",
        "category": "Configuration",
        "rule_id": "DG-CONFIG-DEBUG",
        "remediation": "Disable debug mode for deployed environments.",
    }
    with TestClient(app) as client:
        response = client.post(
            "/api/ai/explain",
            headers={
                "Authorization": f"Bearer {secret}",
                "X-DevGuard-Provider": provider,
                "X-DevGuard-Model": model,
            },
            json=finding,
        )

    assert response.status_code == 200
    assert response.json() == {"explanation": "Risk and safe remediation. [redacted key]"}
    assert forwarded["url"] == ai.PROVIDER_URLS[provider].format(model=model) if provider == "gemini" else ai.PROVIDER_URLS[provider]
    assert forwarded["headers"]["Content-Type"] == "application/json"
    assert forwarded["headers"].get("Authorization", forwarded["headers"].get("x-api-key", forwarded["headers"].get("x-goog-api-key"))) in {f"Bearer {secret}", secret}
    assert forwarded["json"].get("store") is False if provider == "openai" else True
    if provider == "openai":
        assert forwarded["json"]["model"] == model
        sent_summary = json.loads(forwarded["json"]["input"])
    elif provider == "gemini":
        assert forwarded["json"]["systemInstruction"]["parts"][0]["text"] == ai.SYSTEM_INSTRUCTIONS
        sent_summary = json.loads(forwarded["json"]["contents"][0]["parts"][0]["text"])
    elif provider == "anthropic":
        assert forwarded["json"]["model"] == model
        assert forwarded["json"]["system"] == ai.SYSTEM_INSTRUCTIONS
        sent_summary = json.loads(forwarded["json"]["messages"][0]["content"])
    else:
        assert forwarded["json"]["model"] == model
        assert forwarded["json"]["messages"][0] == {"role": "system", "content": ai.SYSTEM_INSTRUCTIONS}
        sent_summary = json.loads(forwarded["json"]["messages"][1]["content"])
    assert sent_summary == finding
    assert not {"evidence", "file_path", "line", "scan_id", "project_id", "source"} & set(sent_summary)
    assert secret not in response.text


def test_explanation_rejects_source_evidence_and_unknown_fields_before_provider_call(monkeypatch):
    monkeypatch.setattr(ai.httpx, "post", lambda *args, **kwargs: pytest.fail("invalid payload must not be sent"))
    finding = {
        "title": "Synthetic finding",
        "description": "A rule matched.",
        "severity": "High",
        "category": "Code",
        "rule_id": "DG-TEST",
        "remediation": "Review the code.",
        "evidence": "do-not-send-this-source-excerpt",
    }
    with TestClient(app) as client:
        response = client.post(
            "/api/ai/explain",
            headers={"Authorization": "Bearer sk-synthetic-validation-key"},
            json=finding,
        )
    assert response.status_code == 422
    assert "do-not-send-this-source-excerpt" not in response.text


def test_invalid_model_and_arbitrary_provider_are_rejected_before_provider_call(monkeypatch):
    monkeypatch.setattr(ai.httpx, "post", lambda *args, **kwargs: pytest.fail("invalid config must not be sent"))
    with TestClient(app) as client:
        bad_model = client.post(
            "/api/ai/test",
            headers={
                "Authorization": "Bearer sk-synthetic-valid-format-model-key",
                "X-DevGuard-Provider": "gemini",
                "X-DevGuard-Model": "../private-host",
            },
        )
        custom_provider = client.post(
            "/api/ai/test",
            headers={
                "Authorization": "Bearer sk-synthetic-valid-format-custom-key",
                "X-DevGuard-Provider": "custom",
                "X-DevGuard-Model": "anything",
            },
        )
    assert bad_model.status_code == 422
    assert bad_model.json()["detail"]["code"] == "invalid_model_id"
    assert custom_provider.status_code == 422


def test_provider_default_models_are_selected_without_fallback():
    assert ai._model_id("openai", None) == "gpt-6-luna"
    assert ai._model_id("gemini", None) == "gemini-3.8-flash"
    assert ai._model_id("anthropic", None) == "claude-sonnet-5"
    with pytest.raises(Exception) as error:
        ai._model_id("openrouter", None)
    assert getattr(error.value, "detail", {}).get("code") == "model_required"
