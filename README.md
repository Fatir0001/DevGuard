# DevGuard

**Scan smarter. Build safer.** DevGuard is a local-first project scanner for students and developers. Upload a ZIP, inspect evidence-backed potential issues, review findings, rescan the same project, and export reports. It never executes uploaded code.

# DevGuard 🛡️
### *Scan smarter. Build safer.*

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Node.js 22.12+](https://img.shields.io/badge/node.js-22.12+-green.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**DevGuard is a local-first project scanner for students and developers. Upload a ZIP, inspect evidence-backed potential issues, review findings, rescan the same project, and export reports. It never executes uploaded code.**

---

## Features

- React, TypeScript and Vite workstation UI with real SQLite-backed dashboard and scan history.
- ZIP validation before a project or scan record is created; limits, traversal checks, symlink and duplicate path rejection, and temporary workspace cleanup.
- Python AST checks, conservative JavaScript TLS pattern check, JSON debug configuration and Docker non-root checks.
- Secret-like value detection with redacted evidence and common example placeholders excluded.
- Exact-version dependency lookup through OSV.dev for pinned `requirements.txt`, exact `package.json` entries, and npm lockfiles.
- Project rescans, findings search/filter/sort, keyboard-accessible finding details, review status, scan comparison, JSON and HTML reports.
- No login, code execution, automatic fixes, arbitrary URL fetching, or Git cloning. Scanning works without AI; optional OpenAI, Gemini, Claude, and OpenRouter BYOK assistance is available in Settings.

## Requirements

- Python 3.11 or newer
- Node.js 22.12+ (or 20.19+)

## Start on Windows

Open PowerShell in the project root. In the first window:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
python -m uvicorn backend.app.main:app --reload
```

In a second window:

```powershell
cd frontend
npm ci
npm run dev
```

Open http://localhost:5173. The API and interactive OpenAPI reference are at http://127.0.0.1:8000 and http://127.0.0.1:8000/docs. If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process RemoteSigned` in that window, then activate the environment.

## Scan the synthetic example

The fixture under `examples/synthetic-project` contains fake demonstration patterns only. It is not a real credential and must not be run. Create a ZIP in the root:

```powershell
Compress-Archive -Path .\examples\synthetic-project\* -DestinationPath .\synthetic-project.zip -Force
```

In DevGuard, choose **New Scan**, create a project named `synthetic-demo`, select `synthetic-project.zip`, and start the scan. Expected potential findings include `DG-SECRET`, `DG-PY-SQL-FSTRING`, `DG-PY-EVAL`, and `DG-TLS-VERIFY`. The secret value should appear only as `[REDACTED]` in evidence and reports. Remove the generated ZIP when finished.

## Run checks

From the root with the virtual environment active:

```powershell
python -m pytest backend\tests -q
```

Frontend:

```powershell
cd frontend
npm test
npm run build
```

The suite uses synthetic source and mocked OSV responses. It does not require a live target or make OSV requests.

## Netlify frontend configuration

Set Netlify's base directory to frontend, build command to npm run build, and publish directory to dist. Set the build-time variable VITE_API_URL to the deployed API base including /api (for example, https://api.example.invalid/api); without it, production builds use the same-origin /api path. For a cross-origin API, set DEVGUARD_CORS_ORIGINS on the API to the exact frontend origins, comma-separated, such as https://your-site.netlify.app. Do not use a wildcard. The backend defaults to `backend/devguard.db`; set `DEVGUARD_DATABASE_PATH` to a writable file path on a persistent mounted volume before starting the service if that disk does not persist the app directory. DevGuard currently supports SQLite only; a host without persistent file storage requires a database migration before production use. CORS is not authentication: this API has no login or access control and must remain private or be protected separately before internet exposure. frontend/public/robots.txt disallows crawling because scans and uploaded projects are private workspace data. Netlify's non-forced SPA rewrite is in frontend/public/_redirects.

## Data flow and privacy

The API validates and safely extracts the uploaded archive into a per-scan temporary directory. The worker inventories and reads supported files as data, performs local checks, and sends only exact package names, ecosystems, and versions to OSV.dev. Uploaded source and detected secret values are not sent to OSV. Temporary source is deleted after the worker finishes. SQLite stores project/scan metadata, review state, and redacted finding evidence in `backend/devguard.db`.

Optional BYOK assistance supports OpenAI, Google Gemini, Anthropic Claude, and OpenRouter. A user chooses the provider and model ID. OpenAI defaults to `gpt-6-luna`, Gemini to `gemini-3.8-flash`, Claude to `claude-sonnet-5`; OpenRouter needs a model ID from its catalog. Defaults may change or may not be enabled for a particular account. Gemini requires a key type accepted by Google's current Gemini API policy; some older unrestricted standard keys may no longer work. Test Connection sends a minimal generation request to the selected model and may incur a small usage charge; it does not merely check whether the key field is nonempty.

Keys remain in the current tab's React memory and are sent in an Authorization header to the configured DevGuard backend only when testing or confirming an explanation. The backend can see the key transiently while forwarding it to the selected provider over HTTPS. DevGuard application code does not store or log keys in SQLite, scan history, reports, or error messages. The browser refuses to send keys over HTTP except to `localhost`, `127.0.0.1`, or `::1`. Ensure hosting proxies do not log Authorization headers. Before an explanation request, the consent dialog lists only finding title, scanner description, severity, category, rule ID, and remediation; source, evidence, paths, line numbers, project/scan identifiers, and reports are excluded. The response is rendered in the current tab and is not saved. Provider privacy, retention, routing, and billing terms apply; review those terms before sending sensitive metadata. Remove Key, refresh, or closing the tab clears the in-memory key.

Custom OpenAI-compatible URLs are not supported because DevGuard does not yet have the DNS pinning, private-address blocking, and egress controls needed to mitigate SSRF safely. The AI module remains lazy-loaded. This backend has no authentication, authorization, rate limiting, or per-user isolation. Keep it private and bound to localhost; do not expose it publicly until those controls are added. CORS is not authentication. The backend operator can access supplied keys while requests are in process memory.

DevGuard is a local development tool without authentication. Keep the API bound to localhost and do not expose it to untrusted networks. The BYOK endpoints do not add user identity or isolation; anyone who can reach this backend can access the existing scan APIs and submit requests using keys they provide. CORS is not authentication. Findings are heuristics unless linked to an OSV advisory. A clean scan does not guarantee that a project is secure.

## Portfolio capture suggestions

Capture the empty dashboard with the local API status visible, the synthetic scan progress/result view, the finding detail drawer with redacted evidence, the scan comparison showing “no longer detected” language, and an exported HTML report. Use synthetic-only data in public screenshots.

## Limitations

See [ARCHITECTURE.md](ARCHITECTURE.md) for exact rule coverage, APIs, queue behavior, and known gaps. ZIP upload is currently the only project input. The queue is bounded and in-process, so interrupted jobs are marked failed on the next server start. Review state is Open/Reviewed only; Reviewed does not mean Resolved. There is no browser end-to-end automation or live OSV integration test yet.


