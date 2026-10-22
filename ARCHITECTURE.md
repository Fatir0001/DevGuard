# DevGuard architecture

## Structure

```text
backend/
  app/main.py        FastAPI routes, SQLite models, bounded worker and reports
  app/scanner.py     ZIP extraction, inventory, source/config rules and OSV client
  tests/             Scanner and API integration tests with synthetic inputs
frontend/
  src/App.tsx        React pages and API-backed interactions
  src/style.css      Existing component styles
  src/workstation.css Terminal-inspired colors, focus, motion and responsive refinements
examples/
  synthetic-project/ Fake vulnerable patterns for a portfolio demo
```

FastAPI exposes OpenAPI docs. SQLAlchemy persists project, scan and finding metadata in SQLite at `backend/devguard.db` by default. Set `DEVGUARD_DATABASE_PATH` before startup to put that SQLite file on a host-mounted persistent volume; this setting does not add support for PostgreSQL or make local/ephemeral disks durable. The schema is created without dropping existing data; a backward-compatible startup update adds nullable `scans.deleted_at` to older databases. On application import, scans left queued/running by an earlier process are marked failed with a restart explanation because the worker queue is not durable. A bounded `ThreadPoolExecutor` has two active workers; a semaphore caps active plus queued scans at ten.

## Scan lifecycle and limits

The API validates the project name and ZIP type, enforces a 25 MB upload cap, extracts to a unique temporary directory, and only then creates database records. ZIP extraction rejects traversal, absolute/drive paths, symlinks, encrypted and duplicate paths, excessive entries, and file-size mismatches. Limits are 5,000 entries/files, 2 MB per extracted file, and 50 MB total actual extracted bytes. Source is deleted after a worker finishes, including failed scans. Uploaded code and build commands are never executed.

Stages reported by the worker are Queued, Analyzing files, Saving findings, Complete, and Failed. File totals are available when inventory finishes; there is no fabricated per-file percent or live finding counter. Cancellation and durable queue recovery are not implemented. Failed scans expose a concise error, not a stack trace.

## Scan History Bin

Moving a completed or failed scan to the Bin sets its `deleted_at` timestamp; the scan row, findings, review state, timestamps, and generated-on-demand reports remain intact. Running and queued scans cannot be moved while work is in progress. Normal scan history, dashboard summaries, project scan lists/counts, global Findings, and comparisons exclude binned records. Exact scan detail, findings, and report endpoints continue to serve the retained record so its data remains available until permanent deletion.

The Bin supports atomic bulk trash and restore, individual restore, individual permanent deletion, and Empty Bin. Permanent deletion removes the selected scan rows and their finding rows in one database transaction. Scan uploads and report files are not persisted: upload staging is temporary and reports are rendered from SQLite on request, so there are no per-scan filesystem artifacts to remove. Permanent deletion is restricted to scans already in the Bin. Scan IDs are validated as UUIDs on mutation endpoints, and missing/conflicting records return HTTP errors without partially applying bulk changes.

## Scanner coverage

| Rule / input | Detection | Intended severity | Limits |
| --- | --- | --- | --- |
| `DG-SECRET` | Credential-like assignments | High | Pattern match only; placeholders are skipped and evidence values are redacted. This does not prove a credential is live or privileged. |
| `DG-SECRET` | Recognized PEM private-key markers (`PRIVATE`, `RSA`, `EC`, `DSA`, `OPENSSH`, and `ENCRYPTED PRIVATE KEY`) | Critical | Marker-based detection; key material is not validated. Marker evidence is replaced with a redacted note. `.pem` and `.key` files are inventoried for this check. |
| `DG-PY-SQL-FSTRING` | Interpolated Python f-string passed to `.execute()` | High | Heuristic sink match; does not prove the interpolated value is attacker-controlled. |
| `DG-PY-EVAL` | Python `eval()` with a non-literal string expression | High | Does not perform taint analysis; literal-only examples are skipped. |
| `DG-CMD-SHELL` | Python subprocess `run`, `Popen`, `call`, or `check_output` with `shell=True` | High | Reports shell use; does not prove external input reaches the command. |
| `DG-TLS-VERIFY` | Python requests/httpx calls using `verify=False`; JS/TS line pattern `rejectUnauthorized: false` | High | Does not parse every language or multiline JS expression. |
| `DG-CONFIG-DEBUG` | JSON object `debug: true`; a module-level Python `DEBUG = True` or `APP_DEBUG = True`; INI/CFG `debug` or `app_debug` set to a recognized true value | Medium | Context warning only; confirm whether the file is used in production. Python checks only direct literal assignments. An environment label such as `ENVIRONMENT = "development"` is not sufficient evidence and is not reported. |
| `DG-DEP-UNRESOLVED` | Dependency declarations without an exact version | Informational | Explains why no exact OSV lookup was done; it is not a vulnerability finding. |
| `OSV` | Advisory returned for an exact package coordinate | Critical, High, Medium, or Low when OSV provides a recognized qualitative severity or valid CVSS vector; otherwise Informational | Qualitative severity labels are read from advisory or matching affected-package `database_specific.severity` and `ecosystem_specific.severity`. OSV CVSS V2/V3/V4 vectors are scored with the pinned `cvss` library. Unknown or missing values are Informational, and the source value is retained when available. |

There is no static rule that assigns Low. Low is currently available through OSV advisory data. Generic credential-like assignments remain High; they are not promoted to Critical based only on a variable name or secret-like value. Critical is reserved for recognized private-key PEM markers or an OSV advisory explicitly classified Critical.

Python source is parsed with the standard-library AST. Supported inventoried extensions include `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.java`, `.json`, `.ini`, `.cfg`, `.yaml`, `.yml`, `.toml`, `.txt`, `.pem`, and `.key`, plus Dockerfiles. The debug rule recognizes explicit true settings in JSON, module-level Python assignments to `DEBUG`/`APP_DEBUG`, and INI/CFG boolean options named `debug`/`app_debug`, including simple sectionless key/value files. It does not infer that a `development` environment label enables debug behavior, inspect assignments nested in Python functions/classes, or recognize framework-specific aliases. Language-specific security analysis is not implemented for Java, YAML, TOML, or general JavaScript/TypeScript. Secret matching applies to supported text files. Dockerfiles have no dedicated rule. Generated/dependency/version-control directories are skipped.

### Dependency data

- Python: exact `name==version` entries in `requirements.txt`; ranges/unpinned entries are informational and are not queried.
- npm: exact versions from package-lock v1 dependency trees or v2/v3 `packages` maps. Exact versions in `package.json` are supported when there is no lock entry; semver ranges are informational and skipped.
- Duplicate ecosystem/name/version coordinates are queried once. When a lockfile resolves a package, its version suppresses the corresponding unresolved package-manifest note.
- OSV requests are sent in batches of 100 with an 8-second request timeout and 3-second connect timeout. Successful exact-coordinate results are cached in memory for the process lifetime. An empty successful result means no matching advisory was returned for that coordinate. Errors and malformed batch responses mark the scan partial; they do not mark packages clean.
- Source text, file paths, finding evidence, and credentials are never submitted. OSV-provided `https` references, identifiers, affected ranges, and fixed versions are retained. Qualitative severities and supported CVSS vectors are normalized; malformed, unknown, or missing severity metadata produces an Informational advisory finding rather than an invented level. The source severity string/vector remains available when present.

## Findings, comparison, and reports

Findings share rule, title, explanation, category, severity, confidence, location/dependency, redacted evidence, remediation, references, advisory metadata, and review state. The scanner assigns severity in its finding payload; the worker JSON-serializes that payload into the SQLite `findings.payload` column. Scan and finding API routes return the stored severity unchanged, and scan summaries count it without reclassification. The React finding type carries the label to the table and detail drawer, where it is rendered as text and a lowercase CSS severity class. Potential heuristic matches are explicitly described as potential. Review is a boolean Open/Reviewed triage state; it does not mark a finding fixed or resolved. False-positive and resolved workflows are not implemented.

Dashboard severity and finding counts use only the latest completed active scan for each project, avoiding duplicate totals from rescans. The Findings page can search title/rule/path and filter severity, category, project and review state, or sort by latest scan, severity, or title; binned findings do not appear in this active view. A comparison only accepts two completed active scans from the same project and matches rule/location or dependency/version/advisory keys. “Not detected in latest” is not presented as verified resolution.

JSON reports use schema version `1.0` and include scan/project identifiers, timestamps/status, duration, scanner/ruleset versions, severity summary, findings, and limitations. HTML reports escape names, paths, titles, remediation, and evidence; only `https` advisory references become links. Both reports preserve the finding review flag and use already-redacted evidence.

## Optional multi-provider BYOK assistance

Optional AI assistance supports OpenAI, Google Gemini, Anthropic Claude, and OpenRouter. Scanning and report generation do not depend on AI. The React feature remains a separate lazy-loaded Vite chunk. Users select a provider and editable model ID; DevGuard sends requests only to that provider's fixed HTTPS API origin. Defaults are `gpt-6-luna`, `gemini-3.8-flash`, and `claude-sonnet-5`; OpenRouter requires a catalog model ID such as `author/model`. Model access depends on the user's account and may change over time. DevGuard does not query a different provider or silently substitute a model.

Provider requests use native protocols: OpenAI Responses API with Bearer authentication and `store: false`; Gemini `generateContent` with the `x-goog-api-key` header; Anthropic Messages API with `x-api-key` and `anthropic-version`; and OpenRouter Chat Completions with Bearer authentication. OpenRouter may apply its own routing policy within that service. Test Connection makes a minimal generation request to the selected model so it checks actual generation access; it can incur a small charge. Provider responses are classified into safe error categories without returning upstream error bodies. Provider generation and data-retention policies still apply; `store: false` only requests non-storage behavior from the OpenAI Responses API.

The selected key remains in the current tab's React memory, is passed in the `Authorization` header to DevGuard for each explicit operation, and is held in request-local FastAPI variables while being forwarded upstream. DevGuard application code does not cache, log, or store keys in SQLite, scan history, reports, or error responses. Refresh or tab close clears the browser value. The browser refuses to send keys over non-HTTPS API URLs except localhost/loopback. Reverse proxies and hosting infrastructure are outside the application's control; disable Authorization-header logging. Backend operators can access keys transiently in process memory.

Generating a finding explanation requires a separate confirmation. The request schema allows only title, scanner description, severity, category, rule ID, and remediation; extra fields such as evidence, source, file paths, line numbers, and scan/project IDs are rejected. The backend does not look up scan or finding records for these endpoints. Provider responses are returned to the requesting tab as plain text and are not persisted in the scan record, database, or report. The AI text is advisory and must be reviewed. Finding metadata confirmed by the user is sent to the selected provider; users should check that provider's current privacy and retention terms before sending sensitive metadata.

Arbitrary custom OpenAI-compatible URLs are intentionally unsupported. Accepting user-selected destinations would create an SSRF path; this backend does not implement DNS pinning, private-address rejection, redirect controls, and egress isolation needed to safely guarantee custom-host requests. DevGuard has no authentication or per-user isolation. Keep the backend private and bound to localhost; do not expose it publicly until authentication, authorization, rate limiting, upload limits, and per-user data isolation are implemented. CORS is not authentication. This local-first BYOK feature is not a secure multi-user or public-hosting design.

## API highlights

- `GET /api/health` — status and scanner/ruleset versions
- `POST /api/scans` — ZIP upload for a new project (`name`) or an existing project (`project_id`)
- `GET /api/scans`, `GET /api/scans/{scan_id}`, `GET /api/scans/{scan_id}/findings`
- `POST /api/scans/{scan_id}/trash`, `POST /api/scans/trash` — move one or several completed scans to the Bin
- `GET /api/bin`, `POST /api/bin/{scan_id}/restore`, `POST /api/bin/restore` — list or restore binned scans
- `DELETE /api/bin/{scan_id}`, `DELETE /api/bin` — permanently delete one binned scan or empty the Bin
- `GET /api/findings` — paginated findings with severity/category/project/review/search filters
- `PATCH /api/findings/{finding_id}` — Open/Reviewed state
- `GET /api/projects`, `GET /api/projects/{project_id}`, `GET /api/projects/{project_id}/compare`
- `GET /api/scans/{scan_id}/report.json` and `/report.html`
- `POST /api/ai/test` — minimal generation check for the selected provider and model (`Authorization`, `X-DevGuard-Provider`, and `X-DevGuard-Model` headers)
- `POST /api/ai/explain` — generate an on-demand explanation from an explicitly approved allowlisted finding summary, with the same provider/model headers

CORS permits the local Vite origins `localhost:5173` and `127.0.0.1:5173`, the local production preview `127.0.0.1:4173`, plus explicitly configured origins from `DEVGUARD_CORS_ORIGINS`. The Netlify frontend accepts a build-time `VITE_API_URL` and defaults to same-origin `/api` for production builds; development retains the local FastAPI URL. CORS is not authentication. No authentication is present, so this is not a multi-user or internet-exposed service design.

## Frontend delivery and accessibility

The dashboard severity view is a small native HTML meter list rather than a charting-library bundle. Severity names and counts stay visible alongside bar lengths, and meters expose their values to assistive technology. The dark palette uses brighter tertiary text where prior label colors fell below WCAG AA contrast; sidebar count badges use a brighter foreground on their dark green surface. The app shell declares English and includes a concise product description. robots.txt disallows crawling, and Netlify serves built files directly before applying the non-forced SPA fallback.

Frontend data loading is route-aware: active scan summaries load on Dashboard, Scan History, Reports, and Scan progress; project lists load on New Scan, Projects, and Findings; the full Bin list loads only on Bin. Other pages request only the Bin total (one list item) for the sidebar count. The API routes and data semantics are unchanged.

Client pages map to the root route and the /scan, /projects, /findings, /history, /bin, /reports, and /settings paths using the existing page state. Scan progress uses /scan-progress/{scan_id} so it can reload the selected scan and its findings. Direct loads, refreshes, and browser back/forward restore the selected page. Existing pages still share the existing App.tsx module; optional AI settings and finding assistance are dynamically imported and built into a separate chunk.

## Verification and remaining work

Backend unit/API tests mock OSV and use synthetic projects, including CVSS vectors, empty results, unavailable-service responses, scan trash/restore, migration, and permanent deletion. Frontend tests cover Bin navigation, confirmation dialogs, restore, API failure handling, dashboard offline state, and database-derived summaries. There is no live OSV integration test, browser automation of ZIP upload, cancellation, folder picker, durable queue, broader language parsing, full migrations framework, or authentication. For setup and the synthetic sample workflow, see [README.md](README.md).
