import json, zipfile
import pytest
from pathlib import Path
from types import SimpleNamespace
from backend.app import scanner
from backend.app.scanner import scan, safe_extract


def test_rules_and_secret_redaction(tmp_path):
    (tmp_path / "app.py").write_text(
        'import subprocess\npassword = "synthetic_fake_secret_12345"\neval(input())\nsubprocess.run("echo hi", shell=True)\n'
    )
    (tmp_path / "requirements.txt").write_text("")
    _, findings, _, _ = scan(tmp_path, osv=False)
    rules = {x["rule_id"] for x in findings}
    assert {"DG-SECRET", "DG-PY-EVAL", "DG-CMD-SHELL"} <= rules
    assert all("synthetic_fake_secret_12345" not in x["evidence"] for x in findings)


def test_clean_project(tmp_path):
    (tmp_path / "safe.py").write_text('print("hello")\n')
    assert scan(tmp_path, osv=False)[1] == []


def test_zip_slip_rejected(tmp_path):
    z = tmp_path / "bad.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("../outside.txt", "bad")
    with pytest.raises(ValueError):
        safe_extract(z, tmp_path / "dest")


def test_malformed_lock_is_partial(tmp_path):
    (tmp_path / "package-lock.json").write_text("{not json")
    _, findings, _, errors = scan(tmp_path, osv=False)
    assert not findings and errors == ["Malformed package-lock.json"]


def test_source_rules_report_real_lines_and_skip_safe_examples(tmp_path):
    (tmp_path / "risky.py").write_text(
        'import subprocess\n# verify=False is only a comment\ncursor.execute(f"SELECT * FROM users WHERE id={user_id}")\neval(user_input)\nrequests.get(url, verify=False)\n'
    )
    (tmp_path / "safe.py").write_text(
        'import subprocess\neval("1 + 1")\nsubprocess.run(["echo", "ok"])\ncursor.execute("SELECT * FROM users WHERE id=?", (user_id,))\n# requests.get(url, verify=False)\n'
    )
    _, findings, _, _ = scan(tmp_path, osv=False)
    rules = {(item["rule_id"], item["file_path"], item["line"]) for item in findings}
    assert ("DG-PY-SQL-FSTRING", "risky.py", 3) in rules
    assert ("DG-PY-EVAL", "risky.py", 4) in rules
    assert ("DG-TLS-VERIFY", "risky.py", 5) in rules
    assert not any(path == "safe.py" for _, path, _ in rules)


def test_secret_placeholders_are_skipped_and_unquoted_values_redacted(tmp_path):
    (tmp_path / "settings.py").write_text(
        'API_KEY="your_api_key_here"\nPASSWORD=synthetic_liveish_value_8f1a\n'
    )
    _, findings, _, _ = scan(tmp_path, osv=False)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DG-SECRET"
    assert findings[0]["line"] == 2
    assert "synthetic_liveish_value_8f1a" not in json.dumps(findings)
    assert "[REDACTED]" in findings[0]["evidence"]


def test_debug_json_is_contextual_configuration_finding(tmp_path):
    (tmp_path / "appsettings.json").write_text(
        '{\n  "logging": {\n    "debug": true\n  }\n}'
    )
    _, findings, _, _ = scan(tmp_path, osv=False)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DG-CONFIG-DEBUG"
    assert findings[0]["category"] == "Configuration"
    assert findings[0]["file_path"] == "appsettings.json"
    assert findings[0]["line"] == 3
    assert findings[0]["severity"] == "Medium"


@pytest.mark.parametrize(
    ("filename", "content", "expected_lines"),
    [
        ("settings.py", "DEBUG = True\nAPP_DEBUG: bool = True\n", [1, 2]),
        (
            "settings.ini",
            "[app]\ndebug = true\napp_debug = false\nenvironment = development\n",
            [2],
        ),
        ("legacy.cfg", "debug: yes\n", [1]),
    ],
)
def test_debug_configuration_formats_report_only_explicit_enabled_settings(
    tmp_path, filename, content, expected_lines
):
    configuration = tmp_path / filename
    configuration.write_text(content)

    files, findings, _, errors = scan(tmp_path, osv=False)

    assert not errors
    assert configuration in files
    assert len(findings) == len(expected_lines)
    assert [item["line"] for item in findings] == expected_lines
    assert all(
        item["rule_id"] == "DG-CONFIG-DEBUG"
        and item["severity"] == "Medium"
        and item["file_path"] == filename
        and item["description"]
        and item["category"] == "Configuration"
        for item in findings
    )


def test_debug_configuration_does_not_flag_disabled_or_environment_labels(tmp_path):
    (tmp_path / "settings.py").write_text(
        'DEBUG = False\nAPP_DEBUG = "true"\nENVIRONMENT = "development"\n'
    )
    (tmp_path / "settings.ini").write_text(
        "[app]\ndebug = false\nenvironment = development\n"
    )
    (tmp_path / "settings.json").write_text(
        '{"debug":false,"environment":"development"}'
    )

    _, findings, _, _ = scan(tmp_path, osv=False)

    assert findings == []


def test_osv_batch_match_keeps_verified_advisory_data_without_source(
    monkeypatch, tmp_path
):
    import json as json_module

    seen = {}

    def fake_post(url, **kwargs):
        seen.update(kwargs["json"])
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-test-unique-0001",
                                "aliases": ["CVE-2099-0001"],
                                "summary": "Synthetic advisory",
                                "database_specific": {"severity": "HIGH"},
                                "affected": [
                                    {
                                        "ranges": [
                                            {
                                                "type": "ECOSYSTEM",
                                                "events": [
                                                    {"introduced": "0"},
                                                    {"fixed": "2.0.0"},
                                                ],
                                            }
                                        ]
                                    }
                                ],
                                "references": [
                                    {"url": "https://example.org/advisory"},
                                    {"url": "javascript:alert(1)"},
                                ],
                            }
                        ]
                    }
                ]
            },
        )

    monkeypatch.setattr(scanner.httpx, "post", fake_post)
    (tmp_path / "requirements.txt").write_text("synthetic-package-unique==1.0.0")
    (tmp_path / "private.py").write_text("source text is not sent")
    _, findings, deps, errors = scan(tmp_path)
    advisory = next(x for x in findings if x["rule_id"] == "OSV")
    assert not errors
    assert len(deps) == 1
    assert advisory["severity"] == "High"
    assert advisory["advisory_id"] == "GHSA-test-unique-0001"
    assert advisory["cve"] == "CVE-2099-0001"
    assert advisory["references"] == ["https://example.org/advisory"]
    assert seen == {
        "queries": [
            {
                "package": {"name": "synthetic-package-unique", "ecosystem": "PyPI"},
                "version": "1.0.0",
            }
        ]
    }


def test_osv_failure_is_partial_not_clean(monkeypatch, tmp_path):
    import httpx

    def offline(url, **kwargs):
        raise httpx.ConnectError("offline", request=httpx.Request("POST", url))

    monkeypatch.setattr(scanner.httpx, "post", offline)
    (tmp_path / "requirements.txt").write_text("offline-package-unique==9.9.9")
    _, findings, deps, errors = scan(tmp_path)
    assert deps and not findings
    assert errors and "unavailable" in errors[0]


def test_successful_osv_lookup_without_advisory_is_distinct_from_failure(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(scanner, "_OSV_CACHE", {})
    monkeypatch.setattr(
        scanner.httpx,
        "post",
        lambda url, **kwargs: SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"results": [{"vulns": []}]},
        ),
    )
    (tmp_path / "requirements.txt").write_text("clean-package-unique==1.2.3")

    _, findings, dependencies, errors = scan(tmp_path)

    assert dependencies
    assert findings == []
    assert errors == []


def test_exact_python_and_npm_dependencies_use_correct_osv_coordinates(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(scanner, "_OSV_CACHE", {})
    requests = []

    def fake_post(url, **kwargs):
        queries = kwargs["json"]["queries"]
        requests.append(queries)
        query = queries[0]
        package = query["package"]
        advisory = {
            "id": f"GHSA-{package['ecosystem'].lower()}-exact-coordinate",
            "summary": "Synthetic exact-coordinate advisory",
            "database_specific": {"severity": "LOW"},
            "affected": [
                {
                    "package": package,
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "9.9.9"},
                            ],
                        }
                    ],
                }
            ],
            "references": [{"url": "https://example.org/fix"}],
        }
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"results": [{"vulns": [advisory]}]},
        )

    monkeypatch.setattr(scanner.httpx, "post", fake_post)
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.5\n")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"minimist": "1.2.5"}})
    )

    _, findings, dependencies, errors = scan(tmp_path)

    assert not errors
    assert requests == [
        [{"package": {"name": "urllib3", "ecosystem": "PyPI"}, "version": "1.26.5"}],
        [{"package": {"name": "minimist", "ecosystem": "npm"}, "version": "1.2.5"}],
    ]
    assert set(dependencies) == {
        ("PyPI", "urllib3@1.26.5"),
        ("npm", "minimist@1.2.5"),
    }
    osv_findings = [item for item in findings if item["rule_id"] == "OSV"]
    assert {(item["dependency_name"], item["dependency_version"]) for item in osv_findings} == {
        ("urllib3", "1.26.5"),
        ("minimist", "1.2.5"),
    }
    assert all(item["severity"] == "Low" for item in osv_findings)
    assert all("9.9.9" in item["remediation"] for item in osv_findings)


@pytest.mark.parametrize(
    ("severity_metadata", "expected", "source"),
    [
        ({"database_specific": {"severity": "CRITICAL"}}, "Critical", "CRITICAL"),
        ({"database_specific": {"severity": "HIGH"}}, "High", "HIGH"),
        ({"ecosystem_specific": {"severity": "moderate"}}, "Medium", "moderate"),
        ({"database_specific": {"severity": "LOW"}}, "Low", "LOW"),
        (
            {
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
                    }
                ]
            },
            "Low",
            "CVSS_V3: CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
        ),
        (
            {
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N",
                    }
                ]
            },
            "Medium",
            "CVSS_V3: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N",
        ),
        (
            {
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    }
                ]
            },
            "High",
            "CVSS_V3: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        ),
        (
            {
                "severity": [
                    {
                        "type": "CVSS_V4",
                        "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
                    }
                ]
            },
            "Critical",
            "CVSS_V4: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
        ),
        (
            {"severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:N"}]},
            "Medium",
            "CVSS_V2: AV:N/AC:L/Au:N/C:P/I:P/A:N",
        ),
        ({"affected_database_severity": "LOW"}, "Low", "LOW"),
        (
            {"database_specific": {"severity": "unrecognized"}},
            "Informational",
            "unrecognized",
        ),
        (
            {"severity": [{"type": "CVSS_V3", "score": "not-a-valid-vector"}]},
            "Informational",
            "CVSS_V3: not-a-valid-vector",
        ),
        ({}, "Informational", None),
    ],
)
def test_osv_pipeline_normalizes_supported_severity_metadata(
    monkeypatch, tmp_path, severity_metadata, expected, source
):
    monkeypatch.setattr(scanner, "_OSV_CACHE", {})
    package_name = "severity-pipeline-package"
    (tmp_path / "requirements.txt").write_text(f"{package_name}==1.0.0\n")
    severity_metadata = dict(severity_metadata)
    affected_database_severity = severity_metadata.pop(
        "affected_database_severity", None
    )
    advisory = {
        "id": "GHSA-synthetic-severity-pipeline",
        "summary": "Synthetic severity pipeline advisory",
        "details": "A deterministic mocked advisory used to verify the scanner pipeline.",
        "affected": [
            {
                "package": {"name": package_name, "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.0.1"}],
                    }
                ],
            }
        ],
        "references": [{"url": "https://example.org/GHSA-synthetic-severity-pipeline"}],
        **severity_metadata,
    }
    if affected_database_severity:
        advisory["affected"][0]["database_specific"] = {
            "severity": affected_database_severity
        }

    def fake_post(url, **kwargs):
        assert kwargs["json"]["queries"] == [
            {
                "package": {"name": package_name, "ecosystem": "PyPI"},
                "version": "1.0.0",
            }
        ]
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"results": [{"vulns": [advisory]}]},
        )

    monkeypatch.setattr(scanner.httpx, "post", fake_post)

    _, findings, dependencies, errors = scan(tmp_path)

    finding = next(item for item in findings if item["rule_id"] == "OSV")
    assert dependencies
    assert not errors
    assert finding["severity"] == expected
    assert finding["source_severity"] == source
    assert finding["advisory_id"] == "GHSA-synthetic-severity-pipeline"
    assert finding["dependency_name"] == package_name
    assert finding["dependency_version"] == "1.0.0"
    assert finding["affected_ranges"] == [
        {
            "type": "ECOSYSTEM",
            "events": [{"introduced": "0"}, {"fixed": "1.0.1"}],
        }
    ]
    assert "1.0.1" in finding["remediation"]


def test_package_manifest_ranges_defer_to_exact_lock_versions(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "^1.3.0", "exact-lib": "2.4.1"}})
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/left-pad": {"version": "1.3.0"},
                    "node_modules/exact-lib": {"version": "2.4.1"},
                },
            }
        )
    )
    _, findings, deps, errors = scan(tmp_path, osv=False)
    assert not errors
    assert {value["name"] + "@" + value["version"] for value in deps.values()} == {
        "left-pad@1.3.0",
        "exact-lib@2.4.1",
    }
    assert not any(item["rule_id"] == "DG-DEP-UNRESOLVED" for item in findings)


def test_unpinned_requirements_are_explained_without_vulnerability_claim(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.0\nflask")
    _, findings, deps, errors = scan(tmp_path, osv=False)
    assert not errors and not deps
    assert len(findings) == 2
    assert all(
        item["rule_id"] == "DG-DEP-UNRESOLVED" and item["severity"] == "Informational"
        for item in findings
    )
    assert all("not a vulnerability" in item["description"] for item in findings)


def test_zip_file_size_limit(tmp_path, monkeypatch):
    archive = tmp_path / "large.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("file.txt", "0123456789")
    monkeypatch.setattr(scanner, "MAX_FILE_BYTES", 5)
    with pytest.raises(ValueError, match="size limits"):
        safe_extract(archive, tmp_path / "extract")


def test_zip_entry_count_limit(tmp_path, monkeypatch):
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("one.py", "1")
        z.writestr("two.py", "2")
    monkeypatch.setattr(scanner, "MAX_ZIP_ENTRIES", 1)
    with pytest.raises(ValueError, match="too many entries"):
        safe_extract(archive, tmp_path / "extract")


@pytest.mark.parametrize(
    "marker",
    [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ],
)
def test_private_key_markers_are_critical_without_duplicate_high_findings(
    tmp_path, marker
):
    (tmp_path / "app.py").write_text(
        'SAMPLE_API_KEY = "synthetic_access_value_9384"\n'
        f'PRIVATE_KEY = "{marker}"\n'
    )

    _, findings, _, _ = scan(tmp_path, osv=False)
    secret_findings = [item for item in findings if item["rule_id"] == "DG-SECRET"]

    assert [(item["title"], item["severity"]) for item in secret_findings] == [
        ("Possible hardcoded secret", "High"),
        ("Possible private key material", "Critical"),
    ]
    assert secret_findings[0]["line"] == 1
    assert secret_findings[1]["line"] == 2
    assert marker not in json.dumps(secret_findings)
    assert "synthetic_access_value_9384" not in json.dumps(secret_findings)
    assert secret_findings[1]["evidence"] == "[REDACTED private-key marker]"


def test_pem_private_key_file_is_scanned_and_classified_critical(tmp_path):
    (tmp_path / "synthetic.pem").write_text(
        "-----BEGIN PRIVATE KEY-----\nsynthetic-key-material\n"
    )

    files, findings, _, _ = scan(tmp_path, osv=False)

    assert [path.name for path in files] == ["synthetic.pem"]
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DG-SECRET"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["evidence"] == "[REDACTED private-key marker]"
    assert "synthetic-key-material" not in json.dumps(findings)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CRITICAL", "Critical"),
        ("HIGH", "High"),
        ("MODERATE", "Medium"),
        ("MEDIUM", "Medium"),
        ("LOW", "Low"),
        ("unrecognized", "Informational"),
    ],
)
def test_osv_severity_mapping(raw, expected):
    assert (
        scanner._osv_severity({"database_specific": {"severity": raw}})
        == expected
    )
