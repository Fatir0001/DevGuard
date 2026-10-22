import io
import json
import time
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect as sqlalchemy_inspect
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker

from backend.app import main, scanner
from backend.app.main import Base, app


def test_database_path_can_target_a_persistent_host_volume(monkeypatch, tmp_path):
    persistent_path = tmp_path / "persistent-data" / "devguard.db"
    monkeypatch.setenv("DEVGUARD_DATABASE_PATH", str(persistent_path))

    assert main.database_path() == persistent_path
    assert persistent_path.parent.is_dir()
    configured_engine = create_engine(
        URL.create("sqlite", database=str(main.database_path()))
    )
    with configured_engine.connect():
        pass
    configured_engine.dispose()
    assert persistent_path.is_file()


@pytest.fixture
def test_database(monkeypatch, tmp_path):
    engine = create_engine(
        URL.create("sqlite", database=str(tmp_path / "test.db")),
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    monkeypatch.setattr(main, "engine", engine)
    monkeypatch.setattr(
        main, "Session", sessionmaker(bind=engine, expire_on_commit=False)
    )
    yield
    engine.dispose()


def zip_project(filename="demo.py", content="print(1)"):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr(filename, content)
    return archive.getvalue()


def test_cors_origins_accept_explicit_origins_only():
    assert main.cors_origins(
        "https://devguard.example, https://devguard.example/, * , "
        "https://devguard.example/path, file://local, https://bad.example:invalid"
    ) == [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:4173",
        "https://devguard.example",
    ]


def test_fastapi_allows_local_production_preview_origin():
    origin = "http://127.0.0.1:4173"
    response = TestClient(app).get("/api/health", headers={"Origin": origin})

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin


def wait_for_scan(client, scan_id):
    for _ in range(100):
        response = client.get(f"/api/scans/{scan_id}")
        if response.json()["status"] in {"completed", "failed"}:
            return response.json()
        time.sleep(0.03)
    raise AssertionError("Scan did not finish within the test timeout")


def seed_scan(session, *, name="bin-test", status="completed", with_finding=True):
    project = main.Project(id=str(uuid.uuid4()), name=name, created=main.now())
    scan_id = str(uuid.uuid4())
    scan = main.Scan(
        id=scan_id,
        project_id=project.id,
        status=status,
        stage="Complete" if status == "completed" else status.title(),
        files=3,
        dependencies=1,
        started=main.now(),
        finished=main.now() if status in {"completed", "failed"} else None,
        db_status="available",
    )
    session.add_all([project, scan])
    finding_id = str(uuid.uuid4())
    if with_finding:
        session.add(
            main.Finding(
                id=finding_id,
                scan_id=scan_id,
                payload=json.dumps(
                    {
                        "title": "Persistent synthetic finding",
                        "severity": "Medium",
                        "category": "Test",
                        "rule_id": "DG-TEST-BIN",
                        "description": "Finding retained while scan is in the Bin.",
                        "remediation": "Restore to continue review.",
                        "evidence": "safe test evidence",
                    }
                ),
                reviewed=True,
            )
        )
    session.commit()
    return project, scan, finding_id


def test_health_and_missing_scan(test_database):
    with TestClient(app) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        assert client.get("/api/scans/not-a-scan").status_code == 404


def test_invalid_upload_does_not_create_orphan_project(
    test_database, tmp_path, monkeypatch
):
    monkeypatch.setattr(main.tempfile, "tempdir", str(tmp_path))
    with TestClient(app) as client:
        bad = client.post(
            "/api/scans",
            data={"name": "bad-archive"},
            files={"project": ("bad.zip", b"not a zip", "application/zip")},
        )
        assert bad.status_code == 400
        assert client.get("/api/projects").json()["items"] == []


def test_upload_review_reports_and_safe_html(test_database, tmp_path, monkeypatch):
    monkeypatch.setattr(main.tempfile, "tempdir", str(tmp_path))
    malicious_title = "<script>alert(1)</script>"

    def fake_scan(root):
        return (
            list(root.glob("*.py")),
            [
                {
                    "rule_id": "TEST",
                    "title": malicious_title,
                    "description": "test",
                    "severity": "Low",
                    "confidence": "High",
                    "category": "Static analysis",
                    "file_path": "demo.py",
                    "line": 1,
                    "evidence": "<img src=x onerror=alert(1)>",
                    "remediation": "Keep reviewing.",
                }
            ],
            {},
            [],
        )

    monkeypatch.setattr(main, "scan", fake_scan)
    with TestClient(app) as client:
        result = client.post(
            "/api/scans",
            data={"name": "api-test"},
            files={"project": ("demo.zip", zip_project(), "application/zip")},
        )
        assert result.status_code == 200
        sid = result.json()["scan_id"]
        pid = result.json()["project_id"]
        status = wait_for_scan(client, sid)
        assert status["status"] == "completed"
        assert status["files_processed"] == 1
        findings = client.get(f"/api/scans/{sid}/findings").json()["items"]
        assert findings[0]["title"] == malicious_title
        assert findings[0]["reviewed"] is False
        review = client.patch(
            f"/api/findings/{findings[0]['id']}", json={"reviewed": True}
        )
        assert review.json()["reviewed"] is True
        assert (
            client.get(f"/api/findings?project_id={pid}&reviewed=true").json()["total"]
            == 1
        )
        report = client.get(f"/api/scans/{sid}/report.json").json()
        assert report["scanner_version"] == main.SCANNER_VERSION
        assert report["findings"][0]["reviewed"] is True
        rendered = client.get(f"/api/scans/{sid}/report.html").text
        assert "<script>alert(1)</script>" not in rendered
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
        assert "&lt;img src=x onerror=alert(1)&gt;" in rendered


def test_rescan_existing_project_and_compare(test_database, tmp_path, monkeypatch):
    monkeypatch.setattr(main.tempfile, "tempdir", str(tmp_path))

    def fake_scan(root):
        text = (Path(root) / "demo.py").read_text()
        found = []
        if "risky" in text:
            found = [
                {
                    "rule_id": "DG-TEST",
                    "title": "Synthetic",
                    "description": "synthetic",
                    "severity": "Medium",
                    "confidence": "High",
                    "category": "Test",
                    "file_path": "demo.py",
                    "line": 1,
                    "evidence": "risky",
                    "remediation": "remove it",
                }
            ]
        return [Path(root) / "demo.py"], found, {}, []

    monkeypatch.setattr(main, "scan", fake_scan)
    with TestClient(app) as client:
        first = client.post(
            "/api/scans",
            data={"name": "repeatable"},
            files={
                "project": ("one.zip", zip_project(content="risky"), "application/zip")
            },
        ).json()
        assert wait_for_scan(client, first["scan_id"])["status"] == "completed"
        second = client.post(
            "/api/scans",
            data={"project_id": first["project_id"]},
            files={
                "project": ("two.zip", zip_project(content="safe"), "application/zip")
            },
        )
        assert second.status_code == 200
        assert wait_for_scan(client, second.json()["scan_id"])["status"] == "completed"
        compared = client.get(
            f"/api/projects/{first['project_id']}/compare?first={first['scan_id']}&second={second.json()['scan_id']}"
        ).json()
        assert len(compared["not_detected_in_latest"]) == 1
        assert "not mean" in compared["note"]


def test_report_query_rejects_invalid_upload_type(test_database):
    with TestClient(app) as client:
        response = client.post(
            "/api/scans",
            data={"name": "bad-type"},
            files={"project": ("sample.txt", b"text", "text/plain")},
        )
        assert response.status_code == 415
        assert client.get("/api/projects").json()["items"] == []


def test_interrupted_scan_is_recovered_as_failed(test_database):
    session = main.Session()
    project = main.Project(
        id="project-interrupted", name="interrupted", created=main.now()
    )
    session.add(project)
    session.add(
        main.Scan(
            id="scan-interrupted",
            project_id=project.id,
            status="running",
            stage="Analyzing",
            started=main.now(),
            db_status="pending",
        )
    )
    session.commit()
    session.close()
    main.mark_interrupted_scans()
    session = main.Session()
    row = session.get(main.Scan, "scan-interrupted")
    assert row.status == "failed"
    assert row.stage == "Interrupted by server restart"
    session.close()


def test_scanner_severities_survive_storage_and_api_responses(
    test_database, tmp_path, monkeypatch
):
    monkeypatch.setattr(main.tempfile, "tempdir", str(tmp_path))

    def fake_osv_post(url, **kwargs):
        assert len(kwargs["json"]["queries"]) == 1
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-synthetic-low-severity",
                                "summary": "Synthetic low severity advisory",
                                "details": "Synthetic OSV response for severity testing.",
                                "database_specific": {"severity": "LOW"},
                                "references": [],
                                "affected": [],
                            }
                        ]
                    }
                ]
            },
        )

    monkeypatch.setattr(scanner.httpx, "post", fake_osv_post)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr(
            "app.py", 'SAMPLE_API_KEY = "synthetic_api_value_9384"\n'
        )
        zipped.writestr(
            "private.pem", "-----BEGIN PRIVATE KEY-----\nsynthetic-key-material\n"
        )
        zipped.writestr("settings.py", "DEBUG = True\n")
        zipped.writestr(
            "requirements.txt",
            "unpinned-sample-package\nlow-severity-sample-package==1.0.0\n",
        )

    with TestClient(app) as client:
        result = client.post(
            "/api/scans",
            data={"name": "severity-flow"},
            files={"project": ("severity-flow.zip", archive.getvalue(), "application/zip")},
        )
        assert result.status_code == 200
        scan_id = result.json()["scan_id"]
        project_id = result.json()["project_id"]
        status = wait_for_scan(client, scan_id)
        assert status["status"] == "completed"
        assert status["database_status"] == "available"
        assert status["severity_counts"] == {
            "Critical": 1,
            "High": 1,
            "Medium": 1,
            "Low": 1,
            "Informational": 1,
        }

        scan_findings = client.get(f"/api/scans/{scan_id}/findings").json()[
            "items"
        ]
        all_findings = client.get(
            f"/api/findings?project_id={project_id}"
        ).json()["items"]
        report_findings = client.get(
            f"/api/scans/{scan_id}/report.json"
        ).json()["findings"]
        expected = {
            "Possible private key material": "Critical",
            "Possible hardcoded secret": "High",
            "Debug mode enabled": "Medium",
            "Synthetic low severity advisory": "Low",
            "Dependency version is not exact": "Informational",
        }
        for response_findings in (scan_findings, all_findings, report_findings):
            severities = {
                item["title"]: item["severity"] for item in response_findings
            }
            assert {title: severities[title] for title in expected} == expected

        session = main.Session()
        stored_payloads = [
            json.loads(row.payload)
            for row in session.query(main.Finding).filter_by(scan_id=scan_id)
        ]
        session.close()
        assert {item["title"]: item["severity"] for item in stored_payloads} == expected


def test_osv_failure_is_visible_as_partial_api_scan(
    test_database, tmp_path, monkeypatch
):
    import httpx

    monkeypatch.setattr(main.tempfile, "tempdir", str(tmp_path))

    def offline(url, **kwargs):
        raise httpx.ConnectError("offline", request=httpx.Request("POST", url))

    monkeypatch.setattr(scanner.httpx, "post", offline)

    with TestClient(app) as client:
        result = client.post(
            "/api/scans",
            data={"name": "offline-dependency-scan"},
            files={
                "project": (
                    "offline-dependency-scan.zip",
                    zip_project("requirements.txt", "offline-package-unique==9.9.9\n"),
                    "application/zip",
                )
            },
        )
        assert result.status_code == 200
        status = wait_for_scan(client, result.json()["scan_id"])

    assert status["status"] == "completed"
    assert status["dependencies_analyzed"] == 1
    assert status["database_status"] == "partial"
    assert status["error"] and "OSV lookup unavailable" in status["error"]


def test_bulk_trash_restore_persists_metadata_and_filters_active_views(test_database):
    session = main.Session()
    first_project, first, _ = seed_scan(session, name="bin-first")
    second_project, second, _ = seed_scan(session, name="bin-second")
    session.close()

    with TestClient(app) as client:
        moved = client.post(
            "/api/scans/trash", json={"scan_ids": [first.id, second.id]}
        )
        assert moved.status_code == 200
        assert moved.json()["updated"] == 2

        active_ids = {item["id"] for item in client.get("/api/scans").json()["items"]}
        assert first.id not in active_ids
        assert second.id not in active_ids
        assert client.get(f"/api/projects/{first_project.id}").json()["scans"] == []
        assert client.get(f"/api/projects/{first_project.id}/compare", params={
            "first": first.id,
            "second": first.id,
        }).status_code == 404
        assert client.get("/api/findings").json()["total"] == 0

        bin_response = client.get("/api/bin?limit=1000").json()
        assert bin_response["total"] == 2
        trashed = bin_response["items"]
        assert {item["id"] for item in trashed} == {first.id, second.id}
        first_bin_row = next(item for item in trashed if item["id"] == first.id)
        assert first_bin_row["project_name"] == first_project.name
        assert first_bin_row["started_at"] == first.started
        assert first_bin_row["findings_count"] == 1
        assert first_bin_row["deleted_at"]

        scan_findings = client.get(f"/api/scans/{first.id}/findings")
        assert scan_findings.status_code == 200
        assert scan_findings.json()["items"][0]["title"] == "Persistent synthetic finding"
        assert scan_findings.json()["items"][0]["reviewed"] is True
        assert client.get(f"/api/scans/{first.id}/report.json").json()["findings"][0]["title"] == "Persistent synthetic finding"
        html_report = client.get(f"/api/scans/{first.id}/report.html")
        assert html_report.status_code == 200
        assert "Persistent synthetic finding" in html_report.text

        restored = client.post(
            "/api/bin/restore", json={"scan_ids": [first.id, second.id]}
        )
        assert restored.status_code == 200
        assert restored.json()["updated"] == 2
        assert {item["id"] for item in client.get("/api/scans").json()["items"]} >= {
            first.id,
            second.id,
        }
        assert client.get(f"/api/projects/{first_project.id}").json()["scans"][0]["id"] == first.id
        assert client.get(f"/api/projects/{second_project.id}").json()["scans"][0]["id"] == second.id
        assert client.get("/api/findings").json()["total"] == 2
        assert client.get("/api/bin").json()["items"] == []


def test_permanent_delete_removes_only_trashed_scan_data_and_keeps_files(
    test_database, tmp_path
):
    session = main.Session()
    _, trashed, _ = seed_scan(session, name="delete-target")
    _, unrelated, _ = seed_scan(session, name="unrelated-active")
    session.close()
    outside_artifact = tmp_path / "unrelated-report.txt"
    outside_artifact.write_text("keep this file", encoding="utf-8")

    with TestClient(app) as client:
        assert client.post(f"/api/scans/{trashed.id}/trash").status_code == 200
        deleted = client.delete(f"/api/bin/{trashed.id}")
        assert deleted.status_code == 200
        assert deleted.json()["deleted"] == 1
        assert client.get(f"/api/scans/{trashed.id}").status_code == 404
        assert client.get(f"/api/scans/{trashed.id}/report.json").status_code == 404
        assert {item["id"] for item in client.get("/api/scans").json()["items"]} == {
            unrelated.id
        }

    session = main.Session()
    assert session.query(main.Finding).filter_by(scan_id=trashed.id).count() == 0
    assert session.query(main.Scan).filter_by(id=trashed.id).count() == 0
    assert session.query(main.Finding).filter_by(scan_id=unrelated.id).count() == 1
    assert session.query(main.Scan).filter_by(id=unrelated.id).count() == 1
    session.close()
    assert outside_artifact.read_text(encoding="utf-8") == "keep this file"


def test_empty_bin_permanently_removes_only_trashed_scans(test_database):
    session = main.Session()
    _, trashed, _ = seed_scan(session, name="empty-target")
    _, active, _ = seed_scan(session, name="keep-active")
    session.close()

    with TestClient(app) as client:
        assert client.post(f"/api/scans/{trashed.id}/trash").status_code == 200
        result = client.delete("/api/bin")
        assert result.status_code == 200
        assert result.json()["deleted"] == 1
        assert client.get(f"/api/scans/{trashed.id}").status_code == 404
        assert client.get(f"/api/scans/{active.id}").status_code == 200
        assert client.get("/api/bin").json()["items"] == []

    session = main.Session()
    assert session.query(main.Finding).filter_by(scan_id=trashed.id).count() == 0
    assert session.query(main.Finding).filter_by(scan_id=active.id).count() == 1
    session.close()


def test_bin_mutations_validate_ids_and_report_missing_or_conflicting_scans(
    test_database,
):
    session = main.Session()
    _, active, _ = seed_scan(session, name="mutation-active")
    _, running, _ = seed_scan(session, name="mutation-running", status="running")
    session.close()
    missing = str(uuid.uuid4())

    with TestClient(app) as client:
        assert client.post("/api/scans/not-a-uuid/trash").status_code == 400
        assert client.post(f"/api/scans/{missing}/trash").status_code == 404
        assert client.post(f"/api/bin/{missing}/restore").status_code == 404
        assert client.delete(f"/api/bin/{missing}").status_code == 404
        assert client.post(f"/api/scans/{running.id}/trash").status_code == 409
        assert client.delete(f"/api/bin/{active.id}").status_code == 409

        assert client.post(f"/api/scans/{active.id}/trash").status_code == 200
        assert client.post(f"/api/scans/{active.id}/trash").status_code == 409
        assert client.delete(f"/api/bin/not-a-uuid").status_code == 400
        assert client.post(f"/api/bin/{active.id}/restore").status_code == 200
        assert client.post(f"/api/bin/{active.id}/restore").status_code == 409


def test_bulk_trash_missing_id_is_atomic(test_database):
    session = main.Session()
    _, scan, _ = seed_scan(session, name="bulk-atomic")
    session.close()
    missing = str(uuid.uuid4())

    with TestClient(app) as client:
        response = client.post(
            "/api/scans/trash", json={"scan_ids": [scan.id, missing]}
        )
        assert response.status_code == 404
        assert scan.id in {
            item["id"] for item in client.get("/api/scans").json()["items"]
        }
        assert client.get("/api/bin").json()["items"] == []


def test_existing_sqlite_schema_migrates_deleted_at_without_losing_rows(tmp_path):
    legacy_engine = create_engine(
        URL.create("sqlite", database=str(tmp_path / "legacy.db")),
        connect_args={"check_same_thread": False},
    )
    with legacy_engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE scans (id VARCHAR PRIMARY KEY)")
        connection.exec_driver_sql("INSERT INTO scans (id) VALUES ('legacy-scan')")

    main.ensure_schema_compatibility(legacy_engine)
    columns = {
        column["name"]
        for column in sqlalchemy_inspect(legacy_engine).get_columns("scans")
    }
    with legacy_engine.connect() as connection:
        row = connection.exec_driver_sql(
            "SELECT id, deleted_at FROM scans WHERE id = ?", ("legacy-scan",)
        ).one()
    assert "deleted_at" in columns
    assert row == ("legacy-scan", None)
    legacy_engine.dispose()
