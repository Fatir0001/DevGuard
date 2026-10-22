import html, json, os, tempfile, threading, uuid, zipfile
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    Text,
    Boolean,
    ForeignKey,
    update,
    inspect as sqlalchemy_inspect,
)
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base, sessionmaker
from .ai import router as ai_router
from .scanner import safe_extract, scan

SCANNER_VERSION = "1.1.0"
RULESET_VERSION = "2026.10"

DEFAULT_DB = Path(__file__).resolve().parents[1] / "devguard.db"


def database_path():
    """Use a host-mounted SQLite path when configured; retain the local default."""
    configured_path = os.getenv("DEVGUARD_DATABASE_PATH")
    path = Path(configured_path).expanduser() if configured_path else DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


DB = database_path()
engine = create_engine(
    URL.create("sqlite", database=str(DB)),
    connect_args={"check_same_thread": False},
)
Base = declarative_base()
Session = sessionmaker(bind=engine, expire_on_commit=False)


class Project(Base):
    __tablename__ = "projects"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    created = Column(String, nullable=False)


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id"))
    status = Column(String)
    stage = Column(String)
    files = Column(Integer, default=0)
    dependencies = Column(Integer, default=0)
    error = Column(String)
    started = Column(String)
    finished = Column(String)
    db_status = Column(String)
    deleted_at = Column(String, nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"))
    payload = Column(Text)
    reviewed = Column(Boolean, default=False)


Base.metadata.create_all(engine)


def ensure_schema_compatibility(database_engine=engine):
    """Add nullable columns introduced after initial installs without data loss."""
    if "scans" not in sqlalchemy_inspect(database_engine).get_table_names():
        return
    columns = {
        column["name"]
        for column in sqlalchemy_inspect(database_engine).get_columns("scans")
    }
    if "deleted_at" not in columns:
        with database_engine.begin() as connection:
            connection.exec_driver_sql("ALTER TABLE scans ADD COLUMN deleted_at VARCHAR")


ensure_schema_compatibility()
app = FastAPI(
    title="DevGuard API", description="Local first project vulnerability scanner"
)
app.include_router(ai_router)


@app.exception_handler(RequestValidationError)
async def sanitize_ai_validation_error(request, exc):
    """Do not echo rejected scan-content fields from optional AI requests."""
    if request.url.path.startswith("/api/ai/"):
        return JSONResponse(
            status_code=422,
            content={
                "detail": "Invalid AI request. Check the required finding summary fields and allowed values."
            },
        )
    return await request_validation_exception_handler(request, exc)


def cors_origins(additional_origins=None):
    """Allow local Vite origins and explicitly configured deployed frontends."""
    if additional_origins is None:
        additional_origins = os.getenv("DEVGUARD_CORS_ORIGINS", "")
    origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:4173",
    ]
    for raw_origin in additional_origins.split(","):
        candidate = raw_origin.strip()
        if not candidate:
            continue
        try:
            parsed = urlsplit(candidate)
            parsed.port  # Validate malformed port values instead of accepting them.
        except ValueError:
            continue
        if (
            parsed.scheme in {"http", "https"}
            and parsed.netloc
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        ):
            origins.append(f"{parsed.scheme}://{parsed.netloc}")
    return list(dict.fromkeys(origins))


app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)
pool = ThreadPoolExecutor(max_workers=2)
locks = {}
scan_slots = threading.BoundedSemaphore(10)


def now():
    return datetime.now(timezone.utc).isoformat()


def mark_interrupted_scans():
    """The local in-process queue is not durable; don't leave old work appearing live."""
    with engine.begin() as connection:
        connection.execute(
            update(Scan)
            .where(Scan.status.in_(["queued", "running"]))
            .values(
                status="failed",
                stage="Interrupted by server restart",
                error="Scan did not finish before the server stopped.",
                finished=now(),
            )
        )


mark_interrupted_scans()


def record_scan(scan_id, root):
    s = Session()
    try:
        row = s.get(Scan, scan_id)
        row.status = "running"
        row.stage = "Analyzing files"
        s.commit()
        files, findings, deps, errors = scan(root)
        row = s.get(Scan, scan_id)
        row.files = len(files)
        row.dependencies = len(deps)
        row.stage = "Saving findings"
        row.db_status = "partial" if errors else "available"
        for f in findings:
            s.add(
                Finding(
                    id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    payload=json.dumps(f),
                    reviewed=False,
                )
            )
        row.status = "completed"
        row.stage = "Complete"
        row.finished = now()
        row.error = "; ".join(errors) if errors else None
        s.commit()
    except Exception as e:
        row = s.get(Scan, scan_id)
        if row:
            row.status = "failed"
            row.stage = "Failed"
            row.error = "Scan failed: " + type(e).__name__
            row.finished = now()
            s.commit()
    finally:
        s.close()
        temp = locks.pop(scan_id, None)
        if temp:
            temp.cleanup()
        scan_slots.release()


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "DevGuard",
        "scanner_version": SCANNER_VERSION,
        "ruleset_version": RULESET_VERSION,
    }


@app.post("/api/scans")
async def create_scan(
    name: str = Form(""),
    project: UploadFile = File(...),
    project_id: str | None = Form(None),
):
    if not project_id and (not name.strip() or len(name) > 100):
        raise HTTPException(400, "Project name must be 1 to 100 characters")
    if not project.filename or not project.filename.lower().endswith(".zip"):
        raise HTTPException(415, "Upload a ZIP archive")
    if not scan_slots.acquire(blocking=False):
        raise HTTPException(
            503, "The local scan queue is full. Try again when a scan finishes."
        )
    temp = tempfile.TemporaryDirectory(prefix="devguard-")
    try:
        archive = Path(temp.name) / "upload.zip"
        data = await project.read(26 * 1024 * 1024 + 1)
        if len(data) > 25 * 1024 * 1024:
            raise HTTPException(413, "ZIP exceeds 25 MB")
        archive.write_bytes(data)
        root = Path(temp.name) / "project"
        root.mkdir()
        safe_extract(archive, root)
        archive.unlink(missing_ok=True)
    except zipfile.BadZipFile:
        temp.cleanup()
        scan_slots.release()
        raise HTTPException(400, "Invalid ZIP archive")
    except ValueError as e:
        temp.cleanup()
        scan_slots.release()
        raise HTTPException(400, str(e))
    except HTTPException:
        temp.cleanup()
        scan_slots.release()
        raise
    except Exception:
        temp.cleanup()
        scan_slots.release()
        raise HTTPException(400, "Unable to read or validate this ZIP archive")
    sid = str(uuid.uuid4())
    s = Session()
    try:
        if project_id:
            existing = s.get(Project, project_id)
            if not existing:
                temp.cleanup()
                scan_slots.release()
                raise HTTPException(404, "Project not found")
            pid = existing.id
        else:
            pid = str(uuid.uuid4())
            s.add(Project(id=pid, name=name.strip(), created=now()))
        s.add(
            Scan(
                id=sid,
                project_id=pid,
                status="queued",
                stage="Queued",
                started=now(),
                db_status="pending",
            )
        )
        s.commit()
    except HTTPException:
        s.rollback()
        raise
    except Exception:
        s.rollback()
        temp.cleanup()
        scan_slots.release()
        raise HTTPException(503, "Could not save scan metadata")
    finally:
        s.close()
    locks[sid] = temp
    try:
        pool.submit(record_scan, sid, root)
    except RuntimeError:
        locks.pop(sid, None)
        temp.cleanup()
        scan_slots.release()
        s = Session()
        row = s.get(Scan, sid)
        row.status = "failed"
        row.stage = "Failed"
        row.error = "The local scan worker is unavailable."
        row.finished = now()
        s.commit()
        s.close()
        raise HTTPException(503, "The local scan worker is unavailable")
    return {"scan_id": sid, "project_id": pid, "status": "queued"}


def scan_data(row, s):
    findings = [
        json.loads(f.payload)
        | {"id": f.id, "reviewed": f.reviewed, "scan_id": f.scan_id}
        for f in s.query(Finding).filter_by(scan_id=row.id).all()
    ]
    counts = {
        k: sum(f["severity"] == k for f in findings)
        for k in ["Critical", "High", "Medium", "Low", "Informational"]
    }
    reviewed_count = sum(1 for f in findings if f["reviewed"])
    duration = None
    if row.started and row.finished:
        try:
            duration = max(
                0,
                round(
                    (
                        datetime.fromisoformat(row.finished)
                        - datetime.fromisoformat(row.started)
                    ).total_seconds(),
                    2,
                ),
            )
        except ValueError:
            pass
    return {
        "id": row.id,
        "project_id": row.project_id,
        "status": row.status,
        "stage": row.stage,
        "files_processed": row.files,
        "dependencies_analyzed": row.dependencies,
        "findings_count": len(findings),
        "reviewed_count": reviewed_count,
        "awaiting_review_count": len(findings) - reviewed_count,
        "severity_counts": counts,
        "error": row.error,
        "database_status": row.db_status,
        "started_at": row.started,
        "finished_at": row.finished,
        "duration_seconds": duration,
        "deleted_at": row.deleted_at,
    }


@app.get("/api/scans")
def scans(limit: int = Query(50, ge=1, le=1000), offset: int = Query(0, ge=0)):
    s = Session()
    rows = (
        s.query(Scan)
        .filter(Scan.deleted_at.is_(None))
        .order_by(Scan.started.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    out = []
    for r in rows:
        d = scan_data(r, s)
        d["project_name"] = s.get(Project, r.project_id).name
        out.append(d)
    s.close()
    return {"items": out, "limit": limit, "offset": offset}


class ScanSelection(BaseModel):
    scan_ids: list[str]


def validate_scan_id(scan_id: str) -> str:
    try:
        return str(uuid.UUID(scan_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(400, "Scan ID must be a valid UUID")


def validated_scan_ids(scan_ids: list[str]) -> list[str]:
    if not scan_ids:
        raise HTTPException(400, "Select at least one scan")
    if len(scan_ids) > 1000:
        raise HTTPException(400, "A maximum of 1000 scans can be changed at once")
    return list(dict.fromkeys(validate_scan_id(scan_id) for scan_id in scan_ids))


def update_bin_state(scan_ids: list[str], *, deleted: bool):
    """Atomically trash or restore a set of scans, failing the whole request on conflicts."""
    ids = validated_scan_ids(scan_ids)
    s = Session()
    try:
        rows = s.query(Scan).filter(Scan.id.in_(ids)).all()
        if len(rows) != len(ids):
            raise HTTPException(404, "One or more scans were not found")
        if deleted:
            if any(row.deleted_at is not None for row in rows):
                raise HTTPException(409, "One or more scans are already in the Bin")
            if any(row.status not in {"completed", "failed"} for row in rows):
                raise HTTPException(409, "Running scans cannot be moved to the Bin")
            timestamp = now()
            changed = (
                s.query(Scan)
                .filter(
                    Scan.id.in_(ids),
                    Scan.deleted_at.is_(None),
                    Scan.status.in_(["completed", "failed"]),
                )
                .update({Scan.deleted_at: timestamp}, synchronize_session=False)
            )
            if changed != len(rows):
                raise HTTPException(409, "One or more scans changed during this request")
        else:
            if any(row.deleted_at is None for row in rows):
                raise HTTPException(409, "One or more scans are not in the Bin")
            changed = (
                s.query(Scan)
                .filter(Scan.id.in_(ids), Scan.deleted_at.is_not(None))
                .update({Scan.deleted_at: None}, synchronize_session=False)
            )
            if changed != len(rows):
                raise HTTPException(409, "One or more scans changed during this request")
            timestamp = None
        s.commit()
        return {"updated": len(rows), "scan_ids": ids, "deleted_at": timestamp}
    except HTTPException:
        s.rollback()
        raise
    except Exception:
        s.rollback()
        raise HTTPException(503, "Could not update scan Bin state")
    finally:
        s.close()


@app.get("/api/bin")
def list_bin(limit: int = Query(1000, ge=1, le=1000), offset: int = Query(0, ge=0)):
    s = Session()
    total = s.query(Scan).filter(Scan.deleted_at.is_not(None)).count()
    rows = (
        s.query(Scan)
        .filter(Scan.deleted_at.is_not(None))
        .order_by(Scan.deleted_at.desc(), Scan.started.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    items = []
    for row in rows:
        item = scan_data(row, s)
        project_row = s.get(Project, row.project_id)
        item["project_name"] = project_row.name if project_row else "Unknown project"
        items.append(item)
    s.close()
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@app.post("/api/scans/trash")
def trash_scans(payload: ScanSelection):
    return update_bin_state(payload.scan_ids, deleted=True)


@app.post("/api/scans/{sid}/trash")
def trash_scan(sid: str):
    return update_bin_state([sid], deleted=True)


@app.post("/api/bin/restore")
def restore_scans(payload: ScanSelection):
    return update_bin_state(payload.scan_ids, deleted=False)


@app.post("/api/bin/{sid}/restore")
def restore_scan(sid: str):
    return update_bin_state([sid], deleted=False)


def permanently_delete_scans(s, ids: list[str]) -> int:
    """Delete DB-owned scan data. Reports are generated on demand; no scan files persist."""
    rows = s.query(Scan).filter(Scan.id.in_(ids)).all()
    if len(rows) != len(ids):
        raise HTTPException(404, "One or more scans were not found in the Bin")
    if any(row.deleted_at is None for row in rows):
        raise HTTPException(409, "Only scans in the Bin can be permanently deleted")
    s.query(Finding).filter(Finding.scan_id.in_(ids)).delete(synchronize_session=False)
    s.query(Scan).filter(Scan.id.in_(ids)).delete(synchronize_session=False)
    return len(rows)


@app.delete("/api/bin/{sid}")
def permanently_delete_scan(sid: str):
    scan_id = validate_scan_id(sid)
    s = Session()
    try:
        deleted = permanently_delete_scans(s, [scan_id])
        s.commit()
        return {"deleted": deleted, "scan_ids": [scan_id]}
    except HTTPException:
        s.rollback()
        raise
    except Exception:
        s.rollback()
        raise HTTPException(503, "Could not permanently delete scan")
    finally:
        s.close()


@app.delete("/api/bin")
def empty_bin():
    s = Session()
    try:
        deleted = s.query(Scan).filter(Scan.deleted_at.is_not(None)).count()
        if deleted:
            binned_scan_ids = s.query(Scan.id).filter(Scan.deleted_at.is_not(None))
            s.query(Finding).filter(Finding.scan_id.in_(binned_scan_ids)).delete(
                synchronize_session=False
            )
            s.query(Scan).filter(Scan.deleted_at.is_not(None)).delete(
                synchronize_session=False
            )
            s.commit()
        return {"deleted": deleted}
    except HTTPException:
        s.rollback()
        raise
    except Exception:
        s.rollback()
        raise HTTPException(503, "Could not empty the Bin")
    finally:
        s.close()


@app.get("/api/scans/{sid}")
def get_scan(sid: str):
    s = Session()
    r = s.get(Scan, sid)
    if not r:
        s.close()
        raise HTTPException(404, "Scan not found")
    out = scan_data(r, s)
    out["project_name"] = s.get(Project, r.project_id).name
    s.close()
    return out


@app.get("/api/scans/{sid}/findings")
def scan_findings(
    sid: str, severity: str | None = None, category: str | None = None, q: str = ""
):
    s = Session()
    r = s.get(Scan, sid)
    if not r:
        s.close()
        raise HTTPException(404, "Scan not found")
    out = scan_data(r, s)
    project_row = s.get(Project, r.project_id)
    items = []
    for f in s.query(Finding).filter_by(scan_id=sid).all():
        d = json.loads(f.payload) | {
            "id": f.id,
            "reviewed": f.reviewed,
            "scan_id": sid,
            "project_id": r.project_id,
            "project_name": project_row.name,
            "scan_started_at": r.started,
        }
        if severity and d["severity"] != severity:
            continue
        if category and d["category"] != category:
            continue
        if q and q.lower() not in json.dumps(d).lower():
            continue
        items.append(d)
    s.close()
    return {"items": items, "scan": out}


@app.get("/api/findings")
def all_findings(
    severity: str | None = None,
    category: str | None = None,
    project_id: str | None = None,
    reviewed: bool | None = None,
    q: str = "",
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    s = Session()
    query = (
        s.query(Finding, Scan, Project)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Project, Scan.project_id == Project.id)
        .filter(Scan.deleted_at.is_(None))
        .order_by(Scan.started.desc())
    )
    if project_id:
        query = query.filter(Scan.project_id == project_id)
    rows = query.all()
    items = []
    needle = q.casefold()
    for finding, scan_row, project_row in rows:
        payload = json.loads(finding.payload)
        if severity and payload.get("severity") != severity:
            continue
        if category and payload.get("category") != category:
            continue
        if reviewed is not None and finding.reviewed != reviewed:
            continue
        searchable = " ".join(
            str(payload.get(k) or "")
            for k in ("title", "rule_id", "file_path", "category", "dependency_name")
        ).casefold()
        if needle and needle not in searchable:
            continue
        items.append(
            payload
            | {
                "id": finding.id,
                "reviewed": finding.reviewed,
                "scan_id": scan_row.id,
                "project_id": project_row.id,
                "project_name": project_row.name,
                "scan_started_at": scan_row.started,
                "scan_status": scan_row.status,
            }
        )
    total = len(items)
    s.close()
    return {
        "items": items[offset : offset + limit],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/findings/{fid}")
def get_finding(fid: str):
    s = Session()
    f = s.get(Finding, fid)
    if not f:
        s.close()
        raise HTTPException(404, "Finding not found")
    out = json.loads(f.payload) | {
        "id": f.id,
        "reviewed": f.reviewed,
        "scan_id": f.scan_id,
    }
    s.close()
    return out


class Review(BaseModel):
    reviewed: bool


@app.patch("/api/findings/{fid}")
def review(fid: str, payload: Review):
    s = Session()
    f = s.get(Finding, fid)
    if not f:
        s.close()
        raise HTTPException(404, "Finding not found")
    f.reviewed = payload.reviewed
    s.commit()
    out = json.loads(f.payload) | {
        "id": f.id,
        "reviewed": f.reviewed,
        "scan_id": f.scan_id,
    }
    s.close()
    return out


@app.get("/api/projects")
def projects():
    s = Session()
    rows = s.query(Project).all()
    out = []
    for p in rows:
        ss = (
            s.query(Scan)
            .filter(Scan.project_id == p.id, Scan.deleted_at.is_(None))
            .order_by(Scan.started.desc())
            .all()
        )
        out.append(
            {
                "id": p.id,
                "name": p.name,
                "scans_count": len(ss),
                "last_scan": ss[0].started if ss else None,
            }
        )
    s.close()
    return {"items": out}


@app.get("/api/projects/{pid}")
def project(pid: str):
    s = Session()
    p = s.get(Project, pid)
    if not p:
        s.close()
        raise HTTPException(404, "Project not found")
    out = {
        "id": p.id,
        "name": p.name,
        "created_at": p.created,
        "scans": [
            scan_data(x, s)
            for x in s.query(Scan)
            .filter(Scan.project_id == pid, Scan.deleted_at.is_(None))
            .order_by(Scan.started.desc())
            .all()
        ],
    }
    s.close()
    return out


@app.get("/api/projects/{pid}/compare")
def compare(pid: str, first: str, second: str):
    s = Session()
    a = s.get(Scan, first)
    b = s.get(Scan, second)
    if (
        not a
        or not b
        or a.project_id != pid
        or b.project_id != pid
        or a.deleted_at is not None
        or b.deleted_at is not None
    ):
        s.close()
        raise HTTPException(404, "Scans for this project were not found")
    if a.status != "completed" or b.status != "completed":
        s.close()
        raise HTTPException(409, "Only completed scans can be compared")

    def keyed_findings(x):
        matches = {}
        for finding in s.query(Finding).filter_by(scan_id=x.id).all():
            p = json.loads(finding.payload)
            stable = [
                p.get("rule_id"),
                p.get("file_path"),
                p.get("line"),
                p.get("dependency_name"),
                p.get("dependency_version"),
                p.get("advisory_id"),
            ]
            matches[json.dumps(stable, separators=(",", ":"))] = p
        return matches

    old, new = keyed_findings(a), keyed_findings(b)
    introduced = [new[key] for key in sorted(new.keys() - old.keys())]
    not_detected = [old[key] for key in sorted(old.keys() - new.keys())]
    persistent = [new[key] for key in sorted(old.keys() & new.keys())]
    s.close()
    return {
        "introduced": introduced,
        "not_detected_in_latest": not_detected,
        "unchanged": len(persistent),
        "persistent": persistent,
        "note": "Not detected in the latest scan does not mean the issue was verified as fixed.",
    }


@app.get("/api/scans/{sid}/report.json")
def json_report(sid: str):
    s = Session()
    r = s.get(Scan, sid)
    if not r:
        s.close()
        raise HTTPException(404, "Scan not found")
    d = scan_data(r, s)
    d["schema_version"] = "1.0"
    d["project_name"] = s.get(Project, r.project_id).name
    d["scanner_version"] = SCANNER_VERSION
    d["ruleset_version"] = RULESET_VERSION
    d["known_limitations"] = [
        "Heuristic static analysis can miss issues and report false positives.",
        "A clean result does not guarantee that a project is secure.",
        "Only supported manifests and exact versions are queried against OSV.dev.",
    ]
    d["findings"] = [
        json.loads(f.payload) | {"id": f.id, "reviewed": f.reviewed}
        for f in s.query(Finding).filter_by(scan_id=sid).all()
    ]
    s.close()
    return JSONResponse(
        d,
        headers={"Content-Disposition": f'attachment; filename="devguard-{sid}.json"'},
    )


@app.get("/api/scans/{sid}/report.html", response_class=HTMLResponse)
def html_report(sid: str):
    s = Session()
    r = s.get(Scan, sid)
    if not r:
        s.close()
        raise HTTPException(404, "Scan not found")
    d = scan_data(r, s)
    name = html.escape(s.get(Project, r.project_id).name)
    items = [
        json.loads(f.payload) for f in s.query(Finding).filter_by(scan_id=sid).all()
    ]
    s.close()

    def render_references(finding: dict) -> str:
        return " ".join(
            '<a rel="noreferrer" href="'
            + html.escape(ref, quote=True)
            + '">Advisory</a>'
            for ref in finding.get("references", [])
            if isinstance(ref, str) and ref.startswith("https://")
        )

    rows = "".join(
        f'<tr><td>{html.escape(x["severity"])}</td><td>{html.escape(x["title"])}</td><td>{html.escape(x.get("category") or "")}</td><td>{html.escape(x.get("file_path") or x.get("dependency_name") or "")}{":"+str(x.get("line")) if x.get("line") else ""}</td><td><code>{html.escape(x.get("rule_id") or "")}</code><br>{html.escape(x.get("advisory_id") or x.get("cve") or "")}</td><td><pre>{html.escape(x.get("evidence") or "")}</pre></td><td>{html.escape(x.get("remediation") or "")}</td><td>{render_references(x)}</td></tr>'
        for x in items
    )
    counts = " · ".join(
        f"{severity}: {count}" for severity, count in d["severity_counts"].items()
    )
    return HTMLResponse(
        f'<!doctype html><meta charset="utf-8"><title>DevGuard report</title><style>body{{background:#080D0C;color:#E5F2EB;font:15px system-ui;margin:32px}}table{{width:100%;border-collapse:collapse}}td,th{{padding:10px;border-bottom:1px solid #243630;text-align:left;vertical-align:top}}small{{color:#849A8F}}pre{{white-space:pre-wrap;max-width:360px;color:#a5c2b2}}code{{font-family:monospace;color:#39FF88}}.note{{padding:12px;border:1px solid #243630;margin:18px 0}}a{{color:#39FF88}}</style><h1>DevGuard scan report</h1><p>{name} · <code>{html.escape(d["id"])}</code> · {html.escape(d["status"])} · {html.escape(d["started_at"] or "")}</p><p>Scanner {SCANNER_VERSION} · ruleset {RULESET_VERSION} · Files: {d["files_processed"]} · Dependencies: {d["dependencies_analyzed"]} · Duration: {d["duration_seconds"] if d["duration_seconds"] is not None else "—"}s</p><p>{html.escape(counts)}</p><div class="note">Automated checks can produce false positives and false negatives. Absence of findings does not guarantee that this project is secure.</div><table><thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Location</th><th>Rule / advisory</th><th>Redacted evidence</th><th>Remediation</th><th>References</th></tr></thead><tbody>{rows}</tbody></table>'
    )
