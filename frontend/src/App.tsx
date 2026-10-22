import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
import SeverityChart from "./SeverityChart";
import {
  Shield,
  LayoutDashboard,
  FolderKanban,
  ScanSearch,
  History,
  Settings,
  Plus,
  Search,
  UploadCloud,
  ChevronRight,
  Activity,
  TriangleAlert,
  Check,
  ExternalLink,
  Menu,
  ArrowUpRight,
  FileCode2,
  ShieldAlert,
  Clock3,
  Trash2,
  RotateCcw,
  Trash,
} from "lucide-react";
const API = (
  import.meta.env.VITE_API_URL?.trim() ||
  (import.meta.env.DEV ? "http://127.0.0.1:8000/api" : "/api")
).replace(/\/+$/, "");
const LazyAiSettingsPanel = lazy(() =>
  import("./AiTools").then((module) => ({ default: module.AiSettingsPanel })),
);
const LazyAiFindingAssistant = lazy(() =>
  import("./AiTools").then((module) => ({ default: module.AiFindingAssistant })),
);
const PAGE_PATHS: Record<string, string> = {
  Dashboard: "/",
  "New Scan": "/scan",
  "Scan progress": "/scan-progress",
  Projects: "/projects",
  Findings: "/findings",
  "Scan History": "/history",
  Bin: "/bin",
  Reports: "/reports",
  Settings: "/settings",
};
const PATH_PAGES = Object.fromEntries(
  Object.entries(PAGE_PATHS).map(([page, path]) => [path, page]),
);
function pageFromPath() {
  const path = window.location.pathname.replace(/\/+$/, "") || "/";
  if (path.startsWith("/scan-progress/")) return "Scan progress";
  return PATH_PAGES[path] || "Dashboard";
}
function scanIdFromPath(path: string) {
  if (!path.startsWith("/scan-progress/")) return null;
  try {
    return decodeURIComponent(path.slice("/scan-progress/".length)) || null;
  } catch {
    return null;
  }
}
type S = {
  id: string;
  project_id: string;
  project_name: string;
  status: string;
  stage: string;
  files_processed: number;
  dependencies_analyzed: number;
  findings_count: number;
  reviewed_count: number;
  awaiting_review_count: number;
  severity_counts: Record<string, number>;
  duration_seconds?: number | null;
  error?: string;
  database_status?: string;
  started_at: string;
  deleted_at?: string | null;
};
type BinAction = {
  kind: "trash" | "restore" | "permanent" | "empty";
  ids: string[];
};
type AiProvider = "openai" | "gemini" | "anthropic" | "openrouter";
type F = {
  id: string;
  title: string;
  severity: string;
  category: string;
  file_path?: string;
  line?: number;
  rule_id: string;
  description: string;
  evidence?: string;
  remediation: string;
  reviewed: boolean;
  advisory_id?: string;
  references?: string[];
  dependency_name?: string;
  confidence: string;
  cve?: string;
  source_severity?: string;
  affected_ranges?: any[];
  project_name?: string;
  scan_id?: string;
  project_id?: string;
  scan_started_at?: string;
};
async function req(path: string, init?: RequestInit) {
  const r = await fetch(API + path, init);
  let body: any = null;
  try {
    body = await r.json();
  } catch {
    // A misconfigured production proxy can return HTML; keep the API error useful.
  }
  if (!r.ok)
    throw new Error(body?.detail || `Request failed (${r.status})`);
  return body;
}
export default function App() {
  const [page, setPage] = useState(pageFromPath),
    [routePath, setRoutePath] = useState(window.location.pathname),
    [scans, setScans] = useState<S[]>([]),
    [binScans, setBinScans] = useState<S[]>([]),
    [binCount, setBinCount] = useState(0),
    [selectedScanIds, setSelectedScanIds] = useState<string[]>([]),
    [selectedBinIds, setSelectedBinIds] = useState<string[]>([]),
    [binAction, setBinAction] = useState<BinAction | null>(null),
    [binActionBusy, setBinActionBusy] = useState(false),
    [binActionError, setBinActionError] = useState(""),
    [binFeedback, setBinFeedback] = useState(""),
    [emptyBinPhrase, setEmptyBinPhrase] = useState(""),
    [projects, setProjects] = useState<any[]>([]),
    [selected, setSelected] = useState<S | null>(null),
    [findings, setFindings] = useState<F[]>([]),
    [detail, setDetail] = useState<F | null>(null),
    [aiApiKey, setAiApiKey] = useState(""),
    [aiProvider, setAiProvider] = useState<AiProvider>("openai"),
    [aiModel, setAiModel] = useState("gpt-6-luna"),
    [query, setQuery] = useState(""),
    [severity, setSeverity] = useState("All"),
    [category, setCategory] = useState("All"),
    [projectFilter, setProjectFilter] = useState("All"),
    [reviewFilter, setReviewFilter] = useState("All"),
    [sortBy, setSortBy] = useState("latest"),
    [loading, setLoading] = useState(false),
    [dataLoading, setDataLoading] = useState(true),
    [err, setErr] = useState(""),
    [name, setName] = useState(""),
    [projectChoice, setProjectChoice] = useState("new"),
    [file, setFile] = useState<File | null>(null),
    [uploadMeta, setUploadMeta] = useState<{
      name: string;
      size: number;
    } | null>(null),
    [collapsed, setCollapsed] = useState(false),
    [apiUp, setApiUp] = useState(false),
    [scannerVersion, setScannerVersion] = useState("unknown"),
    [compareFirst, setCompareFirst] = useState(""),
    [compareSecond, setCompareSecond] = useState(""),
    [comparison, setComparison] = useState<any>(null);
  const confirmDialogRef = useRef<HTMLElement>(null);
  const detailDialogRef = useRef<HTMLElement>(null);
  const binActionBusyRef = useRef(false);
  binActionBusyRef.current = binActionBusy;
  const navigatePage = (nextPage: string) => {
    const path =
      nextPage === "Scan progress" && selected
        ? "/scan-progress/" + encodeURIComponent(selected.id)
        : PAGE_PATHS[nextPage] || "/";
    if (window.location.pathname !== path)
      window.history.pushState({}, "", path);
    setRoutePath(path);
    setPage(nextPage);
  };
  const refresh = async () => {
    setDataLoading(true);
    setErr("");
    const requests: Promise<unknown>[] = [
      req("/health")
      .then((h) => {
        setScannerVersion(h.scanner_version || "unknown");
        setApiUp(true);
      })
      .catch(() => {
        setApiUp(false);
        setErr("API unavailable. Check the configured API endpoint, then retry.");
      }),
    ];
    const pagesWithScans = ["Dashboard", "Scan History", "Reports", "Scan progress"];
    const pagesWithProjects = ["New Scan", "Projects", "Findings"];
    if (pagesWithScans.includes(page)) {
      requests.push(
        req("/scans?limit=1000")
          .then((s) => setScans(s.items))
          .catch(() => setErr((previous) => previous || "Scan history could not be loaded. Try again.")),
      );
    }
    if (pagesWithProjects.includes(page)) {
      requests.push(
        req("/projects")
          .then((p) => setProjects(p.items))
          .catch(() => setErr((previous) => previous || "Projects could not be loaded.")),
      );
    }
    const binLimit = page === "Bin" ? 1000 : 1;
    requests.push(
      req(`/bin?limit=${binLimit}`)
      .then((b) => {
        if (page === "Bin") setBinScans(b.items);
        setBinCount(b.total ?? b.items.length);
      })
      .catch(() => setErr((previous) => previous || "Bin contents could not be loaded.")),
    );
    await Promise.allSettled(requests);
    setDataLoading(false);
  };
  useEffect(() => {
    void refresh();
  }, [page]);
  useEffect(() => {
    const onPopState = () => {
      setPage(pageFromPath());
      setRoutePath(window.location.pathname);
      setErr("");
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  useEffect(() => {
    if (page !== "Scan progress") return;
    const scanId = scanIdFromPath(routePath);
    if (!scanId || selected?.id === scanId) return;
    let active = true;
    setFindings([]);
    req("/scans/" + encodeURIComponent(scanId))
      .then(async (scan) => {
        if (!active) return;
        setSelected(scan);
        if (scan.status === "completed" || scan.status === "failed") {
          const result = await req(
            "/scans/" + encodeURIComponent(scanId) + "/findings",
          );
          if (active) setFindings(result.items);
        }
      })
      .catch((error) => {
        if (active) setErr(String(error));
      });
    return () => {
      active = false;
    };
  }, [page, routePath]);
  useEffect(() => {
    if (page !== "Findings") return;
    let active = true;
    setDataLoading(true);
    req("/findings?limit=1000")
      .then((result) => {
        if (active) setFindings(result.items);
      })
      .catch((error) => {
        if (active) setErr(String(error));
      })
      .finally(() => {
        if (active) setDataLoading(false);
      });
    return () => {
      active = false;
    };
  }, [page]);
  useEffect(() => {
    if (!detail) return;
    const previousFocus = document.activeElement as HTMLElement | null;
    detailDialogRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        if (detailDialogRef.current?.querySelector(".ai-consent-dialog")) return;
        setDetail(null);
      }
      if (event.key === "Tab") {
        const dialog = detailDialogRef.current;
        if (!dialog) return;
        const focusScope =
          dialog.querySelector<HTMLElement>(".ai-consent-dialog") || dialog;
        const focusable = focusScope.querySelectorAll<HTMLElement>(
          'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
        );
        if (!focusable.length) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      previousFocus?.focus?.();
    };
  }, [detail]);
  useEffect(() => {
    if (!binAction) return;
    const previousFocus = document.activeElement as HTMLElement | null;
    confirmDialogRef.current
      ?.querySelector<HTMLElement>('button:not([disabled]), input:not([disabled])')
      ?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !binActionBusyRef.current)
        setBinAction(null);
      if (event.key === "Tab") {
        const dialog = confirmDialogRef.current;
        if (!dialog) return;
        const focusable = dialog.querySelectorAll<HTMLElement>(
          'button:not([disabled]), input:not([disabled])',
        );
        if (!focusable.length) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      previousFocus?.focus?.();
    };
  }, [binAction]);
  useEffect(() => {
    if (
      !selected ||
      selected.status === "completed" ||
      selected.status === "failed"
    )
      return;
    const id = setInterval(async () => {
      try {
        const s = await req("/scans/" + selected.id);
        setSelected(s);
        if (s.status === "completed" || s.status === "failed") {
          clearInterval(id);
          await refresh();
          const f = await req("/scans/" + s.id + "/findings");
          setFindings(f.items);
        }
      } catch {}
    }, 1100);
    return () => clearInterval(id);
  }, [selected?.id, selected?.status]);
  const latestScans = useMemo(() => {
    const latest = new Map<string, S>();
    for (const s of [...scans]
      .filter((x) => x.status === "completed")
      .sort((a, b) => b.started_at.localeCompare(a.started_at)))
      if (!latest.has(s.project_id)) latest.set(s.project_id, s);
    return [...latest.values()];
  }, [scans]);
  const total = latestScans.reduce((a, s) => a + s.findings_count, 0),
    awaiting = latestScans.reduce(
      (a, s) => a + (s.awaiting_review_count || 0),
      0,
    ),
    high = latestScans.reduce(
      (a, s) =>
        a + (s.severity_counts?.Critical || 0) + (s.severity_counts?.High || 0),
      0,
    ),
    chart = ["Critical", "High", "Medium", "Low", "Informational"].map((x) => ({
      name: x,
      count: latestScans.reduce((a, s) => a + (s.severity_counts?.[x] || 0), 0),
    }));
  const go = (p: string) => {
    navigatePage(p);
    setErr("");
  };
  const start = async () => {
    if (!file || (projectChoice === "new" && !name.trim())) {
      setErr(
        "Choose an existing project or enter a name, then select a ZIP file.",
      );
      return;
    }
    setLoading(true);
    setErr("");
    try {
      const d = new FormData();
      if (projectChoice === "new") d.append("name", name);
      else d.append("project_id", projectChoice);
      d.append("project", file);
      setUploadMeta({ name: file.name, size: file.size });
      const x = await req("/scans", { method: "POST", body: d });
      setFile(null);
      const s = await req("/scans/" + x.scan_id);
      setSelected(s);
      if (s.status === "completed")
        setFindings((await req(`/scans/${s.id}/findings`)).items);
      navigatePage("Scan progress");
      await refresh();
    } catch (e) {
      setErr(String(e));
    } finally {
      setLoading(false);
    }
  };
  const acceptFile = (candidate: File | null) => {
    setErr("");
    if (!candidate) return;
    if (!candidate.name.toLowerCase().endsWith(".zip")) {
      setFile(null);
      setErr("Choose a .zip project archive.");
      return;
    }
    if (candidate.size > 25 * 1024 * 1024) {
      setFile(null);
      setErr("The ZIP must be 25 MB or smaller.");
      return;
    }
    setFile(candidate);
  };
  const mark = async (f: F) => {
    try {
      await req("/findings/" + f.id, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reviewed: !f.reviewed }),
      });
      setFindings(
        findings.map((x) =>
          x.id === f.id ? { ...x, reviewed: !x.reviewed } : x,
        ),
      );
      setDetail({ ...f, reviewed: !f.reviewed });
      await refresh();
    } catch (e) {
      setErr(String(e));
    }
  };
  const filtered = useMemo(
    () =>
      findings
        .filter(
          (f) =>
            (severity === "All" || f.severity === severity) &&
            (category === "All" || f.category === category) &&
            (projectFilter === "All" || f.project_id === projectFilter) &&
            (reviewFilter === "All" ||
              (reviewFilter === "Reviewed" ? f.reviewed : !f.reviewed)) &&
            (!query ||
              `${f.title} ${f.rule_id} ${f.file_path} ${f.category} ${f.dependency_name}`
                .toLowerCase()
                .includes(query.toLowerCase())),
        )
        .sort((a, b) =>
          sortBy === "title"
            ? a.title.localeCompare(b.title)
            : sortBy === "severity"
              ? ["Critical", "High", "Medium", "Low", "Informational"].indexOf(
                  a.severity,
                ) -
                ["Critical", "High", "Medium", "Low", "Informational"].indexOf(
                  b.severity,
                )
              : String(b.scan_started_at || "").localeCompare(
                  String(a.scan_started_at || ""),
                ),
        ),
    [findings, severity, category, projectFilter, reviewFilter, query, sortBy],
  );
  const doCompare = async () => {
    try {
      const first = scans.find((x) => x.id === compareFirst),
        second = scans.find((x) => x.id === compareSecond);
      if (!first || !second) return;
      setComparison(
        await req(
          `/projects/${first.project_id}/compare?first=${encodeURIComponent(first.id)}&second=${encodeURIComponent(second.id)}`,
        ),
      );
    } catch (e) {
      setErr(String(e));
    }
  };
  const askBinAction = (kind: BinAction["kind"], ids: string[]) => {
    setBinFeedback("");
    setBinActionError("");
    setEmptyBinPhrase("");
    setBinAction({ kind, ids });
  };
  const confirmBinAction = async () => {
    if (!binAction || binActionBusy) return;
    if (binAction.kind === "empty" && emptyBinPhrase !== "EMPTY") return;
    setBinActionBusy(true);
    setErr("");
    setBinActionError("");
    setBinFeedback("");
    try {
      if (binAction.kind === "trash") {
        await req("/scans/trash", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scan_ids: binAction.ids }),
        });
      } else if (binAction.kind === "restore") {
        await req("/bin/restore", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scan_ids: binAction.ids }),
        });
      } else if (binAction.kind === "permanent") {
        await req(`/bin/${binAction.ids[0]}`, { method: "DELETE" });
      } else {
        await req("/bin", { method: "DELETE" });
      }
      const labels = {
        trash: binAction.ids.length === 1 ? "Scan moved to Bin." : `${binAction.ids.length} scans moved to Bin.`,
        restore: binAction.ids.length === 1 ? "Scan restored to Scan History." : `${binAction.ids.length} scans restored to Scan History.`,
        permanent: "Scan permanently deleted.",
        empty: "Bin emptied. Trashed scans and their findings were permanently deleted.",
      };
      setBinAction(null);
      setSelectedScanIds([]);
      setSelectedBinIds([]);
      if (binAction.kind === "trash" || binAction.kind === "empty") {
        setCompareFirst((id) => (binAction.ids.includes(id) ? "" : id));
        setCompareSecond((id) => (binAction.ids.includes(id) ? "" : id));
        setComparison(null);
      }
      await refresh();
      setBinFeedback(labels[binAction.kind]);
    } catch (e) {
      const actionLabel: Record<BinAction["kind"], string> = {
        trash: "move scans to the Bin",
        restore: "restore scans",
        permanent: "permanently delete the scan",
        empty: "empty the Bin",
      };
      const message = `Could not ${actionLabel[binAction.kind]}: ${String(e).replace(/^Error: /, "")}`;
      setErr(message);
      setBinActionError(message);
    } finally {
      setBinActionBusy(false);
    }
  };
  const nav = [
    ["Dashboard", LayoutDashboard],
    ["New Scan", ScanSearch],
    ["Projects", FolderKanban],
    ["Findings", ShieldAlert],
    ["Scan History", History],
    ["Bin", Trash2],
    ["Reports", FileCode2],
    ["Settings", Settings],
  ] as const;
  return (
    <div className="shell">
      <aside className={collapsed ? "sidebar mini" : "sidebar"}>
        <div className="brand">
          <span className="brand-icon">
            <Shield size={20} />
          </span>
          {!collapsed && (
            <span>
              dev<span className="accent">guard</span>
              <small>SECURITY WORKSPACE</small>
            </span>
          )}
        </div>
        <div className="nav-label">WORKSPACE</div>
        {nav.map(([n, I]) => (
          <button
            key={n}
            className={"nav-item " + (page === n ? "active" : "")}
            onClick={() => go(n)}
          >
            <I size={17} />
            {!collapsed && n}
            {!collapsed && n === "Findings" && total > 0 && <b>{total}</b>}
            {!collapsed && n === "Bin" && binCount > 0 && <b>{binCount}</b>}
          </button>
        ))}
        <div className="side-bottom">
          <span className={apiUp ? "online-dot" : "offline-dot"} />{" "}
          {!collapsed && (
            <>
              LOCAL SCANNER <small>v{scannerVersion}</small>
            </>
          )}
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <button
            className="icon-btn"
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
            onClick={() => setCollapsed(!collapsed)}
          >
            <Menu size={18} />
          </button>
          <div className="crumb">
            Workspace <ChevronRight size={13} />
            <strong>{page}</strong>
          </div>
          <div className="top-actions">
            <span className={"connection " + (apiUp ? "online" : "offline")}>
              <i />
              {apiUp ? "API connected" : "API offline"}
            </span>
            <span className="avatar" aria-label="DevGuard local workspace">
              DG
            </span>
          </div>
        </header>
        <div className="content">
          {err && (
            <div className="notice" role="alert">
              <TriangleAlert size={16} />
              {err}
              {err.startsWith("API unavailable") && (
                <button className="retry" onClick={refresh}>
                  Retry connection
                </button>
              )}
              <button aria-label="Dismiss message" onClick={() => setErr("")}>
                ×
              </button>
            </div>
          )}
          {binFeedback && (
            <div className="success-notice" role="status" aria-live="polite">
              <Check size={15} /> {binFeedback}
              <button aria-label="Dismiss message" onClick={() => setBinFeedback("")}>×</button>
            </div>
          )}
          {page === "Dashboard" && (
            <>
              <section className="welcome">
                <div>
                  <div className="eyebrow">
                    <span className="live-dot" /> LOCAL SECURITY WORKSPACE
                  </div>
                  <h1>Project security overview</h1>
                  <p>
                    Review the latest completed scan for each project. A finding
                    marked reviewed is not necessarily fixed.
                  </p>
                </div>
                <button className="primary" onClick={() => go("New Scan")}>
                  <Plus size={17} /> New scan
                </button>
              </section>
              <section className="stats">
                <Stat
                  icon={<FolderKanban />}
                  label="Projects scanned"
                  value={dataLoading ? "—" : latestScans.length}
                  note="Projects with a completed scan"
                />
                <Stat
                  icon={<ShieldAlert />}
                  label="Latest findings"
                  value={dataLoading ? "—" : total}
                  note="Latest completed scan per project"
                />
                <Stat
                  icon={<Activity />}
                  label="Awaiting review"
                  value={dataLoading ? "—" : awaiting}
                  note="From latest scans"
                />
                <Stat
                  icon={<TriangleAlert />}
                  label="Critical & high"
                  value={dataLoading ? "—" : high}
                  note="Latest scans · review first"
                  red
                />
                <Stat
                  icon={<Activity />}
                  label="Last scan"
                  value={scans[0]?.status || "—"}
                  note={
                    scans[0]?.started_at
                      ? new Date(scans[0].started_at).toLocaleString()
                      : "No scans yet"
                  }
                />
              </section>
              <section className="grid-main">
                <div className="panel chart-panel">
                  <div className="panel-head">
                    <div>
                      <h2>Finding severity</h2>
                      <p>
                        Latest completed scan per project; rescans are not
                        double-counted
                      </p>
                    </div>
                    <span className="tag">{latestScans.length} PROJECTS</span>
                  </div>
                  {dataLoading ? (
                    <div className="empty-chart">
                      <Activity />
                      <strong>Loading scan data…</strong>
                    </div>
                  ) : total ? (
                    <SeverityChart data={chart} />
                  ) : (
                    <div className="empty-chart">
                      <Activity />
                      <strong>No completed scan data yet</strong>
                      <span>
                        Run your first scan to see security insights here.
                      </span>
                    </div>
                  )}
                </div>
                <div className="panel quick-panel">
                  <div className="panel-head">
                    <div>
                      <h2>Quick start</h2>
                      <p>Scan a project in a few steps</p>
                    </div>
                  </div>
                  <div className="quick-steps">
                    <Step
                      n="01"
                      t="Choose a project"
                      d="Upload a ZIP from your computer"
                    />
                    <Step
                      n="02"
                      t="Review findings"
                      d="Explore evidence and guidance"
                    />
                    <Step
                      n="03"
                      t="Ship with confidence"
                      d="Fix, rescan, and track progress"
                    />
                  </div>
                  <button
                    className="text-button"
                    onClick={() => go("New Scan")}
                  >
                    Start a scan <ArrowUpRight size={15} />
                  </button>
                </div>
              </section>
              <div className="section-heading">
                <div>
                  <h2>Recent scans</h2>
                  <p>Your latest project security checks</p>
                </div>
                <button
                  className="text-button"
                  onClick={() => go("Scan History")}
                >
                  View history <ChevronRight size={15} />
                </button>
              </div>
              <div className="panel table-wrap">
                {dataLoading ? (
                  <div className="empty-row">Loading scans…</div>
                ) : scans.length ? (
                  <table>
                    <thead>
                      <tr>
                        <th>PROJECT</th>
                        <th>STATUS</th>
                        <th>FINDINGS</th>
                        <th>SCANNED</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {scans.slice(0, 5).map((s) => (
                        <tr
                          key={s.id}
                          onClick={() => {
                            setSelected(s);
                            navigatePage("Scan progress");
                          }}
                        >
                          <td>
                            <span className="project-cell">
                              <FileCode2 />
                              {s.project_name}
                            </span>
                          </td>
                          <td>
                            <span className={"status " + s.status}>
                              {s.status}
                            </span>
                          </td>
                          <td>{s.findings_count}</td>
                          <td>{new Date(s.started_at).toLocaleString()}</td>
                          <td>
                            <ChevronRight size={16} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="empty-row">
                    Your completed scans will appear here.
                  </div>
                )}
              </div>
            </>
          )}
          {page === "New Scan" && (
            <>
              <PageTitle
                eyebrow="PROJECT SECURITY"
                title="Start a new scan"
                desc="Choose an existing project to add a comparable scan, or create a project. Archives are inspected as data; project code is never run."
              />
              <div className="scan-layout">
                <div className="panel form-panel">
                  <label className="field-label" htmlFor="project-choice">
                    PROJECT TARGET
                  </label>
                  <select
                    id="project-choice"
                    className="input"
                    value={projectChoice}
                    onChange={(e) => setProjectChoice(e.target.value)}
                  >
                    <option value="new">Create a new project</option>
                    {projects.map((p) => (
                      <option value={p.id} key={p.id}>
                        {p.name} · {p.scans_count} scans
                      </option>
                    ))}
                  </select>
                  {projectChoice === "new" && (
                    <>
                      <label className="field-label mt" htmlFor="project-name">
                        PROJECT NAME
                      </label>
                      <input
                        id="project-name"
                        className="input"
                        placeholder="e.g. storefront-api"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                      />
                    </>
                  )}
                  <label className="field-label mt" htmlFor="project-archive">
                    PROJECT ARCHIVE
                  </label>
                  <label
                    className="dropzone"
                    htmlFor="project-archive"
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault();
                      acceptFile(e.dataTransfer.files[0] || null);
                    }}
                  >
                    <UploadCloud size={30} />
                    <strong>
                      {file ? file.name : "Drop your ZIP archive here"}
                    </strong>
                    <span>
                      {file
                        ? `${(file.size / 1024 / 1024).toFixed(1)} MB · ready to scan`
                        : "or click to browse · ZIP only, up to 25 MB"}
                    </span>
                    <input
                      id="project-archive"
                      aria-label="Choose project ZIP archive"
                      type="file"
                      accept=".zip,application/zip"
                      onChange={(e) => acceptFile(e.target.files?.[0] || null)}
                    />
                  </label>
                  <div className="upload-note">
                    <Shield size={15} /> ZIP ≤25 MB · ≤5,000 files · ≤50 MB
                    extracted. Files are isolated, inspected as data, then
                    deleted.
                  </div>
                  <button
                    className="primary wide"
                    onClick={start}
                    disabled={loading}
                  >
                    {loading ? (
                      "Preparing scan…"
                    ) : (
                      <>
                        <ScanSearch size={17} /> Start scan
                      </>
                    )}
                  </button>
                </div>
                <div className="panel what-panel">
                  <div className="panel-head">
                    <div>
                      <h2>What we inspect</h2>
                      <p>Evidence-backed checks for common risks</p>
                    </div>
                  </div>
                  {[
                    [
                      "Source patterns",
                      "SQL construction, dynamic evaluation, shell use, TLS settings",
                    ],
                    [
                      "Hardcoded secrets",
                      "Credential-like values with redacted evidence",
                    ],
                    [
                      "Dependencies",
                      "Pinned PyPI and npm versions checked against OSV.dev",
                    ],
                    ["Container config", "Basic Docker privilege checks"],
                  ].map(([a, b]) => (
                    <div className="inspect-item" key={a}>
                      <Check size={16} />
                      <div>
                        <strong>{a}</strong>
                        <span>{b}</span>
                      </div>
                    </div>
                  ))}
                  <div className="privacy-note">
                    OSV receives package names and versions only. Source code is
                    never sent.
                  </div>
                </div>
              </div>
            </>
          )}
          {page === "Scan progress" && (
            <>
              <PageTitle
                eyebrow="LIVE SCAN"
                title={selected?.project_name || "Scan progress"}
                desc="Current status from the local scanner."
              />
              <div className="panel progress-card">
                <div className="progress-top">
                  <div className="scan-icon">
                    <Activity />
                  </div>
                  <div>
                    <span
                      className={"status " + (selected?.status || "queued")}
                    >
                      {selected?.status || "queued"}
                    </span>
                    <h2>{selected?.stage || "Waiting for scan details"}</h2>
                    <p>
                      {selected?.error ||
                        "Analysis runs in a bounded local background worker."}
                      {uploadMeta && (
                        <>
                          {" "}
                          · Archive: <code>{uploadMeta.name}</code> ·{" "}
                          {(uploadMeta.size / 1024 / 1024).toFixed(1)} MB
                        </>
                      )}
                    </p>
                  </div>
                  <span className="scan-id">
                    SCAN · {selected?.id?.slice(0, 8) || "—"}
                  </span>
                </div>
                <div
                  className={"progress-track " + (selected?.status || "queued")}
                  role="img"
                  aria-label={
                    selected?.status === "running"
                      ? "Scan is running"
                      : "Scan status: " + (selected?.status || "queued")
                  }
                >
                  <span />
                </div>
                <div className="progress-metrics">
                  <div>
                    <span>FILES PROCESSED</span>
                    <strong>{selected?.files_processed ?? "—"}</strong>
                  </div>
                  <div>
                    <span>DEPENDENCIES</span>
                    <strong>{selected?.dependencies_analyzed ?? "—"}</strong>
                  </div>
                  <div>
                    <span>FINDINGS</span>
                    <strong>{selected?.findings_count ?? "—"}</strong>
                  </div>
                  <div>
                    <span>ADVISORY DB</span>
                    <strong>{selected?.database_status || "pending"}</strong>
                  </div>
                </div>
              </div>
              {selected?.status === "completed" && (
                <>
                  <div className="section-heading">
                    <div>
                      <h2>Scan findings</h2>
                      <p>Review evidence and decide what to address.</p>
                    </div>
                    <button
                      className="text-button"
                      onClick={() => go("Findings")}
                    >
                      All findings <ChevronRight size={15} />
                    </button>
                  </div>
                  <FindingTable items={findings} onOpen={setDetail} />
                </>
              )}
            </>
          )}
          {page === "Findings" && (
            <>
              <PageTitle
                eyebrow="SECURITY FINDINGS"
                title="Findings"
                desc="Investigate evidence-backed potential issues across your projects. Reviewed does not mean resolved."
              />
              <div className="filterbar">
                <div className="searchbox">
                  <Search size={16} />
                  <input
                    aria-label="Search findings by title, rule, or file"
                    placeholder="Search findings…"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                  />
                </div>
                <select
                  aria-label="Filter by severity"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                >
                  <option>All</option>
                  {["Critical", "High", "Medium", "Low", "Informational"].map(
                    (x) => (
                      <option key={x}>{x}</option>
                    ),
                  )}
                </select>
                <select
                  aria-label="Filter by category"
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                >
                  <option>All</option>
                  {[...new Set(findings.map((f) => f.category))].map((x) => (
                    <option key={x}>{x}</option>
                  ))}
                </select>
                <select
                  aria-label="Filter by project"
                  value={projectFilter}
                  onChange={(e) => setProjectFilter(e.target.value)}
                >
                  <option value="All">All projects</option>
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
                <select
                  aria-label="Filter by review status"
                  value={reviewFilter}
                  onChange={(e) => setReviewFilter(e.target.value)}
                >
                  <option>All</option>
                  <option>Open</option>
                  <option>Reviewed</option>
                </select>
                <select
                  aria-label="Sort findings"
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value)}
                >
                  <option value="latest">Latest scan</option>
                  <option value="severity">Severity</option>
                  <option value="title">Title</option>
                </select>
                <span className="muted">{filtered.length} results</span>
              </div>
              {dataLoading ? (
                <div className="panel empty-row">Loading findings…</div>
              ) : (
                <FindingTable items={filtered} onOpen={setDetail} />
              )}
            </>
          )}
          {page === "Scan History" && (
            <>
              <PageTitle
                eyebrow="ACTIVITY"
                title="Scan history"
                desc="A persistent record of project scans. Compare completed scans from the same project."
              />
              <div className="compare-tools">
                <label>COMPARE PROJECT SCANS</label>
                <select
                  aria-label="First scan to compare"
                  value={compareFirst}
                  onChange={(e) => {
                    setCompareFirst(e.target.value);
                    setCompareSecond("");
                    setComparison(null);
                  }}
                >
                  <option value="">Select a baseline scan</option>
                  {scans
                    .filter((s) => s.status === "completed")
                    .map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.project_name} ·{" "}
                        {new Date(s.started_at).toLocaleString()} ·{" "}
                        {s.id.slice(0, 8)}
                      </option>
                    ))}
                </select>
                <select
                  aria-label="Second scan to compare"
                  value={compareSecond}
                  onChange={(e) => {
                    setCompareSecond(e.target.value);
                    setComparison(null);
                  }}
                >
                  <option value="">Select a later scan</option>
                  {scans
                    .filter(
                      (s) =>
                        s.status === "completed" &&
                        (!compareFirst ||
                          s.project_id ===
                            scans.find((x) => x.id === compareFirst)
                              ?.project_id),
                    )
                    .map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.project_name} ·{" "}
                        {new Date(s.started_at).toLocaleString()} ·{" "}
                        {s.id.slice(0, 8)}
                      </option>
                    ))}
                </select>
                <button
                  className="secondary"
                  disabled={
                    !compareFirst ||
                    !compareSecond ||
                    compareFirst === compareSecond
                  }
                  onClick={doCompare}
                >
                  Compare
                </button>
                {comparison && (
                  <div className="comparison-result">
                    <strong>
                      {comparison.introduced.length} introduced ·{" "}
                      {comparison.unchanged} persistent ·{" "}
                      {comparison.not_detected_in_latest.length} no longer
                      detected
                    </strong>
                    <small>
                      Not detected in the latest scan does not verify a fix.
                    </small>
                    {comparison.introduced.map((f: any, i: number) => (
                      <div key={"new" + i}>
                        NEW · {f.title} ·{" "}
                        {f.file_path || f.dependency_name || "project"}
                      </div>
                    ))}
                    {comparison.persistent.map((f: any, i: number) => (
                      <div key={"same" + i}>
                        PERSISTENT · {f.title} ·{" "}
                        {f.file_path || f.dependency_name || "project"}
                      </div>
                    ))}
                    {comparison.not_detected_in_latest.map(
                      (f: any, i: number) => (
                        <div key={"old" + i}>
                          NO LONGER DETECTED · {f.title} ·{" "}
                          {f.file_path || f.dependency_name || "project"}
                        </div>
                      ),
                    )}
                  </div>
                )}
              </div>
              {selectedScanIds.length > 0 && (
                <div className="bin-toolbar">
                  <span>{selectedScanIds.length} selected</span>
                  <button
                    className="secondary"
                    onClick={() => askBinAction("trash", selectedScanIds)}
                  >
                    <Trash2 size={14} /> Move selected to Bin
                  </button>
                  <button className="inline" onClick={() => setSelectedScanIds([])}>
                    Clear selection
                  </button>
                </div>
              )}
              <div className="panel table-wrap">
                {dataLoading ? (
                  <div className="empty-row">Loading scan history…</div>
                ) : scans.length ? (
                  <table>
                    <thead>
                      <tr>
                        <th>
                          <input
                            type="checkbox"
                            aria-label="Select all scans"
                            checked={
                              scans.some((scan) => scan.status === "completed" || scan.status === "failed") &&
                              selectedScanIds.length ===
                                scans.filter((scan) => scan.status === "completed" || scan.status === "failed").length
                            }
                            onChange={(e) =>
                              setSelectedScanIds(
                                e.target.checked
                                  ? scans
                                      .filter((scan) => scan.status === "completed" || scan.status === "failed")
                                      .map((scan) => scan.id)
                                  : [],
                              )
                            }
                          />
                        </th>
                        <th>PROJECT</th>
                        <th>STATUS</th>
                        <th>FINDINGS</th>
                        <th>FILES</th>
                        <th>DURATION</th>
                        <th>STARTED</th>
                        <th>REPORT</th>
                        <th>ACTION</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scans.map((s) => (
                        <tr key={s.id}>
                          <td>
                            <input
                              type="checkbox"
                              aria-label={`Select scan ${s.project_name}`}
                              checked={selectedScanIds.includes(s.id)}
                              disabled={s.status !== "completed" && s.status !== "failed"}
                              onChange={(e) =>
                                setSelectedScanIds((current) =>
                                  e.target.checked
                                    ? [...current, s.id]
                                    : current.filter((id) => id !== s.id),
                                )
                              }
                            />
                          </td>
                          <td>
                            <button
                              className="project-link"
                              onClick={async () => {
                                setSelected(s);
                                navigatePage("Scan progress");
                                if (s.status === "completed")
                                  setFindings(
                                    (await req(`/scans/${s.id}/findings`))
                                      .items,
                                  );
                              }}
                            >
                              <FileCode2 />
                              {s.project_name}
                            </button>
                          </td>
                          <td>
                            <span className={"status " + s.status}>
                              {s.status}
                            </span>
                          </td>
                          <td>{s.findings_count}</td>
                          <td>{s.files_processed}</td>
                          <td>
                            {s.duration_seconds == null
                              ? "—"
                              : `${s.duration_seconds}s`}
                          </td>
                          <td>
                            <code>
                              {new Date(s.started_at).toLocaleString()}
                            </code>
                          </td>
                          <td>
                            <a
                              className="download"
                              href={`${API}/scans/${s.id}/report.json`}
                            >
                              JSON <ExternalLink size={13} />
                            </a>{" "}
                            ·{" "}
                            <a
                              className="download"
                              target="_blank"
                              href={`${API}/scans/${s.id}/report.html`}
                            >
                              HTML
                            </a>
                          </td>
                          <td>
                            <button
                              className="row-action"
                              aria-label={`Move ${s.project_name} to Bin`}
                              disabled={s.status !== "completed" && s.status !== "failed"}
                              onClick={() => askBinAction("trash", [s.id])}
                              title="Move this scan to the Bin"
                            >
                              <Trash2 size={15} />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="empty-row">
                    <span>
                      No active scans in history. Start a scan or check the Bin
                      for scans you moved there.
                    </span>
                  </div>
                )}
              </div>
            </>
          )}
          {page === "Bin" && (
            <>
              <PageTitle
                eyebrow="RECOVERABLE SCANS"
                title="Bin"
                desc="Scans here are hidden from active history and dashboard metrics. Restore them to recover their findings and reports, or permanently delete them."
              />
              {binScans.length > 0 && (
                <div className="bin-toolbar">
                  <label>
                    <input
                      type="checkbox"
                      aria-label="Select all scans in Bin"
                      checked={selectedBinIds.length === binScans.length}
                      onChange={(e) =>
                        setSelectedBinIds(
                          e.target.checked ? binScans.map((scan) => scan.id) : [],
                        )
                      }
                    />
                    Select all
                  </label>
                  <span>{selectedBinIds.length} selected</span>
                  <button
                    className="secondary"
                    disabled={!selectedBinIds.length}
                    onClick={() => askBinAction("restore", selectedBinIds)}
                  >
                    <RotateCcw size={14} /> Restore selected
                  </button>
                  <button
                    className="danger"
                    onClick={() => askBinAction("empty", binScans.map((scan) => scan.id))}
                  >
                    <Trash size={14} /> Empty Bin
                  </button>
                </div>
              )}
              <div className="panel table-wrap">
                {dataLoading ? (
                  <div className="empty-row">Loading Bin…</div>
                ) : binScans.length ? (
                  <table>
                    <thead>
                      <tr>
                        <th>SELECT</th>
                        <th>PROJECT</th>
                        <th>STATUS</th>
                        <th>FINDINGS</th>
                        <th>FILES</th>
                        <th>DEPS</th>
                        <th>DURATION</th>
                        <th>STARTED</th>
                        <th>SCAN ID</th>
                        <th>MOVED TO BIN</th>
                        <th>REPORTS</th>
                        <th>ACTIONS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {binScans.map((s) => (
                        <tr key={s.id}>
                          <td>
                            <input
                              type="checkbox"
                              aria-label={`Select binned scan ${s.project_name}`}
                              checked={selectedBinIds.includes(s.id)}
                              onChange={(e) =>
                                setSelectedBinIds((current) =>
                                  e.target.checked
                                    ? [...current, s.id]
                                    : current.filter((id) => id !== s.id),
                                )
                              }
                            />
                          </td>
                          <td>{s.project_name}</td>
                          <td><span className={`status ${s.status}`}>{s.status}</span></td>
                          <td>{s.findings_count}</td>
                          <td>{s.files_processed}</td>
                          <td>{s.dependencies_analyzed}</td>
                          <td>{s.duration_seconds == null ? "—" : `${s.duration_seconds}s`}</td>
                          <td><code>{new Date(s.started_at).toLocaleString()}</code></td>
                          <td><code>{s.id}</code></td>
                          <td><code>{s.deleted_at ? new Date(s.deleted_at).toLocaleString() : "—"}</code></td>
                          <td>
                            <a className="download" href={`${API}/scans/${s.id}/report.json`}>JSON <ExternalLink size={13} /></a>
                            {" · "}
                            <a className="download" target="_blank" rel="noreferrer" href={`${API}/scans/${s.id}/report.html`}>HTML</a>
                          </td>
                          <td className="bin-actions">
                            <button
                              className="row-action restore-action"
                              aria-label={`Restore ${s.project_name}`}
                              onClick={() => askBinAction("restore", [s.id])}
                              title="Restore scan to active history"
                            ><RotateCcw size={15} /></button>
                            <button
                              className="row-action permanent-action"
                              aria-label={`Permanently delete ${s.project_name}`}
                              onClick={() => askBinAction("permanent", [s.id])}
                              title="Permanently delete this scan and its findings"
                            ><Trash size={15} /></button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="empty-row">The Bin is empty. Scans you move here can be restored or permanently deleted.</div>
                )}
              </div>
            </>
          )}
          {page === "Projects" && (
            <>
              <PageTitle
                eyebrow="YOUR WORKSPACE"
                title="Projects"
                desc="Projects are created automatically when you start a scan."
              />
              <div className="project-grid">
                {projects.map((p) => (
                  <button
                    className="panel project-card"
                    key={p.id}
                    onClick={async () => {
                      const d = await req("/projects/" + p.id);
                      const s = d.scans?.[0];
                      if (s) {
                        setSelected({ ...s, project_name: p.name });
                        navigatePage("Scan progress");
                      }
                    }}
                  >
                    <div className="scan-icon">
                      <FolderKanban />
                    </div>
                    <strong>{p.name}</strong>
                    <span>
                      {p.scans_count} scan{p.scans_count === 1 ? "" : "s"}
                    </span>
                    <small>
                      {p.last_scan
                        ? new Date(p.last_scan).toLocaleDateString()
                        : "No scans"}
                    </small>
                  </button>
                ))}
                {!projects.length && (
                  <div className="panel empty-row">
                    Projects will appear here after your first scan.
                  </div>
                )}
              </div>
            </>
          )}
          {page === "Reports" && (
            <>
              <PageTitle
                eyebrow="EXPORTS"
                title="Scan reports"
                desc="Download reports from completed and incomplete scan records."
              />
              <div className="panel table-wrap">
                {scans.length ? (
                  <table>
                    <thead>
                      <tr>
                        <th>PROJECT</th>
                        <th>SCAN ID</th>
                        <th>STATUS</th>
                        <th>FINDINGS</th>
                        <th>REPORTS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scans.map((s) => (
                        <tr key={s.id}>
                          <td>{s.project_name}</td>
                          <td>
                            <code>{s.id.slice(0, 12)}</code>
                          </td>
                          <td>
                            <span className={"status " + s.status}>
                              {s.status}
                            </span>
                          </td>
                          <td>{s.findings_count}</td>
                          <td>
                            <a
                              className="download"
                              href={`${API}/scans/${s.id}/report.json`}
                            >
                              JSON <ExternalLink size={13} />
                            </a>{" "}
                            ·{" "}
                            <a
                              className="download"
                              target="_blank"
                              rel="noreferrer"
                              href={`${API}/scans/${s.id}/report.html`}
                            >
                              HTML
                            </a>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="empty-row">
                    Reports appear after your first scan.
                  </div>
                )}
              </div>
            </>
          )}
          {page === "Settings" && (
            <>
              <PageTitle
                eyebrow="PREFERENCES"
                title="Settings"
                desc="Local scanner configuration and privacy information."
              />
              <div className="panel settings-card">
                <h2>
                  <Shield size={18} /> Privacy & scanner
                </h2>
                <p>
                  DevGuard runs locally. Uploaded source is staged temporarily
                  and removed when analysis finishes. SQLite stores scan and
                  finding metadata.
                </p>
                <p>
                  When dependency data is available, package coordinates are
                  sent to OSV.dev. Source code and detected secret values are
                  not sent or stored.
                </p>
                <Suspense fallback={<p className="ai-loading" role="status">Loading optional AI settings…</p>}>
                  <LazyAiSettingsPanel
                    apiBase={API}
                    apiKey={aiApiKey}
                    provider={aiProvider}
                    model={aiModel}
                    onKeyChange={setAiApiKey}
                    onProviderChange={setAiProvider}
                    onModelChange={setAiModel}
                  />
                </Suspense>
                <div className="setting-row">
                  <span>API endpoint</span>
                  <code>{API}</code>
                </div>
                <div className="setting-row">
                  <span>Maximum ZIP size</span>
                  <code>25 MB</code>
                </div>
                <div className="setting-row">
                  <span>Supported uploads</span>
                  <code>ZIP archives</code>
                </div>
                <div className="privacy-note">
                  Local development tool · heuristic detection · human review
                  recommended
                </div>
              </div>
            </>
          )}
        </div>
      </main>
      {binAction && (
        <div className="confirm-overlay" onClick={() => !binActionBusy && setBinAction(null)}>
          <section
            className="confirm-dialog"
            ref={confirmDialogRef}
            tabIndex={-1}
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="bin-confirm-title"
            aria-describedby="bin-confirm-description"
            onClick={(event) => event.stopPropagation()}
          >
            <span className={binAction.kind === "permanent" || binAction.kind === "empty" ? "confirm-icon destructive" : "confirm-icon"}>
              {binAction.kind === "restore" ? <RotateCcw size={18} /> : <Trash2 size={18} />}
            </span>
            <h2 id="bin-confirm-title">
              {binAction.kind === "trash" && "Move scans to the Bin?"}
              {binAction.kind === "restore" && "Restore scans?"}
              {binAction.kind === "permanent" && "Permanently delete this scan?"}
              {binAction.kind === "empty" && "Empty the Bin permanently?"}
            </h2>
            <p id="bin-confirm-description">
              {binAction.kind === "trash" && `${binAction.ids.length} scan${binAction.ids.length === 1 ? "" : "s"} will leave active history. Their findings and reports remain available in the Bin until you permanently delete them.`}
              {binAction.kind === "restore" && `${binAction.ids.length} scan${binAction.ids.length === 1 ? "" : "s"} will return to active Scan History with their original findings and report access.`}
              {binAction.kind === "permanent" && "This permanently deletes the scan record and its findings. Its report will no longer be available. This action cannot be undone."}
              {binAction.kind === "empty" && `All ${binCount} scan${binCount === 1 ? "" : "s"} in the Bin and their findings will be permanently deleted. This action cannot be undone.`}
            </p>
            {binActionError && <p className="confirm-error" role="alert">{binActionError}</p>}
            {binAction.kind === "empty" && (
              <label className="confirm-phrase">
                Type <code>EMPTY</code> to confirm
                <input
                  aria-label="Type EMPTY to confirm"
                  value={emptyBinPhrase}
                  onChange={(event) => setEmptyBinPhrase(event.target.value)}
                  autoComplete="off"
                />
              </label>
            )}
            <div className="confirm-actions">
              <button className="secondary" disabled={binActionBusy} onClick={() => setBinAction(null)}>
                Cancel
              </button>
              <button
                className={binAction.kind === "permanent" || binAction.kind === "empty" ? "danger" : "primary"}
                disabled={binActionBusy || (binAction.kind === "empty" && emptyBinPhrase !== "EMPTY")}
                onClick={confirmBinAction}
              >
                {binActionBusy ? "Working…" : binAction.kind === "trash" ? "Move to Bin" : binAction.kind === "restore" ? "Restore" : binAction.kind === "empty" ? "Empty Bin permanently" : "Delete permanently"}
              </button>
            </div>
          </section>
        </div>
      )}
      {detail && (
        <div className="overlay" onClick={() => setDetail(null)}>
          <aside
            className="detail-drawer"
            ref={detailDialogRef}
            tabIndex={-1}
            role="dialog"
            aria-modal="true"
            aria-label={detail.title}
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="close"
              aria-label="Close finding details"
              onClick={() => setDetail(null)}
            >
              ×
            </button>
            <span className={"severity " + detail.severity.toLowerCase()}>
              {detail.severity}
            </span>
            <span className="finding-kind">
              {detail.rule_id === "OSV"
                ? "KNOWN ADVISORY · OSV"
                : "HEURISTIC PATTERN"}
            </span>
            <h2>{detail.title}</h2>
            <p>{detail.description}</p>
            <div className="detail-block">
              <span>PROJECT · SCAN</span>
              <code>
                {detail.project_name ||
                  selected?.project_name ||
                  "Current project"}{" "}
                ·{" "}
                {detail.scan_id?.slice(0, 12) ||
                  selected?.id?.slice(0, 12) ||
                  "—"}
              </code>
            </div>
            <div className="detail-block">
              <span>SCAN DATE</span>
              <code>
                {detail.scan_started_at
                  ? new Date(detail.scan_started_at).toLocaleString()
                  : selected?.started_at
                    ? new Date(selected.started_at).toLocaleString()
                    : "—"}
              </code>
            </div>
            <div className="detail-block">
              <span>CATEGORY</span>
              <code>{detail.category}</code>
            </div>
            <div className="detail-block">
              <span>LOCATION</span>
              <code>
                {detail.file_path || detail.dependency_name || "Dependency"}
                {detail.line ? `:${detail.line}` : ""}
              </code>
            </div>
            <div className="detail-block">
              <span>CONFIDENCE · RULE</span>
              <code>
                {detail.confidence} · {detail.rule_id}
              </code>
            </div>
            {(detail.advisory_id || detail.cve) && (
              <div className="detail-block">
                <span>VERIFIED ADVISORY IDENTIFIERS</span>
                <code>
                  {detail.cve || detail.advisory_id}{" "}
                  {detail.cve &&
                    detail.advisory_id &&
                    "· " + detail.advisory_id}
                </code>
                {detail.source_severity && (
                  <small>Source severity: {detail.source_severity}</small>
                )}
              </div>
            )}
            {detail.affected_ranges?.length && (
              <div className="detail-block">
                <span>ADVISORY AFFECTED RANGES</span>
                <pre>{JSON.stringify(detail.affected_ranges, null, 2)}</pre>
              </div>
            )}
            <div className="detail-block">
              <span>EVIDENCE</span>
              <pre>{detail.evidence || "No evidence excerpt available."}</pre>
            </div>
            <div className="detail-block">
              <span>RECOMMENDED REMEDIATION</span>
              <p>{detail.remediation}</p>
            </div>
            <Suspense fallback={<p className="ai-loading" role="status">Loading optional AI assistance…</p>}>
              <LazyAiFindingAssistant
                apiBase={API}
                apiKey={aiApiKey}
                provider={aiProvider}
                model={aiModel}
                finding={detail}
                onOpenSettings={() => {
                  setDetail(null);
                  navigatePage("Settings");
                }}
              />
            </Suspense>
            {detail.references
              ?.filter((r) => r.startsWith("https://"))
              .map((r) => (
                <a
                  className="download"
                  target="_blank"
                  rel="noreferrer"
                  href={r}
                  key={r}
                >
                  Reference <ExternalLink size={13} />
                </a>
              ))}
            <p className="review-note">
              Review is a triage state only; DevGuard does not verify whether a
              finding has been fixed.
            </p>
            <button
              className="primary wide review-btn"
              onClick={() => mark(detail)}
            >
              {detail.reviewed ? (
                <>
                  <Check size={16} /> Mark as unreviewed
                </>
              ) : (
                <>
                  <Check size={16} /> Mark as reviewed
                </>
              )}
            </button>
          </aside>
        </div>
      )}
    </div>
  );
}
function Stat({ icon, label, value, note, red }: any) {
  return (
    <div className="panel stat">
      <span className={"stat-icon " + (red ? "red" : "")}>{icon}</span>
      <span className="stat-label">{label}</span>
      <strong>{value}</strong>
      <small>{note}</small>
    </div>
  );
}
function Step({ n, t, d }: any) {
  return (
    <div className="step">
      <b>{n}</b>
      <div>
        <strong>{t}</strong>
        <span>{d}</span>
      </div>
    </div>
  );
}
function PageTitle({ eyebrow, title, desc }: any) {
  return (
    <section className="page-title">
      <div className="eyebrow">{eyebrow}</div>
      <h1>{title}</h1>
      <p>{desc}</p>
    </section>
  );
}
function FindingTable({ items, onOpen }: any) {
  return (
    <div className="panel table-wrap">
      {items.length ? (
        <table>
          <thead>
            <tr>
              <th>SEVERITY</th>
              <th>RULE / FINDING</th>
              <th>PROJECT / SCAN</th>
              <th>CATEGORY</th>
              <th>LOCATION</th>
              <th>REVIEW</th>
            </tr>
          </thead>
          <tbody>
            {items.map((f: F) => (
              <tr
                key={f.id}
                role="button"
                tabIndex={0}
                aria-label={`Open finding ${f.title}`}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    onOpen(f);
                  }
                }}
                onClick={() => onOpen(f)}
              >
                <td>
                  <span className={"severity " + f.severity.toLowerCase()}>
                    {f.severity}
                  </span>
                </td>
                <td>
                  <strong>{f.title}</strong>
                  <small className="subline">{f.rule_id}</small>
                </td>
                <td>
                  {f.project_name || "Current scan"}
                  <small className="subline mono">
                    {f.scan_id?.slice(0, 8) || "—"}
                  </small>
                </td>
                <td>{f.category}</td>
                <td className="mono">
                  {f.file_path
                    ? `${f.file_path}${f.line ? ":" + f.line : ""}`
                    : f.dependency_name || "—"}
                </td>
                <td>
                  {f.reviewed ? (
                    <span className="reviewed">
                      <Check size={13} /> Reviewed
                    </span>
                  ) : (
                    "Open"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="empty-row">No findings match this view.</div>
      )}
    </div>
  );
}
