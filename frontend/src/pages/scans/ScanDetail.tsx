import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Ban, Code2, Download, RotateCcw } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { RiskGauge } from "../../components/charts";
import {
  Card,
  ErrorBox,
  KeyValue,
  Loading,
  Notice,
  PageHeader,
  Pill,
  SeverityBadge,
  Stat,
  StatusPill,
  Tabs,
  VerificationPill,
} from "../../components/ui";
import { api, reportUrl } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { formatBytes, formatDate, formatDuration, label } from "../../lib/format";
import type { Dependency, Finding, Page, Scan, ScanFile } from "../../lib/types";
import { scanDuration } from "./Scans";

type Tab = "findings" | "files" | "dependencies" | "scanners";

function Progress({ scan }: { scan: Scan }) {
  const percent = scan.progress.percent ?? 0;
  return (
    <Card>
      <div className="mb-2 flex items-center justify-between text-sm">
        <span className="font-medium">{scan.status === "QUEUED" ? "Waiting for a worker…" : `${label(scan.progress.stage ?? "running")}…`}</span>
        <span className="tabular-nums text-muted">{percent}%</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-surface-3">
        <div className="h-full animate-pulse bg-accent transition-all" style={{ width: `${Math.max(4, percent)}%` }} />
      </div>
      <p className="mt-3 text-xs text-muted">
        The worker extracts the code safely and analyses it in an isolated process with CPU, memory and time limits. Nothing is executed.
      </p>
    </Card>
  );
}

export default function ScanDetail() {
  const { projectId = "", scanId = "" } = useParams();
  const { can } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("findings");
  const scan = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.get<Scan>(`/projects/${projectId}/scans/${scanId}`),
    refetchInterval: (query) => (query.state.data && ["QUEUED", "RUNNING"].includes(query.state.data.status) ? 1500 : false),
  });
  const done = scan.data?.status === "COMPLETED";
  const findings = useQuery({
    queryKey: ["scan-findings", scanId],
    queryFn: () => api.get<Page<Finding>>(`/projects/${projectId}/scans/${scanId}/findings`, { page_size: 500 }),
    enabled: done,
  });
  const files = useQuery({
    queryKey: ["scan-files", scanId],
    queryFn: () => api.get<ScanFile[]>(`/projects/${projectId}/scans/${scanId}/files`),
    enabled: done && tab === "files",
  });
  const deps = useQuery({
    queryKey: ["scan-deps", scanId],
    queryFn: () => api.get<Dependency[]>(`/projects/${projectId}/scans/${scanId}/dependencies`),
    enabled: done && tab === "dependencies",
  });
  const cancel = useMutation({
    mutationFn: () => api.post<Scan>(`/projects/${projectId}/scans/${scanId}/cancel`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scan", scanId] }),
  });
  const rescan = useMutation({
    mutationFn: () => api.post<Scan>(`/projects/${projectId}/scans/${scanId}/rescan`, {}),
    onSuccess: (next) => navigate(`/projects/${projectId}/scans/${next.id}`),
  });

  if (scan.isLoading) return <Loading />;
  if (scan.isError) return <ErrorBox error={scan.error} />;
  const s = scan.data!;
  const stats = s.stats;
  const running = s.status === "QUEUED" || s.status === "RUNNING";

  return (
    <>
      <PageHeader
        eyebrow={`Scan · ${label(s.trigger)} · ${label(s.scope)}`}
        title={s.repository_name ?? "Scan"}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <StatusPill value={s.status} /> created {formatDate(s.created_at)}
            {s.finished_at && <> · took {scanDuration(s)}</>}
          </span>
        }
        actions={
          <>
            {running && (can("scan:cancel") || can("scan:create")) && (
              <button className="btn-secondary" onClick={() => cancel.mutate()} disabled={cancel.isPending}>
                <Ban className="h-4 w-4" /> Cancel
              </button>
            )}
            {!running && s.snapshot_id && can("scan:create") && (
              <button className="btn-secondary" onClick={() => rescan.mutate()} disabled={rescan.isPending}>
                <RotateCcw className="h-4 w-4" /> Rescan
              </button>
            )}
            {done && s.snapshot_id && (
              <Link to={`/projects/${projectId}/scans/${scanId}/code`} className="btn-secondary">
                <Code2 className="h-4 w-4" /> Code
              </Link>
            )}
            {done && (
              <div className="flex overflow-hidden rounded-lg border border-line">
                {[
                  ["html", "HTML"],
                  ["sarif", "SARIF"],
                  ["json", "JSON"],
                  ["markdown", "MD"],
                ].map(([fmt, text]) => (
                  <a key={fmt} href={reportUrl(projectId, scanId, fmt)} className="btn-ghost rounded-none border-r border-line last:border-r-0" download>
                    {fmt === "html" && <Download className="h-4 w-4" />} {text}
                  </a>
                ))}
              </div>
            )}
          </>
        }
      />
      {(cancel.isError || rescan.isError) && <ErrorBox error={cancel.error ?? rescan.error} title="Action failed" />}
      {running && <Progress scan={s} />}
      {s.status === "FAILED" && <ErrorBox error={new Error(s.error ?? "The scan failed")} title="Scan failed" />}
      {s.status === "CANCELLED" && <Notice>This scan was cancelled. No results were recorded.</Notice>}

      {done && (
        <>
          <div className="grid gap-4 lg:grid-cols-4">
            <div className="card flex items-center gap-4 p-4 lg:col-span-1">
              <RiskGauge value={s.risk_index} size={104} />
              <div>
                <div className="text-xs uppercase tracking-wide text-muted">Risk index</div>
                <div className="mt-1">
                  <StatusPill value={s.gate_status} />
                </div>
              </div>
            </div>
            <Stat label="Findings" value={stats.findings_total ?? 0} hint={`${stats.findings_by_severity?.CRITICAL ?? 0} critical · ${stats.findings_by_severity?.HIGH ?? 0} high`} />
            <Stat label="Files analysed" value={stats.files_analyzed ?? 0} hint={`of ${stats.files_total ?? 0} · ${stats.lines_analyzed ?? 0} lines`} />
            <Stat label="Dependencies" value={stats.dependencies_total ?? 0} hint={Object.entries(stats.dependencies_by_status ?? {}).map(([k, v]) => `${v} ${label(k).toLowerCase()}`).join(" · ") || "none found"} />
          </div>

          {s.gate_status === "FAIL" && s.gate_reasons.length > 0 && (
            <div className="mt-4 rounded-lg border border-fail/40 bg-fail/10 px-4 py-3 text-sm">
              <div className="font-medium text-fail">Security gate failed</div>
              <ul className="mt-1 list-disc pl-5 text-ink-2">
                {s.gate_reasons.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            </div>
          )}

          {stats.retest && (
            <Card title="Retest against the previous scan" className="mt-4">
              <div className="grid grid-cols-3 gap-3 text-center sm:grid-cols-6">
                {(
                  [
                    ["resolved", "Resolved", "var(--pass)"],
                    ["still_open", "Still open", "var(--med)"],
                    ["new", "New", "var(--crit)"],
                    ["regressions", "Regressions", "var(--crit)"],
                    ["not_tested", "Not tested", "var(--muted)"],
                    ["not_reproduced", "Not reproduced", "var(--muted)"],
                  ] as const
                ).map(([key, text, color]) => (
                  <div key={key}>
                    <div className="text-2xl font-semibold tabular-nums" style={{ color }}>
                      {stats.retest![key]}
                    </div>
                    <div className="text-xs text-muted">{text}</div>
                  </div>
                ))}
              </div>
              <p className="mt-3 text-xs text-muted">
                Resolved means the same file was analysed again by the same scanner and the issue is gone. A missing file is “not reproduced”;
                a file or scanner outside this scan is “not tested”. Neither counts as a fix.{" "}
                <Link to={`/projects/${projectId}/retests`} className="text-accent">
                  Retest details
                </Link>
              </p>
            </Card>
          )}

          <div className="mt-6">
            <Tabs
              tabs={[
                { id: "findings", label: "Findings", count: findings.data?.total },
                { id: "files", label: "Files", count: stats.files_total },
                { id: "dependencies", label: "Dependencies", count: stats.dependencies_total },
                { id: "scanners", label: "Scanners", count: stats.scanners?.length },
              ]}
              value={tab}
              onChange={setTab}
            />
            {tab === "findings" && (
              <div className="card overflow-hidden">
                {findings.isLoading ? (
                  <Loading />
                ) : (
                  <table className="table">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Severity</th>
                        <th>Finding</th>
                        <th>Location</th>
                        <th>Confidence</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findings.data?.items.map((f) => (
                        <tr key={f.id} className="row-link" onClick={() => navigate(`/projects/${projectId}/findings/${f.id}`)}>
                          <td className="whitespace-nowrap font-mono text-xs">{f.public_id}</td>
                          <td>
                            <SeverityBadge severity={f.severity} />
                          </td>
                          <td>
                            <div className="font-medium">{f.title}</div>
                            <div className="mt-0.5 flex gap-1.5">
                              <VerificationPill value={f.verification} />
                              <Pill>{label(f.source_kind)}</Pill>
                            </div>
                          </td>
                          <td className="font-mono text-xs break-all text-ink-2">{f.file_path ? `${f.file_path}:${f.line ?? ""}` : "—"}</td>
                          <td>{label(f.confidence)}</td>
                          <td>
                            <StatusPill value={f.status} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
            {tab === "files" && (
              <div className="card overflow-hidden">
                {files.isLoading ? (
                  <Loading />
                ) : (
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Path</th>
                        <th>Language</th>
                        <th>Size</th>
                        <th>Lines</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {files.data?.map((f) => (
                        <tr
                          key={f.path}
                          className={f.status === "ANALYZED" ? "row-link" : undefined}
                          onClick={() =>
                            f.status === "ANALYZED" && navigate(`/projects/${projectId}/scans/${scanId}/code?path=${encodeURIComponent(f.path)}`)
                          }
                        >
                          <td className="font-mono text-xs break-all">{f.path}</td>
                          <td>{f.language ?? "—"}</td>
                          <td className="tabular-nums">{formatBytes(f.size_bytes)}</td>
                          <td className="tabular-nums">{f.line_count}</td>
                          <td>
                            <Pill tone={f.status === "ANALYZED" ? "good" : f.status === "PARSE_ERROR" ? "warn" : "neutral"} title={f.detail ?? undefined}>
                              {label(f.status)}
                            </Pill>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
            {tab === "dependencies" && (
              <div className="card overflow-hidden">
                {deps.isLoading ? (
                  <Loading />
                ) : deps.data?.length ? (
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Package</th>
                        <th>Version</th>
                        <th>Ecosystem</th>
                        <th>Manifest</th>
                        <th>Known vulnerabilities</th>
                      </tr>
                    </thead>
                    <tbody>
                      {deps.data.map((d) => (
                        <tr key={d.id}>
                          <td className="font-medium">
                            {d.name}
                            {!d.direct && <span className="ml-1 text-xs text-muted">(transitive)</span>}
                            {d.dev && <span className="ml-1 text-xs text-muted">(dev)</span>}
                          </td>
                          <td className="font-mono text-xs">{d.version ?? d.version_spec ?? "—"}</td>
                          <td>{d.ecosystem}</td>
                          <td className="font-mono text-xs break-all text-ink-2">{d.manifest_path}</td>
                          <td>
                            <StatusPill value={d.vuln_status} />
                            {d.advisory_ids.length > 0 && <div className="mt-1 font-mono text-xs text-ink-2">{d.advisory_ids.join(", ")}</div>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p className="p-5 text-sm text-muted">No dependency manifests were found.</p>
                )}
                {deps.data?.some((d) => d.vuln_status === "NOT_VERIFIED") && (
                  <div className="border-t border-line p-4">
                    <Notice tone="warn">
                      NOT VERIFIED means SecureLens could not check the package: the version is not pinned exactly, or no advisory source was
                      reachable. It does not mean the package is safe.
                    </Notice>
                  </div>
                )}
              </div>
            )}
            {tab === "scanners" && (
              <div className="grid gap-4 lg:grid-cols-2">
                <Card title="Scanners" bodyClassName="p-0">
                  <table className="table">
                    <tbody>
                      {stats.scanners?.map((r) => (
                        <tr key={r.scanner}>
                          <td className="font-medium">{r.scanner}</td>
                          <td>
                            <Pill tone={r.status === "ran" ? "good" : r.status === "failed" ? "bad" : "neutral"}>{r.status}</Pill>
                          </td>
                          <td className="text-xs text-ink-2">
                            {r.detail ?? (r.languages.length ? r.languages.join(", ") : "")}
                            {r.status === "ran" && <div className="text-muted">{r.findings} raw results · {formatDuration(r.duration_ms)}</div>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Card>
                <Card title="Run details">
                  <KeyValue
                    items={[
                      ["Scan ID", <span className="font-mono text-xs">{s.id}</span>],
                      ["Scope", label(s.scope)],
                      ["Trigger", label(s.trigger)],
                      ["Queued", formatDate(s.queued_at)],
                      ["Started", formatDate(s.started_at)],
                      ["Finished", formatDate(s.finished_at)],
                      ["Baseline", s.baseline_scan_id ? <Link className="text-accent" to={`/projects/${projectId}/scans/${s.baseline_scan_id}`}>earlier scan</Link> : "automatic"],
                    ]}
                  />
                  {stats.errors && stats.errors.length > 0 && (
                    <div className="mt-4">
                      <div className="label">Analysis notes</div>
                      <ul className="list-disc space-y-1 pl-5 text-xs text-ink-2">
                        {stats.errors.map((e, i) => (
                          <li key={i}>{e}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </Card>
              </div>
            )}
          </div>
        </>
      )}
    </>
  );
}
