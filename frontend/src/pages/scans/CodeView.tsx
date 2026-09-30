import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { ArrowLeft, EyeOff, FileCode2, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { CodeViewer } from "../../components/CodeViewer";
import { EmptyState, ErrorBox, Loading, Notice, PageHeader, SeverityBadge } from "../../components/ui";
import { api } from "../../lib/api";
import { SEVERITY_COLOR, SEVERITY_RANK } from "../../lib/format";
import type { FileContent, Finding, Page, ScanFile, Severity } from "../../lib/types";

export default function CodeView() {
  const { projectId = "", scanId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const [filter, setFilter] = useState("");
  const [onlyWithFindings, setOnlyWithFindings] = useState(true);
  const path = params.get("path");
  const line = Number(params.get("line")) || null;

  const files = useQuery({
    queryKey: ["scan-files", scanId],
    queryFn: () => api.get<ScanFile[]>(`/projects/${projectId}/scans/${scanId}/files`),
  });
  const findings = useQuery({
    queryKey: ["scan-findings", scanId],
    queryFn: () => api.get<Page<Finding>>(`/projects/${projectId}/scans/${scanId}/findings`, { page_size: 500 }),
  });
  const content = useQuery({
    queryKey: ["scan-file", scanId, path],
    queryFn: () => api.get<FileContent>(`/projects/${projectId}/scans/${scanId}/file`, { path }),
    enabled: !!path,
  });

  const perFile = useMemo(() => {
    const map = new Map<string, { count: number; worst: Severity }>();
    for (const f of findings.data?.items ?? []) {
      if (!f.file_path) continue;
      const entry = map.get(f.file_path) ?? { count: 0, worst: "INFO" as Severity };
      entry.count += 1;
      if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[entry.worst]) entry.worst = f.severity;
      map.set(f.file_path, entry);
    }
    return map;
  }, [findings.data]);

  const visible = (files.data ?? [])
    .filter((f) => f.status === "ANALYZED")
    .filter((f) => !onlyWithFindings || perFile.has(f.path))
    .filter((f) => !filter || f.path.toLowerCase().includes(filter.toLowerCase()))
    .sort((a, b) => (perFile.get(b.path)?.count ?? 0) - (perFile.get(a.path)?.count ?? 0) || a.path.localeCompare(b.path));

  const open = (next: string, nextLine?: number | null) => {
    const search = new URLSearchParams({ path: next });
    if (nextLine) search.set("line", String(nextLine));
    setParams(search);
  };

  return (
    <>
      <PageHeader
        eyebrow="Code viewer"
        title={path ?? "Choose a file"}
        subtitle="Secrets are masked before the file leaves the server. Click a coloured dot to open the finding."
        actions={
          <Link to={`/projects/${projectId}/scans/${scanId}`} className="btn-secondary">
            <ArrowLeft className="h-4 w-4" /> Back to scan
          </Link>
        }
      />
      <div className="grid gap-4 lg:grid-cols-[300px_1fr]">
        <aside className="card flex max-h-[76vh] flex-col overflow-hidden">
          <div className="space-y-2 border-b border-line p-3">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted" />
              <input className="input pl-8" placeholder="Filter files" value={filter} onChange={(e) => setFilter(e.target.value)} />
            </div>
            <label className="flex items-center gap-2 text-xs text-ink-2">
              <input type="checkbox" checked={onlyWithFindings} onChange={(e) => setOnlyWithFindings(e.target.checked)} />
              Only files with findings
            </label>
          </div>
          <ul className="flex-1 overflow-y-auto py-1 scrollbar-thin">
            {files.isLoading && <Loading />}
            {visible.map((f) => {
              const info = perFile.get(f.path);
              return (
                <li key={f.path}>
                  <button
                    onClick={() => open(f.path)}
                    className={clsx(
                      "flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-surface-2",
                      f.path === path && "bg-accent/15",
                    )}
                  >
                    <FileCode2 className="h-3.5 w-3.5 shrink-0 text-muted" />
                    <span className="min-w-0 flex-1 truncate font-mono" title={f.path}>
                      {f.path}
                    </span>
                    {info && (
                      <span className="rounded-full px-1.5 text-[10px] font-semibold text-black" style={{ background: SEVERITY_COLOR[info.worst] }}>
                        {info.count}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
            {!files.isLoading && visible.length === 0 && <li className="px-3 py-4 text-xs text-muted">No files match.</li>}
          </ul>
        </aside>
        <div className="min-w-0 space-y-4">
          {!path && (
            <div className="card">
              <EmptyState icon={<FileCode2 className="h-10 w-10" />} title="Pick a file on the left" />
            </div>
          )}
          {path && content.isLoading && <Loading />}
          {path && content.isError && <ErrorBox error={content.error} />}
          {content.data && (
            <>
              {content.data.redacted && (
                <Notice>
                  <span className="inline-flex items-center gap-1.5">
                    <EyeOff className="h-4 w-4" /> Secret values in this file are masked.
                  </span>
                </Notice>
              )}
              <CodeViewer
                path={content.data.path}
                language={content.data.language}
                content={content.data.content}
                markers={content.data.findings}
                focusLine={line ?? content.data.findings[0]?.line}
                onMarkerClick={(m) => navigate(`/projects/${projectId}/findings/${m.finding_id}`)}
              />
              {content.data.findings.length > 0 && (
                <div className="card divide-y divide-line">
                  {content.data.findings.map((m) => (
                    <div key={m.finding_id} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                      <SeverityBadge severity={m.severity} />
                      <button className="font-mono text-xs text-ink-2 hover:text-accent" onClick={() => open(content.data.path, m.line)}>
                        line {m.line}
                      </button>
                      <Link to={`/projects/${projectId}/findings/${m.finding_id}`} className="min-w-0 flex-1 truncate hover:text-accent">
                        <span className="font-mono text-xs text-muted">{m.public_id}</span> {m.title}
                      </Link>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </>
  );
}
