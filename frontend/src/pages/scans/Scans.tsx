import { useQuery } from "@tanstack/react-query";
import { ScanSearch, Upload } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { EmptyState, ErrorBox, Loading, PageHeader, Pagination, StatusPill } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { formatDuration, label, relativeTime, riskColor } from "../../lib/format";
import type { Page, Scan } from "../../lib/types";

export function scanDuration(scan: Scan): string {
  if (!scan.started_at || !scan.finished_at) return "—";
  return formatDuration(new Date(scan.finished_at).getTime() - new Date(scan.started_at).getTime());
}

export default function Scans() {
  const { projectId = "" } = useParams();
  const { can } = useAuth();
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const scans = useQuery({
    queryKey: ["scans", projectId, page, status],
    queryFn: () => api.get<Page<Scan>>(`/projects/${projectId}/scans`, { page, page_size: 25, status }),
    refetchInterval: (query) =>
      query.state.data?.items.some((s) => s.status === "QUEUED" || s.status === "RUNNING") ? 2000 : false,
  });

  return (
    <>
      <PageHeader
        title="Scans"
        subtitle="Every scan is kept, so retests can compare against it."
        actions={
          can("scan:create") && (
            <Link to={`/projects/${projectId}/scans/new`} className="btn-primary">
              <Upload className="h-4 w-4" /> New scan
            </Link>
          )
        }
      />
      <div className="mb-4 flex gap-2">
        <select className="input w-48" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} aria-label="Status">
          <option value="">All statuses</option>
          {["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"].map((s) => (
            <option key={s} value={s}>
              {label(s)}
            </option>
          ))}
        </select>
      </div>
      {scans.isLoading && <Loading />}
      {scans.isError && <ErrorBox error={scans.error} />}
      {scans.data && (
        <div className="card overflow-hidden">
          {scans.data.items.length === 0 ? (
            <EmptyState icon={<ScanSearch className="h-10 w-10" />} title="No scans" />
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th>Risk</th>
                  <th>Gate</th>
                  <th>Duration</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {scans.data.items.map((s) => (
                  <tr key={s.id} className="row-link" onClick={() => navigate(`/projects/${projectId}/scans/${s.id}`)}>
                    <td>
                      <div className="font-medium">{s.repository_name ?? "—"}</div>
                      <div className="text-xs text-muted">
                        {label(s.trigger)} · {label(s.scope)} scan{s.baseline_scan_id ? " · retest" : ""}
                      </div>
                    </td>
                    <td>
                      <StatusPill value={s.status} />
                      {(s.status === "RUNNING" || s.status === "QUEUED") && (
                        <div className="mt-1 text-xs text-muted">
                          {s.progress.stage} {s.progress.percent ?? 0}%
                        </div>
                      )}
                    </td>
                    <td className="tabular-nums">{s.stats.findings_total ?? "—"}</td>
                    <td className="font-semibold tabular-nums" style={{ color: riskColor(s.risk_index) }}>
                      {s.risk_index ?? "—"}
                    </td>
                    <td>
                      <StatusPill value={s.gate_status} />
                    </td>
                    <td className="tabular-nums text-ink-2">{scanDuration(s)}</td>
                    <td className="text-ink-2">{relativeTime(s.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <Pagination page={page} pageSize={25} total={scans.data.total} onChange={setPage} />
        </div>
      )}
    </>
  );
}
