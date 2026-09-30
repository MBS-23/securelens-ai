import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Loading, PageHeader, Pagination, Pill } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { formatDate } from "../../lib/format";
import type { AuditEntry, Page } from "../../lib/types";

export default function AuditLog() {
  const { orgId } = useAuth();
  const [page, setPage] = useState(1);
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState("");
  const [actor, setActor] = useState("");
  const logs = useQuery({
    queryKey: ["audit", orgId, page, action, outcome, actor],
    queryFn: () => api.get<Page<AuditEntry>>(`/organizations/${orgId}/audit-logs`, { page, page_size: 50, action, outcome, actor }),
    enabled: !!orgId,
  });

  return (
    <>
      <PageHeader title="Audit log" subtitle="Append-only record of sign-ins, access changes, scans, triage decisions and settings changes." />
      <div className="card mb-4 flex flex-wrap gap-3 p-4">
        <input className="input w-56" placeholder="Action prefix, e.g. finding." value={action} onChange={(e) => { setAction(e.target.value); setPage(1); }} />
        <input className="input w-56" placeholder="Actor email" value={actor} onChange={(e) => { setActor(e.target.value); setPage(1); }} />
        <select className="input w-44" value={outcome} onChange={(e) => { setOutcome(e.target.value); setPage(1); }} aria-label="Outcome">
          <option value="">Any outcome</option>
          <option value="SUCCESS">Success</option>
          <option value="FAILURE">Failure</option>
          <option value="DENIED">Denied</option>
        </select>
      </div>
      {logs.isLoading && <Loading />}
      {logs.isError && <ErrorBox error={logs.error} />}
      {logs.data && (
        <div className="card overflow-hidden">
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Target</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {logs.data.items.map((e) => (
                <tr key={e.id}>
                  <td className="whitespace-nowrap text-ink-2">{formatDate(e.created_at)}</td>
                  <td>
                    <div className="text-sm">{e.actor_label ?? "system"}</div>
                    {e.ip && <div className="font-mono text-[11px] text-muted">{e.ip}</div>}
                  </td>
                  <td>
                    <div className="font-mono text-xs">{e.action}</div>
                    <Pill tone={e.outcome === "SUCCESS" ? "good" : "bad"}>{e.outcome.toLowerCase()}</Pill>
                  </td>
                  <td className="text-xs text-ink-2">
                    {e.target_type}
                    {e.target_id && <div className="font-mono text-[11px] text-muted">{e.target_id.slice(0, 8)}…</div>}
                  </td>
                  <td className="max-w-md">
                    {Object.keys(e.details).length > 0 && (
                      <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-[11px] text-ink-2">{JSON.stringify(e.details)}</pre>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination page={page} pageSize={50} total={logs.data.total} onChange={setPage} />
        </div>
      )}
    </>
  );
}
