import { useQuery } from "@tanstack/react-query";
import { RefreshCcw } from "lucide-react";
import { useNavigate, useParams } from "react-router";
import { EmptyState, ErrorBox, Loading, PageHeader, StatusPill } from "../../components/ui";
import { api } from "../../lib/api";
import { formatDate } from "../../lib/format";
import type { Retest } from "../../lib/types";

export default function Retests() {
  const { projectId = "" } = useParams();
  const navigate = useNavigate();
  const retests = useQuery({ queryKey: ["retests", projectId], queryFn: () => api.get<Retest[]>(`/projects/${projectId}/retests`) });

  return (
    <>
      <PageHeader
        title="Retests"
        subtitle="Each scan of the same source is compared with the previous one: resolved, still open, new, regressions and what could not be tested."
      />
      {retests.isLoading && <Loading />}
      {retests.isError && <ErrorBox error={retests.error} />}
      {retests.data && (
        <div className="card overflow-hidden">
          {retests.data.length === 0 ? (
            <EmptyState icon={<RefreshCcw className="h-10 w-10" />} title="No retests yet">
              Scan the same repository again (or upload fixed code with “Compare with an earlier scan”) to see what changed.
            </EmptyState>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Resolved</th>
                  <th>Still open</th>
                  <th>New</th>
                  <th>Regressions</th>
                  <th>Not tested</th>
                  <th>Regression check</th>
                </tr>
              </thead>
              <tbody>
                {retests.data.map((r) => (
                  <tr key={r.id} className="row-link" onClick={() => navigate(`/projects/${projectId}/retests/${r.id}`)}>
                    <td>{formatDate(r.created_at)}</td>
                    <td className="tabular-nums text-pass">{r.summary.resolved}</td>
                    <td className="tabular-nums">{r.summary.still_open}</td>
                    <td className="tabular-nums text-crit">{r.summary.new}</td>
                    <td className="tabular-nums text-crit">{r.summary.regressions}</td>
                    <td className="tabular-nums text-muted">{r.summary.not_tested}</td>
                    <td>
                      <StatusPill value={r.summary.regression_check} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </>
  );
}
