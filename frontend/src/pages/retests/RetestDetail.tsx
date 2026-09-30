import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router";
import { Card, ErrorBox, Loading, Notice, PageHeader, StatusPill } from "../../components/ui";
import { api } from "../../lib/api";
import { formatDate, label } from "../../lib/format";
import type { RetestDetail as Detail } from "../../lib/types";

export default function RetestDetail() {
  const { projectId = "", retestId = "" } = useParams();
  const navigate = useNavigate();
  const retest = useQuery({ queryKey: ["retest", retestId], queryFn: () => api.get<Detail>(`/projects/${projectId}/retests/${retestId}`) });

  if (retest.isLoading) return <Loading />;
  if (retest.isError) return <ErrorBox error={retest.error} />;
  const r = retest.data!;
  const s = r.summary;

  return (
    <>
      <PageHeader
        eyebrow="Retest"
        title={`Compared ${formatDate(r.created_at)}`}
        subtitle={
          <span>
            {r.baseline_scan_id && (
              <Link className="text-accent" to={`/projects/${projectId}/scans/${r.baseline_scan_id}`}>
                baseline scan
              </Link>
            )}{" "}
            →{" "}
            {r.retest_scan_id && (
              <Link className="text-accent" to={`/projects/${projectId}/scans/${r.retest_scan_id}`}>
                new scan
              </Link>
            )}
          </span>
        }
      />
      <div className="mb-4 grid grid-cols-3 gap-3 md:grid-cols-7">
        {(
          [
            ["Previous", s.previous_findings, "var(--ink)"],
            ["Resolved", s.resolved, "var(--pass)"],
            ["Still open", s.still_open, "var(--med)"],
            ["New", s.new, "var(--crit)"],
            ["Regressions", s.regressions, "var(--crit)"],
            ["Not tested", s.not_tested, "var(--muted)"],
            ["Not reproduced", s.not_reproduced, "var(--muted)"],
          ] as const
        ).map(([text, value, color]) => (
          <div key={text} className="card p-3 text-center">
            <div className="text-2xl font-semibold tabular-nums" style={{ color }}>
              {value}
            </div>
            <div className="text-xs text-muted">{text}</div>
          </div>
        ))}
      </div>
      <div className="mb-4">
        <Notice>
          A finding is <b>resolved</b> only when its file was analysed again by the same scanner and the issue is gone. If the file disappeared the
          result is <b>not reproduced</b>, and a file or scanner outside the new scan is <b>not tested</b> — neither counts as a fix.
        </Notice>
      </div>
      <Card title="Results" bodyClassName="p-0">
        <table className="table">
          <thead>
            <tr>
              <th>Result</th>
              <th>Finding</th>
              <th>Before</th>
              <th>After</th>
              <th>Why</th>
            </tr>
          </thead>
          <tbody>
            {r.results.map((x) => (
              <tr key={x.finding_id} className="row-link" onClick={() => navigate(`/projects/${projectId}/findings/${x.finding_id}`)}>
                <td>
                  <StatusPill value={x.result} />
                  <div className="mt-1 text-[11px] text-muted">{label(x.match_method)}</div>
                </td>
                <td>
                  <div className="font-medium">
                    <span className="font-mono text-xs text-muted">{x.public_id}</span> {x.title}
                  </div>
                  <div className="text-xs text-muted">{label(x.vuln_class)}</div>
                </td>
                <td className="font-mono text-xs text-ink-2">{x.before ? `${x.before.path}:${x.before.line}` : "—"}</td>
                <td className="font-mono text-xs text-ink-2">{x.after ? `${x.after.path}:${x.after.line}` : "—"}</td>
                <td className="max-w-xs text-xs text-ink-2">{x.notes}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </>
  );
}
