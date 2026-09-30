import { useQuery } from "@tanstack/react-query";
import { FolderPlus, ShieldAlert } from "lucide-react";
import { Link, useNavigate } from "react-router";
import { HorizontalBars, RiskHistoryChart, SeverityDonut, TrendChart } from "../components/charts";
import { Card, EmptyState, ErrorBox, Loading, PageHeader, SeverityBadge, Stat, StatusPill, VerificationPill } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { label, relativeTime, riskColor, SEVERITIES, SEVERITY_COLOR } from "../lib/format";
import type { DashboardSummary, Severity } from "../lib/types";

export function SeverityBar({ counts }: { counts: Record<Severity, number> }) {
  const total = SEVERITIES.reduce((sum, s) => sum + (counts[s] ?? 0), 0);
  if (!total) return <span className="text-xs text-muted">No open findings</span>;
  return (
    <div className="flex h-2 w-40 overflow-hidden rounded-full bg-surface-3" title={SEVERITIES.map((s) => `${s} ${counts[s] ?? 0}`).join(" · ")}>
      {SEVERITIES.map((s) =>
        counts[s] ? <div key={s} style={{ width: `${(100 * counts[s]) / total}%`, background: SEVERITY_COLOR[s] }} /> : null,
      )}
    </div>
  );
}

export default function Dashboard() {
  const { orgId, membership, can } = useAuth();
  const navigate = useNavigate();
  const summary = useQuery({
    queryKey: ["dashboard", orgId],
    queryFn: () => api.get<DashboardSummary>("/dashboard/summary", { organization_id: orgId }),
    enabled: !!orgId,
    refetchInterval: 30_000,
  });

  if (summary.isLoading) return <Loading />;
  if (summary.isError) return <ErrorBox error={summary.error} />;
  const data = summary.data!;
  const openTotal = SEVERITIES.reduce((sum, s) => sum + (data.open_by_severity[s] ?? 0), 0);

  if (data.projects.length === 0) {
    return (
      <>
        <PageHeader title="Security dashboard" subtitle={membership?.organization_name} />
        <div className="card">
          <EmptyState
            icon={<FolderPlus className="h-10 w-10" />}
            title="No projects yet"
            action={
              can("project:create") ? (
                <Link to="/projects" className="btn-primary">
                  Create a project
                </Link>
              ) : undefined
            }
          >
            Create a project, then upload an archive or connect a git repository to run the first scan.
            {!can("project:create") && " Ask a security analyst or administrator to add you to a project."}
          </EmptyState>
        </div>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Security dashboard"
        subtitle={`${membership?.organization_name} · ${data.projects.length} project${data.projects.length === 1 ? "" : "s"} · updated ${relativeTime(data.generated_at)}`}
      />
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
        <Stat label="Open findings" value={openTotal} hint="Open, in progress or reopened" />
        <Stat label="Critical" value={data.open_by_severity.CRITICAL} color="var(--crit)" />
        <Stat label="High" value={data.open_by_severity.HIGH} color="var(--high)" />
        <Stat
          label="Mean time to resolve"
          value={data.mttr_days === null ? "—" : `${data.mttr_days}d`}
          hint={data.mttr_days === null ? "No findings resolved in the last 90 days" : "Findings resolved in the last 90 days"}
        />
        <Stat label="AI-suggested (unconfirmed)" value={data.open_by_verification.AI_SUGGESTED ?? 0} hint="Never counted as confirmed" />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-5">
        <Card title="Open findings by severity" className="xl:col-span-2">
          <SeverityDonut counts={data.open_by_severity} />
        </Card>
        <Card title="New vs resolved — last 30 days" className="xl:col-span-3">
          <TrendChart data={data.trend} />
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card title="SecureLens Risk Index by scan">
          {data.risk_history.length ? (
            <RiskHistoryChart data={data.risk_history} />
          ) : (
            <p className="text-sm text-muted">No completed scans yet.</p>
          )}
          <p className="mt-2 text-xs text-muted">
            A SecureLens-specific prioritisation aid, not CVSS. <Link to="/methodology" className="text-accent">How it is calculated</Link>
          </p>
        </Card>
        <Card title="Most common vulnerability classes">
          {data.top_classes.length ? (
            <HorizontalBars data={data.top_classes.map((c) => ({ name: label(c.vuln_class), value: c.count }))} />
          ) : (
            <p className="text-sm text-muted">No open findings.</p>
          )}
        </Card>
        <Card title="Open findings by source">
          {Object.keys(data.open_by_source).length ? (
            <HorizontalBars
              color="var(--accent-2)"
              data={Object.entries(data.open_by_source).map(([k, v]) => ({ name: label(k), value: v }))}
            />
          ) : (
            <p className="text-sm text-muted">No open findings.</p>
          )}
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Card title="Projects by risk" bodyClassName="p-0">
          <table className="table">
            <thead>
              <tr>
                <th>Project</th>
                <th>Risk</th>
                <th>Open</th>
                <th>Gate</th>
              </tr>
            </thead>
            <tbody>
              {data.projects.map((p) => (
                <tr key={p.id} className="row-link" onClick={() => navigate(`/projects/${p.id}`)}>
                  <td>
                    <div className="font-medium">{p.name}</div>
                    <div className="text-xs text-muted">last scan {relativeTime(p.last_scan_at)}</div>
                  </td>
                  <td className="font-semibold tabular-nums" style={{ color: riskColor(p.risk_index) }}>
                    {p.risk_index ?? "—"}
                  </td>
                  <td>
                    <SeverityBar counts={p.open_by_severity} />
                  </td>
                  <td>
                    <StatusPill value={p.gate_status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
        <Card title="Highest-risk open findings" bodyClassName="p-0">
          {data.top_findings.length === 0 ? (
            <EmptyState icon={<ShieldAlert className="h-8 w-8" />} title="No open findings" />
          ) : (
            <ul className="divide-y divide-line">
              {data.top_findings.map((f) => (
                <li key={f.id}>
                  <Link to={`/projects/${f.project_id}/findings/${f.id}`} className="flex items-start gap-3 px-5 py-3 hover:bg-surface-2">
                    <SeverityBadge severity={f.severity} className="mt-0.5" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">
                        <span className="font-mono text-xs text-muted">{f.public_id}</span> {f.title}
                      </div>
                      <div className="truncate text-xs text-muted">
                        {f.project_name} · {f.file_path ? `${f.file_path}:${f.line ?? ""}` : "—"}
                      </div>
                    </div>
                    <VerificationPill value={f.verification} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="Recent scans" className="mt-4" bodyClassName="p-0">
        <table className="table">
          <thead>
            <tr>
              <th>Project / source</th>
              <th>Status</th>
              <th>Findings</th>
              <th>Risk</th>
              <th>Gate</th>
              <th>Started</th>
            </tr>
          </thead>
          <tbody>
            {data.recent_scans.map((s) => (
              <tr key={s.id} className="row-link" onClick={() => navigate(`/projects/${s.project_id}/scans/${s.id}`)}>
                <td>
                  <div className="font-medium">{s.project_name}</div>
                  <div className="text-xs text-muted">
                    {s.repository_name ?? "—"} · {label(s.trigger)}
                  </div>
                </td>
                <td>
                  <StatusPill value={s.status} />
                </td>
                <td className="tabular-nums">{s.findings ?? "—"}</td>
                <td className="tabular-nums" style={{ color: riskColor(s.risk_index) }}>
                  {s.risk_index ?? "—"}
                </td>
                <td>
                  <StatusPill value={s.gate_status} />
                </td>
                <td className="text-ink-2">{relativeTime(s.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </>
  );
}
