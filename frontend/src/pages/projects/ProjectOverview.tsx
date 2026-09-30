import { useQuery } from "@tanstack/react-query";
import { FileWarning, ScanSearch, Upload } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router";
import { RiskGauge, RiskHistoryChart, SeverityDonut, TrendChart } from "../../components/charts";
import { Card, EmptyState, ErrorBox, KeyValue, Loading, PageHeader, SeverityBadge, StatusPill } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { label, relativeTime } from "../../lib/format";
import type { Project, ProjectMetrics } from "../../lib/types";

export default function ProjectOverview() {
  const { projectId = "" } = useParams();
  const { can } = useAuth();
  const navigate = useNavigate();
  const project = useQuery({ queryKey: ["project", projectId], queryFn: () => api.get<Project>(`/projects/${projectId}`) });
  const metrics = useQuery({
    queryKey: ["project-metrics", projectId],
    queryFn: () => api.get<ProjectMetrics>(`/projects/${projectId}/metrics`),
    refetchInterval: 20_000,
  });

  if (project.isLoading || metrics.isLoading) return <Loading />;
  if (project.isError) return <ErrorBox error={project.error} />;
  if (metrics.isError) return <ErrorBox error={metrics.error} />;
  const p = project.data!;
  const m = metrics.data!;
  const latestRisk = m.projects[0]?.risk_index ?? null;

  return (
    <>
      <PageHeader
        eyebrow="Project"
        title={p.name}
        subtitle={p.description || undefined}
        actions={
          can("scan:create") && (
            <Link to={`/projects/${projectId}/scans/new`} className="btn-primary">
              <Upload className="h-4 w-4" /> New scan
            </Link>
          )
        }
      />
      {m.recent_scans.length === 0 ? (
        <div className="card">
          <EmptyState
            icon={<ScanSearch className="h-10 w-10" />}
            title="No scans yet"
            action={
              can("scan:create") && (
                <Link to={`/projects/${projectId}/scans/new`} className="btn-primary">
                  Run the first scan
                </Link>
              )
            }
          >
            Upload a ZIP/TAR archive or a single file, or scan a git repository you added under Repositories.
          </EmptyState>
        </div>
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-3">
            <Card title="SecureLens Risk Index">
              <div className="flex items-center gap-5">
                <RiskGauge value={latestRisk} />
                <div className="space-y-2 text-sm">
                  <div>
                    Gate <StatusPill value={m.projects[0]?.gate_status} />
                  </div>
                  <KeyValue
                    items={[
                      ["Exposure", label(p.exposure)],
                      ["Criticality", p.business_criticality ? label(p.business_criticality) : "Not set"],
                      ["Last scan", relativeTime(m.projects[0]?.last_scan_at)],
                    ]}
                  />
                </div>
              </div>
            </Card>
            <Card title="Open findings" className="lg:col-span-2">
              <SeverityDonut counts={m.open_by_severity} />
            </Card>
          </div>
          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <Card title="New vs resolved — last 30 days">
              <TrendChart data={m.trend} />
            </Card>
            <Card title="Risk index by scan">
              <RiskHistoryChart data={m.risk_history} />
            </Card>
          </div>
          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <Card title="Files with the most serious open findings" bodyClassName="p-0">
              {m.hotspots.length === 0 ? (
                <EmptyState icon={<FileWarning className="h-8 w-8" />} title="No open findings in files" />
              ) : (
                <table className="table">
                  <tbody>
                    {m.hotspots.map((h) => (
                      <tr
                        key={h.path}
                        className="row-link"
                        onClick={() => navigate(`/projects/${projectId}/findings?path=${encodeURIComponent(h.path)}`)}
                      >
                        <td className="font-mono text-xs break-all">{h.path}</td>
                        <td>
                          <SeverityBadge severity={h.worst} />
                        </td>
                        <td className="text-right tabular-nums text-ink-2">{h.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
            <Card title="Languages in the latest scan" bodyClassName="p-0">
              <table className="table">
                <thead>
                  <tr>
                    <th>Language</th>
                    <th>Files</th>
                    <th>Lines</th>
                    <th>Analysis</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(m.languages).map(([name, v]) => (
                    <tr key={name}>
                      <td className="font-medium">{name}</td>
                      <td className="tabular-nums">{v.files}</td>
                      <td className="tabular-nums">{v.lines}</td>
                      <td className="text-xs text-ink-2">{v.sast ? "SAST + secrets" : "Secrets only"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          </div>
          <Card
            title="Recent scans"
            className="mt-4"
            bodyClassName="p-0"
            actions={
              <Link to={`/projects/${projectId}/scans`} className="text-sm text-accent">
                All scans
              </Link>
            }
          >
            <table className="table">
              <tbody>
                {m.recent_scans.slice(0, 5).map((s) => (
                  <tr key={s.id} className="row-link" onClick={() => navigate(`/projects/${projectId}/scans/${s.id}`)}>
                    <td>
                      <div className="font-medium">{s.repository_name ?? "—"}</div>
                      <div className="text-xs text-muted">{label(s.trigger)}</div>
                    </td>
                    <td>
                      <StatusPill value={s.status} />
                    </td>
                    <td className="tabular-nums">{s.findings ?? "—"} findings</td>
                    <td>
                      <StatusPill value={s.gate_status} />
                    </td>
                    <td className="text-right text-ink-2">{relativeTime(s.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </>
      )}
    </>
  );
}
