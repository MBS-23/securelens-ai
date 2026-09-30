import { useQuery } from "@tanstack/react-query";
import { Bot, Database, Gauge, Wrench } from "lucide-react";
import { Card, ErrorBox, KeyValue, Loading, Notice, PageHeader, Pill } from "../../components/ui";
import { api } from "../../lib/api";
import type { SystemStatus as Status } from "../../lib/types";

export default function SystemStatus() {
  const status = useQuery({ queryKey: ["system-status"], queryFn: () => api.get<Status>("/system/status") });
  if (status.isLoading) return <Loading />;
  if (status.isError) return <ErrorBox error={status.error} />;
  const s = status.data!;
  return (
    <>
      <PageHeader title="System status" subtitle={`SecureLens AI ${s.version} · ${s.environment}`} />
      {s.insecure_default_key && (
        <div className="mb-4">
          <Notice tone="warn">The server uses the insecure development secret key. Set SECURELENS_SECRET_KEY before real use.</Notice>
        </div>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={<span className="flex items-center gap-2"><Bot className="h-4 w-4" /> AI provider</span>}>
          <KeyValue
            items={[
              ["Provider", s.ai.provider],
              ["Status", s.ai.available ? <Pill tone="good">available</Pill> : <Pill tone="warn">not available</Pill>],
              ["Model", s.ai.model ?? "—"],
              ["Endpoint", s.ai.endpoint_host ?? "—"],
            ]}
          />
          <p className="mt-3 text-sm text-ink-2">{s.ai.detail}</p>
          <p className="mt-2 text-xs text-muted">
            Scanning, explanations, retests and reports do not need AI. AI output is always labelled and never marks anything as confirmed or fixed.
          </p>
        </Card>
        <Card title={<span className="flex items-center gap-2"><Database className="h-4 w-4" /> Dependency intelligence</span>}>
          <KeyValue
            items={[
              ["OSV.dev lookup", s.dependency_intelligence.osv_enabled ? <Pill tone="good">enabled</Pill> : <Pill>disabled</Pill>],
              ["Endpoint", s.dependency_intelligence.osv_api_url ?? "—"],
              ["Offline database", s.dependency_intelligence.offline_database ?? "—"],
            ]}
          />
          <p className="mt-3 text-xs text-muted">
            When no source is available, dependencies are reported as NOT VERIFIED. SecureLens never invents vulnerability identifiers.
          </p>
        </Card>
        <Card title={<span className="flex items-center gap-2"><Wrench className="h-4 w-4" /> External analyzers</span>} bodyClassName="p-0">
          <table className="table">
            <tbody>
              {s.external_scanners.map((t) => (
                <tr key={t.name}>
                  <td className="font-medium">{t.name}</td>
                  <td>{t.installed ? <Pill tone="good">installed</Pill> : <Pill>not installed</Pill>}</td>
                  <td>{t.enabled ? <Pill tone="info">enabled</Pill> : <Pill>disabled</Pill>}</td>
                  <td className="text-xs text-muted">{t.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
        <Card title={<span className="flex items-center gap-2"><Gauge className="h-4 w-4" /> Limits</span>}>
          <KeyValue
            items={[
              ["Upload size", `${s.limits.max_upload_mb} MB`],
              ["Extracted size", `${s.limits.max_extracted_mb} MB`],
              ["Files per scan", s.limits.max_files.toLocaleString()],
              ["Largest analysed file", `${s.limits.max_file_kb} KB`],
              ["Scan time limit", `${s.limits.scan_timeout_seconds} s`],
              ["Git hosts", s.git_allowed_hosts.join(", ")],
            ]}
          />
        </Card>
      </div>
    </>
  );
}
