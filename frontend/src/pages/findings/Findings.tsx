import { useQuery } from "@tanstack/react-query";
import { Bug, Search, X } from "lucide-react";
import { useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router";
import { EmptyState, ErrorBox, Loading, PageHeader, Pagination, Pill, SeverityBadge, StatusPill, VerificationPill } from "../../components/ui";
import { api } from "../../lib/api";
import { label, relativeTime, SEVERITIES } from "../../lib/format";
import type { Finding, Page } from "../../lib/types";

const STATUSES = ["OPEN", "IN_PROGRESS", "REOPENED", "RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"];
const SOURCES = ["SAST", "SECRET", "DEPENDENCY", "AI_CODE"];
const VERIFICATIONS = ["DETECTED", "AI_SUGGESTED", "CONFIRMED", "FALSE_POSITIVE"];

function Chips({ options, selected, onToggle }: { options: string[]; selected: string[]; onToggle: (value: string) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map((o) => (
        <button
          key={o}
          onClick={() => onToggle(o)}
          aria-pressed={selected.includes(o)}
          className={`rounded-md border px-2 py-1 text-xs transition-colors ${
            selected.includes(o) ? "border-accent bg-accent/15 text-ink" : "border-line text-ink-2 hover:border-accent/50"
          }`}
        >
          {label(o)}
        </button>
      ))}
    </div>
  );
}

export default function Findings() {
  const { projectId = "" } = useParams();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") ?? "");
  const list = (key: string) => params.getAll(key);
  const severity = list("severity");
  const status = list("status").length ? list("status") : params.get("all") ? [] : ["OPEN", "IN_PROGRESS", "REOPENED"];
  const source = list("source_kind");
  const verification = list("verification");
  const path = params.get("path") ?? "";
  const sort = params.get("sort") ?? "severity";
  const page = Number(params.get("page") ?? 1);

  const update = (mutate: (p: URLSearchParams) => void) => {
    const next = new URLSearchParams(params);
    mutate(next);
    next.delete("page");
    setParams(next);
  };
  const toggle = (key: string, current: string[]) => (value: string) =>
    update((p) => {
      const values = current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
      p.delete(key);
      values.forEach((v) => p.append(key, v));
      if (key === "status" && values.length === 0) p.set("all", "1");
      else if (key === "status") p.delete("all");
    });

  const findings = useQuery({
    queryKey: ["findings", projectId, params.toString()],
    queryFn: () =>
      api.get<Page<Finding>>(`/projects/${projectId}/findings`, {
        severity,
        status,
        source_kind: source,
        verification,
        path,
        q: params.get("q") ?? "",
        sort,
        page,
        page_size: 50,
      }),
  });

  return (
    <>
      <PageHeader title="Findings" subtitle="One finding per issue, tracked across scans. Severity, confidence and verification are independent." />
      <div className="card mb-4 space-y-3 p-4">
        <div className="flex flex-wrap items-center gap-3">
          <form
            className="relative min-w-60 flex-1"
            onSubmit={(e) => {
              e.preventDefault();
              update((p) => (q ? p.set("q", q) : p.delete("q")));
            }}
          >
            <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted" />
            <input className="input pl-8" placeholder="Search title, ID, rule or path — press Enter" value={q} onChange={(e) => setQ(e.target.value)} />
          </form>
          <select className="input w-44" value={sort} onChange={(e) => update((p) => p.set("sort", e.target.value))} aria-label="Sort">
            <option value="severity">Sort: severity</option>
            <option value="risk">Sort: risk score</option>
            <option value="newest">Sort: newest</option>
            <option value="last_seen">Sort: last seen</option>
            <option value="id">Sort: ID</option>
          </select>
          {path && (
            <Pill tone="info">
              {path}
              <button onClick={() => update((p) => p.delete("path"))} aria-label="Clear path filter">
                <X className="h-3 w-3" />
              </button>
            </Pill>
          )}
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <div>
            <div className="label">Severity</div>
            <Chips options={SEVERITIES} selected={severity} onToggle={toggle("severity", severity)} />
          </div>
          <div>
            <div className="label">Status</div>
            <Chips options={STATUSES} selected={status} onToggle={toggle("status", status)} />
          </div>
          <div>
            <div className="label">Source</div>
            <Chips options={SOURCES} selected={source} onToggle={toggle("source_kind", source)} />
          </div>
          <div>
            <div className="label">Verification</div>
            <Chips options={VERIFICATIONS} selected={verification} onToggle={toggle("verification", verification)} />
          </div>
        </div>
      </div>
      {findings.isLoading && <Loading />}
      {findings.isError && <ErrorBox error={findings.error} />}
      {findings.data && (
        <div className="card overflow-hidden">
          {findings.data.items.length === 0 ? (
            <EmptyState icon={<Bug className="h-10 w-10" />} title="No findings match these filters" />
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Location</th>
                  <th>Status</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {findings.data.items.map((f) => (
                  <tr key={f.id} className="row-link" onClick={() => navigate(`/projects/${projectId}/findings/${f.id}`)}>
                    <td className="whitespace-nowrap font-mono text-xs">{f.public_id}</td>
                    <td>
                      <SeverityBadge severity={f.severity} />
                      <div className="mt-1 text-[11px] text-muted">{label(f.confidence)} confidence</div>
                    </td>
                    <td>
                      <div className="font-medium">{f.title}</div>
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        <VerificationPill value={f.verification} />
                        <Pill>{label(f.source_kind)}</Pill>
                        {f.cwe.slice(0, 2).map((c) => (
                          <Pill key={c}>{c}</Pill>
                        ))}
                      </div>
                    </td>
                    <td className="max-w-64 font-mono text-xs break-all text-ink-2">{f.file_path ? `${f.file_path}:${f.line ?? ""}` : "—"}</td>
                    <td>
                      <StatusPill value={f.status} />
                    </td>
                    <td className="whitespace-nowrap text-ink-2">{relativeTime(f.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <Pagination page={page} pageSize={50} total={findings.data.total} onChange={(next) => setParams((p) => { p.set("page", String(next)); return p; })} />
        </div>
      )}
    </>
  );
}
