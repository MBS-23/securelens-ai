import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { Code2, ExternalLink, GraduationCap, ListChecks, ShieldCheck, ShieldX } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router";
import {
  Card,
  CodeBlock,
  ErrorBox,
  Field,
  KeyValue,
  Loading,
  Modal,
  Notice,
  PageHeader,
  Pill,
  SeverityBadge,
  StatusPill,
  VerificationPill,
} from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { formatDate, label, relativeTime, safeHref } from "../../lib/format";
import { usePrefs } from "../../lib/prefs";
import type { Evidence, Explanation, FindingDetail as Detail, FindingStatus, Verification } from "../../lib/types";

// ------------------------------------------------------------ explanation

function Steps({ explanation, compact }: { explanation: Explanation; compact?: boolean }) {
  return (
    <ol className="relative space-y-4 border-l border-line pl-6">
      {explanation.steps.map((step) => (
        <li key={step.number} className="relative">
          <span className="absolute -left-[33px] flex h-6 w-6 items-center justify-center rounded-full border border-accent bg-surface text-xs font-semibold text-accent">
            {step.number}
          </span>
          <div className="font-medium">{step.title}</div>
          {step.detail && <div className={clsx("text-sm text-ink-2", compact && "text-xs")}>{step.detail}</div>}
          {step.code && <CodeBlock code={step.code} className="mt-1.5" />}
        </li>
      ))}
    </ol>
  );
}

function SecureVsInsecure({ example }: { example: NonNullable<Explanation["example"]> }) {
  const [secure, setSecure] = useState(false);
  return (
    <div>
      <div className="mb-2 flex items-center gap-2">
        <div className="flex rounded-lg border border-line p-0.5 text-xs" role="group" aria-label="Code example">
          <button
            onClick={() => setSecure(false)}
            aria-pressed={!secure}
            className={clsx("flex items-center gap-1 rounded-md px-2.5 py-1", !secure ? "bg-crit text-white" : "text-ink-2")}
          >
            <ShieldX className="h-3.5 w-3.5" /> Insecure
          </button>
          <button
            onClick={() => setSecure(true)}
            aria-pressed={secure}
            className={clsx("flex items-center gap-1 rounded-md px-2.5 py-1", secure ? "bg-pass text-black" : "text-ink-2")}
          >
            <ShieldCheck className="h-3.5 w-3.5" /> Secure
          </button>
        </div>
        <span className="text-xs text-muted">{example.language} example from the SecureLens rule catalog</span>
      </div>
      <CodeBlock code={secure ? example.secure : example.insecure} className={secure ? "border-pass/40" : "border-crit/40"} />
    </div>
  );
}

function ExplanationCard({ detail, mode }: { detail: Detail; mode: "learning" | "professional" }) {
  const e = detail.explanation;
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <GraduationCap className="h-4 w-4 text-accent" /> Why did SecureLens detect this?
        </span>
      }
    >
      <Steps explanation={e} compact={mode === "professional"} />
      <p className="mt-4 text-xs text-muted">{e.basis}</p>
      {mode === "learning" && (
        <div className="mt-6 grid gap-5 md:grid-cols-2">
          <div>
            <div className="label">Root cause</div>
            <p className="text-sm text-ink-2">{e.root_cause}</p>
          </div>
          <div>
            <div className="label">What an attacker could do</div>
            <p className="text-sm text-ink-2">{e.impact}</p>
          </div>
          <div className="md:col-span-2">
            <div className="label">How to prevent it</div>
            <p className="text-sm text-ink-2">{e.prevention}</p>
          </div>
          {e.example && (
            <div className="md:col-span-2">
              <SecureVsInsecure example={e.example} />
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

// ------------------------------------------------------------ evidence

function DataFlow({ evidence }: { evidence: Evidence }) {
  const data = evidence.data as {
    sources?: { label: string; path: string; line: number; code: string }[];
    steps?: { path: string; line: number; note: string; code: string }[];
    sink?: string;
    origin?: string;
  };
  return (
    <div className="space-y-2">
      {data.sources?.map((s, i) => (
        <div key={`s${i}`} className="rounded-lg border border-crit/30 bg-crit/5 p-3">
          <div className="text-xs font-medium uppercase tracking-wide text-crit">Source</div>
          <div className="text-sm">
            {s.label} <span className="font-mono text-xs text-muted">{s.path}:{s.line}</span>
          </div>
          {s.code && <CodeBlock code={s.code} className="mt-1.5" />}
        </div>
      ))}
      {data.origin === "unknown" && (
        <Notice tone="warn">The origin of the value could not be traced, so exploitability is not proven.</Notice>
      )}
      {data.steps?.map((s, i) => (
        <div key={`t${i}`} className="rounded-lg border border-line p-3">
          <div className="text-sm">
            {s.note} <span className="font-mono text-xs text-muted">{s.path}:{s.line}</span>
          </div>
          {s.code && <CodeBlock code={s.code} className="mt-1.5" />}
        </div>
      ))}
      {data.sink && (
        <div className="rounded-lg border border-high/40 bg-high/5 p-3">
          <div className="text-xs font-medium uppercase tracking-wide text-high">Sink</div>
          <div className="text-sm">{data.sink}</div>
        </div>
      )}
    </div>
  );
}

function EvidenceCard({ detail }: { detail: Detail }) {
  const occurrence = detail.occurrences[0];
  if (!occurrence) return null;
  return (
    <Card title="Evidence">
      {occurrence.snippet && (
        <div className="mb-4">
          <div className="label">
            {occurrence.file_path}:{occurrence.start_line}
            {occurrence.function_name ? ` · in ${occurrence.function_name}` : ""}
          </div>
          <CodeBlock code={occurrence.snippet} />
        </div>
      )}
      <div className="space-y-4">
        {occurrence.evidence.map((e) => (
          <div key={e.id}>
            <div className="mb-1.5 flex flex-wrap items-center gap-2">
              <Pill tone="info">{label(e.kind)}</Pill>
              <span className="text-xs text-muted">from {e.source}</span>
            </div>
            <p className="mb-2 text-sm text-ink-2">{e.summary}</p>
            {e.kind === "dataflow" && <DataFlow evidence={e} />}
            {e.kind === "secret" && (
              <KeyValue
                items={[
                  ["Type", String(e.data.secret_type ?? "")],
                  ["Value (masked)", <span className="font-mono">{String(e.data.masked ?? "")}</span>],
                  ["Detector", String(e.data.detector ?? "")],
                ]}
              />
            )}
            {e.kind === "dependency" && (
              <KeyValue
                items={[
                  ["Package", `${e.data.name}@${e.data.version} (${e.data.ecosystem})`],
                  ["Advisory", String(e.data.advisory_id ?? "")],
                  ["Fixed in", ((e.data.fixed_versions as string[]) ?? []).join(", ") || "No fix published"],
                ]}
              />
            )}
          </div>
        ))}
      </div>
      <p className="mt-4 text-xs text-muted">Scanners: {occurrence.scanners.join(", ")}</p>
    </Card>
  );
}

// ------------------------------------------------------------ triage

const MANUAL_STATUSES: { value: FindingStatus; triage: boolean; help: string }[] = [
  { value: "OPEN", triage: false, help: "Needs attention" },
  { value: "IN_PROGRESS", triage: false, help: "Someone is fixing it" },
  { value: "FALSE_POSITIVE", triage: true, help: "Not a real issue (reason required)" },
  { value: "ACCEPTED_RISK", triage: true, help: "Real, but accepted (reason required)" },
  { value: "RESOLVED", triage: true, help: "Resolved by hand. Normally a rescan decides this." },
];

function TriageModal({ detail, open, onClose }: { detail: Detail; open: boolean; onClose: () => void }) {
  const { projectId = "" } = useParams();
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<"status" | "verification">("status");
  const [status, setStatus] = useState<FindingStatus>(detail.status === "REOPENED" ? "OPEN" : detail.status);
  const [verification, setVerification] = useState<Verification>(detail.verification === "AI_SUGGESTED" ? "CONFIRMED" : detail.verification);
  const [reason, setReason] = useState("");
  const save = useMutation({
    mutationFn: () =>
      kind === "status"
        ? api.patch(`/projects/${projectId}/findings/${detail.id}/status`, { status, reason: reason || null })
        : api.patch(`/projects/${projectId}/findings/${detail.id}/verification`, { verification, reason: reason || null }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["finding", detail.id] });
      await queryClient.invalidateQueries({ queryKey: ["findings", projectId] });
      setReason("");
      onClose();
    },
  });
  const triage = can("finding:triage");
  return (
    <Modal
      open={open}
      title={`Update ${detail.public_id}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" onClick={() => save.mutate()} disabled={save.isPending}>
            Save
          </button>
        </>
      }
    >
      <div className="space-y-4">
        {save.isError && <ErrorBox error={save.error} title="Not saved" />}
        {triage && (
          <div className="flex rounded-lg border border-line p-0.5 text-sm">
            {(["status", "verification"] as const).map((k) => (
              <button key={k} onClick={() => setKind(k)} className={clsx("flex-1 rounded-md px-3 py-1.5", kind === k ? "bg-accent-bg text-accent-ink" : "text-ink-2")}>
                {k === "status" ? "Lifecycle status" : "Verification"}
              </button>
            ))}
          </div>
        )}
        {kind === "status" ? (
          <div className="space-y-2">
            {MANUAL_STATUSES.filter((s) => !s.triage || triage).map((s) => (
              <label key={s.value} className={clsx("card flex cursor-pointer items-start gap-3 p-3", status === s.value && "border-accent/60")}>
                <input type="radio" name="status" checked={status === s.value} onChange={() => setStatus(s.value)} className="mt-1" />
                <span>
                  <span className="block text-sm font-medium">{label(s.value)}</span>
                  <span className="block text-xs text-muted">{s.help}</span>
                </span>
              </label>
            ))}
            {!triage && (
              <p className="text-xs text-muted">
                Findings are resolved by fixing the code and running a new scan. False positive and accepted risk decisions need the Security
                Analyst role.
              </p>
            )}
          </div>
        ) : (
          <Field label="Verification" hint="AI-suggested is set only by AI analysis and can never be chosen by hand.">
            <select className="input" value={verification} onChange={(e) => setVerification(e.target.value as Verification)}>
              <option value="DETECTED">Detected (scanner evidence)</option>
              <option value="CONFIRMED">Confirmed (reproduced or reviewed)</option>
              <option value="FALSE_POSITIVE">False positive</option>
            </select>
          </Field>
        )}
        <Field label="Reason" hint="Recorded in the audit log.">
          <textarea className="input" rows={3} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
        </Field>
      </div>
    </Modal>
  );
}

// ------------------------------------------------------------ page

export default function FindingDetail() {
  const { projectId = "", findingId = "" } = useParams();
  const { mode } = usePrefs();
  const { can } = useAuth();
  const [triageOpen, setTriageOpen] = useState(false);
  const finding = useQuery({
    queryKey: ["finding", findingId],
    queryFn: () => api.get<Detail>(`/projects/${projectId}/findings/${findingId}`),
  });

  if (finding.isLoading) return <Loading />;
  if (finding.isError) return <ErrorBox error={finding.error} />;
  const d = finding.data!;
  const occurrence = d.occurrences[0];
  const references = d.references.map((r) => ({ r, href: safeHref(r) })).filter((x) => x.href);

  return (
    <>
      <PageHeader
        eyebrow={
          <span>
            <span className="font-mono">{d.public_id}</span> · {label(d.source_kind)} · {d.category}
          </span>
        }
        title={d.title}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={d.severity} />
            <Pill>{label(d.confidence)} confidence</Pill>
            <Pill>{label(d.exploitability)}</Pill>
            <VerificationPill value={d.verification} />
            <StatusPill value={d.status} />
          </span>
        }
        actions={
          <>
            {occurrence?.scan_id && d.file_path && (
              <Link
                to={`/projects/${projectId}/scans/${occurrence.scan_id}/code?path=${encodeURIComponent(d.file_path)}${d.line ? `&line=${d.line}` : ""}`}
                className="btn-secondary"
              >
                <Code2 className="h-4 w-4" /> View in code
              </Link>
            )}
            {can("finding:update_status") && (
              <button className="btn-primary" onClick={() => setTriageOpen(true)}>
                <ListChecks className="h-4 w-4" /> Update status
              </button>
            )}
          </>
        }
      />
      {d.status_reason && (
        <div className="mb-4">
          <Notice>
            <b>{label(d.status)}:</b> {d.status_reason}
          </Notice>
        </div>
      )}
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          {mode === "learning" ? (
            <>
              <ExplanationCard detail={d} mode={mode} />
              <EvidenceCard detail={d} />
            </>
          ) : (
            <>
              <EvidenceCard detail={d} />
              <ExplanationCard detail={d} mode={mode} />
            </>
          )}
          <Card title="How to fix it">
            <p className="text-sm text-ink-2">{d.recommendation}</p>
            {d.remediation_guidance && <CodeBlock code={d.remediation_guidance} className="mt-3" />}
            <p className="mt-3 text-xs text-muted">
              After changing the code, run a new scan (or upload the fixed code as a retest). SecureLens marks the finding resolved only when the
              same file is analysed again and the issue is gone.
            </p>
          </Card>
        </div>
        <div className="space-y-4">
          <Card title="Details">
            <KeyValue
              items={[
                ["Location", d.file_path ? <span className="font-mono text-xs">{d.file_path}:{d.line ?? ""}</span> : "—"],
                ["Rule", <span className="font-mono text-xs">{d.rule_id}</span>],
                ["Class", label(d.vuln_class)],
                ["CWE", d.cwe.join(", ") || "—"],
                ["OWASP", d.owasp.join(", ") || "—"],
                ["Risk score", d.risk_score.toFixed(2)],
                ["First seen", formatDate(d.first_seen_at)],
                ["Last seen", relativeTime(d.last_seen_at)],
                ["Resolved", d.resolved_at ? formatDate(d.resolved_at) : "—"],
              ]}
            />
          </Card>
          <Card title="Description">
            <p className="text-sm text-ink-2">{d.description}</p>
            <div className="label mt-4">Impact</div>
            <p className="text-sm text-ink-2">{d.impact}</p>
          </Card>
          {references.length > 0 && (
            <Card title="References">
              <ul className="space-y-1.5 text-sm">
                {references.map(({ r, href }) => (
                  <li key={r}>
                    <a href={href!} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 break-all text-accent">
                      {r} <ExternalLink className="h-3 w-3 shrink-0" />
                    </a>
                  </li>
                ))}
              </ul>
            </Card>
          )}
          <Card title="Retest history" bodyClassName="p-0">
            {d.retests.length === 0 ? (
              <p className="p-5 text-sm text-muted">Not compared by a retest yet.</p>
            ) : (
              <ul className="divide-y divide-line">
                {d.retests.map((r) => (
                  <li key={r.retest_id} className="px-5 py-3 text-sm">
                    <div className="flex items-center justify-between gap-2">
                      <StatusPill value={r.result} />
                      <span className="text-xs text-muted">{relativeTime(r.created_at)}</span>
                    </div>
                    {r.notes && <p className="mt-1 text-xs text-ink-2">{r.notes}</p>}
                    <div className="mt-1 text-[11px] text-muted">matched by {label(r.match_method)}</div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card title="Seen in scans" bodyClassName="p-0">
            <ul className="divide-y divide-line">
              {d.occurrences.map((o) => (
                <li key={o.id} className="px-5 py-2.5 text-sm">
                  {o.scan_id ? (
                    <Link to={`/projects/${projectId}/scans/${o.scan_id}`} className="text-accent">
                      {relativeTime(o.created_at)}
                    </Link>
                  ) : (
                    relativeTime(o.created_at)
                  )}
                  <span className="ml-2 font-mono text-xs text-muted">
                    {o.file_path}:{o.start_line}
                  </span>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      </div>
      <TriageModal detail={d} open={triageOpen} onClose={() => setTriageOpen(false)} />
    </>
  );
}
