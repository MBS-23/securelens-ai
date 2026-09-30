import clsx from "clsx";
import { AlertTriangle, ChevronLeft, ChevronRight, Info, Loader2, X } from "lucide-react";
import { cloneElement, isValidElement, useEffect, useId, useRef, type ReactNode } from "react";
import { ApiError } from "../lib/api";
import { label, SEVERITY_COLOR } from "../lib/format";
import type { Severity } from "../lib/types";

// ------------------------------------------------------------------ badges

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={clsx("inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-semibold tracking-wide", className)}
      style={{ color: SEVERITY_COLOR[severity], borderColor: SEVERITY_COLOR[severity] }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEVERITY_COLOR[severity] }} />
      {severity}
    </span>
  );
}

const TONES: Record<string, string> = {
  good: "text-pass border-pass/40 bg-pass/10",
  bad: "text-fail border-fail/40 bg-fail/10",
  warn: "text-med border-med/40 bg-med/10",
  info: "text-accent border-accent/40 bg-accent/10",
  neutral: "text-ink-2 border-line bg-surface-2",
};

export function Pill({ tone = "neutral", children, title }: { tone?: keyof typeof TONES; children: ReactNode; title?: string }) {
  return (
    <span title={title} className={clsx("inline-flex items-center gap-1 whitespace-nowrap rounded-md border px-2 py-0.5 text-xs font-medium", TONES[tone])}>
      {children}
    </span>
  );
}

const STATUS_TONE: Record<string, keyof typeof TONES> = {
  OPEN: "bad",
  REOPENED: "bad",
  IN_PROGRESS: "warn",
  RESOLVED: "good",
  FALSE_POSITIVE: "neutral",
  ACCEPTED_RISK: "neutral",
  COMPLETED: "good",
  RUNNING: "info",
  QUEUED: "neutral",
  FAILED: "bad",
  CANCELLED: "neutral",
  PASS: "good",
  FAIL: "bad",
  STILL_OPEN: "warn",
  NEW: "bad",
  REGRESSION: "bad",
  NOT_TESTED: "neutral",
  NOT_REPRODUCED: "neutral",
  VULNERABLE: "bad",
  NO_KNOWN_VULNERABILITIES: "good",
  NOT_VERIFIED: "warn",
};

export function StatusPill({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-muted">—</span>;
  return <Pill tone={STATUS_TONE[value] ?? "neutral"}>{label(value)}</Pill>;
}

const VERIFICATION_HELP: Record<string, string> = {
  DETECTED: "Reported by a deterministic scanner with recorded evidence",
  AI_SUGGESTED: "Supported only by an AI signal; not confirmed",
  CONFIRMED: "Confirmed by a person or by direct dynamic evidence",
  FALSE_POSITIVE: "Triaged as not a real issue",
  NOT_TESTED: "Could not be tested",
};

export function VerificationPill({ value }: { value: string }) {
  const tone = value === "CONFIRMED" ? "bad" : value === "AI_SUGGESTED" ? "info" : value === "FALSE_POSITIVE" ? "neutral" : "warn";
  return (
    <Pill tone={tone} title={VERIFICATION_HELP[value]}>
      {label(value)}
    </Pill>
  );
}

// ------------------------------------------------------------------ layout

export function PageHeader({ title, subtitle, actions, eyebrow }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow && <div className="mb-1 text-xs font-medium uppercase tracking-wider text-muted">{eyebrow}</div>}
        <h1 className="truncate text-2xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <div className="mt-1 text-sm text-ink-2">{subtitle}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Card({ title, actions, children, className, bodyClassName }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClassName?: string }) {
  return (
    <section className={clsx("card", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3.5">
          <h2 className="text-sm font-semibold">{title}</h2>
          {actions}
        </header>
      )}
      <div className={clsx("p-5", bodyClassName)}>{children}</div>
    </section>
  );
}

export function Stat({ label: text, value, hint, color }: { label: string; value: ReactNode; hint?: ReactNode; color?: string }) {
  return (
    <div className="card p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-muted">{text}</div>
      <div className="mt-1.5 text-3xl font-semibold tabular-nums" style={color ? { color } : undefined}>
        {value}
      </div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function EmptyState({ icon, title, children, action }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
      {icon && <div className="mb-3 text-muted">{icon}</div>}
      <div className="font-medium">{title}</div>
      {children && <div className="mt-1 max-w-md text-sm text-ink-2">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={clsx("animate-spin text-muted", className ?? "h-5 w-5")} aria-label="Loading" />;
}

export function Loading({ text = "Loading…" }: { text?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-16 text-sm text-muted">
      <Spinner /> {text}
    </div>
  );
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "Something went wrong";
}

/** Field-level problems from the server's validation errors ("email: value is not a valid email address"). */
export function validationProblems(error: unknown): string[] {
  if (!(error instanceof ApiError) || !Array.isArray(error.details?.problems)) return [];
  return (error.details.problems as { location?: unknown[]; message?: unknown }[]).slice(0, 5).map((problem) => {
    const field = (problem.location ?? []).map(String).filter((part) => part !== "body").join(".");
    const message = String(problem.message ?? "invalid");
    return field ? `${field}: ${message}` : message;
  });
}

export function ErrorBox({ error, title = "Could not load this" }: { error: unknown; title?: string }) {
  const problems = validationProblems(error);
  return (
    <div role="alert" className="flex items-start gap-3 rounded-lg border border-fail/40 bg-fail/10 px-4 py-3 text-sm">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-fail" />
      <div>
        <div className="font-medium">{title}</div>
        <div className="text-ink-2">{errorMessage(error)}</div>
        {problems.length > 0 && (
          <ul className="mt-1 list-disc pl-5 text-ink-2">
            {problems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export function Notice({ children, tone = "info" }: { children: ReactNode; tone?: "info" | "warn" }) {
  return (
    <div className={clsx("flex items-start gap-3 rounded-lg border px-4 py-3 text-sm", tone === "warn" ? "border-med/40 bg-med/10" : "border-accent/30 bg-accent/10")}>
      {tone === "warn" ? <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-med" /> : <Info className="mt-0.5 h-4 w-4 shrink-0 text-accent" />}
      <div className="text-ink-2">{children}</div>
    </div>
  );
}

// ------------------------------------------------------------------ tabs

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: ReactNode; count?: number }[]; value: T; onChange: (id: T) => void }) {
  return (
    <div role="tablist" className="mb-5 flex gap-1 overflow-x-auto border-b border-line scrollbar-thin">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          role="tab"
          aria-selected={value === tab.id}
          onClick={() => onChange(tab.id)}
          className={clsx(
            "-mb-px flex items-center gap-2 whitespace-nowrap border-b-2 px-3.5 py-2.5 text-sm font-medium transition-colors",
            value === tab.id ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink",
          )}
        >
          {tab.label}
          {tab.count !== undefined && <span className="rounded-full bg-surface-3 px-1.5 text-xs tabular-nums text-ink-2">{tab.count}</span>}
        </button>
      ))}
    </div>
  );
}

// ------------------------------------------------------------------ modal

export function Modal({ open, title, onClose, children, footer, wide }: { open: boolean; title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    ref.current?.querySelector<HTMLElement>("input, select, textarea, button")?.focus();
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onMouseDown={onClose}>
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(event) => event.stopPropagation()}
        className={clsx("card max-h-[90vh] w-full overflow-y-auto shadow-2xl", wide ? "max-w-3xl" : "max-w-lg")}
      >
        <div className="flex items-center justify-between border-b border-line px-5 py-3.5">
          <h2 className="font-semibold">{title}</h2>
          <button className="btn-ghost p-1.5" onClick={onClose} aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-line px-5 py-3.5">{footer}</div>}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ misc

export function Pagination({ page, pageSize, total, onChange }: { page: number; pageSize: number; total: number; onChange: (page: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (total <= pageSize) return null;
  return (
    <div className="flex items-center justify-between border-t border-line px-4 py-3 text-sm text-ink-2">
      <span className="tabular-nums">
        {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
      </span>
      <div className="flex items-center gap-1">
        <button className="btn-ghost p-1.5" disabled={page <= 1} onClick={() => onChange(page - 1)} aria-label="Previous page">
          <ChevronLeft className="h-4 w-4" />
        </button>
        <span className="px-2 tabular-nums">
          {page} / {pages}
        </span>
        <button className="btn-ghost p-1.5" disabled={page >= pages} onClick={() => onChange(page + 1)} aria-label="Next page">
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

export function KeyValue({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(110px,auto)_1fr] gap-x-4 gap-y-2 text-sm">
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * A labelled form control. The hint sits outside the <label> and is linked with
 * aria-describedby, so the control's accessible name is the label alone.
 */
export function Field({ label: text, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  const hintId = useId();
  let control = children;
  if (hint && isValidElement<{ "aria-describedby"?: string }>(children)) {
    const existing = children.props["aria-describedby"];
    control = cloneElement(children, { "aria-describedby": existing ? `${existing} ${hintId}` : hintId });
  }
  return (
    <div>
      <label className="block">
        <span className="label">{text}</span>
        {control}
      </label>
      {hint && (
        <span id={hintId} className="mt-1 block text-xs text-muted">
          {hint}
        </span>
      )}
    </div>
  );
}

export function Code({ children }: { children: ReactNode }) {
  return <code className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[12.5px] break-all">{children}</code>;
}

export function CodeBlock({ code, className }: { code: string; className?: string }) {
  return (
    <pre className={clsx("overflow-x-auto whitespace-pre-wrap break-words rounded-lg border border-line bg-surface-2 px-3.5 py-2.5 font-mono text-[12.5px] leading-relaxed scrollbar-thin", className)}>
      {code}
    </pre>
  );
}
