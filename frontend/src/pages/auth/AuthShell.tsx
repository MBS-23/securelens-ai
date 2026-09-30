import { CheckCircle2, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";

const POINTS = [
  "Static analysis with data-flow evidence for 8 languages",
  "Secrets and dependency checks that never show full secret values",
  "Vulnerable → Explain → Fix → Retest, verified by a new scan",
  "AI assistance that is advisory, never authoritative",
];

export function AuthShell({ title, subtitle, children }: { title: string; subtitle: string; children: ReactNode }) {
  return (
    <div className="grid min-h-full lg:grid-cols-2">
      <div className="relative hidden overflow-hidden border-r border-line bg-surface lg:block">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(109,141,255,0.18),transparent_45%),radial-gradient(circle_at_80%_70%,rgba(34,211,166,0.14),transparent_45%)]" />
        <div className="relative flex h-full flex-col justify-between p-12">
          <div className="flex items-center gap-3">
            <ShieldCheck className="h-9 w-9 text-accent-2" />
            <div>
              <div className="text-lg font-semibold">SecureLens AI</div>
              <div className="text-xs text-muted">Application & LLM security testing</div>
            </div>
          </div>
          <div>
            <h2 className="max-w-md text-3xl font-semibold leading-tight tracking-tight">
              Find it. Understand it. Fix it. <span className="text-accent-2">Prove it.</span>
            </h2>
            <ul className="mt-6 space-y-3 text-sm text-ink-2">
              {POINTS.map((point) => (
                <li key={point} className="flex items-start gap-2.5">
                  <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-accent-2" />
                  {point}
                </li>
              ))}
            </ul>
          </div>
          <p className="max-w-md text-xs text-muted">
            SecureLens reports are evidence for review, not a guarantee of security. Every finding shows why it was reported.
          </p>
        </div>
      </div>
      <div className="flex items-center justify-center p-6">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-2.5 lg:hidden">
            <ShieldCheck className="h-7 w-7 text-accent-2" />
            <span className="font-semibold">SecureLens AI</span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          <p className="mt-1 text-sm text-ink-2">{subtitle}</p>
          <div className="mt-6">{children}</div>
        </div>
      </div>
    </div>
  );
}
