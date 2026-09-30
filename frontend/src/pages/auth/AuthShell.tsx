import { CheckCircle2 } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { BrandMark3D, type MarkAnimation } from "../../components/BrandMark3D";
import { Logo, Tagline } from "../../components/Logo";
import { usePrefs } from "../../lib/prefs";

// Only capabilities that exist today; planned features are not advertised here.
const POINTS = [
  "Static analysis with data-flow evidence for 8 language families",
  "Secret and dependency checks that never show full secret values",
  "Every finding explains why it was reported",
  "Retests that verify a fix with a new scan",
];

export function AuthShell({ title, subtitle, children }: { title: string; subtitle: string; children: ReactNode }) {
  const { reduceMotion } = usePrefs();
  // The mark assembles once, then floats and follows the pointer.
  const [animation, setAnimation] = useState<MarkAnimation>(reduceMotion ? "none" : "loading");
  useEffect(() => {
    if (reduceMotion) {
      setAnimation("none");
      return;
    }
    const timer = window.setTimeout(() => setAnimation("idle"), 900);
    return () => window.clearTimeout(timer);
  }, [reduceMotion]);

  return (
    <div className="grid min-h-full lg:grid-cols-2">
      <div className="hidden border-r border-line bg-surface lg:block">
        <div className="flex h-full flex-col justify-between p-12">
          <div>
            <Logo className="h-11 w-auto" glow />
            <Tagline className="mt-2 pl-[3.6rem]" />
          </div>
          <div>
            <BrandMark3D size={176} animation={animation} interactive={!reduceMotion} label={null} className="mb-10" />
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
          <div className="mb-8 lg:hidden">
            <Logo className="h-8 w-auto" />
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          <p className="mt-1 text-sm text-ink-2">{subtitle}</p>
          <div className="mt-6">{children}</div>
        </div>
      </div>
    </div>
  );
}
