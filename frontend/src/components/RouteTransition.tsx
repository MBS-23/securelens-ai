import { Suspense, useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { useLocation } from "react-router";
import { usePrefs } from "../lib/prefs";
import { BrandMark3D } from "./BrandMark3D";
import { LogoMark } from "./Logo";

/** The mark assembles for at least this long, so a fast page still gets a readable transition. */
export const COVER_MIN_MS = 240;
/** Length of the "open through the lens" reveal (matches .sl-route-* in index.css). */
export const OPEN_MS = 420;

type Phase = "cover" | "open" | "idle";

/** Mounts only when the page inside the Suspense boundary has everything it needs to render. */
function ReadySignal({ routeKey, onReady }: { routeKey: string; onReady: (key: string) => void }) {
  useLayoutEffect(() => onReady(routeKey), [routeKey, onReady]);
  return null;
}

function StaticLoading() {
  return (
    <div role="status" className="flex flex-col items-center gap-3 py-20 text-sm text-muted">
      <LogoMark className="h-12 w-12" title={null} />
      Loading…
    </div>
  );
}

/**
 * Page transitions for the signed-in app. On every change of path the content
 * area is covered by the 3D mark, which assembles while the page loads; once
 * the page is ready (and the short minimum has passed) the page opens through
 * the lens. Nothing is delayed beyond real loading plus COVER_MIN_MS, the
 * sidebar and header stay usable, and with reduced motion (the viewer's or the
 * operating system's setting) pages simply appear.
 */
export function RouteTransition({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const { reduceMotion } = usePrefs();
  const [phase, setPhase] = useState<Phase>(reduceMotion ? "idle" : "cover");
  const main = useRef<HTMLElement>(null);
  const latest = useRef(pathname);
  const readyKey = useRef<string | null>(null);
  const minKey = useRef<string | null>(null);
  const timers = useRef<number[]>([]);

  const clearTimers = () => {
    timers.current.forEach((t) => window.clearTimeout(t));
    timers.current = [];
  };

  const tryOpen = useCallback((key: string) => {
    if (key !== latest.current || readyKey.current !== key || minKey.current !== key) return;
    setPhase("open");
    timers.current.push(window.setTimeout(() => setPhase((p) => (p === "open" ? "idle" : p)), OPEN_MS));
  }, []);

  const onReady = useCallback(
    (key: string) => {
      readyKey.current = key;
      tryOpen(key);
    },
    [tryOpen],
  );

  useLayoutEffect(() => {
    latest.current = pathname;
    main.current?.scrollTo?.({ top: 0 });
    clearTimers();
    if (reduceMotion) {
      setPhase("idle");
      return;
    }
    setPhase("cover");
    timers.current.push(
      window.setTimeout(() => {
        minKey.current = pathname;
        tryOpen(pathname);
      }, COVER_MIN_MS),
    );
    return clearTimers;
  }, [pathname, reduceMotion, tryOpen]);

  useEffect(() => clearTimers, []);

  return (
    <div className="sl-route">
      <main ref={main} className="sl-route-main scrollbar-thin" data-phase={phase}>
        <Suspense fallback={reduceMotion ? <StaticLoading /> : null}>
          <ReadySignal routeKey={pathname} onReady={onReady} />
          {children}
        </Suspense>
      </main>
      {phase !== "idle" && (
        <div className="sl-route-overlay" data-phase={phase} data-testid="route-transition">
          <div className="sl-route-stage" role="status" aria-live="polite">
            <BrandMark3D size={112} animation={phase === "open" ? "open" : "loading"} label={null} />
            <span className="sl-route-caption">Loading</span>
            <span className="sr-only">{phase === "open" ? "Page ready" : "Loading page"}</span>
          </div>
        </div>
      )}
    </div>
  );
}
