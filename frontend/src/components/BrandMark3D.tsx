import clsx from "clsx";
import { useEffect, useId, useRef, type CSSProperties } from "react";
import { BRAND, MARK } from "./brand-paths";

/**
 * The SecureLens mark in 3D: each part of the S ribbon and the lens is an SVG
 * plane in a CSS 3D scene, with extruded "slices" behind the faces so the mark
 * has real thickness when it turns. Transforms and opacity only, so it runs on
 * the compositor and renders instantly — it is used as the loading animation.
 *
 *   idle     slow float (auth pages)
 *   loading  pieces assemble, then the mark sways while the lens ring scans
 *   open     the ribbon parts fly apart and the lens widens: the page opens through it
 *   none     static (reduced motion)
 */
export type MarkAnimation = "none" | "idle" | "loading" | "open";

const SLICES = 5;
// Darker tones of the ribbon gradient for the extruded edge (blue above, violet below).
const EDGE = { upper: ["#0a2566", "#0d318a", "#123fae"], lower: ["#24175f", "#2d1d7c", "#37249a"] };

function edge(kind: "upper" | "lower", slice: number): string {
  const tones = EDGE[kind];
  return tones[Math.min(tones.length - 1, Math.floor((slice / SLICES) * tones.length))];
}

function Plane({ z, children, className }: { z: number; children: React.ReactNode; className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={clsx("sl3d-plane", className)} style={{ "--z": z } as CSSProperties} aria-hidden>
      {children}
    </svg>
  );
}

export function BrandMark3D({
  size = 96,
  animation = "idle",
  interactive = false,
  label = "SecureLens AI",
  className,
}: {
  size?: number;
  animation?: MarkAnimation;
  interactive?: boolean;
  label?: string | null;
  className?: string;
}) {
  const id = `sl3d${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const tilt = useRef<HTMLDivElement>(null);

  // Pointer tilt: the mark leans towards the pointer anywhere on the page.
  useEffect(() => {
    const el = tilt.current;
    if (!interactive || !el || animation === "none") return;
    let frame = 0;
    const onMove = (event: PointerEvent) => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const box = el.getBoundingClientRect();
        const dx = (event.clientX - (box.left + box.width / 2)) / Math.max(window.innerWidth / 2, 1);
        const dy = (event.clientY - (box.top + box.height / 2)) / Math.max(window.innerHeight / 2, 1);
        el.style.setProperty("--ry", `${Math.max(-1, Math.min(1, dx)) * 26}deg`);
        el.style.setProperty("--rx", `${Math.max(-1, Math.min(1, -dy)) * 20}deg`);
      });
    };
    const onLeave = () => {
      el.style.setProperty("--ry", "0deg");
      el.style.setProperty("--rx", "0deg");
    };
    window.addEventListener("pointermove", onMove, { passive: true });
    document.documentElement.addEventListener("pointerleave", onLeave);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("pointermove", onMove);
      document.documentElement.removeEventListener("pointerleave", onLeave);
    };
  }, [interactive, animation]);

  const labelled = label !== null;
  const mask = `url(#${id}-m)`;
  const face = (hook: "upper" | "lower") => (
    <>
      <path d={MARK[hook]} fill={`url(#${id}-g)`} mask={mask} />
      <path d={MARK[hook]} fill={`url(#${id}-s${hook})`} mask={mask} />
    </>
  );
  return (
    <div
      className={clsx("sl3d", `sl3d-${animation}`, className)}
      style={{ "--size": `${size}px`, "--d": `${(size / 64) * 0.9}px` } as CSSProperties}
      role={labelled ? "img" : undefined}
      aria-label={labelled ? label : undefined}
      aria-hidden={labelled ? undefined : true}
    >
      <svg width="0" height="0" className="absolute" aria-hidden focusable="false">
        <defs>
          <mask id={`${id}-m`} maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64">
            <rect width="64" height="64" fill="#fff" />
            <circle cx={MARK.lens.cx} cy={MARK.lens.cy} r={MARK.lens.r + MARK.lens.gap} fill="#000" />
          </mask>
          <linearGradient id={`${id}-g`} gradientUnits="userSpaceOnUse" x1="48" y1="6" x2="16" y2="58">
            <stop offset="0" stopColor={BRAND.cyan} />
            <stop offset="0.48" stopColor={BRAND.blue} />
            <stop offset="1" stopColor={BRAND.violet} />
          </linearGradient>
          {(["upper", "lower"] as const).map((hook) => (
            <radialGradient key={hook} id={`${id}-s${hook}`} gradientUnits="userSpaceOnUse" cx="32" cy={MARK.hookCenters[hook]} r={MARK.outer}>
              {MARK.shade.map(([offset, color, opacity]) => (
                <stop key={offset} offset={offset} stopColor={color} stopOpacity={opacity} />
              ))}
            </radialGradient>
          ))}
        </defs>
      </svg>
      <div ref={tilt} className="sl3d-tilt">
        <div className="sl3d-motion">
          <div className="sl3d-group sl3d-lower">
            {Array.from({ length: SLICES }, (_, i) => (
              <Plane key={i} z={-(SLICES - i)}>
                <path d={MARK.lower} fill={edge("lower", i)} mask={mask} />
              </Plane>
            ))}
            <Plane z={0}>{face("lower")}</Plane>
          </div>
          <div className="sl3d-group sl3d-upper">
            {Array.from({ length: SLICES }, (_, i) => (
              <Plane key={i} z={2 - (SLICES - i)}>
                <path d={MARK.upper} fill={edge("upper", i)} mask={mask} />
              </Plane>
            ))}
            <Plane z={2}>{face("upper")}</Plane>
          </div>
          <div className="sl3d-group sl3d-lens">
            {[3, 4, 5].map((z) => (
              <Plane key={z} z={z}>
                <circle cx={MARK.lens.cx} cy={MARK.lens.cy} r={MARK.lens.r} fill="#050a14" />
              </Plane>
            ))}
            <Plane z={6} className="sl3d-glow">
              <circle cx={MARK.lens.cx} cy={MARK.lens.cy} r={MARK.lens.r} fill={BRAND.navy} />
              <circle
                className="sl3d-ring"
                cx={MARK.lens.cx}
                cy={MARK.lens.cy}
                r={MARK.lens.r - MARK.lens.ring}
                fill="none"
                stroke={BRAND.cyan}
                strokeWidth={MARK.lens.ring}
              />
              <g className="sl3d-glyphs" fill="none" stroke={BRAND.glyph} strokeWidth={MARK.glyph} strokeLinecap="round" strokeLinejoin="round">
                {MARK.glyphs.map((d) => (
                  <path key={d} d={d} pathLength={1} />
                ))}
              </g>
            </Plane>
          </div>
        </div>
      </div>
    </div>
  );
}
