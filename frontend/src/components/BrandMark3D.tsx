import clsx from "clsx";
import { useEffect, useId, useRef, type CSSProperties } from "react";
import { MARK } from "./brand-paths";

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
const RIBBON_SHADES = { upper: ["#18307a", "#1d3a92", "#2344aa"], lower: ["#2b2474", "#33298c", "#3c2fa4"] };

function shade(kind: "upper" | "lower", slice: number): string {
  const palette = RIBBON_SHADES[kind];
  return palette[Math.min(palette.length - 1, Math.floor((slice / SLICES) * palette.length))];
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
          <linearGradient id={`${id}-u`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor={MARK.colors.upper[0]} />
            <stop offset="1" stopColor={MARK.colors.upper[1]} />
          </linearGradient>
          <linearGradient id={`${id}-l`} x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor={MARK.colors.lower[0]} />
            <stop offset="1" stopColor={MARK.colors.lower[1]} />
          </linearGradient>
        </defs>
      </svg>
      <div ref={tilt} className="sl3d-tilt">
        <div className="sl3d-motion">
          <div className="sl3d-group sl3d-lower">
            {Array.from({ length: SLICES }, (_, i) => (
              <Plane key={i} z={-(SLICES - i)}>
                <path d={MARK.lower} fill={shade("lower", i)} mask={mask} />
              </Plane>
            ))}
            <Plane z={0}>
              <path d={MARK.lower} fill={`url(#${id}-l)`} mask={mask} />
            </Plane>
          </div>
          <div className="sl3d-group sl3d-upper">
            {Array.from({ length: SLICES }, (_, i) => (
              <Plane key={i} z={2 - (SLICES - i)}>
                <path d={MARK.upper} fill={shade("upper", i)} mask={mask} />
              </Plane>
            ))}
            <Plane z={2}>
              <path d={MARK.upper} fill={`url(#${id}-u)`} mask={mask} />
            </Plane>
          </div>
          <div className="sl3d-group sl3d-lens">
            {[3, 4, 5].map((z) => (
              <Plane key={z} z={z}>
                <circle cx={MARK.lens.cx} cy={MARK.lens.cy} r={MARK.lens.r} fill="#050d1c" />
              </Plane>
            ))}
            <Plane z={6}>
              <circle cx={MARK.lens.cx} cy={MARK.lens.cy} r={MARK.lens.r} fill={MARK.colors.lens} />
              <circle
                className="sl3d-ring"
                cx={MARK.lens.cx}
                cy={MARK.lens.cy}
                r={MARK.lens.r - MARK.lens.ring}
                fill="none"
                stroke={MARK.colors.ring}
                strokeWidth={MARK.lens.ring}
              />
              <g className="sl3d-glyphs" fill="none" stroke={MARK.colors.glyph} strokeWidth={MARK.glyph} strokeLinecap="round" strokeLinejoin="round">
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
