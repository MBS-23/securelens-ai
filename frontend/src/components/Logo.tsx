import clsx from "clsx";
import { useId } from "react";
import { BRAND, MARK, WORDMARK } from "./brand-paths";

/**
 * The SecureLens mark: an S ribbon (cyan → electric blue → violet) wrapped
 * around a lens that holds "</>". `flat` drops the ribbon shading for small
 * sizes; `glow` adds the subtle ring glow used on dark backgrounds. Geometry
 * comes from brand/tools/build_brand.py — never redraw it here.
 */
function MarkShapes({ id, flat = false, glow = false }: { id: string; flat?: boolean; glow?: boolean }) {
  return (
    <>
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
        {!flat &&
          (["upper", "lower"] as const).map((hook) => (
            <radialGradient
              key={hook}
              id={`${id}-s${hook}`}
              gradientUnits="userSpaceOnUse"
              cx="32"
              cy={MARK.hookCenters[hook]}
              r={MARK.outer}
            >
              {MARK.shade.map(([offset, color, opacity]) => (
                <stop key={offset} offset={offset} stopColor={color} stopOpacity={opacity} />
              ))}
            </radialGradient>
          ))}
        {glow && (
          <filter id={`${id}-f`} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="1.6" />
          </filter>
        )}
      </defs>
      <g mask={`url(#${id}-m)`}>
        <path d={MARK.lower} fill={`url(#${id}-g)`} />
        <path d={MARK.upper} fill={`url(#${id}-g)`} />
        {!flat && (
          <>
            <path d={MARK.lower} fill={`url(#${id}-slower)`} />
            <path d={MARK.upper} fill={`url(#${id}-supper)`} />
          </>
        )}
      </g>
      {glow && (
        <circle
          cx={MARK.lens.cx}
          cy={MARK.lens.cy}
          r={MARK.lens.r - 0.9}
          fill="none"
          stroke={BRAND.cyan}
          strokeWidth={2.2}
          opacity={0.55}
          filter={`url(#${id}-f)`}
        />
      )}
      <circle cx={MARK.lens.cx} cy={MARK.lens.cy} r={MARK.lens.r} fill={BRAND.navy} />
      <circle
        cx={MARK.lens.cx}
        cy={MARK.lens.cy}
        r={MARK.lens.r - MARK.lens.ring}
        fill="none"
        stroke={BRAND.cyan}
        strokeWidth={MARK.lens.ring}
      />
      <g fill="none" stroke={BRAND.glyph} strokeWidth={MARK.glyph} strokeLinecap="round" strokeLinejoin="round">
        {MARK.glyphs.map((d) => (
          <path key={d} d={d} />
        ))}
      </g>
    </>
  );
}

function useSvgId(prefix: string): string {
  return `${prefix}${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
}

/** The symbol alone: compact headers, loaders, favicon-like placements. */
export function LogoMark({
  className,
  title = "SecureLens AI",
  flat = false,
  glow = false,
}: {
  className?: string;
  title?: string | null;
  flat?: boolean;
  glow?: boolean;
}) {
  const id = useSvgId("slm");
  const labelled = title !== null;
  return (
    <svg
      viewBox="0 0 64 64"
      className={clsx("shrink-0 overflow-visible", className)}
      role={labelled ? "img" : undefined}
      aria-label={labelled ? title : undefined}
      aria-hidden={labelled ? undefined : true}
      focusable="false"
    >
      <MarkShapes id={id} flat={flat} glow={glow} />
    </svg>
  );
}

/** Symbol + "SecureLens AI" — "AI" carries the cyan → blue gradient; the rest follows --brand-ink. */
export function Logo({ className, glow = false }: { className?: string; glow?: boolean }) {
  const id = useSvgId("sll");
  return (
    <svg
      viewBox={`0 0 ${WORDMARK.width} ${WORDMARK.height}`}
      className={clsx("shrink-0 overflow-visible", className)}
      role="img"
      aria-label="SecureLens AI"
      focusable="false"
    >
      <defs>
        <linearGradient id={`${id}-t`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor={BRAND.cyan} />
          <stop offset="1" stopColor={BRAND.blue} />
        </linearGradient>
      </defs>
      <g transform={`translate(${WORDMARK.markDx} 0)`}>
        <MarkShapes id={id} glow={glow} />
      </g>
      <path d={WORDMARK.name.d} fill="var(--brand-ink)" transform={`translate(${WORDMARK.name.x} ${WORDMARK.name.y})`} />
      <path d={WORDMARK.ai.d} fill={`url(#${id}-t)`} transform={`translate(${WORDMARK.ai.x} ${WORDMARK.ai.y})`} />
    </svg>
  );
}

/** "CODE | ANALYZE | REMEDIATE | VERIFY" (or the secondary line) as live, accessible text. */
export function Tagline({ variant = "primary", className }: { variant?: "primary" | "secondary"; className?: string }) {
  const words = BRAND.taglines[variant];
  return (
    <p className={clsx("font-display text-[10px] font-semibold uppercase tracking-[0.28em] text-[var(--brand-muted)]", className)}>
      {words.map((word, i) => (
        <span key={word}>
          {word}
          {i < words.length - 1 && (
            <>
              {" "}
              <span aria-hidden className="mx-[0.35em] text-line-strong">
                |
              </span>{" "}
            </>
          )}
        </span>
      ))}
    </p>
  );
}
