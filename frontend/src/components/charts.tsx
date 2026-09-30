import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { label, riskColor, SEVERITIES, SEVERITY_COLOR } from "../lib/format";
import type { Severity } from "../lib/types";

const axis = { stroke: "var(--muted)", fontSize: 11, tickLine: false, axisLine: false } as const;
const tooltipStyle = {
  contentStyle: { background: "var(--surface-2)", border: "1px solid var(--line)", borderRadius: 8, fontSize: 12, color: "var(--ink)" },
  labelStyle: { color: "var(--ink-2)" },
  itemStyle: { color: "var(--ink)" },
  cursor: { fill: "var(--surface-3)", opacity: 0.4 },
};

export function RiskGauge({ value, size = 132 }: { value: number | null; size?: number }) {
  const v = value ?? 0;
  const stroke = 12;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  return (
    <div className="relative" style={{ width: size, height: size }} role="img" aria-label={`SecureLens Risk Index ${value ?? "not available"}`}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="var(--surface-3)" strokeWidth={stroke} fill="none" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          stroke={riskColor(value)}
          strokeWidth={stroke}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${(v / 100) * c} ${c}`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-3xl font-semibold tabular-nums">{value === null ? "—" : Math.round(v)}</div>
        <div className="text-[10px] uppercase tracking-wider text-muted">of 100</div>
      </div>
    </div>
  );
}

export function SeverityDonut({ counts }: { counts: Record<Severity, number> }) {
  const data = SEVERITIES.map((s) => ({ name: s, value: counts[s] ?? 0 })).filter((d) => d.value > 0);
  const total = data.reduce((sum, d) => sum + d.value, 0);
  return (
    <div className="flex items-center gap-6">
      <div className="relative h-40 w-40 shrink-0">
        {total > 0 ? (
          <ResponsiveContainer>
            <PieChart>
              <Pie data={data} dataKey="value" nameKey="name" innerRadius={52} outerRadius={72} paddingAngle={2} stroke="none" isAnimationActive={false}>
                {data.map((d) => (
                  <Cell key={d.name} fill={SEVERITY_COLOR[d.name as Severity]} />
                ))}
              </Pie>
              <Tooltip {...tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-full w-full rounded-full border-[20px] border-surface-3" />
        )}
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-2xl font-semibold tabular-nums">{total}</div>
          <div className="text-[10px] uppercase tracking-wider text-muted">open</div>
        </div>
      </div>
      <ul className="space-y-1.5 text-sm">
        {SEVERITIES.map((s) => (
          <li key={s} className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEVERITY_COLOR[s] }} />
            <span className="w-20 text-ink-2">{label(s)}</span>
            <span className="tabular-nums font-medium">{counts[s] ?? 0}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function TrendChart({ data }: { data: { date: string; new: number; resolved: number }[] }) {
  const rows = data.map((d) => ({ ...d, day: d.date.slice(5) }));
  return (
    <div className="h-56">
      <ResponsiveContainer>
        <AreaChart data={rows} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
          <defs>
            <linearGradient id="gNew" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--crit)" stopOpacity={0.35} />
              <stop offset="100%" stopColor="var(--crit)" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gResolved" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--pass)" stopOpacity={0.35} />
              <stop offset="100%" stopColor="var(--pass)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--line)" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="day" {...axis} interval={4} />
          <YAxis {...axis} allowDecimals={false} />
          <Tooltip {...tooltipStyle} />
          <Area type="monotone" dataKey="new" name="New" stroke="var(--crit)" fill="url(#gNew)" strokeWidth={2} isAnimationActive={false} />
          <Area type="monotone" dataKey="resolved" name="Resolved" stroke="var(--pass)" fill="url(#gResolved)" strokeWidth={2} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function RiskHistoryChart({ data }: { data: { finished_at: string | null; risk_index: number }[] }) {
  const rows = data.map((d, i) => ({ i: i + 1, risk: d.risk_index, when: d.finished_at ? new Date(d.finished_at).toLocaleDateString() : "" }));
  return (
    <div className="h-56">
      <ResponsiveContainer>
        <LineChart data={rows} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
          <CartesianGrid stroke="var(--line)" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="when" {...axis} minTickGap={24} />
          <YAxis {...axis} domain={[0, 100]} />
          <Tooltip {...tooltipStyle} />
          <Line type="monotone" dataKey="risk" name="Risk index" stroke="var(--accent)" strokeWidth={2.5} dot={{ r: 3 }} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export function HorizontalBars({ data, color = "var(--accent)" }: { data: { name: string; value: number }[]; color?: string }) {
  return (
    <div style={{ height: Math.max(120, data.length * 30) }}>
      <ResponsiveContainer>
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, left: 8, bottom: 0 }}>
          <XAxis type="number" {...axis} allowDecimals={false} />
          <YAxis type="category" dataKey="name" {...axis} width={170} />
          <Tooltip {...tooltipStyle} />
          <Bar dataKey="value" name="Findings" fill={color} radius={[0, 4, 4, 0]} isAnimationActive={false} barSize={16} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
