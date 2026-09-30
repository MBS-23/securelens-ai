import { CONFIDENCES, label, SEVERITIES } from "../lib/format";
import type { Confidence, GatePolicy, Severity } from "../lib/types";

export const DEFAULT_GATE: GatePolicy = {
  fail_on: ["CRITICAL", "HIGH"],
  min_confidence: "MEDIUM",
  include_ai_suggested: false,
  fail_on_regression: true,
  max_findings: null,
};

export function GatePolicyEditor({ value, onChange, disabled }: { value: GatePolicy; onChange: (v: GatePolicy) => void; disabled?: boolean }) {
  const toggle = (s: Severity) =>
    onChange({ ...value, fail_on: value.fail_on.includes(s) ? value.fail_on.filter((x) => x !== s) : [...value.fail_on, s] });
  return (
    <fieldset disabled={disabled} className="space-y-4">
      <div>
        <span className="label">Fail on severities</span>
        <div className="flex flex-wrap gap-2">
          {SEVERITIES.map((s) => (
            <label key={s} className="flex items-center gap-1.5 rounded-md border border-line px-2.5 py-1.5 text-sm">
              <input type="checkbox" checked={value.fail_on.includes(s)} onChange={() => toggle(s)} /> {label(s)}
            </label>
          ))}
        </div>
      </div>
      <label className="block">
        <span className="label">Minimum confidence</span>
        <select className="input w-56" value={value.min_confidence} onChange={(e) => onChange({ ...value, min_confidence: e.target.value as Confidence })}>
          {CONFIDENCES.map((c) => (
            <option key={c} value={c}>
              {label(c)}
            </option>
          ))}
        </select>
      </label>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={value.fail_on_regression} onChange={(e) => onChange({ ...value, fail_on_regression: e.target.checked })} />
        Fail when a previously resolved finding reappears (regression)
      </label>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={value.include_ai_suggested} onChange={(e) => onChange({ ...value, include_ai_suggested: e.target.checked })} />
        Let AI-suggested (unconfirmed) findings fail the gate
      </label>
      <label className="block">
        <span className="label">Maximum open findings (optional)</span>
        <input
          className="input w-56"
          type="number"
          min={0}
          value={value.max_findings ?? ""}
          onChange={(e) => onChange({ ...value, max_findings: e.target.value === "" ? null : Number(e.target.value) })}
        />
      </label>
    </fieldset>
  );
}
