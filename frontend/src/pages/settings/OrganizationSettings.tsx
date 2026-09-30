import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { DEFAULT_GATE, GatePolicyEditor } from "../../components/GatePolicyEditor";
import { Card, ErrorBox, Loading, Notice, PageHeader } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { label } from "../../lib/format";
import type { GatePolicy, OrgSettings } from "../../lib/types";

type Weights = Record<string, Record<string, number> | number>;

const GROUPS: { key: string; title: string; help: string }[] = [
  { key: "severity", title: "Severity", help: "Impact if the issue is real" },
  { key: "confidence", title: "Confidence", help: "Strength of the evidence" },
  { key: "exploitability", title: "Exploitability", help: "Proven data flow counts more than a pattern match" },
  { key: "verification", title: "Verification", help: "AI-suggested counts half; false positives count zero" },
  { key: "exposure", title: "Exposure", help: "Project setting" },
  { key: "business_criticality", title: "Business criticality", help: "Project setting, used only when set" },
];

export default function OrganizationSettings() {
  const { orgId, can } = useAuth();
  const queryClient = useQueryClient();
  const manage = can("settings:manage");
  const settings = useQuery({ queryKey: ["org-settings", orgId], queryFn: () => api.get<OrgSettings>(`/organizations/${orgId}/settings`), enabled: !!orgId });
  const [weights, setWeights] = useState<Weights>({});
  const [gate, setGate] = useState<GatePolicy>(DEFAULT_GATE);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (settings.data) {
      setWeights(settings.data.risk_weights);
      setGate(settings.data.gate_policy);
    }
  }, [settings.data]);

  const onSaved = (data: OrgSettings) => {
    queryClient.setQueryData(["org-settings", orgId], data);
    setSaved(true);
  };
  const save = useMutation({
    mutationFn: () => api.patch<OrgSettings>(`/organizations/${orgId}/settings`, { risk_weights: weights, gate_policy: gate }),
    onSuccess: onSaved,
  });
  const reset = useMutation({
    mutationFn: () => api.patch<OrgSettings>(`/organizations/${orgId}/settings`, { reset_risk_weights: true }),
    onSuccess: onSaved,
  });

  if (settings.isLoading) return <Loading />;
  if (settings.isError) return <ErrorBox error={settings.error} />;
  const defaults = settings.data!.risk_defaults;

  const setWeight = (group: string, name: string, value: number) => {
    setSaved(false);
    setWeights((w) => ({ ...w, [group]: { ...(w[group] as Record<string, number>), [name]: value } }));
  };

  return (
    <>
      <PageHeader title="Risk & gate policy" subtitle="How the SecureLens Risk Index is weighted, and when the security gate fails a build." />
      <div className="mb-4">
        <Notice>{settings.data!.risk_methodology}</Notice>
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Risk Index weights" className="xl:col-span-2">
          <div className="grid gap-5 md:grid-cols-2">
            {GROUPS.map((g) => (
              <div key={g.key}>
                <div className="text-sm font-medium">{g.title}</div>
                <div className="mb-2 text-xs text-muted">{g.help}</div>
                <div className="space-y-1.5">
                  {Object.entries((weights[g.key] as Record<string, number>) ?? {}).map(([name, value]) => (
                    <label key={name} className="flex items-center justify-between gap-3 text-sm">
                      <span className="text-ink-2">{label(name)}</span>
                      <span className="flex items-center gap-2">
                        {value !== (defaults[g.key] as Record<string, number>)[name] && (
                          <span className="text-[11px] text-muted">default {(defaults[g.key] as Record<string, number>)[name]}</span>
                        )}
                        <input
                          type="number"
                          step="0.05"
                          min={0}
                          max={100}
                          className="input w-24 py-1 text-right tabular-nums"
                          value={value}
                          disabled={!manage}
                          onChange={(e) => setWeight(g.key, name, Number(e.target.value))}
                        />
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            ))}
            <div>
              <div className="text-sm font-medium">Saturation constant K</div>
              <div className="mb-2 text-xs text-muted">Larger K means the index rises more slowly as risk accumulates.</div>
              <input
                type="number"
                min={1}
                max={10000}
                className="input w-32 tabular-nums"
                value={weights.saturation as number}
                disabled={!manage}
                onChange={(e) => {
                  setSaved(false);
                  setWeights((w) => ({ ...w, saturation: Number(e.target.value) }));
                }}
              />
            </div>
          </div>
        </Card>
        <Card title="Default security gate">
          <GatePolicyEditor value={gate} onChange={(g) => { setSaved(false); setGate(g); }} disabled={!manage} />
          <p className="mt-4 text-xs text-muted">Projects can override this under Project settings. CI uses the gate to decide the exit code.</p>
        </Card>
      </div>
      {manage && (
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button className="btn-primary" onClick={() => save.mutate()} disabled={save.isPending}>
            Save
          </button>
          <button className="btn-secondary" onClick={() => reset.mutate()} disabled={reset.isPending}>
            Reset weights to defaults
          </button>
          {saved && <span className="text-sm text-pass">Saved. New scans use these values.</span>}
        </div>
      )}
      {(save.isError || reset.isError) && (
        <div className="mt-3">
          <ErrorBox error={save.error ?? reset.error} title="Not saved" />
        </div>
      )}
    </>
  );
}
