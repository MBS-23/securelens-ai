import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { DEFAULT_GATE, GatePolicyEditor } from "../../components/GatePolicyEditor";
import { Card, ErrorBox, Field, Loading, Notice, PageHeader } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { label } from "../../lib/format";
import type { GatePolicy, Project } from "../../lib/types";

export default function ProjectSettings() {
  const { projectId = "" } = useParams();
  const { can } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const project = useQuery({ queryKey: ["project", projectId], queryFn: () => api.get<Project>(`/projects/${projectId}`) });
  const [form, setForm] = useState({ name: "", description: "", exposure: "UNKNOWN", business_criticality: "" });
  const [customGate, setCustomGate] = useState(false);
  const [gate, setGate] = useState<GatePolicy>(DEFAULT_GATE);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!project.data) return;
    const p = project.data;
    setForm({ name: p.name, description: p.description, exposure: p.exposure, business_criticality: p.business_criticality ?? "" });
    setCustomGate(!!p.gate_policy);
    setGate(p.gate_policy ?? DEFAULT_GATE);
  }, [project.data]);

  const save = useMutation({
    mutationFn: () =>
      api.patch<Project>(`/projects/${projectId}`, {
        name: form.name,
        description: form.description,
        exposure: form.exposure,
        business_criticality: form.business_criticality || null,
        clear_business_criticality: !form.business_criticality,
        gate_policy: customGate ? gate : null,
        clear_gate_policy: !customGate,
      }),
    onSuccess: async () => {
      setSaved(true);
      await queryClient.invalidateQueries({ queryKey: ["project", projectId] });
    },
  });
  const remove = useMutation({
    mutationFn: () => api.del(`/projects/${projectId}`),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      navigate("/projects");
    },
  });

  if (project.isLoading) return <Loading />;
  if (project.isError) return <ErrorBox error={project.error} />;

  return (
    <>
      <PageHeader title="Project settings" subtitle={project.data?.name} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Project">
          <div className="space-y-4">
            <Field label="Name">
              <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </Field>
            <Field label="Description">
              <textarea className="input" rows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </Field>
            <Field label="Exposure" hint="Multiplies each finding's contribution to the Risk Index.">
              <select className="input" value={form.exposure} onChange={(e) => setForm({ ...form, exposure: e.target.value })}>
                {["UNKNOWN", "INTERNET_FACING", "INTERNAL"].map((v) => (
                  <option key={v} value={v}>
                    {label(v)}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Business criticality" hint="Used by the Risk Index only when set.">
              <select className="input" value={form.business_criticality} onChange={(e) => setForm({ ...form, business_criticality: e.target.value })}>
                {["", "LOW", "MEDIUM", "HIGH", "CRITICAL"].map((v) => (
                  <option key={v} value={v}>
                    {v ? label(v) : "Not set"}
                  </option>
                ))}
              </select>
            </Field>
          </div>
        </Card>
        <Card title="Security gate">
          <label className="mb-4 flex items-center gap-2 text-sm">
            <input type="checkbox" checked={customGate} onChange={(e) => setCustomGate(e.target.checked)} />
            Use a project-specific gate (otherwise the organization default applies)
          </label>
          <GatePolicyEditor value={gate} onChange={setGate} disabled={!customGate} />
        </Card>
      </div>
      <div className="mt-4 flex items-center gap-3">
        <button className="btn-primary" onClick={() => save.mutate()} disabled={save.isPending || !can("project:update")}>
          Save changes
        </button>
        {saved && !save.isPending && <span className="text-sm text-pass">Saved. The next scan uses these settings.</span>}
      </div>
      {save.isError && <div className="mt-3"><ErrorBox error={save.error} title="Not saved" /></div>}
      {can("project:delete") && (
        <Card title="Delete project" className="mt-8 border-fail/40">
          <Notice tone="warn">The project is hidden and its name freed; scan history is retained for the audit trail.</Notice>
          <button
            className="btn-danger mt-4"
            onClick={() => window.confirm(`Delete ${project.data?.name}?`) && remove.mutate()}
            disabled={remove.isPending}
          >
            Delete project
          </button>
          {remove.isError && <div className="mt-3"><ErrorBox error={remove.error} title="Not deleted" /></div>}
        </Card>
      )}
    </>
  );
}
