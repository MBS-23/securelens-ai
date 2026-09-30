import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FolderKanban, Plus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { EmptyState, ErrorBox, Field, Loading, Modal, PageHeader, StatusPill } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { label, relativeTime, riskColor } from "../../lib/format";
import type { Project } from "../../lib/types";

const EXPOSURES = ["UNKNOWN", "INTERNET_FACING", "INTERNAL"];
const CRITICALITY = ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

function CreateProject({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { orgId } = useAuth();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: "", description: "", exposure: "UNKNOWN", business_criticality: "" });
  const create = useMutation({
    mutationFn: () =>
      api.post<Project>("/projects", {
        organization_id: orgId,
        name: form.name,
        description: form.description,
        exposure: form.exposure,
        business_criticality: form.business_criticality || null,
      }),
    onSuccess: async (project) => {
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      onClose();
      navigate(`/projects/${project.id}`);
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    create.mutate();
  };
  return (
    <Modal
      open={open}
      title="New project"
      onClose={onClose}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" form="create-project" disabled={create.isPending}>
            Create project
          </button>
        </>
      }
    >
      <form id="create-project" onSubmit={submit} className="space-y-4">
        {create.isError && <ErrorBox error={create.error} title="Could not create the project" />}
        <Field label="Name">
          <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required minLength={2} />
        </Field>
        <Field label="Description">
          <textarea className="input" rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Exposure" hint="Used by the Risk Index">
            <select className="input" value={form.exposure} onChange={(e) => setForm({ ...form, exposure: e.target.value })}>
              {EXPOSURES.map((v) => (
                <option key={v} value={v}>
                  {label(v)}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Business criticality" hint="Only used when set">
            <select className="input" value={form.business_criticality} onChange={(e) => setForm({ ...form, business_criticality: e.target.value })}>
              {CRITICALITY.map((v) => (
                <option key={v} value={v}>
                  {v ? label(v) : "Not set"}
                </option>
              ))}
            </select>
          </Field>
        </div>
      </form>
    </Modal>
  );
}

export default function Projects() {
  const { orgId, can } = useAuth();
  const [creating, setCreating] = useState(false);
  const projects = useQuery({
    queryKey: ["projects", orgId],
    queryFn: () => api.get<Project[]>("/projects", { organization_id: orgId }),
    enabled: !!orgId,
  });

  return (
    <>
      <PageHeader
        title="Projects"
        subtitle="Each project groups repositories, scans and findings."
        actions={
          can("project:create") && (
            <button className="btn-primary" onClick={() => setCreating(true)}>
              <Plus className="h-4 w-4" /> New project
            </button>
          )
        }
      />
      {projects.isLoading && <Loading />}
      {projects.isError && <ErrorBox error={projects.error} />}
      {projects.data?.length === 0 && (
        <div className="card">
          <EmptyState icon={<FolderKanban className="h-10 w-10" />} title="No projects you can see">
            {can("project:create") ? "Create one to start scanning." : "Ask an administrator to give you access to a project."}
          </EmptyState>
        </div>
      )}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {projects.data?.map((p) => (
          <Link key={p.id} to={`/projects/${p.id}`} className="card block p-5 transition-colors hover:border-accent/60">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate font-semibold">{p.name}</div>
                <div className="mt-0.5 line-clamp-2 text-sm text-ink-2">{p.description || "No description"}</div>
              </div>
              <div className="text-right">
                <div className="text-2xl font-semibold tabular-nums" style={{ color: riskColor(p.risk_index) }}>
                  {p.risk_index ?? "—"}
                </div>
                <div className="text-[10px] uppercase tracking-wider text-muted">risk</div>
              </div>
            </div>
            <div className="mt-4 flex flex-wrap items-center gap-3 text-xs text-ink-2">
              <span>
                <b className="tabular-nums text-crit">{p.critical_open}</b> critical
              </span>
              <span>
                <b className="tabular-nums text-high">{p.high_open}</b> high
              </span>
              <span>
                <b className="tabular-nums text-ink">{p.open_findings}</b> open
              </span>
              <span className="ml-auto flex items-center gap-2">
                <StatusPill value={p.last_scan_status} /> {relativeTime(p.last_scan_at)}
              </span>
            </div>
          </Link>
        ))}
      </div>
      <CreateProject open={creating} onClose={() => setCreating(false)} />
    </>
  );
}
