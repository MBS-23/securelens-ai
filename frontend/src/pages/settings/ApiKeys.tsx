import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, KeyRound, Plus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { CodeBlock, EmptyState, ErrorBox, Field, Loading, Modal, Notice, PageHeader, Pill } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { formatDate, label, relativeTime } from "../../lib/format";
import type { ApiKey, Project, Role } from "../../lib/types";

export default function ApiKeys() {
  const { orgId } = useAuth();
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", role: "DEVELOPER" as Role, project_id: "", expires_in_days: 90 });
  const keys = useQuery({ queryKey: ["api-keys", orgId], queryFn: () => api.get<ApiKey[]>(`/organizations/${orgId}/api-keys`), enabled: !!orgId });
  const projects = useQuery({ queryKey: ["projects", orgId], queryFn: () => api.get<Project[]>("/projects", { organization_id: orgId }), enabled: !!orgId });
  const create = useMutation({
    mutationFn: () =>
      api.post<ApiKey & { key: string }>(`/organizations/${orgId}/api-keys`, {
        name: form.name,
        role: form.role,
        project_id: form.project_id || null,
        expires_in_days: form.expires_in_days,
      }),
    onSuccess: async (key) => {
      setCreated(key.key);
      setCreating(false);
      await queryClient.invalidateQueries({ queryKey: ["api-keys", orgId] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.del(`/organizations/${orgId}/api-keys/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["api-keys", orgId] }),
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    create.mutate();
  };
  const projectName = (id: string | null) => projects.data?.find((p) => p.id === id)?.name ?? "—";

  return (
    <>
      <PageHeader
        title="API keys"
        subtitle="For the CLI and CI pipelines (securelens push). Keys are shown once; only a hash is stored."
        actions={
          <button className="btn-primary" onClick={() => setCreating(true)}>
            <Plus className="h-4 w-4" /> New key
          </button>
        }
      />
      {created && (
        <div className="card mb-4 space-y-3 border-pass/50 p-4">
          <div className="font-medium text-pass">Key created — copy it now, it will not be shown again</div>
          <CodeBlock code={created} />
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={() => navigator.clipboard?.writeText(created)}>
              <Copy className="h-4 w-4" /> Copy
            </button>
            <button className="btn-ghost" onClick={() => setCreated(null)}>
              Done
            </button>
          </div>
          <p className="text-xs text-muted">Store it as a CI secret named SECURELENS_API_KEY.</p>
        </div>
      )}
      {revoke.isError && <ErrorBox error={revoke.error} title="Not revoked" />}
      {keys.isLoading && <Loading />}
      {keys.isError && <ErrorBox error={keys.error} />}
      {keys.data && (
        <div className="card overflow-hidden">
          {keys.data.length === 0 ? (
            <EmptyState icon={<KeyRound className="h-10 w-10" />} title="No API keys" />
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Role / scope</th>
                  <th>Last used</th>
                  <th>Expires</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {keys.data.map((k) => (
                  <tr key={k.id}>
                    <td>
                      <div className="font-medium">{k.name}</div>
                      <div className="font-mono text-xs text-muted">{k.prefix}…</div>
                    </td>
                    <td>
                      {label(k.role)}
                      <div className="text-xs text-muted">{k.project_id ? `project: ${projectName(k.project_id)}` : "whole organization"}</div>
                    </td>
                    <td className="text-ink-2">{relativeTime(k.last_used_at)}</td>
                    <td className="text-ink-2">{k.expires_at ? formatDate(k.expires_at) : "never"}</td>
                    <td className="text-right">
                      {k.revoked_at ? (
                        <Pill>revoked</Pill>
                      ) : (
                        <button className="btn-secondary py-1" onClick={() => window.confirm(`Revoke ${k.name}?`) && revoke.mutate(k.id)}>
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
      <Modal
        open={creating}
        title="New API key"
        onClose={() => setCreating(false)}
        footer={
          <>
            <button className="btn-secondary" onClick={() => setCreating(false)}>
              Cancel
            </button>
            <button className="btn-primary" form="new-key" disabled={create.isPending}>
              Create
            </button>
          </>
        }
      >
        <form id="new-key" onSubmit={submit} className="space-y-4">
          {create.isError && <ErrorBox error={create.error} title="Not created" />}
          <Field label="Name">
            <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required placeholder="github-actions" />
          </Field>
          <Field label="Role" hint="A key can never exceed your own role.">
            <select className="input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
              {(["VIEWER", "DEVELOPER", "SECURITY_ANALYST", "ADMIN"] as Role[]).map((r) => (
                <option key={r} value={r}>
                  {label(r)}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Project scope" hint="Developer and viewer keys must be limited to one project.">
            <select className="input" value={form.project_id} onChange={(e) => setForm({ ...form, project_id: e.target.value })}>
              <option value="">Whole organization</option>
              {projects.data?.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Expires after (days)">
            <input
              className="input"
              type="number"
              min={1}
              max={730}
              value={form.expires_in_days}
              onChange={(e) => setForm({ ...form, expires_in_days: Number(e.target.value) })}
            />
          </Field>
          <Notice>Use one key per pipeline so a leaked key can be revoked without breaking others.</Notice>
        </form>
      </Modal>
    </>
  );
}
