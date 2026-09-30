import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FolderGit2, Plus, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useParams } from "react-router";
import { EmptyState, ErrorBox, Field, Loading, Modal, Notice, PageHeader, Pill } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { relativeTime } from "../../lib/format";
import type { Repository, SystemStatus } from "../../lib/types";

export default function Repositories() {
  const { projectId = "" } = useParams();
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ name: "", url: "", default_branch: "" });
  const repos = useQuery({ queryKey: ["repositories", projectId], queryFn: () => api.get<Repository[]>(`/projects/${projectId}/repositories`) });
  const system = useQuery({ queryKey: ["system-status"], queryFn: () => api.get<SystemStatus>("/system/status") });
  const add = useMutation({
    mutationFn: () =>
      api.post(`/projects/${projectId}/repositories`, { name: form.name, source_type: "GIT", url: form.url, default_branch: form.default_branch || null }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["repositories", projectId] });
      setAdding(false);
      setForm({ name: "", url: "", default_branch: "" });
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/projects/${projectId}/repositories/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["repositories", projectId] }),
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    add.mutate();
  };

  return (
    <>
      <PageHeader
        title="Repositories"
        subtitle="Git remotes and upload series in this project. Scans of the same repository are compared over time."
        actions={
          can("scan:create") && (
            <button className="btn-primary" onClick={() => setAdding(true)}>
              <Plus className="h-4 w-4" /> Add git repository
            </button>
          )
        }
      />
      {repos.isLoading && <Loading />}
      {repos.isError && <ErrorBox error={repos.error} />}
      {remove.isError && <ErrorBox error={remove.error} title="Could not remove the repository" />}
      {repos.data && (
        <div className="card overflow-hidden">
          {repos.data.length === 0 ? (
            <EmptyState icon={<FolderGit2 className="h-10 w-10" />} title="No repositories yet">
              Uploads create a repository automatically; add a git repository to scan a branch directly.
            </EmptyState>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Source</th>
                  <th>Default branch</th>
                  <th>Added</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {repos.data.map((r) => (
                  <tr key={r.id}>
                    <td className="font-medium">{r.name}</td>
                    <td>
                      <Pill tone={r.source_type === "GIT" ? "info" : "neutral"}>{r.source_type === "GIT" ? "Git" : "Uploads"}</Pill>
                      {r.url && <div className="mt-1 font-mono text-xs text-ink-2 break-all">{r.url}</div>}
                    </td>
                    <td className="font-mono text-xs">{r.default_branch ?? "—"}</td>
                    <td className="text-ink-2">{relativeTime(r.created_at)}</td>
                    <td className="text-right">
                      {can("project:update") && (
                        <button
                          className="btn-ghost p-1.5"
                          aria-label={`Remove ${r.name}`}
                          onClick={() => window.confirm(`Remove ${r.name}? Scan history is kept.`) && remove.mutate(r.id)}
                        >
                          <Trash2 className="h-4 w-4" />
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
        open={adding}
        title="Add git repository"
        onClose={() => setAdding(false)}
        footer={
          <>
            <button className="btn-secondary" onClick={() => setAdding(false)}>
              Cancel
            </button>
            <button className="btn-primary" form="add-repo" disabled={add.isPending}>
              Add
            </button>
          </>
        }
      >
        <form id="add-repo" onSubmit={submit} className="space-y-4">
          {add.isError && <ErrorBox error={add.error} title="Not added" />}
          <Notice>
            Only credential-free HTTPS URLs on allowed hosts are accepted
            {system.data ? ` (${system.data.git_allowed_hosts.join(", ")})` : ""}. Private repositories use a token configured on the server as an
            environment variable — never pasted here.
          </Notice>
          <Field label="Name">
            <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          </Field>
          <Field label="HTTPS URL">
            <input
              className="input font-mono"
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.target.value })}
              placeholder="https://github.com/owner/repository"
              required
            />
          </Field>
          <Field label="Default branch">
            <input className="input font-mono" value={form.default_branch} onChange={(e) => setForm({ ...form, default_branch: e.target.value })} placeholder="main" />
          </Field>
        </form>
      </Modal>
    </>
  );
}
