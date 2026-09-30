import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { UserMinus, UserPlus, Users } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router";
import { EmptyState, ErrorBox, Loading, Notice, PageHeader } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { label, relativeTime } from "../../lib/format";
import type { Member } from "../../lib/types";

interface ProjectMember {
  user_id: string;
  email: string;
  display_name: string;
  added_at: string;
}

export default function ProjectMembers() {
  const { projectId = "" } = useParams();
  const { can, orgId } = useAuth();
  const queryClient = useQueryClient();
  const [userId, setUserId] = useState("");
  const manage = can("project:members:manage");
  const members = useQuery({ queryKey: ["project-members", projectId], queryFn: () => api.get<ProjectMember[]>(`/projects/${projectId}/members`) });
  const orgMembers = useQuery({
    queryKey: ["members", orgId],
    queryFn: () => api.get<Member[]>(`/organizations/${orgId}/members`),
    enabled: manage && !!orgId,
  });
  const add = useMutation({
    mutationFn: () => api.post(`/projects/${projectId}/members`, { user_id: userId }),
    onSuccess: async () => {
      setUserId("");
      await queryClient.invalidateQueries({ queryKey: ["project-members", projectId] });
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.del(`/projects/${projectId}/members/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["project-members", projectId] }),
  });
  const existing = new Set(members.data?.map((m) => m.user_id));
  const candidates = (orgMembers.data ?? []).filter((m) => (m.role === "DEVELOPER" || m.role === "VIEWER") && !existing.has(m.user_id));

  return (
    <>
      <PageHeader title="Project access" subtitle="Owners, admins and security analysts see every project. Developers and viewers see only projects they are added to." />
      <div className="mb-4">
        <Notice>Objects outside your access are reported as “not found”, so their existence is never disclosed.</Notice>
      </div>
      {manage && (
        <div className="card mb-4 flex flex-wrap items-end gap-3 p-4">
          <label className="min-w-64 flex-1">
            <span className="label">Add a developer or viewer</span>
            <select className="input" value={userId} onChange={(e) => setUserId(e.target.value)}>
              <option value="">Choose a member…</option>
              {candidates.map((m) => (
                <option key={m.user_id} value={m.user_id}>
                  {m.display_name} ({m.email}) — {label(m.role)}
                </option>
              ))}
            </select>
          </label>
          <button className="btn-primary" disabled={!userId || add.isPending} onClick={() => add.mutate()}>
            <UserPlus className="h-4 w-4" /> Add
          </button>
        </div>
      )}
      {(add.isError || remove.isError) && <ErrorBox error={add.error ?? remove.error} title="Not saved" />}
      {members.isLoading && <Loading />}
      {members.isError && <ErrorBox error={members.error} />}
      {members.data && (
        <div className="card overflow-hidden">
          {members.data.length === 0 ? (
            <EmptyState icon={<Users className="h-10 w-10" />} title="No project-specific members" />
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Member</th>
                  <th>Added</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {members.data.map((m) => (
                  <tr key={m.user_id}>
                    <td>
                      <div className="font-medium">{m.display_name}</div>
                      <div className="text-xs text-muted">{m.email}</div>
                    </td>
                    <td className="text-ink-2">{relativeTime(m.added_at)}</td>
                    <td className="text-right">
                      {manage && (
                        <button className="btn-ghost p-1.5" aria-label={`Remove ${m.email}`} onClick={() => remove.mutate(m.user_id)}>
                          <UserMinus className="h-4 w-4" />
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
    </>
  );
}
