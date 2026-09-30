import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Trash2, UserPlus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { ErrorBox, Field, Loading, Modal, PageHeader, Pill } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import { label, relativeTime } from "../../lib/format";
import type { Member, Role } from "../../lib/types";

const ROLES: { role: Role; help: string }[] = [
  { role: "OWNER", help: "Everything, including granting owner and admin" },
  { role: "ADMIN", help: "Members, API keys, settings, audit log, all projects" },
  { role: "SECURITY_ANALYST", help: "All projects; triage false positives and accepted risk; AI security tests" },
  { role: "DEVELOPER", help: "Assigned projects; scan, fix, update status, request AI help" },
  { role: "VIEWER", help: "Assigned projects; read only" },
];

export default function Members() {
  const { orgId, can, membership, me } = useAuth();
  const queryClient = useQueryClient();
  const manage = can("member:manage");
  const [inviting, setInviting] = useState(false);
  const [form, setForm] = useState({ email: "", display_name: "", role: "DEVELOPER" as Role, initial_password: "" });
  const members = useQuery({ queryKey: ["members", orgId], queryFn: () => api.get<Member[]>(`/organizations/${orgId}/members`), enabled: !!orgId });
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["members", orgId] });
  const add = useMutation({
    mutationFn: () => api.post(`/organizations/${orgId}/members`, { ...form, initial_password: form.initial_password || null }),
    onSuccess: async () => {
      await invalidate();
      setInviting(false);
      setForm({ email: "", display_name: "", role: "DEVELOPER", initial_password: "" });
    },
  });
  const update = useMutation({
    mutationFn: ({ id, role }: { id: string; role: Role }) => api.patch(`/organizations/${orgId}/members/${id}`, { role }),
    onSuccess: invalidate,
  });
  const remove = useMutation({ mutationFn: (id: string) => api.del(`/organizations/${orgId}/members/${id}`), onSuccess: invalidate });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    add.mutate();
  };
  const assignable = ROLES.filter((r) => membership?.role === "OWNER" || !["OWNER", "ADMIN"].includes(r.role));

  return (
    <>
      <PageHeader
        title="Members"
        subtitle={membership?.organization_name}
        actions={
          manage && (
            <button className="btn-primary" onClick={() => setInviting(true)}>
              <UserPlus className="h-4 w-4" /> Add member
            </button>
          )
        }
      />
      {(update.isError || remove.isError) && <ErrorBox error={update.error ?? remove.error} title="Not saved" />}
      {members.isLoading && <Loading />}
      {members.isError && <ErrorBox error={members.error} />}
      {members.data && (
        <div className="card overflow-hidden">
          <table className="table">
            <thead>
              <tr>
                <th>Member</th>
                <th>Role</th>
                <th>Joined</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {members.data.map((m) => (
                <tr key={m.membership_id}>
                  <td>
                    <div className="font-medium">
                      {m.display_name} {m.user_id === me?.user?.id && <Pill tone="info">you</Pill>}
                    </div>
                    <div className="text-xs text-muted">{m.email}</div>
                  </td>
                  <td>
                    {manage && m.user_id !== me?.user?.id ? (
                      <select
                        className="input w-48 py-1.5"
                        value={m.role}
                        onChange={(e) => update.mutate({ id: m.membership_id, role: e.target.value as Role })}
                        aria-label={`Role of ${m.email}`}
                      >
                        {ROLES.map((r) => (
                          <option key={r.role} value={r.role} disabled={!assignable.some((a) => a.role === r.role)}>
                            {label(r.role)}
                          </option>
                        ))}
                      </select>
                    ) : (
                      label(m.role)
                    )}
                  </td>
                  <td className="text-ink-2">{relativeTime(m.created_at)}</td>
                  <td className="text-right">
                    {manage && m.user_id !== me?.user?.id && (
                      <button
                        className="btn-ghost p-1.5"
                        aria-label={`Remove ${m.email}`}
                        onClick={() => window.confirm(`Remove ${m.email} from the organization?`) && remove.mutate(m.membership_id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="mt-6 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {ROLES.map((r) => (
          <div key={r.role} className="card p-4">
            <div className="text-sm font-medium">{label(r.role)}</div>
            <div className="mt-1 text-xs text-ink-2">{r.help}</div>
          </div>
        ))}
      </div>
      <Modal
        open={inviting}
        title="Add member"
        onClose={() => setInviting(false)}
        footer={
          <>
            <button className="btn-secondary" onClick={() => setInviting(false)}>
              Cancel
            </button>
            <button className="btn-primary" form="add-member" disabled={add.isPending}>
              Add
            </button>
          </>
        }
      >
        <form id="add-member" onSubmit={submit} className="space-y-4">
          {add.isError && <ErrorBox error={add.error} title="Not added" />}
          <Field label="Email">
            <input className="input" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required />
          </Field>
          <Field label="Name">
            <input className="input" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} required />
          </Field>
          <Field label="Role">
            <select className="input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
              {assignable.map((r) => (
                <option key={r.role} value={r.role}>
                  {label(r.role)} — {r.help}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Initial password" hint="Required for a new account (12+ characters). Share it securely; they can change it under Account.">
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              value={form.initial_password}
              onChange={(e) => setForm({ ...form, initial_password: e.target.value })}
            />
          </Field>
        </form>
      </Modal>
    </>
  );
}
