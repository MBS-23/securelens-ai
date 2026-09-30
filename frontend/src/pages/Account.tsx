import { useMutation } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Card, ErrorBox, Field, KeyValue, Notice, PageHeader } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDate, label } from "../lib/format";

const EMPTY = { current_password: "", new_password: "", confirm: "" };

export default function Account() {
  const { me } = useAuth();
  const [form, setForm] = useState(EMPTY);
  const [mismatch, setMismatch] = useState(false);
  const change = useMutation({
    mutationFn: () =>
      api.post<{ message: string }>("/auth/change-password", {
        current_password: form.current_password,
        new_password: form.new_password,
      }),
    onSuccess: () => setForm(EMPTY),
  });

  const user = me?.user ?? null;
  if (!user) {
    return (
      <>
        <PageHeader title="Account" />
        <Notice>
          You are signed in with an API key{me?.api_key_prefix ? ` (${me.api_key_prefix}…)` : ""}. Account settings are
          available only to people signed in with a password.
        </Notice>
      </>
    );
  }

  const update = (key: keyof typeof EMPTY) => (event: React.ChangeEvent<HTMLInputElement>) => {
    setForm((f) => ({ ...f, [key]: event.target.value }));
    setMismatch(false);
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (form.new_password !== form.confirm) {
      setMismatch(true);
      return;
    }
    change.mutate();
  };

  return (
    <>
      <PageHeader title="Account" subtitle="Your sign-in details and organization roles." />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Profile">
          <KeyValue
            items={[
              ["Name", user.display_name],
              ["Email", user.email],
              ["Last sign-in", formatDate(user.last_login_at)],
              ["Account created", formatDate(user.created_at)],
            ]}
          />
          <h3 className="mt-6 mb-2 text-sm font-semibold">Organizations</h3>
          <ul className="divide-y divide-line text-sm">
            {me?.memberships.map((m) => (
              <li key={m.organization_id} className="flex items-center justify-between gap-3 py-2">
                <span className="min-w-0 truncate">{m.organization_name}</span>
                <span className="text-ink-2">{label(m.role)}</span>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Change password">
          <form onSubmit={submit} className="space-y-4" noValidate={false}>
            {change.isError && <ErrorBox error={change.error} title="Password not changed" />}
            {change.isSuccess && <Notice>{change.data.message}</Notice>}
            <Field label="Current password">
              <input
                className="input"
                type="password"
                value={form.current_password}
                onChange={update("current_password")}
                required
                autoComplete="current-password"
              />
            </Field>
            <Field label="New password" hint="At least 12 characters. Common passwords and your email name are rejected.">
              <input
                className="input"
                type="password"
                value={form.new_password}
                onChange={update("new_password")}
                required
                minLength={12}
                maxLength={128}
                autoComplete="new-password"
              />
            </Field>
            <Field label="Confirm new password">
              <input
                className="input"
                type="password"
                value={form.confirm}
                onChange={update("confirm")}
                required
                autoComplete="new-password"
                aria-invalid={mismatch}
                aria-describedby={mismatch ? "confirm-error" : undefined}
              />
            </Field>
            {mismatch && (
              <p id="confirm-error" role="alert" className="text-sm text-fail">
                The new passwords do not match.
              </p>
            )}
            <p className="text-xs text-muted">Changing your password signs out every other session.</p>
            <button className="btn-primary" disabled={change.isPending}>
              {change.isPending ? "Changing…" : "Change password"}
            </button>
          </form>
        </Card>
      </div>
    </>
  );
}
