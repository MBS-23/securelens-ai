import { useMutation } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router";
import { ErrorBox, Field, Loading } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import type { LoginResponse } from "../../lib/types";
import { AuthShell } from "./AuthShell";

export default function Setup() {
  const { initialised, loading, refresh } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ organization_name: "", display_name: "", email: "", password: "", bootstrap_token: "" });
  const setup = useMutation({
    mutationFn: () =>
      api.post<LoginResponse>("/auth/bootstrap", { ...form, bootstrap_token: form.bootstrap_token || null }),
    onSuccess: async () => {
      await refresh();
      navigate("/", { replace: true });
    },
  });

  if (loading) return <Loading />;
  if (initialised) return <Navigate to="/login" replace />;

  const update = (key: keyof typeof form) => (event: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [key]: event.target.value }));
  const submit = (event: FormEvent) => {
    event.preventDefault();
    setup.mutate();
  };

  return (
    <AuthShell title="Set up SecureLens" subtitle="Create the organization and its first owner account. This page works only once.">
      <form onSubmit={submit} className="space-y-4">
        {setup.isError && <ErrorBox error={setup.error} title="Setup failed" />}
        <Field label="Organization">
          <input className="input" value={form.organization_name} onChange={update("organization_name")} required minLength={2} />
        </Field>
        <Field label="Your name">
          <input className="input" value={form.display_name} onChange={update("display_name")} required autoComplete="name" />
        </Field>
        <Field label="Email">
          <input className="input" type="email" value={form.email} onChange={update("email")} required autoComplete="username" />
        </Field>
        <Field label="Password" hint="At least 12 characters. Common passwords are rejected.">
          <input
            className="input"
            type="password"
            value={form.password}
            onChange={update("password")}
            required
            minLength={12}
            autoComplete="new-password"
          />
        </Field>
        <Field label="Bootstrap token" hint="Only if the server was started with SECURELENS_BOOTSTRAP_TOKEN (required in production).">
          <input className="input" type="password" value={form.bootstrap_token} onChange={update("bootstrap_token")} autoComplete="off" />
        </Field>
        <button className="btn-primary w-full" disabled={setup.isPending}>
          {setup.isPending ? "Creating…" : "Create organization"}
        </button>
      </form>
    </AuthShell>
  );
}
