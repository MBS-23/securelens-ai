import { useMutation } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";
import { ErrorBox, Field, Loading } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import type { LoginResponse } from "../../lib/types";
import { AuthShell } from "./AuthShell";

export default function Login() {
  const { initialised, me, loading, refresh } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const login = useMutation({
    mutationFn: () => api.post<LoginResponse>("/auth/login", { email, password }),
    onSuccess: async () => {
      await refresh();
      const from = (location.state as { from?: string } | null)?.from;
      // Only same-app paths: "//host" would be a protocol-relative URL.
      navigate(from && from.startsWith("/") && !from.startsWith("//") ? from : "/", { replace: true });
    },
  });

  if (loading) return <Loading />;
  if (initialised === false) return <Navigate to="/setup" replace />;
  if (me?.user) return <Navigate to="/" replace />;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    login.mutate();
  };

  return (
    <AuthShell title="Sign in" subtitle="Use the account your SecureLens administrator created for you.">
      <form onSubmit={submit} className="space-y-4">
        {login.isError && <ErrorBox error={login.error} title="Sign-in failed" />}
        <Field label="Email">
          <input className="input" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </Field>
        <Field label="Password">
          <input
            className="input"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </Field>
        <button className="btn-primary w-full" disabled={login.isPending}>
          {login.isPending ? "Signing in…" : "Sign in"}
        </button>
        <p className="text-xs text-muted">Repeated failed attempts temporarily lock the account.</p>
      </form>
    </AuthShell>
  );
}
