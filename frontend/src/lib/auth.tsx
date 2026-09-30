import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from "react";
import { api, ApiError, onUnauthorized } from "./api";
import { usePrefs } from "./prefs";
import type { Me, Membership } from "./types";

interface Auth {
  me: Me | null;
  loading: boolean;
  initialised: boolean | null;
  membership: Membership | null;
  orgId: string | null;
  can: (permission: string) => boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<Auth | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const { orgId: preferredOrg, setOrgId } = usePrefs();

  const status = useQuery({
    queryKey: ["auth-status"],
    queryFn: () => api.get<{ initialised: boolean }>("/auth/status"),
    staleTime: 60_000,
  });
  const me = useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      try {
        return await api.get<Me>("/auth/me");
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) return null;
        throw error;
      }
    },
    enabled: status.data?.initialised === true,
    staleTime: 30_000,
    retry: false,
  });

  useEffect(
    () =>
      onUnauthorized(() => {
        queryClient.setQueryData(["me"], null);
      }),
    [queryClient],
  );

  const memberships = me.data?.memberships ?? [];
  const membership = memberships.find((m) => m.organization_id === preferredOrg) ?? memberships[0] ?? null;

  useEffect(() => {
    if (membership && membership.organization_id !== preferredOrg) setOrgId(membership.organization_id);
  }, [membership, preferredOrg, setOrgId]);

  const refresh = useCallback(async () => {
    await queryClient.invalidateQueries({ queryKey: ["auth-status"] });
    await queryClient.invalidateQueries({ queryKey: ["me"] });
  }, [queryClient]);

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      queryClient.clear();
      queryClient.setQueryData(["me"], null);
    }
  }, [queryClient]);

  const permissions = useMemo(() => new Set(membership?.permissions ?? []), [membership]);
  const value: Auth = {
    me: me.data ?? null,
    loading: status.isLoading || (status.data?.initialised === true && me.isLoading),
    initialised: status.data?.initialised ?? null,
    membership,
    orgId: membership?.organization_id ?? null,
    can: (permission) => permissions.has(permission),
    refresh,
    logout,
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): Auth {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
