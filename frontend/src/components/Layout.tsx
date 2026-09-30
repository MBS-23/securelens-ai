import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import {
  Activity,
  BookOpen,
  Bug,
  Building2,
  FileClock,
  FolderGit2,
  FolderKanban,
  GaugeCircle,
  GraduationCap,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Moon,
  RefreshCcw,
  ScanSearch,
  ServerCog,
  Settings,
  ShieldCheck,
  Sun,
  UserCircle,
  Users,
} from "lucide-react";
import type { ReactNode } from "react";
import { NavLink, Outlet, useMatch, useNavigate } from "react-router";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { label } from "../lib/format";
import { usePrefs } from "../lib/prefs";
import type { Project } from "../lib/types";

function Item({ to, icon, children, end }: { to: string; icon: ReactNode; children: ReactNode; end?: boolean }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        clsx(
          "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors",
          isActive ? "bg-accent/15 font-medium text-ink" : "text-ink-2 hover:bg-surface-3 hover:text-ink",
        )
      }
    >
      <span className="[&>svg]:h-4 [&>svg]:w-4">{icon}</span>
      {children}
    </NavLink>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="mt-5">
      <div className="mb-1.5 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted">{title}</div>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}

function ProjectNav({ projectId }: { projectId: string }) {
  const { can } = useAuth();
  const project = useQuery({ queryKey: ["project", projectId], queryFn: () => api.get<Project>(`/projects/${projectId}`) });
  const base = `/projects/${projectId}`;
  return (
    <Section title={project.data?.name ?? "Project"}>
      <Item to={base} end icon={<GaugeCircle />}>Overview</Item>
      <Item to={`${base}/scans`} icon={<ScanSearch />}>Scans</Item>
      <Item to={`${base}/findings`} icon={<Bug />}>Findings</Item>
      <Item to={`${base}/retests`} icon={<RefreshCcw />}>Retests</Item>
      <Item to={`${base}/repositories`} icon={<FolderGit2 />}>Repositories</Item>
      <Item to={`${base}/members`} icon={<Users />}>Access</Item>
      {can("project:update") && <Item to={`${base}/settings`} icon={<Settings />}>Project settings</Item>}
    </Section>
  );
}

export function Layout() {
  const { me, membership, logout, can } = useAuth();
  const { theme, setTheme, mode, setMode, setOrgId } = usePrefs();
  const navigate = useNavigate();
  const projectMatch = useMatch("/projects/:projectId/*");
  const projectId = projectMatch?.params.projectId;
  const memberships = me?.memberships ?? [];

  return (
    <div className="flex h-full">
      <aside className="hidden w-64 shrink-0 flex-col border-r border-line bg-surface lg:flex">
        <div className="flex items-center gap-2.5 px-5 py-5">
          <ShieldCheck className="h-7 w-7 text-accent-2" />
          <div>
            <div className="font-semibold leading-tight">SecureLens AI</div>
            <div className="text-[11px] text-muted">AppSec · AI security · Secure coding</div>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto px-3 pb-4 scrollbar-thin">
          <div className="space-y-0.5">
            <Item to="/" end icon={<LayoutDashboard />}>Security dashboard</Item>
            <Item to="/projects" end icon={<FolderKanban />}>Projects</Item>
          </div>
          {projectId && projectId !== "new" && <ProjectNav projectId={projectId} />}
          <Section title="Organization">
            {can("member:read") && <Item to="/settings/members" icon={<Users />}>Members</Item>}
            {can("apikey:manage") && <Item to="/settings/api-keys" icon={<KeyRound />}>API keys</Item>}
            {can("audit:read") && <Item to="/settings/audit" icon={<FileClock />}>Audit log</Item>}
            {can("settings:read") && <Item to="/settings/organization" icon={<Building2 />}>Risk & gate policy</Item>}
            <Item to="/settings/system" icon={<ServerCog />}>System status</Item>
          </Section>
          <Section title="Learn">
            <Item to="/methodology" icon={<BookOpen />}>How SecureLens decides</Item>
          </Section>
        </nav>
        <div className="border-t border-line p-3">
          <Item to="/account" icon={<UserCircle />}>{me?.user?.display_name ?? "Account"}</Item>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-3 border-b border-line bg-surface/80 px-4 py-2.5 backdrop-blur lg:px-8">
          <div className="flex min-w-0 items-center gap-3">
            <ShieldCheck className="h-6 w-6 text-accent-2 lg:hidden" />
            {memberships.length > 1 ? (
              <select
                className="input w-auto py-1.5"
                value={membership?.organization_id}
                onChange={(event) => {
                  setOrgId(event.target.value);
                  navigate("/");
                }}
                aria-label="Organization"
              >
                {memberships.map((m) => (
                  <option key={m.organization_id} value={m.organization_id}>
                    {m.organization_name}
                  </option>
                ))}
              </select>
            ) : (
              <span className="truncate text-sm font-medium">{membership?.organization_name}</span>
            )}
            {membership && <span className="hidden text-xs text-muted sm:inline">{label(membership.role)}</span>}
          </div>
          <div className="flex items-center gap-1.5">
            <div className="flex rounded-lg border border-line p-0.5 text-xs" role="group" aria-label="Explanation mode">
              <button
                onClick={() => setMode("learning")}
                className={clsx("flex items-center gap-1 rounded-md px-2.5 py-1", mode === "learning" ? "bg-accent text-accent-ink" : "text-ink-2")}
                aria-pressed={mode === "learning"}
                title="Learning mode: step-by-step explanations and secure coding examples first"
              >
                <GraduationCap className="h-3.5 w-3.5" /> Learning
              </button>
              <button
                onClick={() => setMode("professional")}
                className={clsx("flex items-center gap-1 rounded-md px-2.5 py-1", mode === "professional" ? "bg-accent text-accent-ink" : "text-ink-2")}
                aria-pressed={mode === "professional"}
                title="Professional mode: evidence and triage first"
              >
                <Activity className="h-3.5 w-3.5" /> Professional
              </button>
            </div>
            <button className="btn-ghost p-2" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label="Toggle colour theme">
              {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
            <button
              className="btn-ghost p-2"
              onClick={async () => {
                await logout();
                navigate("/login");
              }}
              aria-label="Sign out"
              title="Sign out"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto scrollbar-thin">
          <div className="mx-auto w-full max-w-7xl px-4 py-6 lg:px-8 lg:py-8">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
