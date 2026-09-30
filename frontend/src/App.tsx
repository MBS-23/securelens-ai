import { lazy, Suspense, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router";
import { Layout } from "./components/Layout";
import { Loading } from "./components/ui";
import { useAuth } from "./lib/auth";

const Setup = lazy(() => import("./pages/auth/Setup"));
const Login = lazy(() => import("./pages/auth/Login"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Projects = lazy(() => import("./pages/projects/Projects"));
const ProjectOverview = lazy(() => import("./pages/projects/ProjectOverview"));
const ProjectSettings = lazy(() => import("./pages/projects/ProjectSettings"));
const ProjectMembers = lazy(() => import("./pages/projects/ProjectMembers"));
const Repositories = lazy(() => import("./pages/projects/Repositories"));
const Scans = lazy(() => import("./pages/scans/Scans"));
const NewScan = lazy(() => import("./pages/scans/NewScan"));
const ScanDetail = lazy(() => import("./pages/scans/ScanDetail"));
const CodeView = lazy(() => import("./pages/scans/CodeView"));
const Findings = lazy(() => import("./pages/findings/Findings"));
const FindingDetail = lazy(() => import("./pages/findings/FindingDetail"));
const Retests = lazy(() => import("./pages/retests/Retests"));
const RetestDetail = lazy(() => import("./pages/retests/RetestDetail"));
const Members = lazy(() => import("./pages/settings/Members"));
const ApiKeys = lazy(() => import("./pages/settings/ApiKeys"));
const AuditLog = lazy(() => import("./pages/settings/AuditLog"));
const OrganizationSettings = lazy(() => import("./pages/settings/OrganizationSettings"));
const SystemStatus = lazy(() => import("./pages/settings/SystemStatus"));
const Methodology = lazy(() => import("./pages/Methodology"));
const Account = lazy(() => import("./pages/Account"));
const NotFound = lazy(() => import("./pages/NotFound"));

function RequireSession({ children }: { children: ReactNode }) {
  const { loading, initialised, me } = useAuth();
  const location = useLocation();
  if (loading || initialised === null) return <Loading />;
  if (!initialised) return <Navigate to="/setup" replace />;
  if (!me?.user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

export function App() {
  return (
    <Suspense fallback={<Loading />}>
      <Routes>
        <Route path="/setup" element={<Setup />} />
        <Route path="/login" element={<Login />} />
        <Route
          element={
            <RequireSession>
              <Layout />
            </RequireSession>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="projects" element={<Projects />} />
          <Route path="projects/:projectId" element={<ProjectOverview />} />
          <Route path="projects/:projectId/settings" element={<ProjectSettings />} />
          <Route path="projects/:projectId/members" element={<ProjectMembers />} />
          <Route path="projects/:projectId/repositories" element={<Repositories />} />
          <Route path="projects/:projectId/scans" element={<Scans />} />
          <Route path="projects/:projectId/scans/new" element={<NewScan />} />
          <Route path="projects/:projectId/scans/:scanId" element={<ScanDetail />} />
          <Route path="projects/:projectId/scans/:scanId/code" element={<CodeView />} />
          <Route path="projects/:projectId/findings" element={<Findings />} />
          <Route path="projects/:projectId/findings/:findingId" element={<FindingDetail />} />
          <Route path="projects/:projectId/retests" element={<Retests />} />
          <Route path="projects/:projectId/retests/:retestId" element={<RetestDetail />} />
          <Route path="settings/members" element={<Members />} />
          <Route path="settings/api-keys" element={<ApiKeys />} />
          <Route path="settings/audit" element={<AuditLog />} />
          <Route path="settings/organization" element={<OrganizationSettings />} />
          <Route path="settings/system" element={<SystemStatus />} />
          <Route path="methodology" element={<Methodology />} />
          <Route path="account" element={<Account />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
