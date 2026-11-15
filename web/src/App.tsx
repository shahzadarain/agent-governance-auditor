// SPDX-License-Identifier: Apache-2.0

import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import { Logo } from "./components/Icons";
import { Shell } from "./components/Shell";
import { ErrorState } from "./components/ui";
import { AuditPage, ConnectPage, NotFoundPage, UsersPage } from "./pages/Admin";
import { AgentDetail } from "./pages/AgentDetail";
import { Compare } from "./pages/Compare";
import { ControlDetail } from "./pages/ControlDetail";
import { FindingDetail, Findings } from "./pages/Findings";
import { Login } from "./pages/Login";
import { Overview } from "./pages/Overview";
import { ProjectDetail } from "./pages/ProjectDetail";
import { Projects } from "./pages/Projects";
import { CatalogPage, PoliciesPage } from "./pages/Reference";
import { ScanPage } from "./pages/ScanPage";
import { Setup } from "./pages/Setup";

function Splash() {
  return (
    <div className="splash" role="status" aria-live="polite">
      <Logo size={56} />
      <p>Loading AgentGov Auditor…</p>
    </div>
  );
}

/** Sends a visitor to setup or sign-in when there is no session. */
function Protected() {
  const { phase } = useAuth();
  const location = useLocation();
  if (phase === "setup") return <Navigate to="/setup" replace />;
  if (phase === "anonymous") return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  return <Shell />;
}

function LoginRoute() {
  const { phase } = useAuth();
  const location = useLocation();
  if (phase === "setup") return <Navigate to="/setup" replace />;
  if (phase === "signed-in") {
    const from = (location.state as { from?: unknown } | null)?.from;
    // Only a local path is accepted as a return target.
    const to = typeof from === "string" && from.startsWith("/") && !from.startsWith("//") ? from : "/";
    return <Navigate to={to} replace />;
  }
  return <Login />;
}

function SetupRoute() {
  const { phase } = useAuth();
  if (phase === "anonymous") return <Navigate to="/login" replace />;
  if (phase === "signed-in") return <Navigate to="/" replace />;
  return <Setup />;
}

function Root() {
  const { phase, error, retry } = useAuth();
  if (phase === "loading") return <Splash />;
  if (phase === "error" && error) {
    return (
      <div className="splash">
        <Logo size={56} />
        <ErrorState error={error} onRetry={retry} />
      </div>
    );
  }
  return (
    <Routes>
      <Route path="/setup" element={<SetupRoute />} />
      <Route path="/login" element={<LoginRoute />} />
      <Route element={<Protected />}>
        <Route index element={<Overview />} />
        <Route path="projects" element={<Projects />} />
        <Route path="projects/:projectId" element={<ProjectDetail />} />
        <Route path="agents/:agentKey" element={<AgentDetail />} />
        <Route path="agents/:agentKey/compare" element={<Compare />} />
        <Route path="scans/:scanId" element={<ScanPage />} />
        <Route path="scans/:scanId/findings" element={<Findings />} />
        <Route path="scans/:scanId/findings/:findingId" element={<FindingDetail />} />
        <Route path="scans/:scanId/controls/:controlId" element={<ControlDetail />} />
        <Route path="connect" element={<ConnectPage />} />
        <Route path="controls" element={<CatalogPage />} />
        <Route path="policies" element={<PoliciesPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="users" element={<UsersPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}

export function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Root />
      </BrowserRouter>
    </AuthProvider>
  );
}
