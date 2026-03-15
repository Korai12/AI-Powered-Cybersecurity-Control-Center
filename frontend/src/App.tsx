import { Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import ActionsPage from '@/pages/ActionsPage'
import Layout from '@/components/Layout'
import { useAuth } from '@/hooks/useAuth'
import DashboardPage from '@/pages/DashboardPage'
import LoginPage from '@/pages/LoginPage'
//Phase 5.4 
import IncidentDetailPage from '@/pages/IncidentDetailPage'
import HuntPage from '@/pages/HuntPage'

//Phase 6 
import MITREPage from '@/pages/MITRE'
const ROLE_LEVELS: Record<string, number> = {
  analyst: 0,
  senior_analyst: 1,
  soc_manager: 2,
}

function hasMinRole(role: string | null, minimumRole: string) {
  if (!role) return false
  return (ROLE_LEVELS[role] ?? -1) >= (ROLE_LEVELS[minimumRole] ?? 0)
}

function RequireMinimumRole({
  minimumRole,
  children,
}: {
  minimumRole: 'analyst' | 'senior_analyst' | 'soc_manager'
  children: React.ReactNode
}) {
  const { isBootstrapping, role } = useAuth()

  if (isBootstrapping) {
    return (
      <FullScreenStatus
        title="Checking permissions"
        message="Validating the analyst role for this workspace."
      />
    )
  }

  if (!hasMinRole(role, minimumRole)) {
    return (
      <FullScreenStatus
        title="Access denied"
        message={`This page requires ${minimumRole} or higher.`}
      />
    )
  }

  return <>{children}</>
}

function FullScreenStatus({
  title,
  message,
}: {
  title: string
  message: string
}) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center px-6">
      <div className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900/80 p-8 shadow-2xl shadow-black/30">
        <div className="mb-4 flex items-center gap-3">
          <div className="h-3 w-3 rounded-full bg-cyan-400 animate-pulse" />
          <span className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-400">
            ACCC
          </span>
        </div>
        <h1 className="text-2xl font-semibold text-slate-50">{title}</h1>
        <p className="mt-2 text-sm leading-6 text-slate-400">{message}</p>
      </div>
    </div>
  )
}

function PlaceholderPage({
  title,
  description,
}: {
  title: string
  description: string
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6 shadow-lg shadow-black/20">
      <div className="mb-3 inline-flex items-center rounded-full border border-slate-700 bg-slate-800/80 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-cyan-300">
        Phase 4 scaffold
      </div>
      <h2 className="text-2xl font-semibold text-slate-50">{title}</h2>
      <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
        {description}
      </p>
    </div>
  )
}

function RequireAuth() {
  const location = useLocation()
  const { isBootstrapping, isAuthenticated } = useAuth()

  if (isBootstrapping) {
    return (
      <FullScreenStatus
        title="Initializing ACCC session"
        message="Restoring analyst context, validating credentials, and preparing the dashboard."
      />
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />
  }

  return <Outlet />
}

function PublicOnlyRoute() {
  const { isBootstrapping, isAuthenticated } = useAuth()

  if (isBootstrapping) {
    return (
      <FullScreenStatus
        title="Preparing login"
        message="Checking whether an active analyst session already exists."
      />
    )
  }

  if (isAuthenticated) {
    return <Navigate to="/" replace />
  }

  return <Outlet />
}

function AppShell() {
  return (
    <Layout>
      <Outlet />
    </Layout>
  )
}

export default function App() {
  return (
    <Routes>
      <Route element={<PublicOnlyRoute />}>
        <Route path="/login" element={<LoginPage />} />
      </Route>

      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route path="/" element={<DashboardPage />} />

          <Route
            path="/events"
            element={
              <PlaceholderPage
                title="Event Feed"
                description="This route remains part of the documented ACCC route map. In Phase 4, the live alert feed is surfaced directly inside the dashboard while the dedicated event feed page can be expanded in later phases."
              />
            }
          />

          <Route
            path="/incidents"
            element={
              <PlaceholderPage
                title="Incident Management"
                description="Incident workflows remain in the route structure so later phases can attach case handling, triage progression, and analyst collaboration without changing navigation contracts."
              />
            }
          />
          <Route path="/incidents/:incidentId" element={<IncidentDetailPage />} />
          <Route
            path="/chat"
            element={
              <PlaceholderPage
                title="NL Query Interface"
                description="The backend chat system already exists from earlier phases. This route is preserved so the frontend copilot and chat workspace can be connected without breaking the planned application structure."
              />
            }
          />

          <Route
            path="/hunt"
            element={
              <Route path="/hunt" element={<HuntPage />} />
            }
          />

          <Route
            path="/mitre"
            element={
              <Route path="/mitre" element={<MITREPage />} />
            }
          />

          <Route
            path="/actions"
            element={
              <Route path="/actions" element={<ActionsPage />} />
            }
          />

          <Route
            path="/reports"
            element={
              <PlaceholderPage
                title="Incident Reports Library"
                description="Reporting remains intentionally scaffolded. This keeps the planned route contract intact and avoids future router churn."
              />
            }
          />

          <Route
            path="/incidents/:id/graph"
            element={
              <PlaceholderPage
                title="Entity Relationship Graph"
                description="This route is reserved for the incident-linked graph visualization described in the ACCC roadmap and remains available in the router from Phase 4 onward."
              />
            }
          />

          <Route
            path="/ciso"
            element={
              <Route
  path="/ciso"
  element={
    <RequireMinimumRole minimumRole="soc_manager">
      <PlaceholderPage
        title="Executive CISO View"
        description="The executive summary route remains part of the documented frontend structure and is reserved for the SOC Manager role."
      />
    </RequireMinimumRole>
  }
/>
            }
          />

          <Route
            path="/settings"
            element={
              <PlaceholderPage
                title="Settings & Configuration"
                description="Settings stays scaffolded as part of the 11-route application map so future configuration and analyst preferences can be added without changing core navigation."
              />
            }
          />
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
  
}