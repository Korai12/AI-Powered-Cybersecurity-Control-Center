import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import AlertsPage from './pages/AlertsPage'
import IncidentsPage from './pages/IncidentsPage'
import IncidentDetailPage from './pages/IncidentDetailPage'
import ChatPage from './pages/ChatPage'
import HuntPage from './pages/HuntPage'
import MitrePage from './pages/MitrePage'
import ActionsPage from './pages/ActionsPage'
import CISOPage from './pages/CISOPage'
import SettingsPage from './pages/SettingsPage'

// Phase 0: routing shell only — auth guards implemented in Phase 2
export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login"              element={<LoginPage />} />
        <Route path="/"                   element={<DashboardPage />} />
        <Route path="/alerts"             element={<AlertsPage />} />
        <Route path="/incidents"          element={<IncidentsPage />} />
        <Route path="/incidents/:id"      element={<IncidentDetailPage />} />
        <Route path="/incidents/:id/graph" element={<IncidentDetailPage />} />
        <Route path="/chat"               element={<ChatPage />} />
        <Route path="/hunt"               element={<HuntPage />} />
        <Route path="/mitre"              element={<MitrePage />} />
        <Route path="/actions"            element={<ActionsPage />} />
        <Route path="/ciso"               element={<CISOPage />} />
        <Route path="/settings"           element={<SettingsPage />} />
        <Route path="*"                   element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
